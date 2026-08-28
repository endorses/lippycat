//go:build processor || tap || all

// Package processor - Lifecycle Management
//
// This file contains the processor lifecycle management methods:
//   - Start()                    - Initialize and start the processor server
//   - Shutdown()                 - Gracefully shut down all components
//   - createReuseAddrListener()  - Create TCP listener with SO_REUSEADDR
//
// The Start() method coordinates the initialization of:
//  1. Filter loading from persistence file
//  2. Unified PCAP writer (optional)
//  3. Per-call PCAP writer (VoIP, optional)
//  4. Auto-rotating PCAP writer (non-VoIP, optional)
//  5. Upstream processor connection (hierarchical mode)
//  6. Hunter monitor (stale connection cleanup)
//  7. Virtual interface manager (packet injection)
//  8. gRPC server with TLS and keepalive configuration
//
// The Shutdown() dependency order is:
//  1. stop ingress (cancel local PacketSource and reject new gRPC streams)
//  2. drain/force-stop gRPC handlers and wait for local producers
//  3. stop packet consumers (LI, upstream, virtual interfaces, subscribers)
//  4. drain and close unified, auto-rotate, and per-call PCAP writers
//
// No QueuePackets producer may remain when the unified writer is stopped.
package processor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/flow"
	"github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// Start begins processor operation
func (p *Processor) Start(ctx context.Context) error {
	if err := p.validateLIConfiguration(); err != nil {
		return fmt.Errorf("invalid LI configuration: %w", err)
	}
	p.ctx, p.cancel = context.WithCancel(ctx)
	defer p.cancel()

	logger.Info("Processor starting", "processor_id", p.config.ProcessorID, "listen_addr", p.config.ListenAddr)
	// Load filters from persistence file
	if err := p.filterManager.Load(); err != nil {
		logger.Warn("Failed to load filters from file", "error", err)
		// Continue anyway - not a fatal error
	}

	// Apply loaded filters to the filter target (needed for tap/local mode)
	// In distributed mode, filters are pushed when hunters connect.
	// In tap mode, we need to apply them immediately to the LocalTarget/ApplicationFilter.
	loadedFilters := p.filterManager.GetAll()
	if len(loadedFilters) > 0 {
		// Use batch apply if available (more efficient - rebuilds automaton once)
		if batchTarget, ok := p.filterTarget.(interface {
			ApplyFilterBatch([]*management.Filter) (uint32, error)
		}); ok {
			if _, err := batchTarget.ApplyFilterBatch(loadedFilters); err != nil {
				logger.Warn("Failed to batch apply loaded filters", "error", err)
			}
		} else {
			// Fall back to individual apply
			for _, filter := range loadedFilters {
				if _, err := p.filterTarget.ApplyFilter(filter); err != nil {
					logger.Warn("Failed to apply loaded filter", "filter_id", filter.Id, "error", err)
				}
			}
		}
	}

	// Initialize PCAP writer if configured
	if p.config.WriteFile != "" {
		writer, err := pcap.NewWriter(p.config.WriteFile)
		if err != nil {
			return fmt.Errorf("failed to initialize PCAP writer: %w", err)
		}
		p.pcapWriter = writer
		p.pcapWriter.Start(p.ctx)

		// Configure flow controller with PCAP queue metrics
		p.flowController.SetPCAPQueue(p.pcapWriter.QueueDepth, p.pcapWriter.QueueCapacity)
	}

	// Create listener with SO_REUSEADDR for fast restarts
	listener, err := createReuseAddrListener("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	p.listenerMu.Lock()
	p.listener = listener
	p.listenerMu.Unlock()
	if p.logSink != nil {
		if err := p.logSink.Start(p.ctx); err != nil {
			return fmt.Errorf("start structured log sink: %w", err)
		}
	}
	if p.eventDispatcher != nil {
		if err := p.eventDispatcher.Start(p.ctx); err != nil {
			return fmt.Errorf("start event dispatcher: %w", err)
		}
		for _, metric := range p.eventDispatcher.QueueMetrics() {
			p.flowController.SetQueueSource(flow.QueuePressureSource{Name: metric.Name, Depth: metric.Depth, Capacity: metric.Capacity})
		}
	}
	if p.logSink != nil {
		p.flowController.SetQueueSource(flow.QueuePressureSource{Name: "structured_logs", Depth: p.logSink.QueueDepth, Capacity: p.logSink.QueueCapacity})
	}

	// Create gRPC server with TLS if configured
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(constants.MaxGRPCMessageSize),
		// Configure server-side keepalive enforcement
		// Lenient settings to survive network interruptions (laptop standby, etc.)
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // Minimum time between client pings
			PermitWithoutStream: true,             // Allow pings without active streams
		}),
		// Configure server keepalive parameters
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second, // Send ping if no activity for 30s
			Timeout: 20 * time.Second, // Wait 20s for ping ack before closing connection
		}),
	}

	// Check for production mode (via environment variable)
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"

	if p.config.TLSEnabled {
		tlsCreds, err := p.buildTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(tlsCreds))

		if p.config.TLSClientAuth {
			logger.Info("gRPC server using TLS with mutual authentication (mTLS)",
				"security", "strong authentication via client certificates")
		} else {
			logger.Warn("gRPC server using TLS WITHOUT mutual authentication",
				"security_risk", "hunters can connect without authentication",
				"recommendation", "enable TLSClientAuth for production deployments",
				"impact", "any network client can register as hunter and access packet data")

			if productionMode {
				return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLSClientAuth=true for mutual TLS authentication")
			}
		}
	} else {
		logger.Warn("gRPC server using insecure connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext, no authentication",
			"recommendation", "enable TLS with mutual authentication for production deployments",
			"severity", "CRITICAL")

		if productionMode {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS to be enabled")
		}
	}

	// Add API key authentication if configured
	if p.config.AuthConfig != nil && p.config.AuthConfig.Enabled {
		validator := auth.NewValidator(*p.config.AuthConfig)
		serverOpts = append(serverOpts,
			grpc.UnaryInterceptor(auth.UnaryServerInterceptor(validator)),
			grpc.StreamInterceptor(auth.StreamServerInterceptor(validator)),
		)

		logger.Info("API key authentication enabled",
			"num_keys", len(p.config.AuthConfig.APIKeys),
			"security", "API key validation on all gRPC methods")

		// In production mode, require either mTLS OR API key auth
		if productionMode && !p.config.TLSClientAuth {
			logger.Info("Production mode: API key authentication replaces mTLS requirement")
		}
	} else if productionMode && !p.config.TLSClientAuth {
		// In production mode without mTLS, require API key auth
		return fmt.Errorf("LIPPYCAT_PRODUCTION=true without mTLS requires API key authentication (set security.api_keys in config)")
	}

	p.grpcServer = grpc.NewServer(serverOpts...)

	// Register services
	data.RegisterDataServiceServer(p.grpcServer, p)
	management.RegisterManagementServiceServer(p.grpcServer, p)

	logger.Info("gRPC server created",
		"addr", listener.Addr().String(),
		"services", []string{"DataService", "ManagementService"},
		"tls", p.config.TLSEnabled)

	// Start server in background
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.grpcServer.Serve(listener); err != nil {
			logger.Error("gRPC server failed", "error", err)
		}
	}()

	// Start upstream connection manager if configured (hierarchical mode)
	// The connection manager handles automatic reconnection on failure
	if p.upstreamManager != nil {
		if err := p.upstreamManager.Start(); err != nil {
			return fmt.Errorf("failed to start upstream connection manager: %w", err)
		}
	}

	// Start hunter monitor (heartbeat monitoring and cleanup)
	p.hunterMonitor.Start(p.ctx)

	// Start call completion monitor (VoIP PCAP file management)
	if p.sessionOutputManager != nil {
		// Wire up voip processor cleanup if available (tap mode with LocalSource)
		if localSrc, ok := p.packetSource.(*source.LocalSource); ok {
			if voipProc := localSrc.GetVoIPProcessor(); voipProc != nil {
				p.sessionOutputManager.SetVoIPPortCleaner(voipProc)
			}
		}
		p.sessionOutputManager.Start()
	}

	// Start LI Manager if configured (no-op if !li build)
	if err := p.startLIManager(); err != nil {
		return fmt.Errorf("failed to start LI manager: %w", err)
	}

	// Start virtual interface if configured
	if p.vifManager != nil {
		if err := p.vifManager.Start(); err != nil {
			// Provide helpful error message for common errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else if errors.Is(err, vinterface.ErrInterfaceExists) {
				logger.Error("Virtual interface already exists",
					"error", err,
					"solution", "Delete existing interface or choose a different name with --vif-name")
			} else {
				logger.Error("Failed to start virtual interface", "error", err)
			}
			logger.Warn("Continuing without virtual interface")
			p.vifManager = nil
		} else {
			logger.Info("Virtual interface started", "interface", p.vifManager.Name())
		}
	}

	logger.Info("Processor started", "listen_addr", p.config.ListenAddr)

	// Start local capture loop if using LocalSource
	if localSource, ok := p.packetSource.(*source.LocalSource); ok {
		logger.Info("Starting local capture mode")

		// Start the local source in a goroutine
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := localSource.Start(p.ctx); err != nil {
				logger.Error("Local capture failed", "error", err)
			}
		}()

		// Start a goroutine to process batches from local source
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for batch := range localSource.Batches() {
				p.processBatch(batch)
			}
		}()
	}

	// Wait for shutdown signal, then run consolidated cleanup
	<-p.ctx.Done()

	return p.Shutdown()
}

// Shutdown gracefully shuts down the processor.
// Safe to call multiple times — only the first call performs cleanup.
func (p *Processor) Shutdown() error {
	p.shutdownOnce.Do(func() {
		logger.Info("Shutting down processor")

		if p.connTracker != nil && p.eventDispatcher != nil {
			for _, ev := range p.connTracker.Close() {
				p.eventDispatcher.Enqueue(ev)
			}
		}
		if p.eventDispatcher != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := p.eventDispatcher.Close(shutdownCtx); err != nil {
				logger.Warn("Failed to close protocol event dispatcher", "error", err)
			}
			cancel()
		}
		if p.cancel != nil {
			p.cancel()
		}

		// Stop accepting streams and let handlers already inside processBatch
		// finish before any packet consumer is closed. A misbehaving client must
		// not make shutdown unbounded.
		if p.grpcServer != nil {
			timeout := p.config.GracefulShutdownTimeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			gracefulStopWithTimeout(p.grpcServer, timeout)
		}

		// Includes the gRPC Serve goroutine and local source/consumer goroutines.
		// Once this returns there is no producer that can call processBatch.
		p.wg.Wait()

		// Stop LI Manager (no-op if !li build)
		p.stopLIManager()

		// Shutdown detector to stop background goroutines
		if p.detector != nil {
			p.detector.Shutdown()
		}

		// Shutdown call correlator to stop cleanup goroutine
		if p.callCorrelator != nil {
			p.callCorrelator.Stop()
		}

		// Stop DNS tunneling detector to stop cleanup goroutine
		if p.dnsTunneling != nil {
			p.dnsTunneling.Stop()
		}

		// Stop lifecycle observation before closing session-owned writers.
		if p.sessionOutputManager != nil {
			if err := p.sessionOutputManager.Close(); err != nil {
				logger.Warn("Failed to close session output manager", "error", err)
			}
		}

		// Close auto-rotate PCAP writer
		if p.autoRotatePcapWriter != nil {
			if err := p.autoRotatePcapWriter.Close(); err != nil {
				logger.Warn("Failed to close auto-rotate PCAP writer", "error", err)
			}
		}

		// Stop unified PCAP writer
		if p.pcapWriter != nil {
			p.pcapWriter.Stop()
		}

		// Close TLS keylog writer
		if p.tlsKeylogWriter != nil {
			if err := p.tlsKeylogWriter.Close(); err != nil {
				logger.Warn("Failed to close TLS keylog writer", "error", err)
			}
		}

		// Disconnect upstream connection
		if p.upstreamManager != nil {
			p.upstreamManager.Disconnect()
		}

		// Stop hunter monitor
		p.hunterMonitor.Stop()

		// Shutdown virtual interface
		if p.vifManager != nil {
			if err := p.vifManager.Shutdown(); err != nil {
				logger.Warn("Failed to shutdown virtual interface", "error", err)
			}
		}

		// Shutdown proxy manager (close all topology subscriptions)
		if p.proxyManager != nil {
			p.proxyManager.Shutdown(5 * time.Second)
		}

		// Shutdown downstream manager (close all downstream connections)
		if p.downstreamManager != nil {
			p.downstreamManager.Shutdown(5 * time.Second)
		}

		logger.Info("Processor shutdown complete")
	})
	return nil
}

type grpcStopper interface {
	GracefulStop()
	Stop()
}

func gracefulStopWithTimeout(server grpcStopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		logger.Warn("Graceful gRPC shutdown timed out; forcing stop", "timeout", timeout)
		server.Stop()
		<-done
	}
}

// ListenAddr returns the actual listening address of the processor.
// This is useful when the processor was started with port ":0" to get a dynamically
// allocated port. Returns an empty string if the processor hasn't started listening yet.
// This method is safe for concurrent access during processor startup.
func (p *Processor) ListenAddr() string {
	p.listenerMu.RLock()
	defer p.listenerMu.RUnlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// createReuseAddrListener creates a TCP listener with SO_REUSEADDR enabled
// for fast restarts without waiting for TIME_WAIT
func createReuseAddrListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockOptErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow immediate rebind after restart
				sockOptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return sockOptErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}
