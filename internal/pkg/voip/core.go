//go:build cli || all

package voip

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/layers"
)

// ProcessorWorkerStats describes bounded flow-shard queue pressure.
type ProcessorWorkerStats struct {
	QueueDepth    int
	HighWaterMark uint64
	Drops         uint64
}

type processorWorkerCounters struct {
	highWater atomic.Uint64
	drops     atomic.Uint64
	queue     chan capture.PacketInfo
}

var currentProcessorWorkers atomic.Pointer[[]*processorWorkerCounters]

// ProcessorWorkersStats returns a point-in-time snapshot for observability.
func ProcessorWorkersStats() []ProcessorWorkerStats {
	workers := currentProcessorWorkers.Load()
	if workers == nil {
		return nil
	}
	result := make([]ProcessorWorkerStats, len(*workers))
	for i, worker := range *workers {
		result[i] = ProcessorWorkerStats{QueueDepth: len(worker.queue), HighWaterMark: worker.highWater.Load(), Drops: worker.drops.Load()}
	}
	return result
}

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	ctx := context.Background()
	config := GetConfig()
	tracker := NewCallTracker()
	defer tracker.Shutdown()
	logger.InfoContext(ctx, "Starting VoIP sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize sniff completion monitor for PCAP file closure when writing is enabled
	if config.WriteVoIP {
		gracePeriod := config.PCAPGracePeriod
		if gracePeriod <= 0 {
			gracePeriod = 5 * time.Second
		}
		closedCallTTL := config.PCAPClosedCallTTL
		if closedCallTTL <= 0 {
			closedCallTTL = time.Hour
		}
		monitor := NewSniffCompletionMonitor(tracker, &SniffCompletionMonitorConfig{
			GracePeriod:   gracePeriod,
			CheckInterval: 1 * time.Second,
			ClosedCallTTL: closedCallTTL,
		})
		SetSniffCompletionMonitor(monitor)
		monitor.Start()
		defer func() {
			monitor.Stop()
			SetSniffCompletionMonitor(nil)
		}()
		logger.Info("Sniff completion monitor initialized",
			"grace_period", gracePeriod,
			"closed_call_ttl", closedCallTTL)
	}

	// Initialize virtual interface FIRST if enabled (before processing any packets)
	// This allows early permission check and avoids wasting time processing packets
	if config.VirtualInterface {
		vifName := config.VIFName
		if vifName == "" {
			vifName = "lc0"
		}

		cfg := vinterface.DefaultConfig()
		cfg.Name = vifName

		// Read interface type from config (default: tap)
		if vifType := config.VIFType; vifType != "" {
			cfg.Type = vifType
		}

		// Read buffer size from config (default: 4096)
		if bufferSize := config.VIFBufferSize; bufferSize > 0 {
			cfg.BufferSize = bufferSize
		}

		// Read network namespace from config (default: empty)
		if netNS := config.VIFNetNS; netNS != "" {
			cfg.NetNS = netNS
		}

		// Read privilege dropping user from config (default: empty)
		if dropPrivUser := config.VIFDropPrivilegesUser; dropPrivUser != "" {
			cfg.DropPrivilegesUser = dropPrivUser
		}

		var err error
		globalVifMgr, err = vinterface.NewManager(cfg)
		if err != nil {
			// Provide helpful error message for common errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else if errors.Is(err, vinterface.ErrInterfaceExists) {
				logger.Error("Virtual interface already exists",
					"error", err,
					"interface_name", vifName,
					"solution", "Delete existing interface or choose a different name with --vif-name")
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", vifName)
			}
			logger.Warn("Continuing without virtual interface")
			globalVifMgr = nil
		} else {
			err = globalVifMgr.Start()
			if err != nil {
				// Provide helpful error message for common errors
				if errors.Is(err, vinterface.ErrPermissionDenied) {
					logger.Error("Virtual interface requires elevated privileges",
						"error", err,
						"interface_name", vifName,
						"solution", "Run with sudo or add CAP_NET_ADMIN capability")
				} else if errors.Is(err, vinterface.ErrInterfaceExists) {
					logger.Error("Virtual interface already exists",
						"error", err,
						"interface_name", vifName,
						"solution", "Delete existing interface or choose a different name with --vif-name")
				} else {
					logger.Error("Failed to start virtual interface",
						"error", err,
						"interface_name", vifName)
				}
				logger.Warn("Continuing without virtual interface")
				globalVifMgr = nil
			}
		}

		if globalVifMgr != nil {
			logger.Info("Virtual interface started successfully",
				"interface_name", globalVifMgr.Name())

			// Initialize timing replayer for virtual interface
			replayTiming := config.VIFReplayTiming
			globalTimingReplay = vinterface.NewTimingReplayer(replayTiming)

			// Wait for external tools (tcpdump, Wireshark) to attach
			startupDelay := config.VIFStartupDelay
			if startupDelay > 0 {
				logger.Info("Waiting for monitoring tools to attach...",
					"delay", startupDelay)
				time.Sleep(startupDelay)
			}
			logger.Info("Starting packet injection")
		}

		// Ensure cleanup on exit
		defer func() {
			if globalVifMgr != nil {
				stats := globalVifMgr.Stats()
				logger.Info("Virtual interface statistics",
					"packets_injected", stats.PacketsInjected,
					"packets_dropped", stats.PacketsDropped,
					"injection_errors", stats.InjectionErrors,
					"conversion_errors", stats.ConversionErrors)

				if err := globalVifMgr.Shutdown(); err != nil {
					logger.Error("Error shutting down virtual interface", "error", err)
				} else {
					logger.Info("Virtual interface shutdown successfully")
				}
			}
		}()
	}

	// Create handler for local file writing
	handler := NewLocalFileHandler(tracker)
	streamFactory := NewSipStreamFactoryWithConfig(ctx, handler, *GetConfig(), tracker.IsCallActive)
	// VoIP owns its (connection-aware reassembly) assembler internally rather
	// than threading it through the shared capture-layer signatures, which stay
	// typed to the legacy *tcpassembly.Assembler for the other protocols.
	assembler := pipeline.NewReassemblyEngine(streamFactory, pipeline.DefaultReassemblyConfig())
	defer func() {
		if err := assembler.Close(); err != nil {
			logger.Error("Failed to close VoIP reassembly engine", "error", err)
		}
	}()
	go func() {
		if err := assembler.Run(ctx); err != nil {
			logger.Error("VoIP reassembly engine stopped", "error", err)
		}
	}()
	// Detect offline mode (reading from PCAP file)
	// Offline interfaces have filenames as their Name(), not network interface names
	isOffline := false
	for _, dev := range devices {
		// Offline interfaces return the filename in Name()
		// which will contain a path separator or .pcap extension
		name := dev.Name()
		if strings.Contains(name, ".pcap") || strings.Contains(name, ".pcapng") || strings.Contains(name, "/") {
			isOffline = true
			break
		}
	}
	processor := func(ch <-chan capture.PacketInfo) { startProcessor(tracker, ch, assembler, isOffline) }

	if isOffline {
		// For offline mode, run until PCAP is fully read
		capture.RunOffline(devices, filter, processor)
	} else {
		// For live mode, run with signal handler (waits for Ctrl+C)
		capture.RunWithSignalHandler(devices, filter, processor)
	}
}

func StartLiveVoipSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartVoipSniffer)
}

func StartOfflineVoipSniffer(readFiles []string, filter string) {
	capture.StartOfflineSniffer(readFiles, filter, StartVoipSniffer)
}

func startProcessor(tracker *CallTracker, ch <-chan capture.PacketInfo, assembler tcpPacketAssembler, offlineMode ...bool) {
	offline := len(offlineMode) > 0 && offlineMode[0]
	defer CloseWriters()

	// Initialize buffer manager (5 second timeout, 200 packet max per call)
	bufferOnce.Do(func() {
		globalBufferMgr = NewBufferManager(5*time.Second, 200)
		logger.Info("Initialized VoIP buffer manager", "max_age", "5s", "max_size", 200)
	})
	defer func() {
		if globalBufferMgr != nil {
			globalBufferMgr.Close()
		}
	}()

	// Note: Virtual interface is now initialized in StartVoipSniffer() before packet processing begins
	// This allows early permission checking and avoids wasting time if permissions are insufficient

	numWorkers := getProcessorWorkerCount()
	if numWorkers <= 1 {
		// Single-threaded path (original behaviour / offline-ordered mode).
		for pkt := range ch {
			processOnePacket(tracker, pkt, assembler, offline)
		}
	} else {
		// Flow-sharded worker pool. Each flow (both directions) is pinned to one
		// worker via a symmetric hash, so RTP-stream ordering and per-call state
		// stay consistent while distinct calls parallelise across cores. All shared
		// state touched by the handlers is mutex-protected: CallTracker.callMap and
		// portToCallID (tracker.mu), per-call PCAP writers (sipWriterMu/rtpWriterMu),
		// the buffer manager (bm.mu) and the async writer. TCP is pinned to worker 0
		// because the reassembly assembler is not concurrency-safe (TCP/SIP volume is
		// negligible here).
		logger.Info("VoIP processor starting flow-sharded workers", "workers", numWorkers)
		workerBuf := getProcessorWorkerBuffer()
		workers := make([]chan capture.PacketInfo, numWorkers)
		counters := make([]*processorWorkerCounters, numWorkers)
		var lastOverloadLog atomic.Int64
		var wg sync.WaitGroup
		for i := range workers {
			workers[i] = make(chan capture.PacketInfo, workerBuf)
			counters[i] = &processorWorkerCounters{queue: workers[i]}
			wg.Add(1)
			go func(in <-chan capture.PacketInfo) {
				defer wg.Done()
				for pkt := range in {
					processOnePacket(tracker, pkt, assembler, offline)
				}
			}(workers[i])
		}
		currentProcessorWorkers.Store(&counters)

		for pkt := range ch {
			packet := pkt.Packet
			netLayer := packet.NetworkLayer()
			transLayer := packet.TransportLayer()
			if netLayer == nil || transLayer == nil {
				continue
			}
			idx := 0
			if _, isTCP := transLayer.(*layers.TCP); !isTCP {
				// FastHash() (uint64) is direction-independent, so both legs of a
				// flow land on the same worker.
				h := netLayer.NetworkFlow().FastHash() ^ transLayer.TransportFlow().FastHash()
				idx = int(h % uint64(numWorkers))
			}
			select {
			case workers[idx] <- pkt:
				depth := uint64(len(workers[idx]))
				for old := counters[idx].highWater.Load(); depth > old && !counters[idx].highWater.CompareAndSwap(old, depth); old = counters[idx].highWater.Load() {
				}
			default:
				drops := counters[idx].drops.Add(1)
				now := time.Now().UnixNano()
				last := lastOverloadLog.Load()
				if now-last >= int64(time.Second) && lastOverloadLog.CompareAndSwap(last, now) {
					logger.Warn("VoIP processor worker queue full; dropping packet to preserve global progress", "worker", idx, "queue_capacity", workerBuf, "worker_drops", drops)
				}
			}
		}
		for _, w := range workers {
			close(w)
		}
		wg.Wait()
	}

	logger.Info("VoIP processor finished")
}

func startProcessorWithTracker(tracker *CallTracker, ch <-chan capture.PacketInfo, assembler tcpPacketAssembler, offlineMode ...bool) {
	startProcessor(tracker, ch, assembler, offlineMode...)
}

// processOnePacket dispatches a single packet to the appropriate transport handler.
// Safe to call from multiple worker goroutines concurrently as long as packets of
// the same flow are delivered to the same worker (see startProcessor) and shared
// call/registry/writer state remains mutex-protected.
func processOnePacket(tracker *CallTracker, pkt capture.PacketInfo, assembler tcpPacketAssembler, offline bool) {
	packet := pkt.Packet
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return
	}
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		handleTcpPackets(pkt, layer, assembler, offline)
	case *layers.UDP:
		handleUdpPackets(tracker, pkt, layer)
	}
}

// getProcessorWorkerCount returns the number of flow-sharded VoIP processing
// workers. Configurable via voip.processor_workers; defaults to NumCPU-2 (leaving
// headroom for the capture/decode goroutine and async writers), minimum 1.
// A value of 1 selects the original single-threaded path.
func getProcessorWorkerCount() int {
	if n := GetConfig().ProcessorWorkers; n >= 1 {
		return n
	}
	n := runtime.NumCPU() - 2
	if n < 1 {
		n = 1
	}
	return n
}

// getProcessorWorkerBuffer returns the per-worker input channel depth.
// Configurable via voip.processor_worker_buffer; defaults to 8192.
func getProcessorWorkerBuffer() int {
	if b := GetConfig().ProcessorWorkerBuffer; b > 0 {
		return b
	}
	return 8192
}
