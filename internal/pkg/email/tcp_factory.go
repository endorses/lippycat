package email

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// smtpStreamFactory manages TCP stream creation for SMTP.
type smtpStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	maxGoroutines    int
	handler          SMTPMessageHandler
	cleanupTicker    *time.Ticker
	allWorkers       sync.WaitGroup
	closed           int32

	// Track server ports to determine direction
	serverPorts map[uint16]bool
	portsMu     sync.RWMutex
}

// SMTPStreamFactoryConfig holds configuration for the factory.
type SMTPStreamFactoryConfig struct {
	MaxGoroutines   int
	CleanupInterval time.Duration
	ServerPorts     []uint16
}

// DefaultSMTPStreamFactoryConfig returns default configuration.
func DefaultSMTPStreamFactoryConfig() SMTPStreamFactoryConfig {
	return SMTPStreamFactoryConfig{
		MaxGoroutines:   1000,
		CleanupInterval: 30 * time.Second,
		ServerPorts:     DefaultSMTPPorts,
	}
}

// NewSMTPStreamFactory creates a new SMTP stream factory.
func NewSMTPStreamFactory(ctx context.Context, handler SMTPMessageHandler, config SMTPStreamFactoryConfig) tcpassembly.StreamFactory {
	ctx, cancel := context.WithCancel(ctx)

	if config.MaxGoroutines <= 0 {
		config.MaxGoroutines = 1000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 30 * time.Second
	}
	if len(config.ServerPorts) == 0 {
		config.ServerPorts = DefaultSMTPPorts
	}

	factory := &smtpStreamFactory{
		ctx:           ctx,
		cancel:        cancel,
		maxGoroutines: config.MaxGoroutines,
		handler:       handler,
		cleanupTicker: time.NewTicker(config.CleanupInterval),
		serverPorts:   make(map[uint16]bool),
	}

	// Initialize server ports map
	for _, port := range config.ServerPorts {
		factory.serverPorts[port] = true
	}

	// Start cleanup routine
	factory.allWorkers.Add(1)
	go factory.cleanupRoutine()

	return factory
}

// New creates a new SMTP stream (implements tcpassembly.StreamFactory).
func (f *smtpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// Check goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.maxGoroutines) {
		logger.Warn("SMTP stream dropped: goroutine limit reached",
			"active", current,
			"max", f.maxGoroutines)
		return &r
	}

	// Determine if this is from server (source port is a known server port)
	srcPort := uint16(transport.Src().Raw()[0])<<8 | uint16(transport.Src().Raw()[1])

	isFromServer := f.isServerPort(srcPort)

	// Create session ID from flow
	sessionID := createSessionID(net, transport)

	// Create and start stream
	stream := createSMTPStream(&r, f.ctx, f, net, transport.Reverse(), isFromServer, sessionID)

	atomic.AddInt64(&f.activeGoroutines, 1)
	go stream.run()

	return &r
}

// isServerPort checks if a port is configured as a server port.
func (f *smtpStreamFactory) isServerPort(port uint16) bool {
	f.portsMu.RLock()
	defer f.portsMu.RUnlock()
	return f.serverPorts[port]
}

// createSessionID creates a unique session ID from flows.
func createSessionID(net, transport gopacket.Flow) string {
	// Normalize to smaller IP first for consistent ID
	srcIP := net.Src().String()
	dstIP := net.Dst().String()
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()

	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
}

// cleanupRoutine periodically performs cleanup tasks.
func (f *smtpStreamFactory) cleanupRoutine() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.cleanupTicker.C:
			// Log statistics periodically
			active := atomic.LoadInt64(&f.activeGoroutines)
			if active > 0 {
				logger.Debug("SMTP stream stats",
					"active_streams", active,
					"max_goroutines", f.maxGoroutines)
			}
		}
	}
}

// Close shuts down the factory.
func (f *smtpStreamFactory) Close() {
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return
	}

	f.cancel()
	f.cleanupTicker.Stop()
	f.allWorkers.Wait()

	logger.Info("SMTP stream factory closed")
}

// GetActiveGoroutines returns the current number of active goroutines.
func (f *smtpStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum number of goroutines allowed.
func (f *smtpStreamFactory) GetMaxGoroutines() int {
	return f.maxGoroutines
}
