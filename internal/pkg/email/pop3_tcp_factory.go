package email

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// pop3StreamFactory manages TCP stream creation for POP3.
type pop3StreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	maxGoroutines    int
	handler          POP3MessageHandler
	cleanupTicker    *time.Ticker
	allWorkers       sync.WaitGroup
	closed           int32

	// Track server ports to determine direction
	serverPorts map[uint16]bool
	portsMu     sync.RWMutex

	// Body capture configuration
	captureBody bool
	maxBodySize int
}

// POP3StreamFactoryConfig holds configuration for the factory.
type POP3StreamFactoryConfig struct {
	MaxGoroutines   int
	CleanupInterval time.Duration
	ServerPorts     []uint16
	CaptureBody     bool // Enable body content capture
	MaxBodySize     int  // Maximum body size to capture (bytes), 0 = default 64KB
}

// DefaultPOP3StreamFactoryConfig returns default configuration.
func DefaultPOP3StreamFactoryConfig() POP3StreamFactoryConfig {
	return POP3StreamFactoryConfig{
		MaxGoroutines:   1000,
		CleanupInterval: 30 * time.Second,
		ServerPorts:     DefaultPOP3Ports,
	}
}

// NewPOP3StreamFactory creates a new POP3 stream factory.
func NewPOP3StreamFactory(ctx context.Context, handler POP3MessageHandler, config POP3StreamFactoryConfig) tcpassembly.StreamFactory {
	ctx, cancel := context.WithCancel(ctx)

	if config.MaxGoroutines <= 0 {
		config.MaxGoroutines = 1000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 30 * time.Second
	}
	if len(config.ServerPorts) == 0 {
		config.ServerPorts = DefaultPOP3Ports
	}

	// Default max body size is 64KB
	maxBodySize := config.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = 64 * 1024 // 64KB default
	}

	factory := &pop3StreamFactory{
		ctx:           ctx,
		cancel:        cancel,
		maxGoroutines: config.MaxGoroutines,
		handler:       handler,
		cleanupTicker: time.NewTicker(config.CleanupInterval),
		serverPorts:   make(map[uint16]bool),
		captureBody:   config.CaptureBody,
		maxBodySize:   maxBodySize,
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

// New creates a new POP3 stream (implements tcpassembly.StreamFactory).
func (f *pop3StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// Check goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.maxGoroutines) {
		logger.Warn("POP3 stream dropped: goroutine limit reached",
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
	stream := createPOP3Stream(&r, f.ctx, f, net, transport.Reverse(), isFromServer, sessionID)

	atomic.AddInt64(&f.activeGoroutines, 1)
	go stream.run()

	return &r
}

// isServerPort checks if a port is configured as a server port.
func (f *pop3StreamFactory) isServerPort(port uint16) bool {
	f.portsMu.RLock()
	defer f.portsMu.RUnlock()
	return f.serverPorts[port]
}

// cleanupRoutine periodically performs cleanup tasks.
func (f *pop3StreamFactory) cleanupRoutine() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.cleanupTicker.C:
			// Log statistics periodically
			active := atomic.LoadInt64(&f.activeGoroutines)
			if active > 0 {
				logger.Debug("POP3 stream stats",
					"active_streams", active,
					"max_goroutines", f.maxGoroutines)
			}
		}
	}
}

// Close shuts down the factory.
func (f *pop3StreamFactory) Close() {
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return
	}

	f.cancel()
	f.cleanupTicker.Stop()
	f.allWorkers.Wait()

	logger.Info("POP3 stream factory closed")
}

// GetActiveGoroutines returns the current number of active goroutines.
func (f *pop3StreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum number of goroutines allowed.
func (f *pop3StreamFactory) GetMaxGoroutines() int {
	return f.maxGoroutines
}
