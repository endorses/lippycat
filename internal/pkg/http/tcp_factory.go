//go:build cli || all

package http

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// HTTPMessageHandler processes HTTP messages after TCP reassembly.
type HTTPMessageHandler interface {
	// HandleHTTPMessage is called for each complete HTTP request or response.
	// Parameters:
	//   - metadata: parsed HTTP metadata
	//   - sessionID: session identifier for correlation
	//   - flow: network flow identifier
	HandleHTTPMessage(metadata *types.HTTPMetadata, sessionID string, flow gopacket.Flow)
}

// httpStreamFactory manages TCP stream creation for HTTP.
type httpStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	maxGoroutines    int
	handler          HTTPMessageHandler
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

// HTTPStreamFactoryConfig holds configuration for the factory.
type HTTPStreamFactoryConfig struct {
	MaxGoroutines   int
	CleanupInterval time.Duration
	ServerPorts     []uint16
	CaptureBody     bool // Enable body content capture
	MaxBodySize     int  // Maximum body size to capture (bytes), 0 = default 64KB
}

// DefaultHTTPStreamFactoryConfig returns default configuration.
func DefaultHTTPStreamFactoryConfig() HTTPStreamFactoryConfig {
	return HTTPStreamFactoryConfig{
		MaxGoroutines:   1000,
		CleanupInterval: 30 * time.Second,
		ServerPorts:     DefaultHTTPPorts,
	}
}

// NewHTTPStreamFactory creates a new HTTP stream factory.
func NewHTTPStreamFactory(ctx context.Context, handler HTTPMessageHandler, config HTTPStreamFactoryConfig) tcpassembly.StreamFactory {
	ctx, cancel := context.WithCancel(ctx)

	if config.MaxGoroutines <= 0 {
		config.MaxGoroutines = 1000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 30 * time.Second
	}
	if len(config.ServerPorts) == 0 {
		config.ServerPorts = DefaultHTTPPorts
	}

	// Default max body size is 64KB
	maxBodySize := config.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = 64 * 1024 // 64KB default
	}

	factory := &httpStreamFactory{
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

// New creates a new HTTP stream (implements tcpassembly.StreamFactory).
func (f *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// Check goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.maxGoroutines) {
		logger.Warn("HTTP stream dropped: goroutine limit reached",
			"active", current,
			"max", f.maxGoroutines)
		return &r
	}

	// Determine if this is from server (source port is a known server port)
	srcPort := uint16(transport.Src().Raw()[0])<<8 | uint16(transport.Src().Raw()[1])

	isFromServer := f.isServerPort(srcPort)

	// Create session ID from flow
	sessionID := createHTTPSessionID(net, transport)

	// Create and start stream
	stream := createHTTPStream(&r, f.ctx, f, net, transport.Reverse(), isFromServer, sessionID)

	atomic.AddInt64(&f.activeGoroutines, 1)
	go stream.run()

	return &r
}

// isServerPort checks if a port is configured as a server port.
func (f *httpStreamFactory) isServerPort(port uint16) bool {
	f.portsMu.RLock()
	defer f.portsMu.RUnlock()
	return f.serverPorts[port]
}

// createHTTPSessionID creates a unique session ID from flows.
func createHTTPSessionID(net, transport gopacket.Flow) string {
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
func (f *httpStreamFactory) cleanupRoutine() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.cleanupTicker.C:
			// Log statistics periodically
			active := atomic.LoadInt64(&f.activeGoroutines)
			if active > 0 {
				logger.Debug("HTTP stream stats",
					"active_streams", active,
					"max_goroutines", f.maxGoroutines)
			}
		}
	}
}

// Close shuts down the factory.
func (f *httpStreamFactory) Close() {
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return
	}

	f.cancel()
	f.cleanupTicker.Stop()
	f.allWorkers.Wait()

	logger.Info("HTTP stream factory closed")
}

// GetActiveGoroutines returns the current number of active goroutines.
func (f *httpStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum number of goroutines allowed.
func (f *httpStreamFactory) GetMaxGoroutines() int {
	return f.maxGoroutines
}
