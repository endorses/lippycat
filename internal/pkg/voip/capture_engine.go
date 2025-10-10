package voip

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// CaptureEngine provides unified packet capture with automatic fallback
// Tries AF_XDP first, falls back to standard capture if unavailable
type CaptureEngine struct {
	config       *CaptureConfig
	mode         CaptureMode
	xdpSocket    *XDPSocket
	packetChan   chan []byte
	ctx          context.Context
	cancel       context.CancelFunc
	stats        CaptureStats
	running      atomic.Bool
	bufferPool   *BufferPool
}

// CaptureConfig configures the capture engine
type CaptureConfig struct {
	Interface      string
	UseXDP         bool   // Try to use XDP if available
	XDPQueueID     int    // XDP queue ID
	SnapLen        int    // Snapshot length
	Promiscuous    bool   // Promiscuous mode
	BufferSize     int    // Channel buffer size
	BatchSize      int    // Batch processing size
	Timeout        time.Duration
	EnableStats    bool
	StatsInterval  time.Duration
}

// CaptureMode indicates which capture method is active
type CaptureMode int

const (
	CaptureModeUnknown CaptureMode = iota
	CaptureModeXDP                 // Using AF_XDP
	CaptureModeStandard            // Using standard pcap
)

func (m CaptureMode) String() string {
	switch m {
	case CaptureModeXDP:
		return "AF_XDP"
	case CaptureModeStandard:
		return "Standard"
	default:
		return "Unknown"
	}
}

// CaptureStats holds capture statistics
type CaptureStats struct {
	PacketsReceived  atomic.Uint64
	BytesReceived    atomic.Uint64
	PacketsDropped   atomic.Uint64
	PacketsProcessed atomic.Uint64
	BatchesProcessed atomic.Uint64
	Errors           atomic.Uint64
}

// DefaultCaptureConfig returns default configuration
func DefaultCaptureConfig(iface string) *CaptureConfig {
	return &CaptureConfig{
		Interface:     iface,
		UseXDP:        true, // Try XDP by default
		XDPQueueID:    0,
		SnapLen:       65536,
		Promiscuous:   true,
		BufferSize:    1000,
		BatchSize:     64,
		Timeout:       100 * time.Millisecond,
		EnableStats:   true,
		StatsInterval: 10 * time.Second,
	}
}

// NewCaptureEngine creates a new capture engine
func NewCaptureEngine(config *CaptureConfig) (*CaptureEngine, error) {
	if config == nil {
		config = DefaultCaptureConfig("")
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &CaptureEngine{
		config:     config,
		mode:       CaptureModeUnknown,
		packetChan: make(chan []byte, config.BufferSize),
		ctx:        ctx,
		cancel:     cancel,
		bufferPool: GetBufferPool(),
	}

	// Try to initialize capture
	if err := engine.initialize(); err != nil {
		cancel()
		return nil, err
	}

	return engine, nil
}

// initialize sets up the capture backend
func (ce *CaptureEngine) initialize() error {
	// Try AF_XDP first if requested
	if ce.config.UseXDP && IsXDPSupported() {
		if err := ce.initializeXDP(); err != nil {
			logger.Warn("AF_XDP initialization failed, falling back to standard capture",
				"error", err)
			return ce.initializeStandard()
		}
		ce.mode = CaptureModeXDP
		logger.Info("Capture engine initialized with AF_XDP",
			"interface", ce.config.Interface)
		return nil
	}

	// Use standard capture
	return ce.initializeStandard()
}

// initializeXDP sets up AF_XDP capture
func (ce *CaptureEngine) initializeXDP() error {
	xdpConfig := DefaultXDPConfig(ce.config.Interface)
	xdpConfig.QueueID = ce.config.XDPQueueID
	xdpConfig.BatchSize = ce.config.BatchSize

	socket, err := NewXDPSocket(xdpConfig)
	if err != nil {
		return fmt.Errorf("failed to create XDP socket: %w", err)
	}

	ce.xdpSocket = socket
	return nil
}

// initializeStandard sets up standard pcap capture
func (ce *CaptureEngine) initializeStandard() error {
	// This would use gopacket/pcap for standard capture
	// For now, just mark the mode
	ce.mode = CaptureModeStandard

	logger.Info("Capture engine initialized with standard capture",
		"interface", ce.config.Interface)

	return nil
}

// Start begins packet capture
func (ce *CaptureEngine) Start() error {
	if !ce.running.CompareAndSwap(false, true) {
		return fmt.Errorf("already running")
	}

	logger.Info("Starting packet capture",
		"mode", ce.mode.String(),
		"interface", ce.config.Interface)

	// Start capture goroutine
	go ce.captureLoop()

	// Start stats reporting if enabled
	if ce.config.EnableStats {
		go ce.statsLoop()
	}

	return nil
}

// captureLoop is the main capture loop
func (ce *CaptureEngine) captureLoop() {
	defer ce.running.Store(false)

	switch ce.mode {
	case CaptureModeXDP:
		ce.captureLoopXDP()
	case CaptureModeStandard:
		ce.captureLoopStandard()
	default:
		logger.Error("Unknown capture mode", "mode", ce.mode)
	}
}

// captureLoopXDP handles XDP packet capture
func (ce *CaptureEngine) captureLoopXDP() {
	batchSize := ce.config.BatchSize

	for {
		select {
		case <-ce.ctx.Done():
			return
		default:
		}

		// Receive batch of packets
		packets, err := ce.xdpSocket.ReceiveBatch(batchSize)
		if err != nil {
			ce.stats.Errors.Add(1)
			logger.Debug("XDP receive error", "error", err)
			time.Sleep(constants.PollingInterval)
			continue
		}

		if len(packets) == 0 {
			time.Sleep(constants.IdleLoopDelay)
			continue
		}

		// Process batch
		ce.stats.BatchesProcessed.Add(1)

		for _, pkt := range packets {
			ce.stats.PacketsReceived.Add(1)
			ce.stats.BytesReceived.Add(uint64(len(pkt)))

			// Copy packet data (in production, might use zero-copy)
			pktCopy := ce.bufferPool.Get(len(pkt))
			pktCopy = append(pktCopy, pkt...)

			select {
			case ce.packetChan <- pktCopy:
				ce.stats.PacketsProcessed.Add(1)
			case <-ce.ctx.Done():
				return
			default:
				// Channel full, drop packet
				ce.stats.PacketsDropped.Add(1)
			}
		}
	}
}

// captureLoopStandard handles standard pcap capture
func (ce *CaptureEngine) captureLoopStandard() {
	// Placeholder for standard capture loop
	// In production, this would use gopacket/pcap

	logger.Info("Standard capture loop running")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ce.ctx.Done():
			return
		case <-ticker.C:
			// Placeholder - would normally read from pcap handle
			logger.Debug("Standard capture tick")
		}
	}
}

// statsLoop periodically logs statistics
func (ce *CaptureEngine) statsLoop() {
	ticker := time.NewTicker(ce.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ce.ctx.Done():
			return
		case <-ticker.C:
			ce.logStats()
		}
	}
}

// logStats logs current statistics
func (ce *CaptureEngine) logStats() {
	logger.Info("Capture statistics",
		"mode", ce.mode.String(),
		"packets_received", ce.stats.PacketsReceived.Load(),
		"bytes_received", ce.stats.BytesReceived.Load(),
		"packets_processed", ce.stats.PacketsProcessed.Load(),
		"packets_dropped", ce.stats.PacketsDropped.Load(),
		"batches", ce.stats.BatchesProcessed.Load(),
		"errors", ce.stats.Errors.Load())

	// Log XDP-specific stats if available
	if ce.mode == CaptureModeXDP && ce.xdpSocket != nil {
		xdpStats := ce.xdpSocket.GetStats()
		logger.Info("XDP socket statistics", "stats", xdpStats.String())
	}
}

// Packets returns the packet channel
func (ce *CaptureEngine) Packets() <-chan []byte {
	return ce.packetChan
}

// GetStats returns current statistics
func (ce *CaptureEngine) GetStats() CaptureStats {
	return ce.stats
}

// GetMode returns the current capture mode
func (ce *CaptureEngine) GetMode() CaptureMode {
	return ce.mode
}

// Stop stops packet capture
func (ce *CaptureEngine) Stop() error {
	if !ce.running.Load() {
		return fmt.Errorf("not running")
	}

	logger.Info("Stopping packet capture")

	ce.cancel()

	// Wait for capture loop to finish
	for ce.running.Load() {
		time.Sleep(constants.PollingInterval)
	}

	return nil
}

// Close closes the capture engine
func (ce *CaptureEngine) Close() error {
	if ce.running.Load() {
		if err := ce.Stop(); err != nil {
			logger.Warn("Error stopping capture", "error", err)
		}
	}

	var firstErr error

	// Close XDP socket if active
	if ce.xdpSocket != nil {
		if err := ce.xdpSocket.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Close packet channel
	close(ce.packetChan)

	// Log final stats
	ce.logStats()

	logger.Info("Capture engine closed",
		"mode", ce.mode.String(),
		"total_packets", ce.stats.PacketsReceived.Load())

	return firstErr
}

// IsUsingXDP returns true if using AF_XDP
func (ce *CaptureEngine) IsUsingXDP() bool {
	return ce.mode == CaptureModeXDP
}

// SwitchMode attempts to switch capture mode (hot-swap)
func (ce *CaptureEngine) SwitchMode(mode CaptureMode) error {
	if ce.mode == mode {
		return fmt.Errorf("already in mode %s", mode.String())
	}

	logger.Info("Switching capture mode",
		"from", ce.mode.String(),
		"to", mode.String())

	// Stop current capture
	if err := ce.Stop(); err != nil {
		return fmt.Errorf("failed to stop current capture: %w", err)
	}

	// Switch mode
	oldMode := ce.mode
	ce.mode = mode

	// Initialize new mode
	var err error
	switch mode {
	case CaptureModeXDP:
		err = ce.initializeXDP()
	case CaptureModeStandard:
		err = ce.initializeStandard()
	default:
		return fmt.Errorf("unknown mode: %v", mode)
	}

	if err != nil {
		// Revert on failure
		ce.mode = oldMode
		return fmt.Errorf("failed to initialize new mode: %w", err)
	}

	// Restart capture
	return ce.Start()
}