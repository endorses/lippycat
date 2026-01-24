package capture

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
)

type PacketInfo struct {
	LinkType  layers.LinkType
	Packet    gopacket.Packet
	Interface string // Name of the interface where packet was captured
}

// SIP method prefixes for fast detection (no allocations)
var (
	sipMethodINVITE   = []byte("INVITE")
	sipMethodREGISTER = []byte("REGISTER")
	sipMethodOPTIONS  = []byte("OPTIONS")
	sipMethodACK      = []byte("ACK")
	sipMethodBYE      = []byte("BYE")
	sipMethodCANCEL   = []byte("CANCEL")
	sipResponse       = []byte("SIP/2.0")
)

// Default SIP priority buffer size (SIP is low volume, doesn't need large buffer)
const DefaultSIPBufferSize = 1000

type PacketBuffer struct {
	ch         chan PacketInfo
	sipCh      chan PacketInfo // High-priority channel for SIP packets
	mergedCh   chan PacketInfo // Merged output channel (prioritizes SIP)
	ctx        context.Context
	cancel     context.CancelFunc
	dropped    int64
	sipDropped int64 // Separate counter for dropped SIP packets (should be rare)
	bufferSize int
	closed     int32          // atomic flag: 0 = open, 1 = closed
	sendersMu  sync.Mutex     // protects closed-check-and-add sequence to prevent race with Wait()
	sendersWg  sync.WaitGroup // tracks active Send() operations to prevent race on channel close
	mergerWg   sync.WaitGroup // tracks merger goroutine
	pauseFn    func() bool    // optional: if set and returns true, Send skips packet (for TUI pause)
	pauseMu    sync.RWMutex   // protects pauseFn
}

func NewPacketBuffer(ctx context.Context, bufferSize int) *PacketBuffer {
	ctx, cancel := context.WithCancel(ctx)
	pb := &PacketBuffer{
		ch:         make(chan PacketInfo, bufferSize),
		sipCh:      make(chan PacketInfo, DefaultSIPBufferSize),
		mergedCh:   make(chan PacketInfo, bufferSize), // Same size as main for smooth flow
		ctx:        ctx,
		cancel:     cancel,
		bufferSize: bufferSize,
		closed:     0,
	}

	// Start merger goroutine that prioritizes SIP packets
	pb.mergerWg.Add(1)
	go pb.mergeChannels()

	return pb
}

// mergeChannels reads from both sipCh and ch, prioritizing SIP packets.
// This ensures SIP packets are delivered first even when the main buffer is full.
func (pb *PacketBuffer) mergeChannels() {
	defer pb.mergerWg.Done()
	defer close(pb.mergedCh)

	for {
		// Priority select: always check SIP channel first
		select {
		case pkt, ok := <-pb.sipCh:
			if !ok {
				// SIP channel closed, drain main channel
				pb.drainMainChannel()
				return
			}
			select {
			case pb.mergedCh <- pkt:
			case <-pb.ctx.Done():
				return
			}
		default:
			// No SIP packet available, check both channels
			select {
			case pkt, ok := <-pb.sipCh:
				if !ok {
					pb.drainMainChannel()
					return
				}
				select {
				case pb.mergedCh <- pkt:
				case <-pb.ctx.Done():
					return
				}
			case pkt, ok := <-pb.ch:
				if !ok {
					// Main channel closed, drain SIP channel
					pb.drainSIPChannel()
					return
				}
				select {
				case pb.mergedCh <- pkt:
				case <-pb.ctx.Done():
					return
				}
			case <-pb.ctx.Done():
				return
			}
		}
	}
}

// drainMainChannel drains remaining packets from main channel after SIP channel closes
func (pb *PacketBuffer) drainMainChannel() {
	for {
		select {
		case pkt, ok := <-pb.ch:
			if !ok {
				return
			}
			select {
			case pb.mergedCh <- pkt:
			case <-pb.ctx.Done():
				return
			}
		case <-pb.ctx.Done():
			return
		}
	}
}

// drainSIPChannel drains remaining packets from SIP channel after main channel closes
func (pb *PacketBuffer) drainSIPChannel() {
	for {
		select {
		case pkt, ok := <-pb.sipCh:
			if !ok {
				return
			}
			select {
			case pb.mergedCh <- pkt:
			case <-pb.ctx.Done():
				return
			}
		case <-pb.ctx.Done():
			return
		}
	}
}

// SetPauseFn sets an optional pause check function.
// If set and returns true, Send() will skip packets (drop them silently).
// This is used by the TUI to pause packet capture without stopping the capture source.
func (pb *PacketBuffer) SetPauseFn(fn func() bool) {
	pb.pauseMu.Lock()
	defer pb.pauseMu.Unlock()
	pb.pauseFn = fn
}

func (pb *PacketBuffer) Send(pkt PacketInfo) bool {
	// Fast path: check pause state first (skip packet if paused)
	pb.pauseMu.RLock()
	pauseFn := pb.pauseFn
	pb.pauseMu.RUnlock()
	if pauseFn != nil && pauseFn() {
		return false // Paused - drop packet silently
	}

	// Fast path: check if already closed (no lock needed for read)
	if atomic.LoadInt32(&pb.closed) == 1 {
		return false
	}

	// Use mutex to ensure closed-check-and-add is atomic with respect to Close()
	// This prevents the race between Add() and Wait() on sendersWg
	pb.sendersMu.Lock()
	if atomic.LoadInt32(&pb.closed) == 1 {
		pb.sendersMu.Unlock()
		return false
	}
	pb.sendersWg.Add(1)
	pb.sendersMu.Unlock()

	defer pb.sendersWg.Done()

	// Check context cancellation first with higher priority
	select {
	case <-pb.ctx.Done():
		return false
	default:
	}

	// Fast SIP detection - route SIP to priority channel
	isSIP := pb.isSIPPacket(pkt.Packet)

	if isSIP {
		// Try SIP priority channel first
		select {
		case pb.sipCh <- pkt:
			return true
		case <-pb.ctx.Done():
			return false
		default:
			// SIP channel full - this is bad but rare
			// Try main channel as fallback
			select {
			case pb.ch <- pkt:
				return true
			case <-pb.ctx.Done():
				return false
			default:
				// Both channels full - drop SIP packet (very rare)
				dropped := atomic.AddInt64(&pb.sipDropped, 1)
				if dropped%100 == 0 {
					logger.Warn("SIP packets dropped due to buffer overflow (critical)",
						"sip_dropped", dropped)
				}
				return false
			}
		}
	}

	// Regular packet - send to main channel
	select {
	case pb.ch <- pkt:
		return true
	case <-pb.ctx.Done():
		return false
	default:
		// Non-blocking send failed - buffer full
		dropped := atomic.AddInt64(&pb.dropped, 1)
		if dropped%1000 == 0 {
			logger.Warn("Packets dropped due to buffer overflow",
				"total_dropped", dropped)
		}
		return false
	}
}

// isSIPPacket performs fast SIP detection on a packet.
// Checks for common SIP methods and responses in TCP/UDP payload.
func (pb *PacketBuffer) isSIPPacket(pkt gopacket.Packet) bool {
	if pkt == nil {
		return false
	}

	transLayer := pkt.TransportLayer()
	if transLayer == nil {
		return false
	}

	var payload []byte
	switch trans := transLayer.(type) {
	case *layers.TCP:
		payload = trans.LayerPayload()
	case *layers.UDP:
		payload = trans.LayerPayload()
	default:
		return false
	}

	return isSIPBytes(payload)
}

// isSIPBytes performs fast SIP detection using byte comparison.
// Checks for common SIP methods (INVITE, REGISTER, etc.) and responses (SIP/2.0).
func isSIPBytes(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}

	// Check for common SIP methods and responses
	if len(payload) >= len(sipMethodINVITE) && bytesEqual(payload[:len(sipMethodINVITE)], sipMethodINVITE) {
		return true
	}
	if len(payload) >= len(sipMethodREGISTER) && bytesEqual(payload[:len(sipMethodREGISTER)], sipMethodREGISTER) {
		return true
	}
	if len(payload) >= len(sipMethodOPTIONS) && bytesEqual(payload[:len(sipMethodOPTIONS)], sipMethodOPTIONS) {
		return true
	}
	if len(payload) >= len(sipResponse) && bytesEqual(payload[:len(sipResponse)], sipResponse) {
		return true
	}
	if len(payload) >= len(sipMethodACK) && bytesEqual(payload[:len(sipMethodACK)], sipMethodACK) {
		return true
	}
	if len(payload) >= len(sipMethodBYE) && bytesEqual(payload[:len(sipMethodBYE)], sipMethodBYE) {
		return true
	}
	if len(payload) >= len(sipMethodCANCEL) && bytesEqual(payload[:len(sipMethodCANCEL)], sipMethodCANCEL) {
		return true
	}

	return false
}

// bytesEqual compares two byte slices for equality.
// This is a simple implementation; for high performance, SIMD could be used.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (pb *PacketBuffer) Receive() <-chan PacketInfo {
	return pb.mergedCh
}

// Len returns the current number of buffered packets (all channels including merged output)
func (pb *PacketBuffer) Len() int {
	return len(pb.ch) + len(pb.sipCh) + len(pb.mergedCh)
}

// Cap returns the capacity of the packet buffer (main channel only)
func (pb *PacketBuffer) Cap() int {
	return cap(pb.ch)
}

// SIPLen returns the current number of buffered SIP packets
func (pb *PacketBuffer) SIPLen() int {
	return len(pb.sipCh)
}

// SIPCap returns the capacity of the SIP priority buffer
func (pb *PacketBuffer) SIPCap() int {
	return cap(pb.sipCh)
}

// GetSIPDropped returns the number of dropped SIP packets (should be rare/zero)
func (pb *PacketBuffer) GetSIPDropped() int64 {
	return atomic.LoadInt64(&pb.sipDropped)
}

// GetDropped returns the number of dropped regular packets
func (pb *PacketBuffer) GetDropped() int64 {
	return atomic.LoadInt64(&pb.dropped)
}

func (pb *PacketBuffer) Close() {
	// Use mutex to ensure no Send() can Add() after we set closed and before Wait()
	pb.sendersMu.Lock()
	alreadyClosed := !atomic.CompareAndSwapInt32(&pb.closed, 0, 1)
	pb.sendersMu.Unlock()

	if !alreadyClosed {
		// First Close() call - do full cleanup
		pb.cancel()

		// Wait for all active Send() operations to complete
		pb.sendersWg.Wait()

		// Close both input channels (order matters: close sipCh first to drain priority packets)
		close(pb.sipCh)
		close(pb.ch)
	}

	// Always wait for merger goroutine to finish (it will close mergedCh)
	pb.mergerWg.Wait()

	// Log drop statistics (only on first close to avoid duplicate logs)
	if !alreadyClosed {
		dropped := atomic.LoadInt64(&pb.dropped)
		sipDropped := atomic.LoadInt64(&pb.sipDropped)
		if dropped > 0 || sipDropped > 0 {
			logger.Info("Packet buffer closed with drops",
				"regular_dropped", dropped,
				"sip_dropped", sipDropped)
		}
	}
}

func (pb *PacketBuffer) IsClosed() bool {
	return atomic.LoadInt32(&pb.closed) == 1
}

// CloseInputs signals that no more packets will be sent to this buffer.
// Unlike Close(), this does NOT cancel the context, allowing the merger
// to drain remaining packets before closing the output channel.
func (pb *PacketBuffer) CloseInputs() {
	pb.sendersMu.Lock()
	if !atomic.CompareAndSwapInt32(&pb.closed, 0, 1) {
		pb.sendersMu.Unlock()
		return
	}
	pb.sendersMu.Unlock()

	// Wait for all active Send() operations to complete
	pb.sendersWg.Wait()

	// Close input channels - merger will drain and close mergedCh
	close(pb.sipCh)
	close(pb.ch)
}

func Init(ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	InitWithContext(context.Background(), ifaces, filter, packetProcessor, assembler, nil)
}

// InitWithContext starts packet capture with a cancellable context.
// The optional pauseFn parameter, if provided, allows the caller to pause packet capture.
// When pauseFn returns true, packets are dropped at the source to reduce CPU usage.
// Note: Signal handling should be done by the caller. This function only respects context cancellation.
func InitWithContext(ctx context.Context, ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler, pauseFn func() bool) {
	// Use a configurable buffer size with proper backpressure handling
	bufferSize := getPacketBufferSize()
	packetBuffer := NewPacketBuffer(ctx, bufferSize)
	if pauseFn != nil {
		packetBuffer.SetPauseFn(pauseFn)
	}
	defer packetBuffer.Close()

	InitWithBuffer(ctx, ifaces, filter, packetBuffer, packetProcessor, assembler)
}

// InitWithBuffer starts packet capture with an external PacketBuffer
// This allows the caller to own the buffer and read from it directly, avoiding
// double-buffering when the processor would just copy packets to another buffer.
func InitWithBuffer(ctx context.Context, ifaces []pcaptypes.PcapInterface, filter string, buffer *PacketBuffer, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	packetBuffer := buffer

	var wg sync.WaitGroup
	var processorWg sync.WaitGroup
	processorWg.Add(1)

	// Track if any capture succeeded (for error handling)
	var captureSuccessCount atomic.Int32

	for _, iface := range ifaces {
		wg.Add(1)
		go func(pif pcaptypes.PcapInterface) {
			defer wg.Done()
			logger.Debug("Capture goroutine starting", "interface", pif.Name())
			defer logger.Debug("Capture goroutine exiting", "interface", pif.Name())

			err := pif.SetHandle()
			if err != nil {
				logger.Error("Error setting pcap handle",
					"error", err,
					"interface", pif.Name())
				return
			}
			handle, err := pif.Handle()
			if err != nil || handle == nil {
				logger.Error("Error getting pcap handle",
					"error", err,
					"interface", pif.Name())
				return
			}
			defer handle.Close()

			// Mark that at least one capture succeeded
			captureSuccessCount.Add(1)

			// Close handle when context is cancelled to unblock packet reads
			// This ensures captureFromInterface exits promptly on context cancellation
			go func() {
				<-ctx.Done()
				logger.Debug("Context cancelled, closing pcap handle", "interface", pif.Name())
				handle.Close() // This will cause packetSource.Packets() channel to close
			}()

			captureFromInterface(ctx, pif, filter, packetBuffer)
		}(iface)
	}

	// If packetProcessor is provided, start it in a goroutine
	// If nil, the caller is responsible for reading from buffer.Receive()
	if packetProcessor != nil {
		go func() {
			defer processorWg.Done()
			packetProcessor(packetBuffer.Receive(), assembler)
		}()
	} else {
		// No processor - caller will read directly from buffer
		processorWg.Done()
	}

	// Monitor for capture completion - close inputs when all captures finish
	// This handles both failed starts AND normal completion (PCAP EOF, interface down)
	captureFinishedCh := make(chan struct{})
	go func() {
		wg.Wait()

		// Signal end of input so processor can drain and exit
		if packetProcessor != nil {
			packetBuffer.CloseInputs()
		}

		if captureSuccessCount.Load() == 0 {
			logger.Error("All capture interfaces failed to start - exiting")
		} else {
			logger.Info("All capture interfaces finished",
				"interfaces_started", captureSuccessCount.Load())
		}

		close(captureFinishedCh)
	}()

	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		// Context cancelled, wait for capture goroutines to stop
		wg.Wait()
		// If we own the buffer (packetProcessor != nil), close it
		// Otherwise, the caller owns it and will close it
		if packetProcessor != nil {
			// Close the buffer which will cause the processor to exit
			packetBuffer.Close()
		}
		// Signal that shutdown has started
		close(shutdownCh)
	}()

	// Wait for processor to complete or timeout after shutdown
	done := make(chan struct{})
	go func() {
		processorWg.Wait()
		close(done)
	}()

	// Wait for either completion, shutdown, or capture finish
	select {
	case <-done:
		// Completed normally (before or after shutdown)
		return
	case <-captureFinishedCh:
		// All captures finished - wait for processor to drain
		select {
		case <-done:
			return
		case <-time.After(500 * time.Millisecond):
			// Force exit if processor doesn't finish quickly
			return
		}
	case <-shutdownCh:
		// Shutdown started, now wait with timeout for processor to finish draining
		select {
		case <-done:
			// Processor finished draining
			return
		case <-time.After(2 * time.Second):
			// Force exit after timeout
			if packetProcessor != nil {
				logger.Warn("Forcing shutdown after drain timeout", "timeout", "2s")
			}
			return
		}
	}
}

func captureFromInterface(ctx context.Context, iface pcaptypes.PcapInterface, filter string, buffer *PacketBuffer) {
	logger.Debug("captureFromInterface starting", "interface", iface.Name())
	defer logger.Debug("captureFromInterface exiting", "interface", iface.Name())

	handle, err := iface.Handle()
	if err != nil || handle == nil {
		logger.Error("Unable to get interface handle",
			"error", err,
			"interface", iface.Name())
		return
	}
	filterErr := handle.SetBPFFilter(filter)
	if filterErr != nil {
		logger.Error("Error setting BPF filter",
			"filter", filter,
			"error", filterErr,
			"interface", iface.Name())
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Add periodic stats logging
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Batched atomic updates: use local counter and periodically sync to atomic
	// Both counters are atomic so the stats goroutine can safely read the total
	var packetCount atomic.Int64 // flushed counter
	var localCount atomic.Int64  // unflushed counter (for accurate stats reporting)
	const batchThreshold = 100   // flush to packetCount every N packets

	go func() {
		logger.Debug("Stats logging goroutine starting", "interface", iface.Name())
		defer logger.Debug("Stats logging goroutine exiting", "interface", iface.Name())
		for {
			select {
			case <-ctx.Done():
				logger.Debug("Stats goroutine received context cancellation", "interface", iface.Name())
				return
			case <-ticker.C:
				// Include both flushed and unflushed counts for accurate reporting
				count := packetCount.Load() + localCount.Load()
				dropped := atomic.LoadInt64(&buffer.dropped)
				logger.Info("Capture heartbeat",
					"interface", iface.Name(),
					"packets_processed", count,
					"packets_dropped", dropped,
					"buffer_len", buffer.Len(),
					"buffer_closed", buffer.IsClosed())
			}
		}
	}()

	// Use a goroutine to read packets and forward them to a channel
	packetCh := packetSource.Packets()

	for {
		// Check context cancellation with priority BEFORE attempting to read packets
		// This ensures we exit promptly when Restart() is called
		select {
		case <-ctx.Done():
			logger.Debug("Packet loop received context cancellation (priority check)", "interface", iface.Name())
			// Flush remaining local count before exit
			if lc := localCount.Load(); lc > 0 {
				packetCount.Add(lc)
				localCount.Store(0)
			}
			return
		default:
		}

		// Now read packets (non-blocking select to ensure ctx.Done() is checked frequently)
		select {
		case <-ctx.Done():
			logger.Debug("Packet loop received context cancellation (select check)", "interface", iface.Name())
			// Flush remaining local count before exit
			if lc := localCount.Load(); lc > 0 {
				packetCount.Add(lc)
				localCount.Store(0)
			}
			return
		case packet, ok := <-packetCh:
			if !ok {
				logger.Info("Capture: packet channel closed unexpectedly",
					"interface", iface.Name(),
					"packets_processed", packetCount.Load()+localCount.Load())
				// Channel closed, flush and exit
				if lc := localCount.Load(); lc > 0 {
					packetCount.Add(lc)
					localCount.Store(0)
				}
				return
			}
			pktInfo := PacketInfo{
				LinkType:  handle.LinkType(),
				Packet:    packet,
				Interface: filepath.Base(iface.Name()), // Use basename for display (removes path for PCAP files)
			}
			buffer.Send(pktInfo)

			// Batched atomic update: increment local counter
			lc := localCount.Add(1)
			if lc >= batchThreshold {
				packetCount.Add(lc)
				localCount.Store(0)
			}
		}
	}
}

// getPacketBufferSize returns the configured packet buffer size
// Default is 10000 packets, but can be overridden via configuration
func getPacketBufferSize() int {
	const defaultBufferSize = DefaultPacketBufferSize

	// Check for configuration via viper (environment variables, config files, etc.)
	if viper.IsSet("packet_buffer_size") {
		size := viper.GetInt("packet_buffer_size")
		if size > 0 {
			return size
		}
	}

	// Fall back to default
	return defaultBufferSize
}

// GetPcapTimeout returns the configured pcap read timeout
// This timeout allows graceful shutdown while maintaining smooth packet display.
// Default is 200ms, but can be overridden via configuration (pcap_timeout_ms).
// Values: 50-1000ms recommended. Lower = more responsive shutdown, Higher = smoother display
func GetPcapTimeout() time.Duration {
	const defaultTimeout = DefaultPcapTimeout

	// Check for configuration via viper (environment variables, config files, etc.)
	if viper.IsSet("pcap_timeout_ms") {
		timeoutMs := viper.GetInt("pcap_timeout_ms")
		if timeoutMs > 0 {
			return time.Duration(timeoutMs) * time.Millisecond
		}
	}

	// Fall back to default
	return defaultTimeout
}
