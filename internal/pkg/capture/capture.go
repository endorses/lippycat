package capture

import (
	"bytes"
	"context"
	"encoding/binary"
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

// espNullSPICache maps ESP SPIs confirmed as NULL-encrypted to their inner IP protocol.
// Once a SPI is confirmed via content heuristic (SIP/RTP detected), subsequent packets
// from the same SPI are decapsulated without requiring a SIP/RTP payload at the start.
// This handles TCP continuation segments that carry SDP or later SIP message fragments.
var espNullSPICache sync.Map // key: uint32 SPI, value: layers.IPProtocol

// ipv6FragInfo holds transport-layer information extracted from the first IPv6 fragment.
// It is used to synthesise a complete transport header for non-first fragments, which
// carry only the raw continuation bytes of the original datagram.
type ipv6FragInfo struct {
	innerProto layers.IPProtocol
	srcPort    uint16
	dstPort    uint16
}

// ipv6FragIDCache maps IPv6 Fragment Identification values to the transport info
// that was extracted from the corresponding first fragment.
var ipv6FragIDCache sync.Map // key: uint32 fragID, value: ipv6FragInfo

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

// SendBlocking sends a packet to the buffer, blocking until there's space.
// Unlike Send(), this will NOT drop packets due to buffer full conditions.
// Use this for offline PCAP reading where all packets MUST be processed.
// Returns false only if the buffer is closed or context is cancelled.
func (pb *PacketBuffer) SendBlocking(pkt PacketInfo) bool {
	// Check pause state first (skip packet if paused)
	pb.pauseMu.RLock()
	pauseFn := pb.pauseFn
	pb.pauseMu.RUnlock()
	if pauseFn != nil && pauseFn() {
		return false // Paused - drop packet silently
	}

	// Check if already closed
	if atomic.LoadInt32(&pb.closed) == 1 {
		return false
	}

	// Use mutex to ensure closed-check-and-add is atomic with respect to Close()
	pb.sendersMu.Lock()
	if atomic.LoadInt32(&pb.closed) == 1 {
		pb.sendersMu.Unlock()
		return false
	}
	pb.sendersWg.Add(1)
	pb.sendersMu.Unlock()

	defer pb.sendersWg.Done()

	// Check context cancellation first
	select {
	case <-pb.ctx.Done():
		return false
	default:
	}

	// Fast SIP detection - route SIP to priority channel
	isSIP := pb.isSIPPacket(pkt.Packet)

	if isSIP {
		// Try SIP priority channel first (blocking)
		select {
		case pb.sipCh <- pkt:
			return true
		case <-pb.ctx.Done():
			return false
		}
	}

	// Regular packet - send to main channel (blocking)
	select {
	case pb.ch <- pkt:
		return true
	case <-pb.ctx.Done():
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

	// Create a single shared IPv4 defragmenter for all interfaces.
	// This is critical for multi-interface capture: IP fragments from the same
	// packet may arrive on different interfaces (e.g., due to port mirror splits).
	// A per-interface defragmenter would never reassemble such packets.
	sharedDefragmenter := NewIPv4Defragmenter()

	// Start a single cleanup goroutine for stale fragments (shared across all interfaces)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				discarded := sharedDefragmenter.DiscardOlderThan(time.Now().Add(-30 * time.Second))
				if discarded > 0 {
					logger.Debug("Discarded stale IP fragments", "count", discarded)
				}
			}
		}
	}()

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

			captureFromInterface(ctx, pif, filter, packetBuffer, sharedDefragmenter)
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

func captureFromInterface(ctx context.Context, iface pcaptypes.PcapInterface, filter string, buffer *PacketBuffer, defragmenter *IPv4Defragmenter) {
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

	// Note: defragmenter is shared across all interfaces to correctly reassemble
	// IP fragments that may arrive on different interfaces (e.g., due to port mirror splits)

	// Add periodic stats logging
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Batched atomic updates: use local counter and periodically sync to atomic
	// Both counters are atomic so the stats goroutine can safely read the total
	var packetCount atomic.Int64        // flushed counter
	var localCount atomic.Int64         // unflushed counter (for accurate stats reporting)
	var fragmentsReceived atomic.Int64  // IP fragments received
	var packetsReassembled atomic.Int64 // Successfully reassembled packets
	const batchThreshold = 100          // flush to packetCount every N packets

	go func() {
		logger.Debug("Stats logging goroutine starting", "interface", iface.Name())
		defer logger.Debug("Stats logging goroutine exiting", "interface", iface.Name())
		for {
			select {
			case <-ctx.Done():
				logger.Debug("Stats goroutine received context cancellation", "interface", iface.Name())
				return
			case <-ticker.C:
				// Note: stale fragment cleanup is handled by a single shared goroutine
				// in InitWithBuffer to avoid duplicate cleanup across interfaces

				// Include both flushed and unflushed counts for accurate reporting
				count := packetCount.Load() + localCount.Load()
				dropped := atomic.LoadInt64(&buffer.dropped)
				frags := fragmentsReceived.Load()
				reassembled := packetsReassembled.Load()
				logger.Info("Capture heartbeat",
					"interface", iface.Name(),
					"packets_processed", count,
					"packets_dropped", dropped,
					"ip_fragments", frags,
					"reassembled", reassembled,
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

			// Handle IPv4 fragmentation - reassemble fragmented packets
			// This is critical for SIP messages that exceed MTU (>1500 bytes)
			// Without reassembly, the second fragment (containing SDP with media ports)
			// would be dropped, causing RTP-only calls
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip4 := ipLayer.(*layers.IPv4)
				// Check if this is a fragment (more fragments flag or non-zero offset)
				if ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset > 0 {
					fragmentsReceived.Add(1)

					// Feed fragment to defragmenter
					reassembledIP, err := defragmenter.DefragIPv4(ip4)
					if err != nil {
						logger.Debug("IPv4 defragmentation error",
							"error", err,
							"src", ip4.SrcIP,
							"dst", ip4.DstIP,
							"id", ip4.Id)
						continue // Skip this fragment
					}
					if reassembledIP == nil {
						// Still waiting for more fragments - don't forward yet
						continue
					}

					// Successfully reassembled - rebuild the packet
					packetsReassembled.Add(1)
					logger.Debug("IPv4 packet reassembled",
						"src", reassembledIP.SrcIP,
						"dst", reassembledIP.DstIP,
						"payload_len", len(reassembledIP.Payload))

					// Rebuild packet from reassembled IP layer
					packet = rebuildReassembledPacket(packet, reassembledIP, handle.LinkType())
				}
			}

			// Handle VXLAN decapsulation - extract the inner Ethernet frame so all
			// downstream processing (SIP detection, RTP correlation, etc.) sees the
			// real traffic rather than the VXLAN tunnel wrapper.
			linkType := handle.LinkType()
			if inner, ok := decapsulateVXLAN(packet); ok {
				packet = inner
				linkType = layers.LinkTypeEthernet
			}

			// Handle ESP with NULL cipher - common in IMS/VoLTE where ESP transport
			// mode provides integrity without encryption. Must run after VXLAN
			// decapsulation so it sees the inner packets from VXLAN tunnels.
			if inner, ok := decapsulateESPNull(packet); ok {
				packet = inner
			} else if inner, ok := decapsulateIPv6FragmentESP(packet); ok {
				packet = inner
			}

			pktInfo := PacketInfo{
				LinkType:  linkType,
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

// rebuildReassembledPacket creates a new gopacket.Packet from a reassembled IPv4 layer.
// This is used after IP defragmentation to produce a complete packet that can be
// decoded with transport layer (UDP/TCP) intact.
//
// The original packet is used to preserve metadata (timestamp, capture info).
// The reassembled IPv4 layer contains the complete payload across all fragments.
func rebuildReassembledPacket(original gopacket.Packet, reassembledIP *layers.IPv4, linkType layers.LinkType) gopacket.Packet {
	// Serialize the reassembled IPv4 layer back to bytes
	// We need to build a complete packet: Ethernet + IPv4 + payload
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Get the link layer from original packet (Ethernet header)
	var ethLayer *layers.Ethernet
	if eth := original.Layer(layers.LayerTypeEthernet); eth != nil {
		ethLayer = eth.(*layers.Ethernet)
	}

	// Check for VLAN tag (802.1Q) - must be preserved for proper packet reconstruction
	// VLAN tags sit between Ethernet and IP layers and must be included in serialization
	var dot1qLayer *layers.Dot1Q
	if dot1q := original.Layer(layers.LayerTypeDot1Q); dot1q != nil {
		dot1qLayer = dot1q.(*layers.Dot1Q)
	}

	// Serialize the packet layers
	var err error
	if ethLayer != nil && dot1qLayer != nil {
		// Packet with VLAN tag: Ethernet + Dot1Q + IPv4 + payload
		err = gopacket.SerializeLayers(buf, opts,
			ethLayer,
			dot1qLayer,
			reassembledIP,
			gopacket.Payload(reassembledIP.Payload),
		)
	} else if ethLayer != nil {
		// Standard Ethernet packet without VLAN: Ethernet + IPv4 + payload
		err = gopacket.SerializeLayers(buf, opts,
			ethLayer,
			reassembledIP,
			gopacket.Payload(reassembledIP.Payload),
		)
	} else {
		// No Ethernet layer (e.g., loopback or raw IP capture)
		err = gopacket.SerializeLayers(buf, opts,
			reassembledIP,
			gopacket.Payload(reassembledIP.Payload),
		)
	}

	if err != nil {
		logger.Debug("Failed to serialize reassembled packet", "error", err)
		// Return original packet as fallback (incomplete, but better than nothing)
		return original
	}

	// Create new packet from serialized bytes
	newPacket := gopacket.NewPacket(buf.Bytes(), linkType, gopacket.Default)

	// Preserve original packet metadata (timestamp, capture length, etc.)
	if original.Metadata() != nil {
		newMeta := newPacket.Metadata()
		newMeta.Timestamp = original.Metadata().Timestamp
		newMeta.CaptureLength = len(buf.Bytes())
		newMeta.Length = len(buf.Bytes())
	}

	return newPacket
}

// decapsulateVXLAN checks if a packet is VXLAN-encapsulated (outer UDP dst port 4789)
// and if so, returns a new packet built from the inner Ethernet frame.
// VXLAN (RFC 7348) always encapsulates an Ethernet frame.
//
// Returns (inner packet, true) on successful decapsulation, or (original, false) if
// the packet is not VXLAN-encapsulated or decapsulation fails.
func decapsulateVXLAN(packet gopacket.Packet) (gopacket.Packet, bool) {
	vxlanLayer := packet.Layer(layers.LayerTypeVXLAN)
	if vxlanLayer == nil {
		return packet, false
	}

	vxlan, ok := vxlanLayer.(*layers.VXLAN)
	if !ok {
		return packet, false
	}

	innerData := vxlan.LayerPayload()
	if len(innerData) == 0 {
		return packet, false
	}

	// Inner VXLAN payload is always an Ethernet frame (RFC 7348)
	innerPacket := gopacket.NewPacket(innerData, layers.LinkTypeEthernet, gopacket.Default)

	// Preserve outer packet metadata (timestamp is critical for ordering)
	if meta := packet.Metadata(); meta != nil {
		innerMeta := innerPacket.Metadata()
		innerMeta.Timestamp = meta.Timestamp
		innerMeta.CaptureLength = len(innerData)
		innerMeta.Length = len(innerData)
	}

	logger.Debug("VXLAN decapsulation",
		"vni", vxlan.VNI,
		"inner_bytes", len(innerData))

	return innerPacket, true
}

// decapsulateESPNull checks if a packet uses ESP with NULL cipher (RFC 3686 / RFC 4835),
// where the ESP payload is unencrypted. This is common in IMS/VoLTE networks where
// ESP transport mode provides integrity protection without encryption.
//
// The heuristic parses the ESP payload as a UDP header, validates the length field, and
// checks that the inner UDP payload looks like SIP or RTP. This avoids false positives
// with genuinely encrypted ESP traffic.
//
// Returns (rebuilt packet, true) on success, or (original, false) if the packet is not
// ESP-NULL-encapsulated, decapsulation fails, or the inner payload is not SIP/RTP.
func decapsulateESPNull(packet gopacket.Packet) (gopacket.Packet, bool) {
	espLayer := packet.Layer(layers.LayerTypeIPSecESP)
	if espLayer == nil {
		return packet, false
	}

	esp, ok := espLayer.(*layers.IPSecESP)
	if !ok {
		return packet, false
	}

	// gopacket puts all ESP bytes into LayerContents() and leaves LayerPayload() empty,
	// because it cannot determine where the encrypted/NULLed payload ends without an SA.
	// Layout: [SPI(4)][Seq(4)][inner data / NULL-cipher payload][pad][pad_len][next_hdr][ICV]
	espContent := esp.LayerContents()
	// Need the 8-byte SPI+Seq header plus ≥2 bytes for the ESP trailer.
	if len(espContent) < 10 {
		return packet, false
	}

	// The actual (potentially unencrypted) payload starts after the 8-byte SPI+Seq header.
	espPayload := espContent[8:]

	// Read the SPI (Security Parameter Index) from the first 4 bytes of the ESP header.
	// SPIs are per-direction security association identifiers. We use them to remember
	// which SPIs we have confirmed are NULL-encrypted (via successful SIP/RTP content match),
	// so that subsequent packets — including TCP continuation segments that do not start with
	// SIP text — can also be decapsulated.
	spi := binary.BigEndian.Uint32(espContent[0:4])

	// Determine the inner protocol and the number of bytes to splice into the rebuilt packet.
	var innerProto layers.IPProtocol
	var innerLen int

	// Try UDP first: bytes 4-5 of the UDP header carry the total UDP length.
	if len(espPayload) >= 10 {
		udpLen := int(binary.BigEndian.Uint16(espPayload[4:6]))
		// UDP length must include the 8-byte header and fit within the ESP payload,
		// leaving at least 2 bytes for the ESP trailer (pad_len + next_header).
		if udpLen >= 8 && udpLen <= len(espPayload)-2 {
			udpPayload := espPayload[8:udpLen]
			if mightBeSIPorRTP(udpPayload) {
				innerProto = layers.IPProtocolUDP
				innerLen = udpLen
			}
		}
	}

	// Try TCP if UDP did not match.
	// The TCP data offset nibble (high 4 bits of byte 12) gives the TCP header length
	// in 32-bit words; valid range is 5..15 (20..60 bytes).
	if innerProto == 0 && len(espPayload) >= 20 {
		tcpDataOff := int(espPayload[12] >> 4)
		if tcpDataOff >= 5 && tcpDataOff <= 15 {
			tcpHeaderLen := tcpDataOff * 4
			if tcpHeaderLen <= len(espPayload) {
				tcpPayload := espPayload[tcpHeaderLen:]
				if mightBeSIPorRTP(tcpPayload) {
					innerProto = layers.IPProtocolTCP
					// Use the full espPayload length; any trailing ICV bytes fall past
					// the SIP double-CRLF body terminator and do not affect SIP parsing.
					innerLen = len(espPayload)
				}
			}
		}
	}

	// If content heuristics did not match, check the SPI cache. A previously confirmed
	// NULL SPI means this is a continuation segment (e.g., TCP SDP body without SIP header).
	// A single SA can carry both UDP and TCP flows, so when the cached protocol fails we
	// also try the alternative protocol before giving up.
	if innerProto == 0 {
		if cached, ok := espNullSPICache.Load(spi); ok {
			proto := cached.(layers.IPProtocol)
			// tryProto attempts to identify innerProto/innerLen for the given protocol.
			tryProto := func(p layers.IPProtocol) {
				switch p {
				case layers.IPProtocolUDP:
					if len(espPayload) >= 10 {
						udpLen := int(binary.BigEndian.Uint16(espPayload[4:6]))
						if udpLen >= 8 && udpLen <= len(espPayload) {
							innerProto = layers.IPProtocolUDP
							innerLen = udpLen
						}
					}
				case layers.IPProtocolTCP:
					if len(espPayload) >= 20 {
						tcpDataOff := int(espPayload[12] >> 4)
						if tcpDataOff >= 5 && tcpDataOff <= 15 {
							innerProto = layers.IPProtocolTCP
							innerLen = len(espPayload)
						}
					}
				}
			}
			// Try the cached protocol first, then the alternative.
			tryProto(proto)
			if innerProto == 0 {
				if proto == layers.IPProtocolUDP {
					tryProto(layers.IPProtocolTCP)
				} else {
					tryProto(layers.IPProtocolUDP)
				}
			}
		}
	}

	if innerProto == 0 {
		return packet, false
	}

	// Record this SPI as NULL-encrypted on first confirmed detection.
	// Subsequent packets (including TCP continuations) will bypass content checks.
	espNullSPICache.Store(spi, innerProto)

	rawData := packet.Data()
	if len(rawData) == 0 {
		return packet, false
	}

	// Calculate the byte offset of the ESP header within rawData.
	// rawData = [pre-ESP bytes][ESP content (SPI+Seq+payload)]
	espOffset := len(rawData) - len(espContent)
	if espOffset <= 0 {
		return packet, false
	}

	// Build new raw packet: [IP headers up to (not including) ESP][inner transport data]
	newRaw := make([]byte, espOffset+innerLen)
	copy(newRaw[:espOffset], rawData[:espOffset])
	copy(newRaw[espOffset:], espPayload[:innerLen])

	// Patch the IP Next Header / Protocol field to the inner protocol and fix the
	// IP payload-length field so gopacket parses the new packet correctly.
	switch ipLayer := packet.NetworkLayer().(type) {
	case *layers.IPv6:
		// Only handle direct IPv6/ESP (no extension headers between IPv6 and ESP).
		if ipLayer.NextHeader != layers.IPProtocolESP {
			return packet, false
		}
		ipv6Contents := ipLayer.LayerContents()
		// IPv6 header offset: rawData = [eth][ipv6][esp][...]
		ipv6Off := len(rawData) - len(ipv6Contents) - len(ipLayer.LayerPayload())
		if ipv6Off < 0 || ipv6Off+8 > len(newRaw) {
			return packet, false
		}
		newRaw[ipv6Off+6] = byte(innerProto) // Next Header
		binary.BigEndian.PutUint16(newRaw[ipv6Off+4:], uint16(innerLen))

	case *layers.IPv4:
		if ipLayer.Protocol != layers.IPProtocolESP {
			return packet, false
		}
		ipv4Contents := ipLayer.LayerContents()
		ipv4Off := len(rawData) - len(ipv4Contents) - len(ipLayer.LayerPayload())
		if ipv4Off < 0 || ipv4Off+20 > len(newRaw) {
			return packet, false
		}
		newRaw[ipv4Off+9] = byte(innerProto) // Protocol
		binary.BigEndian.PutUint16(newRaw[ipv4Off+2:], uint16(len(newRaw)-ipv4Off))
		// Zero the checksum — gopacket accepts unchecked checksums.
		newRaw[ipv4Off+10] = 0
		newRaw[ipv4Off+11] = 0

	default:
		return packet, false
	}

	// Determine link type for re-parsing.
	linkType := layers.LinkTypeEthernet
	if packet.Layer(layers.LayerTypeEthernet) == nil {
		if packet.Layer(layers.LayerTypeLinuxSLL) != nil {
			linkType = layers.LinkTypeLinuxSLL
		} else {
			return packet, false
		}
	}

	innerPacket := gopacket.NewPacket(newRaw, linkType, gopacket.Default)

	// Verify the expected transport layer is present in the rebuilt packet.
	switch innerProto {
	case layers.IPProtocolUDP:
		if innerPacket.Layer(layers.LayerTypeUDP) == nil {
			return packet, false
		}
	case layers.IPProtocolTCP:
		if innerPacket.Layer(layers.LayerTypeTCP) == nil {
			return packet, false
		}
	default:
		return packet, false
	}

	// Preserve capture metadata (timestamp is critical for ordering).
	if meta := packet.Metadata(); meta != nil {
		innerMeta := innerPacket.Metadata()
		innerMeta.Timestamp = meta.Timestamp
		innerMeta.CaptureLength = meta.CaptureLength
		innerMeta.Length = meta.Length
	}

	logger.Debug("ESP-NULL decapsulation",
		"proto", innerProto,
		"inner_len", innerLen)

	return innerPacket, true
}

// decapsulateIPv6FragmentESP handles IPv6 packets where a Fragment extension header
// precedes an ESP-NULL-encrypted transport segment. This occurs in IMS/VoLTE when a
// large SIP message is fragmented at the IPv6 layer before ESP encapsulation.
//
// For the first fragment (offset == 0), the fragment payload begins with the ESP header
// (SPI+Seq) followed by the inner transport header (UDP/TCP) and the start of the SIP
// body. We rebuild the packet as a plain IPv6/UDP or IPv6/TCP packet so downstream
// protocol detectors see the SIP content.
//
// For non-first fragments the inner transport header is absent; we only detect them
// when the SPI has already been cached from the first fragment, and we expose the raw
// fragment bytes as a UDP payload so TCP reassembly or call-tracker see the continuation.
func decapsulateIPv6FragmentESP(packet gopacket.Packet) (gopacket.Packet, bool) {
	fragLayer := packet.Layer(layers.LayerTypeIPv6Fragment)
	if fragLayer == nil {
		return packet, false
	}
	frag, ok := fragLayer.(*layers.IPv6Fragment)
	if !ok {
		return packet, false
	}
	// Only handle the ESP protocol inside the fragment.
	if frag.NextHeader != layers.IPProtocolESP {
		return packet, false
	}

	// The fragment payload is the raw ESP data (SPI + Seq + inner content...).
	fragPayload := frag.LayerPayload()
	if len(fragPayload) < 10 {
		return packet, false
	}

	spi := binary.BigEndian.Uint32(fragPayload[0:4])
	// Inner content starts after the 8-byte ESP base header (SPI + Seq).
	espInner := fragPayload[8:]

	var innerProto layers.IPProtocol
	var innerLen int
	// syntheticTransport is non-nil when we build a fake transport header for a non-first
	// fragment so that the gopacket decoder can parse the resulting packet correctly.
	var syntheticTransport []byte

	if frag.FragmentOffset == 0 {
		// First fragment: the inner transport header is present.
		// Try UDP. The UDP length field may exceed the fragment size when
		// the payload spans multiple IPv6 fragments, so we cap at espInner length.
		if len(espInner) >= 10 {
			udpLen := int(binary.BigEndian.Uint16(espInner[4:6]))
			// Cap: use whatever bytes are available in this fragment.
			actualLen := min(udpLen, len(espInner))
			if udpLen >= 8 && actualLen >= 8 {
				udpPayload := espInner[8:actualLen]
				if mightBeSIPorRTP(udpPayload) {
					innerProto = layers.IPProtocolUDP
					innerLen = actualLen
					// Store transport port info for non-first fragment reconstruction.
					ipv6FragIDCache.Store(frag.Identification, ipv6FragInfo{
						innerProto: innerProto,
						srcPort:    binary.BigEndian.Uint16(espInner[0:2]),
						dstPort:    binary.BigEndian.Uint16(espInner[2:4]),
					})
				}
			}
		}
		// Try TCP if UDP did not match.
		if innerProto == 0 && len(espInner) >= 20 {
			tcpDataOff := int(espInner[12] >> 4)
			if tcpDataOff >= 5 && tcpDataOff <= 15 {
				tcpHeaderLen := tcpDataOff * 4
				if tcpHeaderLen <= len(espInner) {
					tcpPayload := espInner[tcpHeaderLen:]
					if mightBeSIPorRTP(tcpPayload) {
						innerProto = layers.IPProtocolTCP
						innerLen = len(espInner)
						ipv6FragIDCache.Store(frag.Identification, ipv6FragInfo{
							innerProto: innerProto,
							srcPort:    binary.BigEndian.Uint16(espInner[0:2]),
							dstPort:    binary.BigEndian.Uint16(espInner[2:4]),
						})
					}
				}
			}
		}
		if innerProto != 0 {
			espNullSPICache.Store(spi, innerProto)
		}
	}

	// For non-first fragments, use the fragment ID cache first (preferred: provides
	// accurate port numbers so the synthetic packet is fully parseable), then fall
	// back to the SPI cache (provides proto only; port numbers will be garbage).
	if innerProto == 0 {
		if cached, ok := ipv6FragIDCache.Load(frag.Identification); ok {
			info := cached.(ipv6FragInfo)
			innerProto = info.innerProto
			// Build a synthetic transport header so gopacket can parse the packet
			// and downstream flow caches can match it by port.
			if innerProto == layers.IPProtocolUDP {
				syntheticTransport = make([]byte, 8+len(espInner))
				binary.BigEndian.PutUint16(syntheticTransport[0:2], info.srcPort)
				binary.BigEndian.PutUint16(syntheticTransport[2:4], info.dstPort)
				binary.BigEndian.PutUint16(syntheticTransport[4:6], uint16(8+len(espInner)))
				// checksum left at 0 (unchecked)
				copy(syntheticTransport[8:], espInner)
				innerLen = len(syntheticTransport)
			} else {
				innerLen = len(espInner)
			}
		} else if cached, ok := espNullSPICache.Load(spi); ok {
			innerProto = cached.(layers.IPProtocol)
			innerLen = len(espInner)
		}
	}
	if innerProto == 0 {
		return packet, false
	}

	// Build a new raw packet: [Ethernet][IPv6 without Fragment ext hdr][inner transport]
	// The IPv6 header immediately precedes the Fragment extension header in rawData.
	rawData := packet.Data()
	if len(rawData) == 0 {
		return packet, false
	}

	ipv6Layer, isIPv6 := packet.NetworkLayer().(*layers.IPv6)
	if !isIPv6 {
		return packet, false
	}

	// Locate the IPv6 header in rawData.
	ipv6Contents := ipv6Layer.LayerContents()
	ipv6Off := len(rawData) - len(ipv6Contents) - len(ipv6Layer.LayerPayload())
	if ipv6Off < 0 {
		return packet, false
	}

	// The Fragment extension header (8 bytes, RFC 2460) sits between the IPv6 header
	// and the ESP data; its start in rawData is derived from fragPayload's position.
	espStartInRaw := len(rawData) - len(fragPayload)
	if espStartInRaw < ipv6Off+len(ipv6Contents) {
		return packet, false
	}

	// New raw packet layout: pre-IPv6 + IPv6(40) + inner transport data
	// We splice out the Fragment extension header and ESP header, keeping only the inner.
	preIPv6Len := ipv6Off
	newRaw := make([]byte, preIPv6Len+len(ipv6Contents)+innerLen)
	copy(newRaw[:preIPv6Len], rawData[:preIPv6Len])
	copy(newRaw[preIPv6Len:preIPv6Len+len(ipv6Contents)], ipv6Contents)
	if syntheticTransport != nil {
		copy(newRaw[preIPv6Len+len(ipv6Contents):], syntheticTransport)
	} else {
		copy(newRaw[preIPv6Len+len(ipv6Contents):], espInner[:innerLen])
	}

	// Patch the IPv6 header: clear the Fragment extension header by setting
	// Next Header directly to the inner protocol, and fix the payload length.
	ipv6HdrOff := preIPv6Len
	newRaw[ipv6HdrOff+6] = byte(innerProto)
	binary.BigEndian.PutUint16(newRaw[ipv6HdrOff+4:], uint16(innerLen))

	linkType := layers.LinkTypeEthernet
	if packet.Layer(layers.LayerTypeEthernet) == nil {
		if packet.Layer(layers.LayerTypeLinuxSLL) != nil {
			linkType = layers.LinkTypeLinuxSLL
		} else {
			return packet, false
		}
	}

	innerPacket := gopacket.NewPacket(newRaw, linkType, gopacket.Default)

	// Verify the expected transport layer is present.
	switch innerProto {
	case layers.IPProtocolUDP:
		if innerPacket.Layer(layers.LayerTypeUDP) == nil {
			return packet, false
		}
	case layers.IPProtocolTCP:
		if innerPacket.Layer(layers.LayerTypeTCP) == nil {
			return packet, false
		}
	default:
		return packet, false
	}

	if meta := packet.Metadata(); meta != nil {
		innerMeta := innerPacket.Metadata()
		innerMeta.Timestamp = meta.Timestamp
		innerMeta.CaptureLength = meta.CaptureLength
		innerMeta.Length = meta.Length
	}

	logger.Debug("IPv6-fragment ESP-NULL decapsulation",
		"spi", spi,
		"frag_offset", frag.FragmentOffset,
		"proto", innerProto,
		"inner_len", innerLen)

	return innerPacket, true
}

// mightBeSIPorRTP is a heuristic that returns true when a payload byte slice looks like
// cleartext SIP or RTP content. Used to guard ESP-NULL decapsulation from false-positives
// on genuinely encrypted ESP traffic, whose payload bytes appear random.
func mightBeSIPorRTP(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}

	// SIP is a text protocol. Every SIP message starts with a method name or "SIP/2.0".
	for _, prefix := range [][]byte{
		[]byte("SIP/2.0"), []byte("INVITE "), []byte("BYE "), []byte("ACK "),
		[]byte("REGISTER"), []byte("OPTIONS "), []byte("SUBSCRIBE"),
		[]byte("NOTIFY "), []byte("CANCEL "), []byte("PRACK "),
		[]byte("INFO "), []byte("REFER "), []byte("MESSAGE "),
		[]byte("UPDATE "), []byte("PUBLISH "),
	} {
		if bytes.HasPrefix(payload, prefix) {
			return true
		}
	}

	// RTP (RFC 3550): version field occupies the top 2 bits of the first byte
	// and must be 2. Minimum RTP header is 12 bytes.
	if len(payload) >= 12 && (payload[0]>>6) == 2 {
		return true
	}

	return false
}
