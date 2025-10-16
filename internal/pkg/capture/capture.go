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

type PacketBuffer struct {
	ch         chan PacketInfo
	ctx        context.Context
	cancel     context.CancelFunc
	dropped    int64
	bufferSize int
	closed     int32          // atomic flag: 0 = open, 1 = closed
	sendersWg  sync.WaitGroup // tracks active Send() operations to prevent race on channel close
}

func NewPacketBuffer(ctx context.Context, bufferSize int) *PacketBuffer {
	ctx, cancel := context.WithCancel(ctx)
	return &PacketBuffer{
		ch:         make(chan PacketInfo, bufferSize),
		ctx:        ctx,
		cancel:     cancel,
		bufferSize: bufferSize,
		closed:     0,
	}
}

func (pb *PacketBuffer) Send(pkt PacketInfo) bool {
	// Fast path: check if already closed
	if atomic.LoadInt32(&pb.closed) == 1 {
		return false
	}

	// Register this sender to prevent channel close race
	pb.sendersWg.Add(1)
	defer pb.sendersWg.Done()

	// Double-check closed flag after registering (in case Close() was called concurrently)
	if atomic.LoadInt32(&pb.closed) == 1 {
		return false
	}

	// Check context cancellation first with higher priority
	select {
	case <-pb.ctx.Done():
		return false
	default:
	}

	// Now attempt send with context check
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

func (pb *PacketBuffer) Receive() <-chan PacketInfo {
	return pb.ch
}

// Len returns the current number of buffered packets
func (pb *PacketBuffer) Len() int {
	return len(pb.ch)
}

// Cap returns the capacity of the packet buffer
func (pb *PacketBuffer) Cap() int {
	return cap(pb.ch)
}

func (pb *PacketBuffer) Close() {
	// Set closed flag atomically before closing channel
	if !atomic.CompareAndSwapInt32(&pb.closed, 0, 1) {
		// Already closed, return early
		return
	}

	pb.cancel()

	// Wait for all active Send() operations to complete
	// This prevents closing the channel while senders are still active
	pb.sendersWg.Wait()

	close(pb.ch)
	if dropped := atomic.LoadInt64(&pb.dropped); dropped > 0 {
		logger.Info("Packet buffer closed with drops",
			"total_dropped", dropped)
	}
}

func (pb *PacketBuffer) IsClosed() bool {
	return atomic.LoadInt32(&pb.closed) == 1
}

func Init(ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	InitWithContext(context.Background(), ifaces, filter, packetProcessor, assembler)
}

// InitWithContext starts packet capture with a cancellable context
// Note: Signal handling should be done by the caller. This function only respects context cancellation.
func InitWithContext(ctx context.Context, ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	// Use a configurable buffer size with proper backpressure handling
	bufferSize := getPacketBufferSize()
	packetBuffer := NewPacketBuffer(ctx, bufferSize)
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

	for _, iface := range ifaces {
		wg.Add(1)
		go func(pif pcaptypes.PcapInterface) {
			defer wg.Done()
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

	// Wait for either completion or shutdown + timeout
	select {
	case <-done:
		// Completed normally (before or after shutdown)
		return
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
	var packetCount int64      // shared atomic counter
	var localCount int64       // goroutine-local counter (no atomic needed)
	const batchThreshold = 100 // flush to atomic every N packets

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count := atomic.LoadInt64(&packetCount)
				dropped := atomic.LoadInt64(&buffer.dropped)
				logger.Info("Interface packet statistics",
					"interface", iface.Name(),
					"packets_processed", count,
					"packets_dropped", dropped)
			}
		}
	}()

	// Use a goroutine to read packets and forward them to a channel
	packetCh := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining local count before exit
			if localCount > 0 {
				atomic.AddInt64(&packetCount, localCount)
			}
			return
		case packet, ok := <-packetCh:
			if !ok {
				// Channel closed, flush and exit
				if localCount > 0 {
					atomic.AddInt64(&packetCount, localCount)
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
			localCount++
			if localCount >= batchThreshold {
				atomic.AddInt64(&packetCount, localCount)
				localCount = 0
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
