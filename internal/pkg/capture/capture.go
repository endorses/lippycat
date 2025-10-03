package capture

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
)

type PacketInfo struct {
	LinkType layers.LinkType
	Packet   gopacket.Packet
}

type PacketBuffer struct {
	ch         chan PacketInfo
	ctx        context.Context
	cancel     context.CancelFunc
	dropped    int64
	bufferSize int
	closed     int32 // atomic flag: 0 = open, 1 = closed
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

	// Single select with all cases - more efficient
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

func (pb *PacketBuffer) Close() {
	// Set closed flag atomically before closing channel
	if !atomic.CompareAndSwapInt32(&pb.closed, 0, 1) {
		// Already closed, return early
		return
	}

	pb.cancel()

	// Give senders a small window to finish
	time.Sleep(10 * time.Millisecond)

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
func InitWithContext(ctx context.Context, ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set up signal handler for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigCh
		logger.Info("Received signal, shutting down gracefully", "signal", sig.String())
		cancel()
	}()

	// Use a configurable buffer size with proper backpressure handling
	bufferSize := getPacketBufferSize()
	packetBuffer := NewPacketBuffer(ctx, bufferSize)
	defer packetBuffer.Close()

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

	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		// Context cancelled, wait for capture goroutines to stop
		wg.Wait()
		// Close the buffer which will cause the processor to exit
		packetBuffer.Close()
		// Signal that shutdown has started
		close(shutdownCh)
	}()

	// Start a single goroutine that calls the user-provided packet processor
	// The packet processor is responsible for reading from the channel
	go func() {
		defer processorWg.Done()
		packetProcessor(packetBuffer.Receive(), assembler)
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
			logger.Warn("Forcing shutdown after drain timeout", "timeout", "2s")
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
	var packetCount int64 // shared atomic counter
	var localCount int64  // goroutine-local counter (no atomic needed)
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
				LinkType: handle.LinkType(),
				Packet:   packet,
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
