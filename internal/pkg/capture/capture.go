package capture

import (
	"context"
	"os"
	"os/signal"
	"runtime"
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
	// Check if already closed before attempting send
	if atomic.LoadInt32(&pb.closed) == 1 {
		return false
	}

	// Use defer/recover to handle potential panic from closed channel
	defer func() {
		if r := recover(); r != nil {
			// Channel was closed during send, mark as closed
			atomic.StoreInt32(&pb.closed, 1)
		}
	}()

	// Check context first to ensure consistent behavior
	select {
	case <-pb.ctx.Done():
		return false
	default:
	}

	select {
	case pb.ch <- pkt:
		return true
	case <-pb.ctx.Done():
		return false
	default:
		// Non-blocking send with drop counting
		atomic.AddInt64(&pb.dropped, 1)
		if atomic.LoadInt64(&pb.dropped)%1000 == 0 {
			logger.Warn("Packets dropped due to buffer overflow",
				"total_dropped", atomic.LoadInt64(&pb.dropped))
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
	ctx, cancel := context.WithCancel(context.Background())
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
	numProcessors := runtime.NumCPU()
	processorWg.Add(numProcessors)

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

	go func() {
		select {
		case <-ctx.Done():
			// Context cancelled, force cleanup
			packetBuffer.Close()
		default:
			wg.Wait()
			packetBuffer.Close()
		}
	}()

	for range numProcessors {
		go func() {
			defer processorWg.Done()
			// Create a context-aware packet processor that can be cancelled
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Run packet processor with context monitoring
					packetProcessor(packetBuffer.Receive(), assembler)
					// Check if buffer is closed
					if packetBuffer.IsClosed() {
						return
					}
				}
			}
		}()
	}

	processorWg.Wait()
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

	packetCount := int64(0)
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
			return
		case packet, ok := <-packetCh:
			if !ok {
				// Channel closed, exit
				return
			}
			pktInfo := PacketInfo{
				LinkType: handle.LinkType(),
				Packet:   packet,
			}
			buffer.Send(pktInfo)
			atomic.AddInt64(&packetCount, 1)
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
