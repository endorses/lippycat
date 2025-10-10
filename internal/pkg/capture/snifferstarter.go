package capture

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/spf13/viper"
)

func StartLiveSniffer(interfaces, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	var devices []pcaptypes.PcapInterface
	for _, device := range strings.Split(interfaces, ",") {
		iface := pcaptypes.CreateLiveInterface(device)
		devices = append(devices, iface)
	}
	startSniffer(devices, filter)
}

func StartOfflineSniffer(readFile, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	file, err := os.Open(readFile)
	if err != nil {
		logger.Error("Could not read file",
			"file", readFile,
			"error", err)
		return
	}

	// Create a context with timeout to prevent indefinite blocking
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Ensure file is always closed, even if startSniffer blocks
	defer file.Close()

	iface := pcaptypes.CreateOfflineInterface(file)
	devices := []pcaptypes.PcapInterface{iface}

	// Run startSniffer in a goroutine with context monitoring
	done := make(chan struct{})
	go func() {
		defer close(done)
		startSniffer(devices, filter)
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		// Completed normally
	case <-ctx.Done():
		logger.Error("Offline sniffer timed out, forcing cleanup",
			"file", readFile,
			"error", ctx.Err())
	}
}

// RunWithSignalHandler runs the capture in background and handles signals for graceful shutdown
// This is the common pattern used by hunt, sniff, and sniff voip commands
func RunWithSignalHandler(devices []pcaptypes.PcapInterface, filter string,
	processor func(ch <-chan PacketInfo, asm *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {

	// Create cancellable context for capture
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handler for graceful shutdown
	cleanup := signals.SetupHandler(ctx, cancel)
	defer cleanup()

	// Run capture in background (like hunter nodes do)
	go func() {
		InitWithContext(ctx, devices, filter, processor, assembler)
	}()

	// Wait for signal (blocks until context is cancelled)
	<-ctx.Done()

	// Give a brief moment for graceful cleanup (like hunt nodes do)
	time.Sleep(500 * time.Millisecond)
}

func StartSniffer(devices []pcaptypes.PcapInterface, filter string) {
	fmt.Println("Starting Sniffer")

	// For basic sniffing, we don't need TCP stream reassembly
	// Pass nil assembler to skip expensive TCP assembly
	processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
		processPacketSimple(ch)
	}

	RunWithSignalHandler(devices, filter, processor, nil)
}

// processPacketSimple is a lightweight processor without TCP reassembly
func processPacketSimple(packetChan <-chan PacketInfo) {
	packetCount := 0
	lastStatsTime := time.Now()
	startTime := time.Now()
	quietMode := viper.GetBool("sniff.quiet")

	for p := range packetChan {
		packetCount++

		// Print each packet (basic info) unless in quiet mode
		if !quietMode {
			fmt.Printf("%s\n", p.Packet)
		}

		// Print statistics summary every second
		if time.Since(lastStatsTime) >= 1*time.Second {
			elapsed := time.Since(startTime).Seconds()
			if elapsed > 0 {
				logger.Info("Packet statistics",
					"total_processed", packetCount,
					"rate_pps", int64(float64(packetCount)/elapsed))
			}
			lastStatsTime = time.Now()
		}
	}

	logger.Info("Packet processing completed", "total_packets", packetCount)
}

const maxStreamWorkers = 50 // Maximum concurrent stream processing goroutines

type streamFactory struct {
	workerPool chan struct{}
	wg         sync.WaitGroup
}

func NewStreamFactory() tcpassembly.StreamFactory {
	return &streamFactory{
		workerPool: make(chan struct{}, maxStreamWorkers),
	}
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// Try to acquire a worker from the pool (non-blocking)
	select {
	case f.workerPool <- struct{}{}:
		// Got a worker slot, start processing
		f.wg.Add(1)
		go f.processStreamWithPool(&r)
	default:
		// Pool is full, log and skip processing to prevent goroutine explosion
		logger.Warn("Stream worker pool exhausted, skipping stream processing",
			"max_workers", maxStreamWorkers)
	}

	return &r
}

func (f *streamFactory) processStreamWithPool(r io.Reader) {
	defer func() {
		// Release worker slot back to pool
		<-f.workerPool
		f.wg.Done()

		if rec := recover(); rec != nil {
			logger.Error("Stream processing panic recovered",
				"panic_value", rec)
		}
	}()

	processStream(r)
}

// Shutdown waits for all active stream workers to complete
func (f *streamFactory) Shutdown() {
	f.wg.Wait()
}

func processStream(r io.Reader) {
	// Process the stream data properly
	buffer := make([]byte, 4096)
	for {
		n, err := r.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading stream", "error", err)
			}
			return
		}
		if n == 0 {
			return
		}

		// Process the data (this is a placeholder - real processing would depend on protocol)
		data := buffer[:n]
		if len(data) > 0 {
			logger.Debug("Processed bytes from stream",
				"bytes_count", len(data))
			// Here you would implement actual protocol parsing
		}
	}
}

func processPacket(packetChan <-chan PacketInfo, assembler *tcpassembly.Assembler) {
	packetCount := 0
	lastPrintTime := time.Now()

	for p := range packetChan {
		packet := p.Packet
		packetCount++

		// Print summary less frequently to avoid blocking on I/O
		if time.Since(lastPrintTime) >= 1*time.Second {
			logger.Debug("Processed packets", "count", packetCount)
			lastPrintTime = time.Now()
		}

		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			// Recover from any panics in the TCP assembler (e.g., malformed packets)
			func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("TCP assembler panic recovered",
							"panic_value", r,
							"packet", packet)
					}
				}()

				// Validate network layer exists before passing to assembler
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					assembler.AssembleWithTimestamp(
						netLayer.NetworkFlow(),
						layer,
						packet.Metadata().Timestamp,
					)
				}
			}()
		case *layers.UDP:
			// UDP packets - no processing needed for basic sniff
		}
	}

	logger.Info("Packet processing completed", "total_packets", packetCount)
}

func processPacketWithContext(p PacketInfo, assembler *tcpassembly.Assembler, ctx context.Context) {
	packet := p.Packet
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		// Recover from any panics in the TCP assembler (e.g., malformed packets)
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("TCP assembler panic recovered",
						"panic_value", r,
						"packet", packet)
				}
			}()

			// Validate network layer exists before passing to assembler
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				assembler.AssembleWithTimestamp(
					netLayer.NetworkFlow(),
					layer,
					packet.Metadata().Timestamp,
				)
			}
		}()
	case *layers.UDP:
		// fmt.Println("UDP")
	}
	fmt.Printf("%s\n", p.Packet)
}
