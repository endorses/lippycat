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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
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

func StartSniffer(devices []pcaptypes.PcapInterface, filter string) {
	fmt.Println("Starting Sniffer")
	streamFactory := NewStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	Init(devices, filter, processPacket, assembler)
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
	for p := range packetChan {
		packet := p.Packet
		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			// fmt.Println("TCP")
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
		case *layers.UDP:
			// fmt.Println("UDP")
		}
		fmt.Printf("%s\n", p.Packet)
	}
}
