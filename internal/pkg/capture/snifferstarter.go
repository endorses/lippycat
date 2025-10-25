package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	// #nosec G304 -- readFile is from CLI --read-file flag, intentional user-specified path
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
	time.Sleep(constants.SnifferCleanupTimeout)
}

func StartSniffer(devices []pcaptypes.PcapInterface, filter string) {
	logger.Info("Starting packet sniffer")

	// For basic sniffing, we don't need TCP stream reassembly
	// Pass nil assembler to skip expensive TCP assembly
	processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
		processPacketSimple(ch)
	}

	// Check if this is offline mode (reading from PCAP file)
	// Offline interfaces have filenames as their Name(), not network interface names
	isOffline := false
	for _, dev := range devices {
		// Offline interfaces return the filename in Name()
		// which will contain a path separator or .pcap extension
		name := dev.Name()
		if strings.Contains(name, ".pcap") || strings.Contains(name, ".pcapng") || strings.Contains(name, "/") {
			isOffline = true
			break
		}
	}

	if isOffline {
		// For offline mode, run until PCAP is fully read
		RunOffline(devices, filter, processor, nil)
	} else {
		// For live mode, run with signal handler (waits for Ctrl+C)
		RunWithSignalHandler(devices, filter, processor, nil)
	}
}

// RunOffline runs the capture for offline PCAP files and exits when complete
// Unlike RunWithSignalHandler, this cancels the context when all packets are read
func RunOffline(devices []pcaptypes.PcapInterface, filter string,
	processor func(ch <-chan PacketInfo, asm *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {

	// For offline mode, we use a custom implementation that detects EOF
	// and cancels the context to trigger cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create buffer
	bufferSize := getPacketBufferSize()
	packetBuffer := NewPacketBuffer(ctx, bufferSize)
	defer packetBuffer.Close()

	// Start capture goroutines
	var captureWg sync.WaitGroup
	for _, iface := range devices {
		captureWg.Add(1)
		go func(pif pcaptypes.PcapInterface) {
			defer captureWg.Done()

			err := pif.SetHandle()
			if err != nil {
				logger.Error("Error setting pcap handle", "error", err, "interface", pif.Name())
				return
			}
			handle, err := pif.Handle()
			if err != nil || handle == nil {
				logger.Error("Error getting pcap handle", "error", err, "interface", pif.Name())
				return
			}
			defer handle.Close()

			captureFromInterface(ctx, pif, filter, packetBuffer)
		}(iface)
	}

	// Start processor
	var processorWg sync.WaitGroup
	processorWg.Add(1)
	go func() {
		defer processorWg.Done()
		processor(packetBuffer.Receive(), assembler)
	}()

	// Wait for all capture goroutines to finish (EOF reached)
	captureWg.Wait()

	// Flush TCP assembler if present (forces reassembly of any remaining streams)
	// Note: This can sometimes panic with gopacket's known index out of range bug
	// but since virtual interface creation now happens first, permission errors abort early
	if assembler != nil {
		// Use FlushOlderThan instead of FlushAll to reduce panic frequency
		// FlushAll has a known issue with index out of range when called on certain states
		// FlushOlderThan(time.Now()) achieves the same result but is more robust
		_, _ = assembler.FlushOlderThan(time.Now())
		// Give assembler time to process flushed streams
		// This ensures SIP messages are extracted before we close the buffer
		time.Sleep(100 * time.Millisecond)
	}

	// Close the buffer so processor can exit
	packetBuffer.Close()

	// Wait for processor to finish draining
	processorWg.Wait()
}

// processPacketSimple is a lightweight processor without TCP reassembly
func processPacketSimple(packetChan <-chan PacketInfo) {
	packetCount := 0
	lastStatsTime := time.Now()
	startTime := time.Now()
	quietMode := viper.GetBool("sniff.quiet")
	format := viper.GetString("sniff.format")
	writeFile := viper.GetString("sniff.write_file")

	// Initialize virtual interface if enabled
	var vifMgr vinterface.Manager
	var timingReplayer *vinterface.TimingReplayer
	if viper.GetBool("sniff.virtual_interface") {
		vifName := viper.GetString("sniff.vif_name")
		if vifName == "" {
			vifName = "lc0"
		}

		cfg := vinterface.DefaultConfig()
		cfg.Name = vifName

		var err error
		vifMgr, err = vinterface.NewManager(cfg)
		if err != nil {
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
				logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
				return
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", vifName)
				logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
				return
			}
		}

		err = vifMgr.Start()
		if err != nil {
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else {
				logger.Error("Failed to start virtual interface",
					"error", err,
					"interface_name", vifName)
			}
			logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
			return
		}

		logger.Info("Virtual interface started successfully",
			"interface_name", vifMgr.Name())

		// Wait for external tools (tcpdump, Wireshark) to attach
		startupDelay := viper.GetDuration("sniff.vif_startup_delay")
		if startupDelay > 0 {
			logger.Info("Waiting for monitoring tools to attach...",
				"delay", startupDelay)
			time.Sleep(startupDelay)
		}
		logger.Info("Starting packet injection")

		// Initialize timing replayer for virtual interface
		replayTiming := viper.GetBool("sniff.vif_replay_timing")
		timingReplayer = vinterface.NewTimingReplayer(replayTiming)

		// Ensure cleanup on exit
		defer func() {
			if vifMgr != nil {
				stats := vifMgr.Stats()
				logger.Info("Virtual interface statistics",
					"packets_injected", stats.PacketsInjected,
					"packets_dropped", stats.PacketsDropped,
					"injection_errors", stats.InjectionErrors,
					"conversion_errors", stats.ConversionErrors)

				if err := vifMgr.Shutdown(); err != nil {
					logger.Error("Error shutting down virtual interface", "error", err)
				} else {
					logger.Info("Virtual interface shutdown successfully")
				}
			}
		}()
	}

	// Create JSON encoder if using JSON format
	var jsonEncoder *json.Encoder
	if format == "json" {
		jsonEncoder = json.NewEncoder(os.Stdout)
	}

	// Create PCAP writer if write_file is specified
	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	if writeFile != "" {
		// #nosec G304 -- writeFile is from CLI --write-file flag, intentional user-specified path
		f, err := os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create PCAP file", "file", writeFile, "error", err)
		} else {
			pcapFile = f
			pcapWriter = pcapgo.NewWriter(pcapFile)
			// Write PCAP header with snaplen of 65535 (max packet size)
			if err := pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to write PCAP header", "error", err)
				pcapFile.Close()
				pcapWriter = nil
				pcapFile = nil
			} else {
				logger.Info("Writing packets to PCAP file", "file", writeFile)
				defer func() {
					if pcapFile != nil {
						pcapFile.Close()
						logger.Info("PCAP file written successfully", "file", writeFile, "packets", packetCount)
					}
				}()
			}
		}
	}

	for p := range packetChan {
		packetCount++

		// Inject packet into virtual interface if enabled
		if vifMgr != nil {
			// Handle packet timing replay (respects PCAP timestamps like tcpreplay)
			if timingReplayer != nil {
				timingReplayer.WaitForPacketTime(p.Packet.Metadata().Timestamp)
			}

			display := ConvertPacketToDisplay(p)
			if err := vifMgr.InjectPacketBatch([]types.PacketDisplay{display}); err != nil {
				logger.Debug("Failed to inject packet to virtual interface", "error", err)
			}
		}

		// Write to PCAP file if writer is available
		if pcapWriter != nil {
			if err := pcapWriter.WritePacket(p.Packet.Metadata().CaptureInfo, p.Packet.Data()); err != nil {
				logger.Error("Failed to write packet to PCAP", "error", err)
			}
		}

		// Print each packet unless in quiet mode
		if !quietMode {
			if format == "json" {
				// Convert to structured PacketDisplay and output as JSON
				display := ConvertPacketToDisplay(p)
				if err := jsonEncoder.Encode(display); err != nil {
					logger.Error("Failed to encode packet as JSON", "error", err)
				}
			} else {
				// Default text format (gopacket's String() representation)
				fmt.Printf("%s\n", p.Packet)
			}
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
