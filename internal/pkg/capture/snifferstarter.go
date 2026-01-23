package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

// StartOfflineSnifferOrdered opens PCAP files and starts a timestamp-ordered sniffer.
// This ensures packets from multiple files are processed in chronological order,
// which is essential for VoIP analysis where SIP signaling must precede RTP.
func StartOfflineSnifferOrdered(readFiles []string, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	if len(readFiles) == 0 {
		logger.Error("No files provided for offline capture")
		return
	}

	// Open all files and create interfaces
	var files []*os.File
	var devices []pcaptypes.PcapInterface

	for _, readFile := range readFiles {
		// #nosec G304 -- readFile is from CLI positional args, intentional user-specified path
		file, err := os.Open(readFile)
		if err != nil {
			logger.Error("Could not read file",
				"file", readFile,
				"error", err)
			// Close any files we already opened
			for _, f := range files {
				f.Close()
			}
			return
		}
		files = append(files, file)
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}

	// Log multi-file capture info
	if len(readFiles) > 1 {
		logger.Info("Starting timestamp-ordered multi-file offline capture",
			"file_count", len(readFiles))
	}

	// Ensure all files are closed when done
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	// Run the sniffer (blocks until complete)
	startSniffer(devices, filter)
}

func StartOfflineSniffer(readFiles []string, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	if len(readFiles) == 0 {
		logger.Error("No files provided for offline capture")
		return
	}

	// Open all files and create interfaces
	var files []*os.File
	var devices []pcaptypes.PcapInterface

	for _, readFile := range readFiles {
		// #nosec G304 -- readFile is from CLI positional args, intentional user-specified path
		file, err := os.Open(readFile)
		if err != nil {
			logger.Error("Could not read file",
				"file", readFile,
				"error", err)
			// Close any files we already opened
			for _, f := range files {
				f.Close()
			}
			return
		}
		files = append(files, file)
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}

	// Log multi-file capture info
	if len(readFiles) > 1 {
		logger.Info("Starting multi-file offline capture",
			"file_count", len(readFiles),
			"files", readFiles)
	}

	// Create a context with timeout to prevent indefinite blocking
	// Scale timeout with number of files
	timeout := time.Duration(len(readFiles)) * 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Ensure all files are closed when done
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

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
			"files", readFiles,
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

	// Channel to signal when capture exits (for early exit on capture failure)
	captureDone := make(chan struct{})

	// Run capture in background (like hunter nodes do)
	go func() {
		InitWithContext(ctx, devices, filter, processor, assembler, nil)
		close(captureDone)
	}()

	// Wait for signal OR capture completion (e.g., all captures failed)
	select {
	case <-ctx.Done():
		// Signal received, wait for capture to finish
		<-captureDone
	case <-captureDone:
		// Capture finished early (likely all captures failed)
		// No need to wait, just exit
	}

	// Give a brief moment for graceful cleanup (like hunt nodes do)
	time.Sleep(constants.SnifferCleanupTimeout)
}

// checkCapturePermissions validates that we can open capture handles on all devices
// Returns true if at least one device is accessible, false if all fail
func checkCapturePermissions(devices []pcaptypes.PcapInterface) bool {
	hasPermission := false
	allFailed := true

	for _, dev := range devices {
		// Try to set the handle (this will fail if insufficient permissions)
		err := dev.SetHandle()
		if err != nil {
			logger.Error("Error setting pcap handle", "error", err, "interface", dev.Name())
			continue
		}

		// Success - at least one device is accessible
		hasPermission = true
		allFailed = false

		// Close the handle immediately - we'll reopen in capture goroutines
		if handle, err := dev.Handle(); err == nil && handle != nil {
			handle.Close()
		}
	}

	if allFailed {
		logger.Error("All capture interfaces failed to start - insufficient permissions")
		return false
	}

	return hasPermission
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

	// For live capture, check permissions upfront before starting goroutines
	if !isOffline {
		if !checkCapturePermissions(devices) {
			// All captures failed - exit immediately
			return
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

	// Track if any capture succeeded (for error handling)
	var captureSuccessCount atomic.Int32

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

			// Mark that at least one capture succeeded
			captureSuccessCount.Add(1)

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

	// If no captures succeeded, all goroutines failed (likely permission error)
	// Exit immediately without waiting for signal
	if captureSuccessCount.Load() == 0 {
		logger.Error("All capture interfaces failed to start - exiting")
		// Close buffer immediately so processor can exit
		packetBuffer.Close()
		processorWg.Wait()
		return
	}

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

// RunOfflineOrdered reads all packets from multiple PCAP files, sorts them by timestamp,
// and processes them in chronological order. This is essential for VoIP analysis where
// SIP signaling must be processed before corresponding RTP packets to establish call mappings.
//
// Unlike RunOffline which processes files in parallel (non-deterministic order),
// this function ensures proper temporal ordering across all files.
func RunOfflineOrdered(devices []pcaptypes.PcapInterface, filter string,
	processor func(ch <-chan PacketInfo, asm *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {

	logger.Info("Starting timestamp-ordered offline capture",
		"file_count", len(devices))

	// Phase 1: Read all packets from all files into memory
	var allPackets []PacketInfo
	for _, dev := range devices {
		packets, err := readAllPacketsFromDevice(dev, filter)
		if err != nil {
			logger.Error("Error reading packets from file",
				"file", dev.Name(),
				"error", err)
			continue
		}
		logger.Debug("Read packets from file",
			"file", dev.Name(),
			"count", len(packets))
		allPackets = append(allPackets, packets...)
	}

	if len(allPackets) == 0 {
		logger.Error("No packets read from any file")
		return
	}

	// Phase 2: Sort all packets by timestamp
	sort.Slice(allPackets, func(i, j int) bool {
		return allPackets[i].Packet.Metadata().Timestamp.Before(
			allPackets[j].Packet.Metadata().Timestamp)
	})

	logger.Info("Sorted packets by timestamp",
		"total_packets", len(allPackets),
		"first_timestamp", allPackets[0].Packet.Metadata().Timestamp,
		"last_timestamp", allPackets[len(allPackets)-1].Packet.Metadata().Timestamp)

	// Phase 3: Create buffer and send packets in order
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bufferSize := getPacketBufferSize()
	packetBuffer := NewPacketBuffer(ctx, bufferSize)
	defer packetBuffer.Close()

	// Start processor
	var processorWg sync.WaitGroup
	processorWg.Add(1)
	go func() {
		defer processorWg.Done()
		processor(packetBuffer.Receive(), assembler)
	}()

	// Send all packets in timestamp order
	for _, pkt := range allPackets {
		if !packetBuffer.Send(pkt) {
			// Buffer closed or context cancelled
			break
		}
	}

	// Flush TCP assembler if present
	if assembler != nil {
		_, _ = assembler.FlushOlderThan(time.Now())
		time.Sleep(100 * time.Millisecond)
	}

	// Close the buffer so processor can exit
	packetBuffer.Close()

	// Wait for processor to finish
	processorWg.Wait()

	logger.Info("Timestamp-ordered offline capture completed",
		"total_packets", len(allPackets))
}

// readAllPacketsFromDevice reads all packets from a single PCAP device/file
func readAllPacketsFromDevice(dev pcaptypes.PcapInterface, filter string) ([]PacketInfo, error) {
	err := dev.SetHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to set handle: %w", err)
	}

	handle, err := dev.Handle()
	if err != nil || handle == nil {
		return nil, fmt.Errorf("failed to get handle: %w", err)
	}
	defer handle.Close()

	// Apply BPF filter if specified
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			logger.Warn("Could not apply BPF filter",
				"filter", filter,
				"error", err)
		}
	}

	linkType := handle.LinkType()
	ifaceName := dev.Name()

	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetSource.NoCopy = true
	packetSource.DecodeStreamsAsDatagrams = true

	var packets []PacketInfo
	for packet := range packetSource.Packets() {
		// Make a copy of the packet data since NoCopy=true
		data := make([]byte, len(packet.Data()))
		copy(data, packet.Data())

		// Re-decode with the copied data
		newPacket := gopacket.NewPacket(data, linkType, gopacket.Default)
		// Copy metadata
		newPacket.Metadata().Timestamp = packet.Metadata().Timestamp
		newPacket.Metadata().CaptureLength = packet.Metadata().CaptureLength
		newPacket.Metadata().Length = packet.Metadata().Length

		packets = append(packets, PacketInfo{
			LinkType:  linkType,
			Packet:    newPacket,
			Interface: ifaceName,
		})
	}

	return packets, nil
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

		// Read type from config (default: tap)
		if vifType := viper.GetString("sniff.vif_type"); vifType != "" {
			cfg.Type = vifType
		}

		// Read buffer size from config (default: 4096)
		if bufferSize := viper.GetInt("sniff.vif_buffer_size"); bufferSize > 0 {
			cfg.BufferSize = bufferSize
		}

		// Read network namespace from config (default: empty)
		if netNS := viper.GetString("sniff.vif_netns"); netNS != "" {
			cfg.NetNS = netNS
		}

		// Read privilege dropping user from config (default: empty)
		if dropPrivUser := viper.GetString("sniff.vif_drop_privileges"); dropPrivUser != "" {
			cfg.DropPrivilegesUser = dropPrivUser
		}

		var err error
		vifMgr, err = vinterface.NewManager(cfg)
		if err != nil {
			// Provide helpful error message for common errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else if errors.Is(err, vinterface.ErrInterfaceExists) {
				logger.Error("Virtual interface already exists",
					"error", err,
					"interface_name", vifName,
					"solution", "Delete existing interface or choose a different name with --vif-name")
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", vifName)
			}
			logger.Warn("Continuing without virtual interface")
			vifMgr = nil
		} else {
			err = vifMgr.Start()
			if err != nil {
				// Provide helpful error message for common errors
				if errors.Is(err, vinterface.ErrPermissionDenied) {
					logger.Error("Virtual interface requires elevated privileges",
						"error", err,
						"interface_name", vifName,
						"solution", "Run with sudo or add CAP_NET_ADMIN capability")
				} else if errors.Is(err, vinterface.ErrInterfaceExists) {
					logger.Error("Virtual interface already exists",
						"error", err,
						"interface_name", vifName,
						"solution", "Delete existing interface or choose a different name with --vif-name")
				} else {
					logger.Error("Failed to start virtual interface",
						"error", err,
						"interface_name", vifName)
				}
				logger.Warn("Continuing without virtual interface")
				vifMgr = nil
			}
		}

		if vifMgr != nil {
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
		}

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
	// Note: The PCAP header is written on the first packet to use the correct link type
	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	var pcapHeaderWritten bool
	if writeFile != "" {
		// #nosec G304 -- writeFile is from CLI --write-file flag, intentional user-specified path
		f, err := os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create PCAP file", "file", writeFile, "error", err)
		} else {
			pcapFile = f
			pcapWriter = pcapgo.NewWriter(pcapFile)
			logger.Info("Writing packets to PCAP file", "file", writeFile)
			defer func() {
				if pcapFile != nil {
					pcapFile.Close()
					logger.Info("PCAP file written successfully", "file", writeFile, "packets", packetCount)
				}
			}()
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
			// Preserve raw packet data for virtual interface injection
			display.RawData = p.Packet.Data()
			display.LinkType = p.LinkType
			if err := vifMgr.InjectPacketBatch([]types.PacketDisplay{display}); err != nil {
				logger.Debug("Failed to inject packet to virtual interface", "error", err)
			}
		}

		// Write to PCAP file if writer is available
		if pcapWriter != nil {
			// Write PCAP header on first packet to use correct link type
			if !pcapHeaderWritten {
				if err := pcapWriter.WriteFileHeader(65535, p.LinkType); err != nil {
					logger.Error("Failed to write PCAP header", "error", err)
					pcapFile.Close()
					pcapWriter = nil
					pcapFile = nil
				} else {
					pcapHeaderWritten = true
					logger.Debug("Wrote PCAP header with link type", "link_type", p.LinkType)
				}
			}
			if pcapWriter != nil {
				if err := pcapWriter.WritePacket(p.Packet.Metadata().CaptureInfo, p.Packet.Data()); err != nil {
					logger.Error("Failed to write packet to PCAP", "error", err)
				}
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
