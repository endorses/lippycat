package capture

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// RunWithSignalHandler runs the capture in background and handles signals for graceful shutdown
// This is the common pattern used by hunt, sniff, and sniff voip commands
func RunWithSignalHandler(devices []pcaptypes.PcapInterface, filter string,
	processor func(<-chan PacketInfo)) {

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
		InitWithContext(ctx, devices, filter, func(ch <-chan PacketInfo, _ *TCPAssembler) {
			processor(ch)
		}, nil, nil)
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

// RunOfflineOrdered reads all packets from multiple PCAP files, sorts them by timestamp,
// and processes them in chronological order. This is essential for VoIP analysis where
// SIP signaling must be processed before corresponding RTP packets to establish call mappings.
//
// It ensures proper temporal ordering across all files.
func RunOfflineOrdered(devices []pcaptypes.PcapInterface, filter string,
	processor func(<-chan PacketInfo)) {

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
	// Keep source/file order deterministic when capture timestamps are equal.
	sort.SliceStable(allPackets, func(i, j int) bool {
		return allPackets[i].Packet.Metadata().Timestamp.Before(
			allPackets[j].Packet.Metadata().Timestamp)
	})

	logger.Info("Sorted packets by timestamp",
		"total_packets", len(allPackets),
		"first_timestamp", allPackets[0].Packet.Metadata().Timestamp,
		"last_timestamp", allPackets[len(allPackets)-1].Packet.Metadata().Timestamp)

	// Phase 3: Send packets through a plain channel in sorted order. The live
	// PacketBuffer deliberately prioritizes SIP traffic, which is useful under
	// load but would let a later SIP packet overtake an earlier non-SIP packet
	// during lossless replay.
	packetStream := make(chan PacketInfo)

	// Start processor
	var processorWg sync.WaitGroup
	processorWg.Add(1)
	go func() {
		defer processorWg.Done()
		processor(packetStream)
	}()

	// Send all packets in timestamp order using blocking sends so replay cannot
	// drop packets or advance until the consumer accepts the preceding packet.
	for _, pkt := range allPackets {
		observePacket(pkt)
		packetStream <- pkt
	}
	close(packetStream)

	// Wait for the processor to finish after packetStream closes.
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

	// IP defragmenters for this file. Fragments of a single datagram never span
	// files, so per-file defragmenters are sufficient. This mirrors the live
	// capture path (captureFromInterface): without reassembly the second fragment
	// of a large SIP INVITE/200 OK (containing the SDP media ports) is dropped,
	// so RTP never correlates to its call and shows up as an RTP-only call.
	defragmenter := NewIPv4Defragmenter()
	v6defragmenter := NewIPv6Defragmenter()

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

		// Reassemble IPv4 fragments before any further processing. A fragmented
		// SIP message would otherwise have its SDP body stranded in a later
		// fragment and never parsed.
		if ipLayer := newPacket.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)
			if ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset > 0 {
				reassembledIP, err := defragmenter.DefragIPv4(ip4)
				if err != nil {
					logger.Debug("IPv4 defragmentation error (offline)",
						"error", err, "src", ip4.SrcIP, "dst", ip4.DstIP, "id", ip4.Id)
					continue // Skip this fragment
				}
				if reassembledIP == nil {
					continue // Still waiting for more fragments
				}
				reassembled := rebuildReassembledPacket(newPacket, reassembledIP, linkType)
				reassembled.Metadata().Timestamp = newPacket.Metadata().Timestamp
				newPacket = reassembled
			}
		}

		// Reassemble plain (non-ESP) IPv6 fragments. gopacket has no built-in
		// IPv6 reassembly; ESP-encapsulated fragments are handled by
		// decapsulateIPv6FragmentESP below.
		if fragLayer := newPacket.Layer(layers.LayerTypeIPv6Fragment); fragLayer != nil {
			if frag, ok := fragLayer.(*layers.IPv6Fragment); ok && frag.NextHeader != layers.IPProtocolESP {
				if ip6Layer := newPacket.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
					ip6 := ip6Layer.(*layers.IPv6)
					reassembledIP6, err := v6defragmenter.DefragIPv6(ip6, frag)
					if err != nil {
						logger.Debug("IPv6 defragmentation error (offline)",
							"error", err, "src", ip6.SrcIP, "dst", ip6.DstIP, "id", frag.Identification)
						continue // Skip this fragment
					}
					if reassembledIP6 == nil {
						continue // Still waiting for more fragments
					}
					reassembled := rebuildReassembledIPv6Packet(newPacket, reassembledIP6, linkType)
					reassembled.Metadata().Timestamp = newPacket.Metadata().Timestamp
					newPacket = reassembled
				}
			}
		}

		// Handle VXLAN decapsulation - extract the inner Ethernet frame so all
		// downstream processing (SIP detection, RTP correlation, etc.) sees the
		// real traffic rather than the VXLAN tunnel wrapper.
		effectiveLinkType := linkType
		if inner, ok := decapsulateVXLAN(newPacket); ok {
			newPacket = inner
			effectiveLinkType = layers.LinkTypeEthernet
		}

		// Handle ESP with NULL cipher - common in IMS/VoLTE where ESP transport
		// mode provides integrity without encryption. Must run after VXLAN
		// decapsulation so it sees the inner packets from VXLAN tunnels.
		if ESPDecapEnabled() {
			if inner, ok := decapsulateESPNull(newPacket); ok {
				newPacket = inner
			} else if inner, ok := decapsulateIPv6FragmentESP(newPacket); ok {
				newPacket = inner
			}
		}

		packets = append(packets, PacketInfo{
			LinkType:  effectiveLinkType,
			Packet:    newPacket,
			Interface: ifaceName,
		})
	}

	return packets, nil
}
