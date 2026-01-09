//go:build cli || tui || all

package tls

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
)

// Global state for TLS sniffer
var (
	tlsParser        *Parser
	tlsTracker       *Tracker
	tlsAggregator    *Aggregator
	tlsContentFilter *ContentFilter
	tlsPcapWriter    *pcapgo.Writer
	tlsOutputFile    *os.File
)

// StartTLSSniffer starts the TLS sniffer on the specified interfaces.
func StartTLSSniffer(devices []pcaptypes.PcapInterface, filter string) {
	logger.Info("Starting TLS sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize parser
	tlsParser = NewParser()

	// Initialize tracker if connection tracking enabled
	if viper.GetBool("tls.track_connections") {
		tlsTracker = NewTracker(DefaultTrackerConfig())
	}

	// Initialize aggregator for statistics
	tlsAggregator = NewAggregator(10000)

	// Initialize content filter
	tlsContentFilter = buildContentFilter()

	// PCAP writer if output file specified
	if writeFile := viper.GetString("tls.write_file"); writeFile != "" {
		var err error
		tlsOutputFile, err = os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create output file", "error", err, "file", writeFile)
		} else {
			tlsPcapWriter = pcapgo.NewWriter(tlsOutputFile)
			if err := tlsPcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to write PCAP header", "error", err)
				tlsPcapWriter = nil
			} else {
				logger.Info("Writing TLS packets to file", "file", writeFile)
			}
		}
	}

	// Detect offline mode
	isOffline := false
	for _, dev := range devices {
		name := dev.Name()
		if strings.Contains(name, ".pcap") || strings.Contains(name, ".pcapng") || strings.Contains(name, "/") {
			isOffline = true
			break
		}
	}

	// Create processor function
	processor := func(packetChan <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
		processTLSPackets(packetChan)
	}

	// Run capture with appropriate mode
	if isOffline {
		capture.RunOffline(devices, filter, processor, nil)
	} else {
		capture.RunWithSignalHandler(devices, filter, processor, nil)
	}

	// Print statistics and cleanup
	printStatistics(tlsAggregator, tlsTracker)
	cleanup()
}

// processTLSPackets processes packets from the channel.
func processTLSPackets(packetChan <-chan capture.PacketInfo) {
	quietMode := viper.GetBool("sniff.quiet")
	format := viper.GetString("sniff.format")

	// Create JSON encoder if using JSON format
	var jsonEncoder *json.Encoder
	if format == "json" {
		jsonEncoder = json.NewEncoder(os.Stdout)
	}

	for pktInfo := range packetChan {
		packet := pktInfo.Packet

		// Parse TLS
		metadata := tlsParser.Parse(packet)
		if metadata == nil {
			continue
		}

		// Apply content filter if configured
		if tlsContentFilter.HasFilters() && !tlsContentFilter.Match(metadata) {
			continue
		}

		// Create packet display
		pktDisplay := createPacketDisplayFromInfo(pktInfo, metadata)

		// Track connection correlation
		if tlsTracker != nil {
			if metadata.IsServer {
				tlsTracker.CorrelateServerHello(pktDisplay, metadata)
			} else {
				tlsTracker.TrackClientHello(pktDisplay, metadata)
			}
		}

		// Record for aggregation
		tlsAggregator.RecordHandshake(metadata, pktDisplay.SrcIP, pktDisplay.DstIP)

		// Print to console unless quiet mode
		if !quietMode {
			if format == "json" {
				// Output as JSON (omit RawData for cleaner output)
				pktDisplay.RawData = nil
				if err := jsonEncoder.Encode(pktDisplay); err != nil {
					logger.Error("Failed to encode packet as JSON", "error", err)
				}
			} else {
				printTLSPacket(pktDisplay, metadata)
			}
		}

		// Write to PCAP if configured
		if tlsPcapWriter != nil {
			ci := gopacket.CaptureInfo{
				Timestamp:      packet.Metadata().Timestamp,
				CaptureLength:  len(packet.Data()),
				Length:         len(packet.Data()),
				InterfaceIndex: 0,
			}
			if err := tlsPcapWriter.WritePacket(ci, packet.Data()); err != nil {
				logger.Error("Failed to write packet to PCAP", "error", err)
			}
		}
	}
}

// buildContentFilter creates a content filter from viper config.
func buildContentFilter() *ContentFilter {
	config := ContentFilterConfig{}

	// SNI pattern
	if pattern := viper.GetString("tls.sni_pattern"); pattern != "" {
		config.SNIPatterns = []string{pattern}
	}
	if patterns := viper.GetStringSlice("tls.sni_patterns"); len(patterns) > 0 {
		config.SNIPatterns = append(config.SNIPatterns, patterns...)
	}

	// JA3 hashes
	if hash := viper.GetString("tls.ja3"); hash != "" {
		config.JA3Hashes = []string{hash}
	}
	if hashes := viper.GetStringSlice("tls.ja3_hashes"); len(hashes) > 0 {
		config.JA3Hashes = append(config.JA3Hashes, hashes...)
	}

	// JA3S hashes
	if hash := viper.GetString("tls.ja3s"); hash != "" {
		config.JA3SHashes = []string{hash}
	}
	if hashes := viper.GetStringSlice("tls.ja3s_hashes"); len(hashes) > 0 {
		config.JA3SHashes = append(config.JA3SHashes, hashes...)
	}

	// JA4 fingerprints
	if fp := viper.GetString("tls.ja4"); fp != "" {
		config.JA4Fingerprints = []string{fp}
	}
	if fps := viper.GetStringSlice("tls.ja4_fingerprints"); len(fps) > 0 {
		config.JA4Fingerprints = append(config.JA4Fingerprints, fps...)
	}

	return NewContentFilter(config)
}

// cleanup releases resources.
func cleanup() {
	if tlsTracker != nil {
		tlsTracker.Stop()
	}
	if tlsOutputFile != nil {
		if err := tlsOutputFile.Close(); err != nil {
			logger.Error("Failed to close output file", "error", err)
		}
	}
}

// createPacketDisplayFromInfo creates a PacketDisplay from capture info.
func createPacketDisplayFromInfo(pktInfo capture.PacketInfo, metadata *types.TLSMetadata) *types.PacketDisplay {
	packet := pktInfo.Packet

	var srcIP, dstIP, srcPort, dstPort string

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		flow := netLayer.NetworkFlow()
		srcIP = flow.Src().String()
		dstIP = flow.Dst().String()
	}

	if transLayer := packet.TransportLayer(); transLayer != nil {
		flow := transLayer.TransportFlow()
		srcPort = flow.Src().String()
		dstPort = flow.Dst().String()
	}

	return &types.PacketDisplay{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  "TLS",
		Length:    len(packet.Data()),
		Info:      formatTLSInfo(metadata),
		RawData:   packet.Data(),
		NodeID:    "Local",
		Interface: pktInfo.Interface,
		TLSData:   metadata,
		LinkType:  layers.LinkTypeEthernet,
	}
}

// formatTLSInfo formats TLS metadata for display.
func formatTLSInfo(metadata *types.TLSMetadata) string {
	var parts []string

	parts = append(parts, metadata.HandshakeType)
	parts = append(parts, metadata.Version)

	if metadata.SNI != "" {
		parts = append(parts, fmt.Sprintf("SNI=%s", metadata.SNI))
	}

	if metadata.JA3Fingerprint != "" {
		parts = append(parts, fmt.Sprintf("JA3=%s", metadata.JA3Fingerprint[:8]+"..."))
	}

	if metadata.JA3SFingerprint != "" {
		parts = append(parts, fmt.Sprintf("JA3S=%s", metadata.JA3SFingerprint[:8]+"..."))
	}

	return strings.Join(parts, " ")
}

// printTLSPacket prints a TLS packet to the console.
func printTLSPacket(pkt *types.PacketDisplay, metadata *types.TLSMetadata) {
	timestamp := pkt.Timestamp.Format("15:04:05.000")

	var direction string
	if metadata.IsServer {
		direction = "<-"
	} else {
		direction = "->"
	}

	// Build info string
	var info strings.Builder
	info.WriteString(metadata.HandshakeType)
	info.WriteString(" ")
	info.WriteString(metadata.Version)

	if metadata.SNI != "" {
		info.WriteString(" SNI=")
		info.WriteString(metadata.SNI)
	}

	if metadata.JA3Fingerprint != "" {
		info.WriteString(" JA3=")
		info.WriteString(metadata.JA3Fingerprint)
	}

	if metadata.JA3SFingerprint != "" {
		info.WriteString(" JA3S=")
		info.WriteString(metadata.JA3SFingerprint)
	}

	if metadata.CorrelatedPeer && metadata.HandshakeTimeMs > 0 {
		info.WriteString(fmt.Sprintf(" (%dms)", metadata.HandshakeTimeMs))
	}

	fmt.Printf("%s %s:%s %s %s:%s  %s\n",
		timestamp,
		pkt.SrcIP, pkt.SrcPort,
		direction,
		pkt.DstIP, pkt.DstPort,
		info.String(),
	)
}

// StartLiveTLSSniffer starts TLS capture on live network interfaces.
func StartLiveTLSSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartTLSSniffer)
}

// StartOfflineTLSSniffer starts TLS capture from a PCAP file.
func StartOfflineTLSSniffer(readFile, filter string) {
	capture.StartOfflineSniffer(readFile, filter, StartTLSSniffer)
}

// printStatistics prints capture statistics.
func printStatistics(aggregator *Aggregator, tracker *Tracker) {
	fmt.Println("\n--- TLS Capture Statistics ---")

	stats := aggregator.Stats()
	fmt.Printf("\nTotal handshakes: %d\n", stats.TotalHandshakes)
	fmt.Printf("  ClientHello: %d\n", stats.ClientHelloCount)
	fmt.Printf("  ServerHello: %d\n", stats.ServerHelloCount)

	// Version distribution
	if len(stats.VersionCounts) > 0 {
		fmt.Println("\nTLS Version Distribution:")
		for version, count := range stats.VersionCounts {
			fmt.Printf("  %s: %d\n", version, count)
		}
	}

	// Top SNIs
	topSNIs := aggregator.GetTopSNIs(10)
	if len(topSNIs) > 0 {
		fmt.Println("\nTop SNIs:")
		for i, sni := range topSNIs {
			fmt.Printf("  %d. %s (%d)\n", i+1, sni.Name, sni.Count)
		}
	}

	// Tracker stats
	if tracker != nil {
		trackerStats := tracker.Stats()
		fmt.Printf("\nConnection Tracking:\n")
		fmt.Printf("  Completed handshakes: %d\n", trackerStats.CompletedHandshakes)
		fmt.Printf("  Pending handshakes: %d\n", trackerStats.PendingHandshakes)
	}
}

// Aggregator tracks TLS handshake statistics.
type Aggregator struct {
	maxSNIs          int
	sniCounts        map[string]int
	versionCounts    map[string]int
	clientHelloCount int
	serverHelloCount int
	totalHandshakes  int
}

// NewAggregator creates a new TLS aggregator.
func NewAggregator(maxSNIs int) *Aggregator {
	return &Aggregator{
		maxSNIs:       maxSNIs,
		sniCounts:     make(map[string]int),
		versionCounts: make(map[string]int),
	}
}

// RecordHandshake records a TLS handshake.
func (a *Aggregator) RecordHandshake(metadata *types.TLSMetadata, srcIP, dstIP string) {
	a.totalHandshakes++

	if metadata.IsServer {
		a.serverHelloCount++
	} else {
		a.clientHelloCount++
	}

	// Count versions
	if metadata.Version != "" {
		a.versionCounts[metadata.Version]++
	}

	// Count SNIs
	if metadata.SNI != "" && len(a.sniCounts) < a.maxSNIs {
		a.sniCounts[metadata.SNI]++
	}
}

// AggregatorStats holds aggregator statistics.
type AggregatorStats struct {
	TotalHandshakes  int
	ClientHelloCount int
	ServerHelloCount int
	VersionCounts    map[string]int
}

// Stats returns aggregator statistics.
func (a *Aggregator) Stats() AggregatorStats {
	return AggregatorStats{
		TotalHandshakes:  a.totalHandshakes,
		ClientHelloCount: a.clientHelloCount,
		ServerHelloCount: a.serverHelloCount,
		VersionCounts:    a.versionCounts,
	}
}

// SNICount represents an SNI and its count.
type SNICount struct {
	Name  string
	Count int
}

// GetTopSNIs returns the top N SNIs by count.
func (a *Aggregator) GetTopSNIs(n int) []SNICount {
	var snis []SNICount
	for name, count := range a.sniCounts {
		snis = append(snis, SNICount{Name: name, Count: count})
	}

	// Sort by count descending
	for i := 0; i < len(snis); i++ {
		for j := i + 1; j < len(snis); j++ {
			if snis[j].Count > snis[i].Count {
				snis[i], snis[j] = snis[j], snis[i]
			}
		}
	}

	if len(snis) > n {
		snis = snis[:n]
	}

	return snis
}

// ParseTLSPayload parses TLS from raw payload (for external use).
func ParseTLSPayload(payload []byte) *types.TLSMetadata {
	parser := NewParser()
	return parser.ParsePayload(payload)
}

// GetTLSVersionString returns a human-readable TLS version.
func GetTLSVersionString(version uint16) string {
	return VersionString(version)
}

// FormatHandshakeTime formats handshake time for display.
func FormatHandshakeTime(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.2fs", float64(ms)/1000.0)
}

// init sets viper defaults
func init() {
	viper.SetDefault("tls.track_connections", true)
	viper.SetDefault("tls.ports", "443")
}

// Variables for timestamp formatting
var _ = time.Now // Keep time import
