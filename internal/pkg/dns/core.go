//go:build cli || all

package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
)

// Global state for DNS sniffer
var (
	dnsParser         *Parser
	dnsTracker        *QueryTracker
	dnsTunneling      *TunnelingDetector
	dnsAggregator     *QueryAggregator
	dnsPcapWriter     *pcapgo.Writer
	dnsOutputFile     *os.File
	dnsDomainPatterns []string // Domain patterns to filter (glob-style)
)

// StartDNSSniffer starts the DNS sniffer on the specified interfaces.
// This is the callback function passed to capture.StartLiveSniffer/StartOfflineSniffer.
func StartDNSSniffer(devices []pcaptypes.PcapInterface, filter string) {
	logger.Info("Starting DNS sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize parser and optionally tracker/tunneling detector
	dnsParser = NewParser()

	if viper.GetBool("dns.track_queries") {
		dnsTracker = NewQueryTracker(DefaultTrackerConfig())
	}

	if viper.GetBool("dns.detect_tunneling") {
		dnsTunneling = NewTunnelingDetector(DefaultTunnelingConfig())
	}

	// Initialize domain patterns from viper
	dnsDomainPatterns = nil
	if pattern := viper.GetString("dns.domain_pattern"); pattern != "" {
		dnsDomainPatterns = []string{pattern}
		logger.Info("DNS domain filter enabled", "pattern", pattern)
	}
	if patterns := viper.GetStringSlice("dns.domain_patterns"); len(patterns) > 0 {
		dnsDomainPatterns = append(dnsDomainPatterns, patterns...)
		logger.Info("DNS domain patterns loaded", "count", len(patterns))
	}

	// Create aggregator for statistics
	dnsAggregator = NewQueryAggregator(10000)

	// PCAP writer if output file specified
	if writeFile := viper.GetString("dns.write_file"); writeFile != "" {
		var err error
		dnsOutputFile, err = os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create output file", "error", err, "file", writeFile)
		} else {
			dnsPcapWriter = pcapgo.NewWriter(dnsOutputFile)
			if err := dnsPcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to write PCAP header", "error", err)
				dnsPcapWriter = nil
			} else {
				logger.Info("Writing DNS packets to file", "file", writeFile)
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
		processDNSPackets(packetChan)
	}

	// Run capture with appropriate mode
	if isOffline {
		capture.RunOffline(devices, filter, processor, nil)
	} else {
		capture.RunWithSignalHandler(devices, filter, processor, nil)
	}

	// Print statistics and cleanup
	printStatistics(dnsAggregator, dnsTracker, dnsTunneling)
	cleanup()
}

// processDNSPackets processes packets from the channel.
func processDNSPackets(packetChan <-chan capture.PacketInfo) {
	quietMode := viper.GetBool("sniff.quiet")
	format := viper.GetString("sniff.format")

	// Create JSON encoder if using JSON format
	var jsonEncoder *json.Encoder
	if format == "json" {
		jsonEncoder = json.NewEncoder(os.Stdout)
	}

	for pktInfo := range packetChan {
		packet := pktInfo.Packet

		// Parse DNS
		metadata := dnsParser.Parse(packet)
		if metadata == nil {
			continue
		}

		// Apply domain filter if configured
		if len(dnsDomainPatterns) > 0 && !filtering.MatchAnyGlob(dnsDomainPatterns, metadata.QueryName) {
			continue
		}

		// Create packet display
		pktDisplay := createPacketDisplayFromInfo(pktInfo, metadata)

		// Track query/response correlation
		if dnsTracker != nil {
			if metadata.IsResponse {
				dnsTracker.CorrelateResponse(pktDisplay, metadata)
			} else {
				dnsTracker.TrackQuery(pktDisplay, metadata)
			}
		}

		// Analyze for tunneling
		if dnsTunneling != nil {
			dnsTunneling.Analyze(metadata)
		}

		// Record for aggregation
		dnsAggregator.RecordQuery(metadata, pktDisplay.SrcIP)

		// Print to console unless quiet mode
		if !quietMode {
			if format == "json" {
				// Output as JSON (omit RawData for cleaner output)
				pktDisplay.RawData = nil
				if err := jsonEncoder.Encode(pktDisplay); err != nil {
					logger.Error("Failed to encode packet as JSON", "error", err)
				}
			} else {
				printDNSPacket(pktDisplay, metadata)
			}
		}

		// Write to PCAP if configured
		if dnsPcapWriter != nil {
			ci := gopacket.CaptureInfo{
				Timestamp:      packet.Metadata().Timestamp,
				CaptureLength:  len(packet.Data()),
				Length:         len(packet.Data()),
				InterfaceIndex: 0,
			}
			if err := dnsPcapWriter.WritePacket(ci, packet.Data()); err != nil {
				logger.Error("Failed to write packet to PCAP", "error", err)
			}
		}
	}
}

// cleanup releases resources.
func cleanup() {
	if dnsTunneling != nil {
		dnsTunneling.Stop()
	}
	if dnsOutputFile != nil {
		if err := dnsOutputFile.Close(); err != nil {
			logger.Error("Failed to close output file", "error", err)
		}
	}
}

// createPacketDisplayFromInfo creates a PacketDisplay from capture info.
func createPacketDisplayFromInfo(pktInfo capture.PacketInfo, metadata *types.DNSMetadata) *types.PacketDisplay {
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
		Protocol:  "DNS",
		Length:    len(packet.Data()),
		Info:      formatDNSInfo(metadata),
		RawData:   packet.Data(),
		NodeID:    "Local",
		Interface: pktInfo.Interface,
		DNSData:   metadata,
		LinkType:  layers.LinkTypeEthernet, // Default to Ethernet
	}
}

// printDNSPacket prints a DNS packet to the console.
func printDNSPacket(pkt *types.PacketDisplay, metadata *types.DNSMetadata) {
	timestamp := pkt.Timestamp.Format("15:04:05.000")

	var direction string
	if metadata.IsResponse {
		direction = "<-"
	} else {
		direction = "->"
	}

	// Format answers if present
	var answersStr string
	if len(metadata.Answers) > 0 {
		var answers []string
		for _, a := range metadata.Answers {
			answers = append(answers, a.Data)
		}
		answersStr = " = " + strings.Join(answers, ", ")
	}

	// Add response code for responses
	var rcodeStr string
	if metadata.IsResponse && metadata.ResponseCode != "NOERROR" {
		rcodeStr = " [" + metadata.ResponseCode + "]"
	}

	// Add tunneling warning if score is high
	var tunnelingStr string
	if metadata.TunnelingScore > 0.5 {
		tunnelingStr = fmt.Sprintf(" [TUNNELING:%.0f%%]", metadata.TunnelingScore*100)
	}

	// Add response time if correlated
	var rttStr string
	if metadata.CorrelatedQuery && metadata.QueryResponseTimeMs > 0 {
		rttStr = fmt.Sprintf(" (%dms)", metadata.QueryResponseTimeMs)
	}

	fmt.Printf("%s %s:%s %s %s:%s  %s %s%s%s%s%s\n",
		timestamp,
		pkt.SrcIP, pkt.SrcPort,
		direction,
		pkt.DstIP, pkt.DstPort,
		metadata.QueryType,
		metadata.QueryName,
		answersStr,
		rcodeStr,
		rttStr,
		tunnelingStr,
	)
}

// StartLiveDNSSniffer starts DNS capture on live network interfaces.
func StartLiveDNSSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartDNSSniffer)
}

// StartOfflineDNSSniffer starts DNS capture from a PCAP file.
func StartOfflineDNSSniffer(readFile, filter string) {
	capture.StartOfflineSniffer(readFile, filter, StartDNSSniffer)
}

// printStatistics prints capture statistics.
func printStatistics(aggregator *QueryAggregator, tracker *QueryTracker, tunneling *TunnelingDetector) {
	fmt.Println("\n--- DNS Capture Statistics ---")

	// Top domains
	topDomains := aggregator.GetTopDomains(10)
	if len(topDomains) > 0 {
		fmt.Println("\nTop Queried Domains:")
		for i, stats := range topDomains {
			avgRTT := time.Duration(0)
			if stats.ResponseCount > 0 {
				avgRTT = stats.TotalResponseTime / time.Duration(stats.ResponseCount)
			}
			fmt.Printf("  %d. %s - %d queries, %d responses",
				i+1, stats.Domain, stats.QueryCount, stats.ResponseCount)
			if avgRTT > 0 {
				fmt.Printf(", avg RTT: %v", avgRTT)
			}
			if stats.NXDomainCount > 0 {
				fmt.Printf(", NXDOMAIN: %d", stats.NXDomainCount)
			}
			fmt.Println()
		}
	}

	// Tunneling suspects
	if tunneling != nil {
		suspects := tunneling.GetSuspiciousDomains(0.3, 5)
		if len(suspects) > 0 {
			fmt.Println("\nPotential DNS Tunneling Detected:")
			for _, report := range suspects {
				fmt.Printf("  - %s (score: %.0f%%, queries: %d, unique subdomains: %d)\n",
					report.Domain, report.Score*100, report.QueryCount, report.UniqueSubdomains)
				fmt.Printf("    Indicators: %s\n", strings.Join(report.Indicators, ", "))
			}
		}
	}

	// Pending queries (unanswered)
	if tracker != nil {
		stats := tracker.Stats()
		if stats.PendingQueries > 0 {
			fmt.Printf("\nUnanswered queries: %d\n", stats.PendingQueries)
		}
	}
}
