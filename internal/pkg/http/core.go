//go:build cli || all

package http

import (
	"context"
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

// Global state for HTTP sniffer
var (
	httpParser        *Parser
	httpTracker       *RequestTracker
	httpAggregator    *RequestAggregator
	httpContentFilter *ContentFilter
	httpPcapWriter    *pcapgo.Writer
	httpOutputFile    *os.File
	httpFactory       tcpassembly.StreamFactory
	httpAssembler     *tcpassembly.Assembler
	httpHandler       *cliHTTPHandler
)

// cliHTTPHandler processes HTTP messages for CLI output.
type cliHTTPHandler struct {
	quietMode   bool
	jsonEncoder *json.Encoder
}

// HandleHTTPMessage implements HTTPMessageHandler.
func (h *cliHTTPHandler) HandleHTTPMessage(metadata *types.HTTPMetadata, sessionID string, flow gopacket.Flow) {
	// Apply content filter if configured
	if httpContentFilter != nil && !httpContentFilter.Match(metadata) {
		return
	}

	// Track request/response correlation
	if httpTracker != nil {
		srcIP := flow.Src().String()
		dstIP := flow.Dst().String()
		srcPort := ""
		dstPort := ""
		// Extract ports from session ID if available
		if parts := strings.Split(sessionID, "-"); len(parts) == 2 {
			if srcParts := strings.Split(parts[0], ":"); len(srcParts) == 2 {
				srcPort = srcParts[1]
			}
			if dstParts := strings.Split(parts[1], ":"); len(dstParts) == 2 {
				dstPort = dstParts[1]
			}
		}

		if metadata.Type == "request" {
			httpTracker.TrackRequest(srcIP, dstIP, srcPort, dstPort, metadata)
			httpAggregator.RecordRequest(metadata)
		} else if metadata.Type == "response" {
			httpTracker.CorrelateResponse(srcIP, dstIP, srcPort, dstPort, metadata)
			httpAggregator.RecordResponse(metadata)
		}
	}

	// Create packet display
	pktDisplay := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     flow.Src().String(),
		DstIP:     flow.Dst().String(),
		Protocol:  "HTTP",
		Info:      httpParser.FormatInfo(metadata),
		NodeID:    "Local",
		HTTPData:  metadata,
		LinkType:  layers.LinkTypeEthernet,
	}

	// Print to console unless quiet mode
	if !h.quietMode {
		if h.jsonEncoder != nil {
			if err := h.jsonEncoder.Encode(pktDisplay); err != nil {
				logger.Error("Failed to encode packet as JSON", "error", err)
			}
		} else {
			printHTTPPacket(pktDisplay, metadata)
		}
	}
}

// StartHTTPSniffer starts the HTTP sniffer on the specified interfaces.
func StartHTTPSniffer(devices []pcaptypes.PcapInterface, filter string) {
	logger.Info("Starting HTTP sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize parser
	httpParser = NewParser()

	// Initialize tracker
	if viper.GetBool("http.track_requests") {
		httpTracker = NewRequestTracker(DefaultTrackerConfig())
	}

	// Create aggregator for statistics
	httpAggregator = NewRequestAggregator(10000)

	// Initialize content filter
	filterConfig := buildContentFilterConfig()
	if filterConfig.hasFilters() {
		httpContentFilter = NewContentFilter(filterConfig)
		logger.Info("HTTP content filter enabled")
	}

	// PCAP writer if output file specified
	if writeFile := viper.GetString("http.write_file"); writeFile != "" {
		var err error
		httpOutputFile, err = os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create output file", "error", err, "file", writeFile)
		} else {
			httpPcapWriter = pcapgo.NewWriter(httpOutputFile)
			if err := httpPcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to write PCAP header", "error", err)
				httpPcapWriter = nil
			} else {
				logger.Info("Writing HTTP packets to file", "file", writeFile)
			}
		}
	}

	// Create CLI handler
	quietMode := viper.GetBool("sniff.quiet")
	format := viper.GetString("sniff.format")
	httpHandler = &cliHTTPHandler{
		quietMode: quietMode,
	}
	if format == "json" {
		httpHandler.jsonEncoder = json.NewEncoder(os.Stdout)
	}

	// Create TCP reassembly factory
	ctx := context.Background()
	factoryConfig := DefaultHTTPStreamFactoryConfig()

	// Configure ports from viper
	if ports := viper.GetIntSlice("http.ports"); len(ports) > 0 {
		factoryConfig.ServerPorts = make([]uint16, len(ports))
		for i, p := range ports {
			factoryConfig.ServerPorts[i] = uint16(p)
		}
	}

	factoryConfig.CaptureBody = viper.GetBool("http.capture_body")
	if maxSize := viper.GetInt("http.max_body_size"); maxSize > 0 {
		factoryConfig.MaxBodySize = maxSize
	}

	httpFactory = NewHTTPStreamFactory(ctx, httpHandler, factoryConfig)

	// Create assembler
	streamPool := tcpassembly.NewStreamPool(httpFactory)
	httpAssembler = tcpassembly.NewAssembler(streamPool)

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
		processHTTPPackets(packetChan, asm)
	}

	// Run capture with appropriate mode
	if isOffline {
		capture.RunOffline(devices, filter, processor, httpAssembler)
	} else {
		capture.RunWithSignalHandler(devices, filter, processor, httpAssembler)
	}

	// Print statistics and cleanup
	printStatistics()
	cleanup()
}

// processHTTPPackets processes packets from the channel.
func processHTTPPackets(packetChan <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
	for pktInfo := range packetChan {
		packet := pktInfo.Packet

		// Feed TCP packets to assembler
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		// Feed to assembler for reassembly
		asm.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, packet.Metadata().Timestamp)

		// Write to PCAP if configured
		if httpPcapWriter != nil {
			ci := gopacket.CaptureInfo{
				Timestamp:      packet.Metadata().Timestamp,
				CaptureLength:  len(packet.Data()),
				Length:         len(packet.Data()),
				InterfaceIndex: 0,
			}
			if err := httpPcapWriter.WritePacket(ci, packet.Data()); err != nil {
				logger.Error("Failed to write packet to PCAP", "error", err)
			}
		}
	}

	// Flush remaining streams
	if asm != nil {
		asm.FlushAll()
	}
}

// buildContentFilterConfig builds content filter config from viper.
func buildContentFilterConfig() ContentFilterConfig {
	return ContentFilterConfig{
		HostPatterns:        viper.GetStringSlice("http.host_patterns"),
		URLPatterns:         viper.GetStringSlice("http.url_patterns"),
		Methods:             viper.GetStringSlice("http.methods"),
		StatusCodes:         viper.GetStringSlice("http.status_codes"),
		UserAgentPatterns:   viper.GetStringSlice("http.user_agent_patterns"),
		ContentTypePatterns: viper.GetStringSlice("http.content_type_patterns"),
		Keywords:            viper.GetStringSlice("http.keywords"),
	}
}

// hasFilters returns true if any filters are configured.
func (c ContentFilterConfig) hasFilters() bool {
	return len(c.HostPatterns) > 0 ||
		len(c.URLPatterns) > 0 ||
		len(c.Methods) > 0 ||
		len(c.StatusCodes) > 0 ||
		len(c.UserAgentPatterns) > 0 ||
		len(c.ContentTypePatterns) > 0 ||
		len(c.Keywords) > 0
}

// cleanup releases resources.
func cleanup() {
	if httpTracker != nil {
		httpTracker.Close()
	}
	if closer, ok := httpFactory.(interface{ Close() }); ok {
		closer.Close()
	}
	if httpOutputFile != nil {
		if err := httpOutputFile.Close(); err != nil {
			logger.Error("Failed to close output file", "error", err)
		}
	}
}

// printHTTPPacket prints an HTTP packet to the console.
func printHTTPPacket(pkt *types.PacketDisplay, metadata *types.HTTPMetadata) {
	timestamp := pkt.Timestamp.Format("15:04:05.000")

	var direction string
	if metadata.IsServer {
		direction = "<-"
	} else {
		direction = "->"
	}

	// Format status for responses
	var statusStr string
	if metadata.Type == "response" {
		statusStr = fmt.Sprintf("%d %s", metadata.StatusCode, metadata.StatusReason)
	} else {
		statusStr = fmt.Sprintf("%s %s", metadata.Method, metadata.Path)
	}

	// Add host
	var hostStr string
	if metadata.Host != "" {
		hostStr = fmt.Sprintf(" [%s]", metadata.Host)
	}

	// Add RTT if correlated
	var rttStr string
	if metadata.CorrelatedResponse && metadata.RequestResponseTimeMs > 0 {
		rttStr = fmt.Sprintf(" (%dms)", metadata.RequestResponseTimeMs)
	}

	// Add content type
	var ctStr string
	if metadata.ContentType != "" {
		ctStr = fmt.Sprintf(" %s", metadata.ContentType)
	}

	fmt.Printf("%s %s %s %s  %s%s%s%s\n",
		timestamp,
		pkt.SrcIP,
		direction,
		pkt.DstIP,
		statusStr,
		hostStr,
		rttStr,
		ctStr,
	)
}

// StartLiveHTTPSniffer starts HTTP capture on live network interfaces.
func StartLiveHTTPSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartHTTPSniffer)
}

// StartOfflineHTTPSniffer starts HTTP capture from a PCAP file.
func StartOfflineHTTPSniffer(readFile, filter string) {
	capture.StartOfflineSniffer(readFile, filter, StartHTTPSniffer)
}

// printStatistics prints capture statistics.
func printStatistics() {
	fmt.Println("\n--- HTTP Capture Statistics ---")

	// Tracker stats
	if httpTracker != nil {
		stats := httpTracker.Stats()
		fmt.Printf("\nRequest/Response Tracking:\n")
		fmt.Printf("  Total Requests:  %d\n", stats.TotalRequests)
		fmt.Printf("  Total Responses: %d\n", stats.TotalResponses)
		fmt.Printf("  Correlated:      %d\n", stats.CorrelatedCount)
		fmt.Printf("  Uncorrelated:    %d\n", stats.UncorrelatedCount)
		fmt.Printf("  Expired:         %d\n", stats.ExpiredCount)
	}

	// Aggregator stats
	if httpAggregator != nil {
		// Top hosts
		topHosts := httpAggregator.GetTopHosts(10)
		if len(topHosts) > 0 {
			fmt.Println("\nTop Hosts:")
			for i, stats := range topHosts {
				fmt.Printf("  %d. %s - %d requests\n",
					i+1, stats.Host, stats.RequestCount)
			}
		}

		// Top paths
		topPaths := httpAggregator.GetTopPaths(10)
		if len(topPaths) > 0 {
			fmt.Println("\nTop Paths:")
			for i, stats := range topPaths {
				errCount := stats.Status4xx + stats.Status5xx
				fmt.Printf("  %d. %s - %d requests, %d errors",
					i+1, stats.Path, stats.RequestCount, errCount)
				if stats.AvgResponseTimeMs > 0 {
					fmt.Printf(", avg: %dms", stats.AvgResponseTimeMs)
				}
				fmt.Println()
			}
		}
	}
}
