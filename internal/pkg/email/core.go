//go:build cli || all

package email

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

// Global state for email sniffer
var (
	emailParser     *Parser
	emailTracker    *SessionTracker
	emailPcapWriter *pcapgo.Writer
	emailOutputFile *os.File
	emailFactory    tcpassembly.StreamFactory
	emailAssembler  *tcpassembly.Assembler
	emailHandler    *cliSMTPHandler
)

// cliSMTPHandler handles SMTP messages for CLI output.
type cliSMTPHandler struct {
	quietMode     bool
	jsonEncoder   *json.Encoder
	tracker       *SessionTracker
	contentFilter *ContentFilter
}

func (h *cliSMTPHandler) HandleSMTPLine(line string, metadata *types.EmailMetadata, sessionID string, flow gopacket.Flow) {
	// Update tracker
	if h.tracker != nil {
		h.tracker.UpdateSession(sessionID, metadata)
	}

	// Apply content filter if configured
	if h.contentFilter != nil && h.contentFilter.HasFilters() {
		if !h.contentFilter.Match(metadata) {
			return // Skip this message - doesn't match filter
		}
	}

	if h.quietMode {
		return
	}

	// Create packet display
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		Protocol:  "SMTP",
		Info:      FormatInfo(metadata),
		EmailData: metadata,
	}

	// Extract IPs from flow
	pkt.SrcIP = flow.Src().String()
	pkt.DstIP = flow.Dst().String()

	if h.jsonEncoder != nil {
		if err := h.jsonEncoder.Encode(pkt); err != nil {
			logger.Error("Failed to encode packet as JSON", "error", err)
		}
	} else {
		printEmailPacket(pkt, metadata)
	}
}

// StartEmailSniffer starts the email sniffer on the specified interfaces.
func StartEmailSniffer(devices []pcaptypes.PcapInterface, filter string) {
	logger.Info("Starting Email sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize parser and tracker
	emailParser = NewParser()

	if viper.GetBool("email.track_sessions") {
		emailTracker = NewSessionTracker(DefaultTrackerConfig())
	}

	// PCAP writer if output file specified
	if writeFile := viper.GetString("email.write_file"); writeFile != "" {
		var err error
		emailOutputFile, err = os.Create(writeFile)
		if err != nil {
			logger.Error("Failed to create output file", "error", err, "file", writeFile)
		} else {
			emailPcapWriter = pcapgo.NewWriter(emailOutputFile)
			if err := emailPcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to write PCAP header", "error", err)
				emailPcapWriter = nil
			} else {
				logger.Info("Writing email packets to file", "file", writeFile)
			}
		}
	}

	// Initialize handler
	quietMode := viper.GetBool("sniff.quiet")
	format := viper.GetString("sniff.format")

	var jsonEncoder *json.Encoder
	if format == "json" {
		jsonEncoder = json.NewEncoder(os.Stdout)
	}

	// Build content filter from viper configuration
	var contentFilter *ContentFilter
	filterConfig := buildContentFilterConfig()
	if filterConfig.hasPatterns() {
		contentFilter = NewContentFilter(filterConfig)
		logger.Info("Email content filter enabled",
			"address_patterns", len(filterConfig.AddressPatterns),
			"sender_patterns", len(filterConfig.SenderPatterns),
			"recipient_patterns", len(filterConfig.RecipientPatterns),
			"subject_patterns", len(filterConfig.SubjectPatterns),
			"keywords", len(filterConfig.Keywords))
	}

	emailHandler = &cliSMTPHandler{
		quietMode:     quietMode,
		jsonEncoder:   jsonEncoder,
		tracker:       emailTracker,
		contentFilter: contentFilter,
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

	// Create processor function with TCP reassembly
	processor := func(packetChan <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
		processEmailPackets(packetChan, asm)
	}

	// Create TCP assembler for SMTP
	ctx := context.Background()
	emailFactory = NewSMTPStreamFactory(ctx, emailHandler, DefaultSMTPStreamFactoryConfig())
	streamPool := tcpassembly.NewStreamPool(emailFactory)
	emailAssembler = tcpassembly.NewAssembler(streamPool)

	// Run capture with appropriate mode
	if isOffline {
		capture.RunOffline(devices, filter, processor, emailAssembler)
	} else {
		capture.RunWithSignalHandler(devices, filter, processor, emailAssembler)
	}

	// Print statistics and cleanup
	printStatistics()
	cleanup()
}

// processEmailPackets processes packets from the channel.
func processEmailPackets(packetChan <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
	for pktInfo := range packetChan {
		packet := pktInfo.Packet

		// Check for TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		// Get network layer for flow
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}

		// Feed to assembler
		if asm != nil {
			asm.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}

		// Write to PCAP if configured
		if emailPcapWriter != nil {
			ci := gopacket.CaptureInfo{
				Timestamp:      packet.Metadata().Timestamp,
				CaptureLength:  len(packet.Data()),
				Length:         len(packet.Data()),
				InterfaceIndex: 0,
			}
			if err := emailPcapWriter.WritePacket(ci, packet.Data()); err != nil {
				logger.Error("Failed to write packet to PCAP", "error", err)
			}
		}
	}

	// Flush assembler on channel close
	if asm != nil {
		asm.FlushAll()
	}
}

// cleanup releases resources.
func cleanup() {
	if emailTracker != nil {
		emailTracker.Stop()
	}
	if emailOutputFile != nil {
		if err := emailOutputFile.Close(); err != nil {
			logger.Error("Failed to close output file", "error", err)
		}
	}
	if factory, ok := emailFactory.(*smtpStreamFactory); ok {
		factory.Close()
	}
}

// printEmailPacket prints an email packet to the console.
func printEmailPacket(pkt *types.PacketDisplay, metadata *types.EmailMetadata) {
	timestamp := pkt.Timestamp.Format("15:04:05.000")

	var direction string
	if metadata.IsServer {
		direction = "<-"
	} else {
		direction = "->"
	}

	var info string
	if metadata.IsServer {
		info = fmt.Sprintf("%d %s", metadata.ResponseCode, metadata.ResponseText)
		if len(info) > 60 {
			info = info[:60] + "..."
		}
	} else {
		info = metadata.Command
		if metadata.MailFrom != "" {
			info += " FROM:" + metadata.MailFrom
		}
		if len(metadata.RcptTo) > 0 {
			info += " TO:" + metadata.RcptTo[0]
		}
	}

	fmt.Printf("%s %s %s %s  %s\n",
		timestamp,
		pkt.SrcIP,
		direction,
		pkt.DstIP,
		info,
	)
}

// StartLiveEmailSniffer starts email capture on live network interfaces.
func StartLiveEmailSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartEmailSniffer)
}

// StartOfflineEmailSniffer starts email capture from a PCAP file.
func StartOfflineEmailSniffer(readFile, filter string) {
	capture.StartOfflineSniffer(readFile, filter, StartEmailSniffer)
}

// printStatistics prints capture statistics.
func printStatistics() {
	fmt.Println("\n--- Email Capture Statistics ---")

	if emailTracker != nil {
		stats := emailTracker.Stats()
		fmt.Printf("\nSession Statistics:\n")
		fmt.Printf("  Active sessions: %d\n", stats.ActiveSessions)
		fmt.Printf("  Total messages: %d\n", stats.TotalMessages)
		fmt.Printf("  Encrypted sessions: %d\n", stats.EncryptedSessions)
	}
}

// buildContentFilterConfig builds a ContentFilterConfig from viper configuration.
func buildContentFilterConfig() ContentFilterConfig {
	config := ContentFilterConfig{}

	// Load single patterns from viper
	if pattern := viper.GetString("email.address_pattern"); pattern != "" {
		config.AddressPatterns = []string{pattern}
	}
	if pattern := viper.GetString("email.sender_pattern"); pattern != "" {
		config.SenderPatterns = []string{pattern}
	}
	if pattern := viper.GetString("email.recipient_pattern"); pattern != "" {
		config.RecipientPatterns = []string{pattern}
	}
	if pattern := viper.GetString("email.subject_pattern"); pattern != "" {
		config.SubjectPatterns = []string{pattern}
	}

	// Append patterns loaded from files
	if patterns := viper.GetStringSlice("email.address_patterns"); len(patterns) > 0 {
		config.AddressPatterns = append(config.AddressPatterns, patterns...)
	}
	if patterns := viper.GetStringSlice("email.sender_patterns"); len(patterns) > 0 {
		config.SenderPatterns = append(config.SenderPatterns, patterns...)
	}
	if patterns := viper.GetStringSlice("email.recipient_patterns"); len(patterns) > 0 {
		config.RecipientPatterns = append(config.RecipientPatterns, patterns...)
	}
	if patterns := viper.GetStringSlice("email.subject_patterns"); len(patterns) > 0 {
		config.SubjectPatterns = append(config.SubjectPatterns, patterns...)
	}

	// Load keywords for Aho-Corasick matching
	if keywords := viper.GetStringSlice("email.keywords"); len(keywords) > 0 {
		config.Keywords = keywords
	}

	return config
}

// hasPatterns returns true if any patterns are configured.
func (c ContentFilterConfig) hasPatterns() bool {
	return len(c.AddressPatterns) > 0 ||
		len(c.SenderPatterns) > 0 ||
		len(c.RecipientPatterns) > 0 ||
		len(c.SubjectPatterns) > 0 ||
		len(c.Keywords) > 0
}
