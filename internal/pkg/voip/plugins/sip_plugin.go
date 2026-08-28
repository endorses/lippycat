package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SIPPlugin handles SIP protocol processing
type SIPPlugin struct {
	name    string
	version string
	enabled atomic.Bool
	metrics SIPMetrics
}

// SIPMetrics tracks SIP-specific metrics
type SIPMetrics struct {
	PacketsProcessed atomic.Int64
	InvitesSeen      atomic.Int64
	ResponsesSeen    atomic.Int64
	CallsDetected    atomic.Int64
	ErrorCount       atomic.Int64
	ProcessingTime   atomic.Int64
}

// NewSIPPlugin creates a new SIP protocol plugin
func NewSIPPlugin() *SIPPlugin {
	return &SIPPlugin{
		name:    "SIP Protocol Handler",
		version: "1.0.0",
	}
}

// Name returns the plugin name
func (s *SIPPlugin) Name() string {
	return s.name
}

// Version returns the plugin version
func (s *SIPPlugin) Version() string {
	return s.version
}

// SupportedProtocols returns protocols this plugin handles
func (s *SIPPlugin) SupportedProtocols() []string {
	return []string{"sip"}
}

// Initialize sets up the plugin with configuration
func (s *SIPPlugin) Initialize(config map[string]interface{}) error {
	s.enabled.Store(true)

	logger.Info("SIP plugin initialized",
		"name", s.name,
		"version", s.version)

	return nil
}

// ProcessPacket processes a SIP packet
func (s *SIPPlugin) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*ProcessResult, error) {
	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		s.metrics.ProcessingTime.Add(processingTime.Nanoseconds())
		s.metrics.PacketsProcessed.Add(1)
	}()

	// Extract payload from transport layer to get the full unparsed data
	// Note: We use transport layer instead of application layer because gopacket's
	// protocol parsers may consume/modify the payload (e.g., SIP parser separates
	// headers from body), making it unsuitable for protocol detection
	var payloadBytes []byte
	if transLayer := packet.TransportLayer(); transLayer != nil {
		payloadBytes = transLayer.LayerPayload()
	}

	if len(payloadBytes) == 0 {
		return nil, nil
	}

	if !s.isSIPPacket(string(payloadBytes)) {
		return nil, nil
	}

	event, err := sharedsip.Parse(payloadBytes, sipParseOptions(packet))
	if err != nil {
		s.metrics.ErrorCount.Add(1)
		return nil, fmt.Errorf("parse SIP packet: %w", err)
	}

	// Extract SIP information
	result := &ProcessResult{
		Protocol:       "sip",
		Action:         "track",
		Metadata:       make(map[string]interface{}),
		Confidence:     0.95,
		ProcessingTime: time.Since(start),
		ShouldContinue: true,
	}

	if event.CallID != "" {
		result.CallID = event.CallID
		result.Metadata["call_id"] = event.CallID
	}

	// Determine SIP method or response
	if method := event.Method; method != "RESPONSE" {
		result.Metadata["method"] = method
		result.Action = s.getActionForMethod(method)

		if method == "INVITE" {
			s.metrics.InvitesSeen.Add(1)
			s.metrics.CallsDetected.Add(1)
		}
	} else {
		statusCode := strconv.Itoa(event.ResponseCode)
		result.Metadata["status_code"] = statusCode
		result.Metadata["response_type"] = s.getResponseType(statusCode)
		s.metrics.ResponsesSeen.Add(1)
	}

	copySIPHeaders(event.Headers, result.Metadata)

	// Extract network information
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		if ipv4, ok := networkLayer.(*layers.IPv4); ok {
			result.Metadata["src_ip"] = ipv4.SrcIP.String()
			result.Metadata["dst_ip"] = ipv4.DstIP.String()
		}
	}

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		if udp, ok := transportLayer.(*layers.UDP); ok {
			result.Metadata["src_port"] = udp.SrcPort.String()
			result.Metadata["dst_port"] = udp.DstPort.String()
			result.Metadata["transport"] = "UDP"
		} else if tcp, ok := transportLayer.(*layers.TCP); ok {
			result.Metadata["src_port"] = tcp.SrcPort.String()
			result.Metadata["dst_port"] = tcp.DstPort.String()
			result.Metadata["transport"] = "TCP"
		}
	}

	return result, nil
}

func sipParseOptions(packet gopacket.Packet) sharedsip.ParseOptions {
	opts := sharedsip.ParseOptions{Timestamp: packet.Metadata().Timestamp}
	if ipv4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
		opts.SourceIP, opts.DestinationIP = ipv4.SrcIP.String(), ipv4.DstIP.String()
	}
	switch transport := packet.TransportLayer().(type) {
	case *layers.UDP:
		opts.SourcePort, opts.DestinationPort = uint16(transport.SrcPort), uint16(transport.DstPort)
	case *layers.TCP:
		opts.SourcePort, opts.DestinationPort = uint16(transport.SrcPort), uint16(transport.DstPort)
	}
	return opts
}

// isSIPPacket determines if the payload contains SIP content
func (s *SIPPlugin) isSIPPacket(payload string) bool {
	if len(payload) < 8 {
		return false
	}

	firstLine := payload
	if newline := strings.IndexByte(firstLine, '\n'); newline >= 0 {
		firstLine = firstLine[:newline]
	}
	return sharedsip.IsStartLine(strings.TrimSpace(firstLine))
}

func copySIPHeaders(headers map[string]string, metadata map[string]interface{}) {
	for header, key := range map[string]string{
		"from": "from", "to": "to", "contact": "contact", "via": "via",
		"content-length": "content_length", "user-agent": "user_agent",
		"server": "server", "cseq": "cseq",
	} {
		if value := headers[header]; value != "" {
			metadata[key] = value
		}
	}
}

// getActionForMethod returns appropriate action for SIP method
func (s *SIPPlugin) getActionForMethod(method string) string {
	switch method {
	case "INVITE":
		return "call_start"
	case "BYE":
		return "call_end"
	case "CANCEL":
		return "call_cancel"
	case "REGISTER":
		return "registration"
	default:
		return "track"
	}
}

// getResponseType categorizes SIP response codes
func (s *SIPPlugin) getResponseType(statusCode string) string {
	if len(statusCode) < 1 {
		return "unknown"
	}

	switch statusCode[0] {
	case '1':
		return "provisional"
	case '2':
		return "success"
	case '3':
		return "redirect"
	case '4':
		return "client_error"
	case '5':
		return "server_error"
	case '6':
		return "global_failure"
	default:
		return "unknown"
	}
}

// Shutdown gracefully shuts down the plugin
func (s *SIPPlugin) Shutdown(ctx context.Context) error {
	s.enabled.Store(false)
	logger.Info("SIP plugin shutdown complete")
	return nil
}

// HealthCheck returns the current health status
func (s *SIPPlugin) HealthCheck() HealthStatus {
	status := HealthHealthy
	message := "SIP plugin operating normally"
	details := make(map[string]interface{})

	// Check if plugin is enabled
	if !s.enabled.Load() {
		status = HealthUnhealthy
		message = "SIP plugin is disabled"
	}

	// Check error rate
	processed := s.metrics.PacketsProcessed.Load()
	errors := s.metrics.ErrorCount.Load()
	if processed > 100 && errors > processed/10 { // Error rate > 10%
		status = HealthDegraded
		message = "High error rate detected"
	}

	details["packets_processed"] = processed
	details["errors"] = errors
	details["invites_seen"] = s.metrics.InvitesSeen.Load()
	details["responses_seen"] = s.metrics.ResponsesSeen.Load()
	details["calls_detected"] = s.metrics.CallsDetected.Load()

	return HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}
}

// Metrics returns current plugin metrics
func (s *SIPPlugin) Metrics() PluginMetrics {
	return PluginMetrics{
		PacketsProcessed: s.metrics.PacketsProcessed.Load(),
		ProcessingTime:   time.Duration(s.metrics.ProcessingTime.Load()),
		ErrorCount:       s.metrics.ErrorCount.Load(),
		CustomMetrics: map[string]interface{}{
			"invites_seen":   s.metrics.InvitesSeen.Load(),
			"responses_seen": s.metrics.ResponsesSeen.Load(),
			"calls_detected": s.metrics.CallsDetected.Load(),
		},
	}
}

// SIPPluginFactory creates SIP plugin instances
type SIPPluginFactory struct{}

// CreatePlugin creates a new SIP plugin instance
func (f *SIPPluginFactory) CreatePlugin() ProtocolHandler {
	return NewSIPPlugin()
}

// PluginInfo returns information about the SIP plugin
func (f *SIPPluginFactory) PluginInfo() PluginInfo {
	return PluginInfo{
		Name:        "SIP Protocol Handler",
		Version:     "1.0.0",
		Author:      "lippycat",
		Description: "Handles SIP (Session Initiation Protocol) packet analysis and call tracking",
		Protocols:   []string{"sip"},
		Config: PluginConfig{
			Enabled:  true,
			Priority: 100,
			Timeout:  5 * time.Second,
		},
	}
}
