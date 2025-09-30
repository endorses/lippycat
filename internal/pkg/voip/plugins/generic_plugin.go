package plugins

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GenericPlugin handles generic protocol processing for unknown or fallback protocols
type GenericPlugin struct {
	name    string
	version string
	enabled atomic.Bool
	metrics GenericMetrics
}

// GenericMetrics tracks generic plugin metrics
type GenericMetrics struct {
	PacketsProcessed atomic.Int64
	UDPPackets      atomic.Int64
	TCPPackets      atomic.Int64
	UnknownPackets  atomic.Int64
	ProcessingTime  atomic.Int64
	ErrorCount      atomic.Int64
}

// NewGenericPlugin creates a new generic protocol plugin
func NewGenericPlugin() *GenericPlugin {
	return &GenericPlugin{
		name:    "Generic Protocol Handler",
		version: "1.0.0",
	}
}

// Name returns the plugin name
func (g *GenericPlugin) Name() string {
	return g.name
}

// Version returns the plugin version
func (g *GenericPlugin) Version() string {
	return g.version
}

// SupportedProtocols returns protocols this plugin handles
func (g *GenericPlugin) SupportedProtocols() []string {
	return []string{"generic", "unknown"}
}

// Initialize sets up the plugin with configuration
func (g *GenericPlugin) Initialize(config map[string]interface{}) error {
	g.enabled.Store(true)

	logger.Info("Generic plugin initialized",
		"name", g.name,
		"version", g.version)

	return nil
}

// ProcessPacket processes a generic packet
func (g *GenericPlugin) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*ProcessResult, error) {
	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		g.metrics.ProcessingTime.Add(processingTime.Nanoseconds())
		g.metrics.PacketsProcessed.Add(1)
	}()

	// Create basic processing result
	result := &ProcessResult{
		Protocol:       "generic",
		Action:         "track",
		Metadata:       make(map[string]interface{}),
		Confidence:     0.5, // Lower confidence for generic processing
		ProcessingTime: time.Since(start),
		ShouldContinue: true,
	}

	// Extract basic network information
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		if ipv4, ok := networkLayer.(*layers.IPv4); ok {
			result.Metadata["src_ip"] = ipv4.SrcIP.String()
			result.Metadata["dst_ip"] = ipv4.DstIP.String()
			result.Metadata["protocol"] = ipv4.Protocol.String()
			result.Metadata["length"] = ipv4.Length
		} else if ipv6, ok := networkLayer.(*layers.IPv6); ok {
			result.Metadata["src_ip"] = ipv6.SrcIP.String()
			result.Metadata["dst_ip"] = ipv6.DstIP.String()
			result.Metadata["next_header"] = ipv6.NextHeader.String()
			result.Metadata["payload_length"] = ipv6.Length
		}
	}

	// Extract transport layer information
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		if udp, ok := transportLayer.(*layers.UDP); ok {
			result.Metadata["src_port"] = udp.SrcPort.String()
			result.Metadata["dst_port"] = udp.DstPort.String()
			result.Metadata["transport"] = "UDP"
			result.Metadata["length"] = udp.Length
			g.metrics.UDPPackets.Add(1)
		} else if tcp, ok := transportLayer.(*layers.TCP); ok {
			result.Metadata["src_port"] = tcp.SrcPort.String()
			result.Metadata["dst_port"] = tcp.DstPort.String()
			result.Metadata["transport"] = "TCP"
			result.Metadata["seq"] = tcp.Seq
			result.Metadata["ack"] = tcp.Ack
			result.Metadata["window"] = tcp.Window

			// TCP flags
			flags := make([]string, 0)
			if tcp.SYN {
				flags = append(flags, "SYN")
			}
			if tcp.ACK {
				flags = append(flags, "ACK")
			}
			if tcp.FIN {
				flags = append(flags, "FIN")
			}
			if tcp.RST {
				flags = append(flags, "RST")
			}
			if tcp.PSH {
				flags = append(flags, "PSH")
			}
			if tcp.URG {
				flags = append(flags, "URG")
			}
			result.Metadata["tcp_flags"] = strings.Join(flags, ",")
			g.metrics.TCPPackets.Add(1)
		} else {
			g.metrics.UnknownPackets.Add(1)
		}
	}

	// Extract application layer information if available
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		result.Metadata["payload_size"] = len(payload)

		// Try to detect protocol hints from payload
		if len(payload) > 0 {
			protocolHint := g.detectProtocolHint(payload)
			if protocolHint != "" {
				result.Metadata["protocol_hint"] = protocolHint
				result.Protocol = protocolHint
				result.Confidence = 0.7 // Higher confidence with protocol hint
			}
		}
	}

	// Add timestamp
	result.Metadata["timestamp"] = packet.Metadata().Timestamp

	// Try to generate a pseudo call ID for tracking related packets
	if callID := g.generatePseudoCallID(result.Metadata); callID != "" {
		result.CallID = callID
	}

	return result, nil
}

// detectProtocolHint attempts to detect protocol from payload content
func (g *GenericPlugin) detectProtocolHint(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	payloadStr := string(payload[:min(len(payload), 100)])

	// Check for common protocol signatures
	if strings.Contains(strings.ToUpper(payloadStr), "HTTP/") {
		return "http"
	}

	if strings.Contains(strings.ToUpper(payloadStr), "RTSP/") {
		return "rtsp"
	}

	// Check for SIP (fallback in case SIP plugin missed it)
	if strings.Contains(payloadStr, "SIP/2.0") ||
	   strings.HasPrefix(payloadStr, "INVITE ") ||
	   strings.HasPrefix(payloadStr, "REGISTER ") {
		return "sip"
	}

	// Check for STUN/TURN
	if len(payload) >= 20 && payload[0] == 0x00 && (payload[1] == 0x01 || payload[1] == 0x11) {
		return "stun"
	}

	// Check for DNS
	if len(payload) >= 12 && payload[2]&0x80 == 0 { // Query flag
		return "dns"
	}

	// Check for DHCP
	if len(payload) >= 4 && (payload[0] == 0x01 || payload[0] == 0x02) {
		return "dhcp"
	}

	return ""
}

// generatePseudoCallID creates a pseudo call ID for packet correlation
func (g *GenericPlugin) generatePseudoCallID(metadata map[string]interface{}) string {
	srcIP, hasSrcIP := metadata["src_ip"].(string)
	dstIP, hasDstIP := metadata["dst_ip"].(string)
	srcPort, hasSrcPort := metadata["src_port"].(string)
	dstPort, hasDstPort := metadata["dst_port"].(string)

	if !hasSrcIP || !hasDstIP || !hasSrcPort || !hasDstPort {
		return ""
	}

	// Create a deterministic call ID based on connection 5-tuple
	// Sort IPs and ports to ensure same ID regardless of direction
	var ip1, ip2, port1, port2 string
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		ip1, ip2, port1, port2 = srcIP, dstIP, srcPort, dstPort
	} else {
		ip1, ip2, port1, port2 = dstIP, srcIP, dstPort, srcPort
	}

	return "generic_" + ip1 + "_" + port1 + "_" + ip2 + "_" + port2
}

// Shutdown gracefully shuts down the plugin
func (g *GenericPlugin) Shutdown(ctx context.Context) error {
	g.enabled.Store(false)
	logger.Info("Generic plugin shutdown complete")
	return nil
}

// HealthCheck returns the current health status
func (g *GenericPlugin) HealthCheck() HealthStatus {
	status := HealthHealthy
	message := "Generic plugin operating normally"
	details := make(map[string]interface{})

	// Check if plugin is enabled
	if !g.enabled.Load() {
		status = HealthUnhealthy
		message = "Generic plugin is disabled"
	}

	// Check error rate
	processed := g.metrics.PacketsProcessed.Load()
	errors := g.metrics.ErrorCount.Load()
	if processed > 100 && errors > processed/10 { // Error rate > 10%
		status = HealthDegraded
		message = "High error rate detected"
	}

	details["packets_processed"] = processed
	details["errors"] = errors
	details["udp_packets"] = g.metrics.UDPPackets.Load()
	details["tcp_packets"] = g.metrics.TCPPackets.Load()
	details["unknown_packets"] = g.metrics.UnknownPackets.Load()

	return HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}
}

// Metrics returns current plugin metrics
func (g *GenericPlugin) Metrics() PluginMetrics {
	return PluginMetrics{
		PacketsProcessed: g.metrics.PacketsProcessed.Load(),
		ProcessingTime:   time.Duration(g.metrics.ProcessingTime.Load()),
		ErrorCount:       g.metrics.ErrorCount.Load(),
		CustomMetrics: map[string]interface{}{
			"udp_packets":     g.metrics.UDPPackets.Load(),
			"tcp_packets":     g.metrics.TCPPackets.Load(),
			"unknown_packets": g.metrics.UnknownPackets.Load(),
		},
	}
}

// GenericPluginFactory creates generic plugin instances
type GenericPluginFactory struct{}

// CreatePlugin creates a new generic plugin instance
func (f *GenericPluginFactory) CreatePlugin() ProtocolHandler {
	return NewGenericPlugin()
}

// PluginInfo returns information about the generic plugin
func (f *GenericPluginFactory) PluginInfo() PluginInfo {
	return PluginInfo{
		Name:        "Generic Protocol Handler",
		Version:     "1.0.0",
		Author:      "lippycat",
		Description: "Handles generic packet analysis for unknown protocols and provides fallback processing",
		Protocols:   []string{"generic", "unknown"},
		Config: PluginConfig{
			Enabled:  true,
			Priority: 10, // Lowest priority - fallback plugin
			Timeout:  1 * time.Second,
		},
	}
}

// Helper function (define locally since it's commonly used)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}