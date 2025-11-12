package analyzer

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VoIPProtocol implements Protocol for VoIP traffic analysis (SIP + RTP)
type VoIPProtocol struct {
	name    string
	version string
	enabled atomic.Bool
	metrics voipMetrics
}

// voipMetrics tracks VoIP-specific metrics
type voipMetrics struct {
	packetsProcessed atomic.Int64
	sipPackets       atomic.Int64
	rtpPackets       atomic.Int64
	callsDetected    atomic.Int64
	errorCount       atomic.Int64
	processingTime   atomic.Int64
}

// NewVoIPProtocol creates a new VoIP protocol analyzer
func NewVoIPProtocol() *VoIPProtocol {
	return &VoIPProtocol{
		name:    "VoIP Protocol Analyzer",
		version: "1.0.0",
	}
}

// Name returns the analyzer name
func (v *VoIPProtocol) Name() string {
	return v.name
}

// Version returns the analyzer version
func (v *VoIPProtocol) Version() string {
	return v.version
}

// SupportedProtocols returns the protocols this analyzer handles
func (v *VoIPProtocol) SupportedProtocols() []string {
	return []string{"sip", "rtp", "voip"}
}

// ProcessPacket analyzes a VoIP packet
func (v *VoIPProtocol) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*Result, error) {
	if !v.enabled.Load() {
		return nil, nil
	}

	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		v.metrics.packetsProcessed.Add(1)
		v.metrics.processingTime.Add(processingTime.Nanoseconds())
	}()

	// Check for SIP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		// Common SIP ports: 5060 (UDP), 5061 (TLS)
		if udp.SrcPort == 5060 || udp.DstPort == 5060 || udp.SrcPort == 5061 || udp.DstPort == 5061 {
			// This is a simplified example - real implementation would parse SIP headers
			// and delegate to existing voip package functionality
			v.metrics.sipPackets.Add(1)

			// Extract Call-ID from SIP message (simplified)
			payload := string(udp.Payload)
			callID := extractCallID(payload)

			if callID != "" {
				v.metrics.callsDetected.Add(1)
				return &Result{
					CallID:         callID,
					Protocol:       "sip",
					Action:         "track",
					Confidence:     0.95,
					ProcessingTime: time.Since(start),
					ShouldContinue: false, // VoIP analyzer has handled this packet
					Metadata: map[string]interface{}{
						"src_port": udp.SrcPort.String(),
						"dst_port": udp.DstPort.String(),
					},
				}, nil
			}
		}

		// Check for RTP (common range: 10000-20000, 16384-32767)
		srcPort := int(udp.SrcPort)
		dstPort := int(udp.DstPort)
		if (srcPort >= 10000 && srcPort <= 20000) || (dstPort >= 10000 && dstPort <= 20000) ||
			(srcPort >= 16384 && srcPort <= 32767) || (dstPort >= 16384 && dstPort <= 32767) {
			v.metrics.rtpPackets.Add(1)

			return &Result{
				Protocol:       "rtp",
				Action:         "track",
				Confidence:     0.7,
				ProcessingTime: time.Since(start),
				ShouldContinue: false,
				Metadata: map[string]interface{}{
					"src_port": udp.SrcPort.String(),
					"dst_port": udp.DstPort.String(),
				},
			}, nil
		}
	}

	return nil, nil
}

// extractCallID extracts Call-ID from SIP message (simplified)
func extractCallID(payload string) string {
	// This is a simplified implementation
	// Real implementation should use proper SIP parsing from voip package
	// TODO: Integrate with existing voip.ParseSIPHeaders()
	return ""
}

// Initialize sets up the VoIP analyzer
func (v *VoIPProtocol) Initialize(config map[string]interface{}) error {
	v.enabled.Store(true)
	logger.Info("VoIP protocol analyzer initialized", "config", config)
	return nil
}

// Shutdown gracefully shuts down the analyzer
func (v *VoIPProtocol) Shutdown(ctx context.Context) error {
	v.enabled.Store(false)
	logger.Info("VoIP protocol analyzer shutdown")
	return nil
}

// HealthCheck returns the analyzer health status
func (v *VoIPProtocol) HealthCheck() HealthStatus {
	if !v.enabled.Load() {
		return HealthStatus{
			Status:    HealthUnhealthy,
			Message:   "Analyzer disabled",
			Timestamp: time.Now(),
		}
	}

	return HealthStatus{
		Status:    HealthHealthy,
		Message:   "Operating normally",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"packets_processed": v.metrics.packetsProcessed.Load(),
			"sip_packets":       v.metrics.sipPackets.Load(),
			"rtp_packets":       v.metrics.rtpPackets.Load(),
			"calls_detected":    v.metrics.callsDetected.Load(),
		},
	}
}

// Metrics returns current analyzer metrics
func (v *VoIPProtocol) Metrics() Metrics {
	return Metrics{
		PacketsProcessed: v.metrics.packetsProcessed.Load(),
		ProcessingTime:   time.Duration(v.metrics.processingTime.Load()),
		ErrorCount:       v.metrics.errorCount.Load(),
		CustomMetrics: map[string]interface{}{
			"sip_packets":    v.metrics.sipPackets.Load(),
			"rtp_packets":    v.metrics.rtpPackets.Load(),
			"calls_detected": v.metrics.callsDetected.Load(),
		},
	}
}

// Register the VoIP protocol analyzer at initialization
func init() {
	config := DefaultConfig()
	config.Priority = 100 // Higher priority for VoIP
	config.Timeout = 5 * time.Second

	GetRegistry().MustRegister("voip", NewVoIPProtocol(), config)
}
