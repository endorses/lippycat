package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RTPPlugin handles RTP protocol processing
type RTPPlugin struct {
	name    string
	version string
	enabled atomic.Bool
	metrics RTPMetrics
}

// RTPMetrics tracks RTP-specific metrics
type RTPMetrics struct {
	PacketsProcessed atomic.Int64
	AudioPackets     atomic.Int64
	VideoPackets     atomic.Int64
	SequenceErrors   atomic.Int64
	PayloadTypes     map[uint8]*atomic.Int64 // payload type -> count
	ProcessingTime   atomic.Int64
	ErrorCount       atomic.Int64
}

// RTPHeader represents the RTP header structure
type RTPHeader struct {
	Version        uint8
	Padding        bool
	Extension      bool
	CSRCCount      uint8
	Marker         bool
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
}

// NewRTPPlugin creates a new RTP protocol plugin
func NewRTPPlugin() *RTPPlugin {
	return &RTPPlugin{
		name:    "RTP Protocol Handler",
		version: "1.0.0",
		metrics: RTPMetrics{
			PayloadTypes: make(map[uint8]*atomic.Int64),
		},
	}
}

// Name returns the plugin name
func (r *RTPPlugin) Name() string {
	return r.name
}

// Version returns the plugin version
func (r *RTPPlugin) Version() string {
	return r.version
}

// SupportedProtocols returns protocols this plugin handles
func (r *RTPPlugin) SupportedProtocols() []string {
	return []string{"rtp", "rtcp"}
}

// Initialize sets up the plugin with configuration
func (r *RTPPlugin) Initialize(config map[string]interface{}) error {
	r.enabled.Store(true)

	logger.Info("RTP plugin initialized",
		"name", r.name,
		"version", r.version)

	return nil
}

// ProcessPacket processes an RTP packet
func (r *RTPPlugin) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*ProcessResult, error) {
	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		r.metrics.ProcessingTime.Add(processingTime.Nanoseconds())
		r.metrics.PacketsProcessed.Add(1)
	}()

	// Check if this is an RTP/RTCP packet
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return nil, nil
	}

	payload := appLayer.Payload()
	if len(payload) < 12 {
		return nil, nil // RTP header is at least 12 bytes
	}

	// Check if this looks like RTP
	if !r.isRTPPacket(payload) {
		return nil, nil
	}

	// Parse RTP header
	header, err := r.parseRTPHeader(payload)
	if err != nil {
		r.metrics.ErrorCount.Add(1)
		return nil, err
	}

	// Create processing result
	result := &ProcessResult{
		Protocol:       "rtp",
		Action:         "track",
		Metadata:       make(map[string]interface{}),
		Confidence:     0.90,
		ProcessingTime: time.Since(start),
		ShouldContinue: true,
	}

	// Add RTP metadata
	result.Metadata["rtp_version"] = header.Version
	result.Metadata["payload_type"] = header.PayloadType
	result.Metadata["sequence_number"] = header.SequenceNumber
	result.Metadata["timestamp"] = header.Timestamp
	result.Metadata["ssrc"] = header.SSRC
	result.Metadata["marker"] = header.Marker

	// Track payload type statistics
	r.trackPayloadType(header.PayloadType)

	// Determine media type
	mediaType := r.getMediaType(header.PayloadType)
	result.Metadata["media_type"] = mediaType

	if mediaType == "audio" {
		r.metrics.AudioPackets.Add(1)
	} else if mediaType == "video" {
		r.metrics.VideoPackets.Add(1)
	}

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
		}
	}

	// Calculate payload size
	headerSize := 12 + int(header.CSRCCount)*4
	if header.Extension {
		if len(payload) >= headerSize+4 {
			extLength := binary.BigEndian.Uint16(payload[headerSize+2:])
			headerSize += 4 + int(extLength)*4
		}
	}

	if len(payload) > headerSize {
		result.Metadata["payload_size"] = len(payload) - headerSize
	}

	return result, nil
}

// isRTPPacket determines if the payload contains RTP content
func (r *RTPPlugin) isRTPPacket(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}

	// Check RTP version (should be 2)
	version := (payload[0] >> 6) & 0x03
	if version != 2 {
		return false
	}

	// Check payload type (should be valid RTP payload type)
	payloadType := payload[1] & 0x7F
	if payloadType > 127 {
		return false
	}

	// Additional heuristics for RTP detection
	// RTP packets typically have reasonable sequence numbers and timestamps
	return true
}

// parseRTPHeader parses the RTP header from packet payload
func (r *RTPPlugin) parseRTPHeader(payload []byte) (*RTPHeader, error) {
	if len(payload) < 12 {
		return nil, ErrInvalidRTPPacket
	}

	header := &RTPHeader{
		Version:        (payload[0] >> 6) & 0x03,
		Padding:        (payload[0]>>5)&0x01 == 1,
		Extension:      (payload[0]>>4)&0x01 == 1,
		CSRCCount:      payload[0] & 0x0F,
		Marker:         (payload[1]>>7)&0x01 == 1,
		PayloadType:    payload[1] & 0x7F,
		SequenceNumber: binary.BigEndian.Uint16(payload[2:4]),
		Timestamp:      binary.BigEndian.Uint32(payload[4:8]),
		SSRC:           binary.BigEndian.Uint32(payload[8:12]),
	}

	return header, nil
}

// trackPayloadType tracks statistics for RTP payload types
func (r *RTPPlugin) trackPayloadType(payloadType uint8) {
	if counter, exists := r.metrics.PayloadTypes[payloadType]; exists {
		counter.Add(1)
	} else {
		counter := &atomic.Int64{}
		counter.Add(1)
		r.metrics.PayloadTypes[payloadType] = counter
	}
}

// getMediaType determines media type based on payload type
func (r *RTPPlugin) getMediaType(payloadType uint8) string {
	// Standard RTP payload types (RFC 3551)
	switch payloadType {
	case 0: // PCMU
		return "audio"
	case 3: // GSM
		return "audio"
	case 4: // G723
		return "audio"
	case 5: // DVI4 8kHz
		return "audio"
	case 6: // DVI4 16kHz
		return "audio"
	case 7: // LPC
		return "audio"
	case 8: // PCMA
		return "audio"
	case 9: // G722
		return "audio"
	case 10, 11: // L16
		return "audio"
	case 12: // QCELP
		return "audio"
	case 13: // CN
		return "audio"
	case 14: // MPA
		return "audio"
	case 15: // G728
		return "audio"
	case 16: // DVI4 11kHz
		return "audio"
	case 17: // DVI4 22kHz
		return "audio"
	case 18: // G729
		return "audio"
	case 25: // CelB
		return "video"
	case 26: // JPEG
		return "video"
	case 28: // nv
		return "video"
	case 31: // H261
		return "video"
	case 32: // MPV
		return "video"
	case 33: // MP2T
		return "video"
	case 34: // H263
		return "video"
	default:
		if payloadType >= 96 && payloadType <= 127 {
			return "dynamic" // Dynamic payload types
		}
		return "unknown"
	}
}

// Shutdown gracefully shuts down the plugin
func (r *RTPPlugin) Shutdown(ctx context.Context) error {
	r.enabled.Store(false)
	logger.Info("RTP plugin shutdown complete")
	return nil
}

// HealthCheck returns the current health status
func (r *RTPPlugin) HealthCheck() HealthStatus {
	status := HealthHealthy
	message := "RTP plugin operating normally"
	details := make(map[string]interface{})

	// Check if plugin is enabled
	if !r.enabled.Load() {
		status = HealthUnhealthy
		message = "RTP plugin is disabled"
	}

	// Check error rate
	processed := r.metrics.PacketsProcessed.Load()
	errors := r.metrics.ErrorCount.Load()
	if processed > 100 && errors > processed/10 { // Error rate > 10%
		status = HealthDegraded
		message = "High error rate detected"
	}

	details["packets_processed"] = processed
	details["errors"] = errors
	details["audio_packets"] = r.metrics.AudioPackets.Load()
	details["video_packets"] = r.metrics.VideoPackets.Load()
	details["sequence_errors"] = r.metrics.SequenceErrors.Load()

	return HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}
}

// Metrics returns current plugin metrics
func (r *RTPPlugin) Metrics() PluginMetrics {
	customMetrics := map[string]interface{}{
		"audio_packets":    r.metrics.AudioPackets.Load(),
		"video_packets":    r.metrics.VideoPackets.Load(),
		"sequence_errors":  r.metrics.SequenceErrors.Load(),
		"payload_types":    make(map[string]int64),
	}

	// Add payload type statistics
	payloadTypes := customMetrics["payload_types"].(map[string]int64)
	for pt, counter := range r.metrics.PayloadTypes {
		payloadTypes[string(rune(pt))] = counter.Load()
	}

	return PluginMetrics{
		PacketsProcessed: r.metrics.PacketsProcessed.Load(),
		ProcessingTime:   time.Duration(r.metrics.ProcessingTime.Load()),
		ErrorCount:       r.metrics.ErrorCount.Load(),
		CustomMetrics:    customMetrics,
	}
}

// RTPPluginFactory creates RTP plugin instances
type RTPPluginFactory struct{}

// CreatePlugin creates a new RTP plugin instance
func (f *RTPPluginFactory) CreatePlugin() ProtocolHandler {
	return NewRTPPlugin()
}

// PluginInfo returns information about the RTP plugin
func (f *RTPPluginFactory) PluginInfo() PluginInfo {
	return PluginInfo{
		Name:        "RTP Protocol Handler",
		Version:     "1.0.0",
		Author:      "lippycat",
		Description: "Handles RTP (Real-time Transport Protocol) packet analysis and media stream tracking",
		Protocols:   []string{"rtp", "rtcp"},
		Config: PluginConfig{
			Enabled:  true,
			Priority: 90,
			Timeout:  3 * time.Second,
		},
	}
}

// Common RTP errors
var (
	ErrInvalidRTPPacket = fmt.Errorf("invalid RTP packet format")
)