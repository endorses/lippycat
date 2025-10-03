package application

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// MySQLSignature detects MySQL protocol traffic
type MySQLSignature struct{}

// NewMySQLSignature creates a new MySQL signature detector
func NewMySQLSignature() *MySQLSignature {
	return &MySQLSignature{}
}

func (m *MySQLSignature) Name() string {
	return "MySQL Detector"
}

func (m *MySQLSignature) Protocols() []string {
	return []string{"MySQL"}
}

func (m *MySQLSignature) Priority() int {
	return 90 // High priority for database protocol
}

func (m *MySQLSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (m *MySQLSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// MySQL packet structure:
	// Payload length (3 bytes) + Sequence ID (1 byte) + Payload
	// Minimum packet is 4 bytes header + 1 byte payload

	// MySQL uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known MySQL port (3306)
	if ctx.SrcPort != 3306 && ctx.DstPort != 3306 {
		return nil
	}

	if len(ctx.Payload) < 5 {
		return nil
	}

	payload := ctx.Payload

	// Extract packet length (little-endian, 3 bytes)
	packetLen := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16

	// Sequence ID
	seqID := payload[3]

	// Validate packet length
	// MySQL packets have a maximum size of 16MB (0xFFFFFF)
	if packetLen == 0 || packetLen > 0xFFFFFF {
		return nil
	}

	// Be more conservative: if packet length is unreasonably large compared to what we have,
	// it's probably not MySQL
	if packetLen > 64*1024 && len(payload) < int(4+min(int(packetLen), 1024)) {
		// Large packet but we don't have enough data even for a reasonable chunk
		return nil
	}

	// Check if we have enough data
	if len(payload) < int(4+packetLen) {
		// Packet might be fragmented, but we can still try to detect it
		// if it's a handshake packet
	}

	// Detect server handshake (protocol version 10)
	// First byte after header should be 0x0a (protocol version 10)
	if len(payload) >= 5 && payload[4] == 0x0a {
		return m.detectHandshake(ctx, payload, seqID, packetLen)
	}

	// Detect client authentication packet
	// Starts with capability flags (4 bytes)
	if seqID == 1 && len(payload) >= 32 {
		return m.detectAuth(ctx, payload, seqID, packetLen)
	}

	// Detect command packet (seqID = 0, first byte is command)
	// But be careful not to match other protocols (especially TLS which starts with 0x16)
	if seqID == 0 && len(payload) >= 5 {
		command := payload[4]
		// Valid MySQL commands are 0x00-0x1f
		// But exclude commands that might be false positives from other protocols
		// 0x16 is TLS Handshake, so skip it
		if command <= 0x1f && command != 0x16 && command != 0x17 && command != 0x14 && command != 0x15 {
			return m.detectCommand(ctx, payload, command, packetLen)
		}
	}

	return nil
}

func (m *MySQLSignature) detectHandshake(ctx *signatures.DetectionContext, payload []byte, seqID byte, packetLen uint32) *signatures.DetectionResult {
	if len(payload) < 10 {
		return nil
	}

	protocolVersion := payload[4]

	// Extract server version string (null-terminated)
	versionStart := 5
	versionEnd := versionStart
	for versionEnd < len(payload) && payload[versionEnd] != 0x00 && versionEnd < versionStart+50 {
		versionEnd++
	}

	if versionEnd >= len(payload) {
		return nil
	}

	serverVersion := string(payload[versionStart:versionEnd])

	metadata := map[string]interface{}{
		"type":             "handshake",
		"protocol_version": protocolVersion,
		"server_version":   serverVersion,
		"sequence_id":      seqID,
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "valid_protocol_version", Weight: 0.5, Confidence: signatures.ConfidenceHigh},
		{Name: "server_version_string", Weight: 0.3, Confidence: signatures.ConfidenceHigh},
	}

	// TCP transport (MySQL is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{3306})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{3306})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "MySQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (m *MySQLSignature) detectAuth(ctx *signatures.DetectionContext, payload []byte, seqID byte, packetLen uint32) *signatures.DetectionResult {
	metadata := map[string]interface{}{
		"type":        "auth",
		"sequence_id": seqID,
	}

	// Extract capability flags (4 bytes, little-endian)
	if len(payload) >= 8 {
		capabilities := binary.LittleEndian.Uint32(payload[4:8])
		metadata["capabilities"] = capabilities
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "auth_packet", Weight: 0.7, Confidence: signatures.ConfidenceMedium},
	}

	// TCP transport
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{3306})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{3306})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "MySQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (m *MySQLSignature) detectCommand(ctx *signatures.DetectionContext, payload []byte, command byte, packetLen uint32) *signatures.DetectionResult {
	metadata := map[string]interface{}{
		"type":         "command",
		"command_code": command,
		"command_name": m.commandToString(command),
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "valid_command", Weight: 0.7, Confidence: signatures.ConfidenceMedium},
	}

	// TCP transport
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{3306})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{3306})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "MySQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (m *MySQLSignature) commandToString(command byte) string {
	commands := map[byte]string{
		0x00: "COM_SLEEP",
		0x01: "COM_QUIT",
		0x02: "COM_INIT_DB",
		0x03: "COM_QUERY",
		0x04: "COM_FIELD_LIST",
		0x05: "COM_CREATE_DB",
		0x06: "COM_DROP_DB",
		0x07: "COM_REFRESH",
		0x08: "COM_SHUTDOWN",
		0x09: "COM_STATISTICS",
		0x0a: "COM_PROCESS_INFO",
		0x0b: "COM_CONNECT",
		0x0c: "COM_PROCESS_KILL",
		0x0d: "COM_DEBUG",
		0x0e: "COM_PING",
		0x0f: "COM_TIME",
		0x10: "COM_DELAYED_INSERT",
		0x11: "COM_CHANGE_USER",
		0x12: "COM_BINLOG_DUMP",
		0x13: "COM_TABLE_DUMP",
		0x14: "COM_CONNECT_OUT",
		0x15: "COM_REGISTER_SLAVE",
		0x16: "COM_STMT_PREPARE",
		0x17: "COM_STMT_EXECUTE",
		0x18: "COM_STMT_SEND_LONG_DATA",
		0x19: "COM_STMT_CLOSE",
		0x1a: "COM_STMT_RESET",
		0x1b: "COM_SET_OPTION",
		0x1c: "COM_STMT_FETCH",
		0x1d: "COM_DAEMON",
		0x1e: "COM_BINLOG_DUMP_GTID",
		0x1f: "COM_RESET_CONNECTION",
	}

	if name, ok := commands[command]; ok {
		return name
	}
	return "Unknown"
}
