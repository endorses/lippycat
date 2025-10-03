package application

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// PostgreSQLSignature detects PostgreSQL protocol traffic
type PostgreSQLSignature struct{}

// NewPostgreSQLSignature creates a new PostgreSQL signature detector
func NewPostgreSQLSignature() *PostgreSQLSignature {
	return &PostgreSQLSignature{}
}

func (p *PostgreSQLSignature) Name() string {
	return "PostgreSQL Detector"
}

func (p *PostgreSQLSignature) Protocols() []string {
	return []string{"PostgreSQL"}
}

func (p *PostgreSQLSignature) Priority() int {
	return 90 // High priority for database protocol
}

func (p *PostgreSQLSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (p *PostgreSQLSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// PostgreSQL message structure:
	// For startup: Length (4 bytes) + Protocol version (4 bytes) + parameters
	// For regular: Type (1 byte) + Length (4 bytes) + payload

	// PostgreSQL uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known PostgreSQL port (5432)
	// Message type detection is too permissive (any uppercase letter)
	if ctx.SrcPort != 5432 && ctx.DstPort != 5432 {
		return nil
	}

	if len(ctx.Payload) < 8 {
		return nil
	}

	payload := ctx.Payload

	// Check for startup message (no type byte, starts with length)
	// PostgreSQL protocol version 3.0 is represented as 0x00030000 (196608)
	if len(payload) >= 8 {
		length := binary.BigEndian.Uint32(payload[0:4])
		protocolVersion := binary.BigEndian.Uint32(payload[4:8])

		// Check for valid startup message
		// Protocol version 3.0 (0x00030000) or SSL request (0x04d2162f = 80877103)
		if protocolVersion == 0x00030000 || protocolVersion == 80877103 {
			return p.detectStartup(ctx, payload, length, protocolVersion)
		}

		// Check for cancel request (protocol version 0x04d2162e = 80877102)
		if protocolVersion == 80877102 {
			return p.detectCancelRequest(ctx, payload, length)
		}
	}

	// Check for regular message (has type byte)
	if len(payload) >= 5 {
		msgType := payload[0]
		length := binary.BigEndian.Uint32(payload[1:5])

		// Validate message type (uppercase letter or specific characters)
		if p.isValidMessageType(msgType) {
			return p.detectMessage(ctx, payload, msgType, length)
		}
	}

	return nil
}

func (p *PostgreSQLSignature) detectStartup(ctx *signatures.DetectionContext, payload []byte, length uint32, protocolVersion uint32) *signatures.DetectionResult {
	// Validate length is reasonable (8 bytes to 10KB)
	if length < 8 || length > 10240 {
		return nil
	}

	metadata := map[string]interface{}{
		"type":             "startup",
		"protocol_version": protocolVersion,
	}

	if protocolVersion == 80877103 {
		metadata["ssl_request"] = true
		metadata["message"] = "SSL Request"
	} else if protocolVersion == 0x00030000 {
		metadata["message"] = "Startup Message (v3.0)"
		// Try to extract username/database from parameters
		if len(payload) > 8 {
			params := p.extractParameters(payload[8:])
			if len(params) > 0 {
				metadata["parameters"] = params
			}
		}
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "valid_protocol_version", Weight: 0.6, Confidence: signatures.ConfidenceVeryHigh},
	}

	// TCP transport (PostgreSQL is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.4,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{5432})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{5432})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "PostgreSQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *PostgreSQLSignature) detectCancelRequest(ctx *signatures.DetectionContext, payload []byte, length uint32) *signatures.DetectionResult {
	metadata := map[string]interface{}{
		"type":    "cancel_request",
		"message": "Cancel Request",
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "cancel_request", Weight: 0.7, Confidence: signatures.ConfidenceHigh},
	}

	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{5432})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{5432})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "PostgreSQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *PostgreSQLSignature) detectMessage(ctx *signatures.DetectionContext, payload []byte, msgType byte, length uint32) *signatures.DetectionResult {
	// Validate length is reasonable (5 bytes to 1MB)
	if length < 4 || length > 1048576 {
		return nil
	}

	metadata := map[string]interface{}{
		"type":         "message",
		"message_type": string(msgType),
		"message_name": p.messageTypeToString(msgType),
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "valid_message_type", Weight: 0.7, Confidence: signatures.ConfidenceMedium},
	}

	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{5432})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{5432})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "PostgreSQL",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *PostgreSQLSignature) isValidMessageType(msgType byte) bool {
	// Valid PostgreSQL message types are uppercase letters and a few special chars
	validTypes := map[byte]bool{
		'R': true, // Authentication
		'S': true, // ParameterStatus / Sync
		'K': true, // BackendKeyData
		'Z': true, // ReadyForQuery
		'T': true, // RowDescription
		'D': true, // DataRow
		'C': true, // CommandComplete
		'E': true, // ErrorResponse / Execute
		'N': true, // NoticeResponse
		'I': true, // EmptyQueryResponse
		'1': true, // ParseComplete
		'2': true, // BindComplete
		'3': true, // CloseComplete
		's': true, // PortalSuspended
		'n': true, // NoData
		't': true, // ParameterDescription
		'Q': true, // Query
		'P': true, // Parse
		'B': true, // Bind
		'F': true, // FunctionCall
		'H': true, // Flush / CopyOutResponse
		'X': true, // Terminate
		'd': true, // CopyData
		'c': true, // CopyDone
		'f': true, // CopyFail
		'G': true, // CopyInResponse
		'W': true, // CopyBothResponse
		'A': true, // NotificationResponse
		'V': true, // FunctionCallResponse
	}
	return validTypes[msgType]
}

func (p *PostgreSQLSignature) messageTypeToString(msgType byte) string {
	types := map[byte]string{
		'R': "Authentication",
		'S': "ParameterStatus",
		'K': "BackendKeyData",
		'Z': "ReadyForQuery",
		'T': "RowDescription",
		'D': "DataRow",
		'C': "CommandComplete",
		'E': "ErrorResponse",
		'N': "NoticeResponse",
		'I': "EmptyQueryResponse",
		'Q': "Query",
		'P': "Parse",
		'B': "Bind",
		'X': "Terminate",
		'A': "NotificationResponse",
	}

	if name, ok := types[msgType]; ok {
		return name
	}
	return "Unknown"
}

func (p *PostgreSQLSignature) extractParameters(paramData []byte) map[string]string {
	params := make(map[string]string)

	// Parameters are null-terminated key-value pairs
	// Format: key\0value\0key\0value\0\0
	i := 0
	for i < len(paramData)-1 {
		// Find key
		keyStart := i
		for i < len(paramData) && paramData[i] != 0 {
			i++
		}
		if i >= len(paramData) {
			break
		}
		key := string(paramData[keyStart:i])
		i++ // Skip null terminator

		if key == "" {
			break // End of parameters
		}

		// Find value
		valueStart := i
		for i < len(paramData) && paramData[i] != 0 {
			i++
		}
		if i >= len(paramData) {
			break
		}
		value := string(paramData[valueStart:i])
		i++ // Skip null terminator

		params[key] = value
	}

	return params
}
