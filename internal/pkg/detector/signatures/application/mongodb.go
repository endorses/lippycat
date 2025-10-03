package application

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// MongoDBSignature detects MongoDB wire protocol traffic
type MongoDBSignature struct{}

// NewMongoDBSignature creates a new MongoDB signature detector
func NewMongoDBSignature() *MongoDBSignature {
	return &MongoDBSignature{}
}

func (m *MongoDBSignature) Name() string {
	return "MongoDB Detector"
}

func (m *MongoDBSignature) Protocols() []string {
	return []string{"MongoDB"}
}

func (m *MongoDBSignature) Priority() int {
	return 90 // High priority for database protocol
}

func (m *MongoDBSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (m *MongoDBSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// MongoDB Wire Protocol structure:
	// Header (16 bytes):
	//   - messageLength (4 bytes, int32, little-endian)
	//   - requestID (4 bytes, int32)
	//   - responseTo (4 bytes, int32)
	//   - opCode (4 bytes, int32)
	// Body: varies by opCode

	if len(ctx.Payload) < 16 {
		return nil
	}

	payload := ctx.Payload

	// Extract header fields (all little-endian)
	messageLength := int32(binary.LittleEndian.Uint32(payload[0:4]))
	requestID := int32(binary.LittleEndian.Uint32(payload[4:8]))
	responseTo := int32(binary.LittleEndian.Uint32(payload[8:12]))
	opCode := int32(binary.LittleEndian.Uint32(payload[12:16]))

	// Validate message length (16 bytes to 48MB)
	if messageLength < 16 || messageLength > 48*1024*1024 {
		return nil
	}

	// Validate opCode
	// Valid MongoDB opCodes:
	// 1    = OP_REPLY (deprecated)
	// 1000 = OP_MSG (modern)
	// 2001 = OP_UPDATE (deprecated)
	// 2002 = OP_INSERT (deprecated)
	// 2003 = Reserved
	// 2004 = OP_QUERY (deprecated)
	// 2005 = OP_GET_MORE (deprecated)
	// 2006 = OP_DELETE (deprecated)
	// 2007 = OP_KILL_CURSORS (deprecated)
	// 2010 = OP_COMMAND (deprecated)
	// 2011 = OP_COMMANDREPLY (deprecated)
	// 2013 = OP_MSG (3.6+)
	if !m.isValidOpCode(opCode) {
		return nil
	}

	metadata := map[string]interface{}{
		"message_length": messageLength,
		"request_id":     requestID,
		"response_to":    responseTo,
		"op_code":        opCode,
		"op_name":        m.opCodeToString(opCode),
	}

	// Determine if this is a request or response
	if responseTo == 0 {
		metadata["type"] = "request"
	} else {
		metadata["type"] = "response"
	}

	// Calculate confidence
	confidence := m.calculateConfidence(ctx, metadata, opCode)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{27017, 27018, 27019})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{27017, 27018, 27019})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "MongoDB",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (m *MongoDBSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, opCode int32) float64 {
	indicators := []signatures.Indicator{}

	// Valid opCode
	if m.isValidOpCode(opCode) {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_opcode",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Modern OP_MSG (opCode 2013) is most common in recent versions
	if opCode == 2013 || opCode == 1000 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "modern_opcode",
			Weight:     0.2,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// TCP transport (MongoDB is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (m *MongoDBSignature) isValidOpCode(opCode int32) bool {
	validCodes := map[int32]bool{
		1:    true, // OP_REPLY
		1000: true, // OP_MSG (old)
		2001: true, // OP_UPDATE
		2002: true, // OP_INSERT
		2004: true, // OP_QUERY
		2005: true, // OP_GET_MORE
		2006: true, // OP_DELETE
		2007: true, // OP_KILL_CURSORS
		2010: true, // OP_COMMAND
		2011: true, // OP_COMMANDREPLY
		2012: true, // OP_COMPRESSED
		2013: true, // OP_MSG (modern, 3.6+)
	}
	return validCodes[opCode]
}

func (m *MongoDBSignature) opCodeToString(opCode int32) string {
	codes := map[int32]string{
		1:    "OP_REPLY",
		1000: "OP_MSG (legacy)",
		2001: "OP_UPDATE",
		2002: "OP_INSERT",
		2004: "OP_QUERY",
		2005: "OP_GET_MORE",
		2006: "OP_DELETE",
		2007: "OP_KILL_CURSORS",
		2010: "OP_COMMAND",
		2011: "OP_COMMANDREPLY",
		2012: "OP_COMPRESSED",
		2013: "OP_MSG",
	}
	if name, ok := codes[opCode]; ok {
		return name
	}
	return "Unknown"
}
