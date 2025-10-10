package application

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// DNSSignature detects DNS (Domain Name System) traffic
type DNSSignature struct{}

// NewDNSSignature creates a new DNS signature detector
func NewDNSSignature() *DNSSignature {
	return &DNSSignature{}
}

func (d *DNSSignature) Name() string {
	return "DNS Detector"
}

func (d *DNSSignature) Protocols() []string {
	return []string{"DNS"}
}

func (d *DNSSignature) Priority() int {
	return 120 // Medium-high priority
}

func (d *DNSSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (d *DNSSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// DNS requires minimum 12 bytes for header
	if len(ctx.Payload) < 12 {
		return nil
	}

	payload := ctx.Payload

	// DNS header structure:
	// ID(2) + Flags(2) + Questions(2) + Answers(2) + Authority(2) + Additional(2)

	// Extract flags
	flags := uint16(payload[2])<<8 | uint16(payload[3])

	// Extract counts
	questionCount := uint16(payload[4])<<8 | uint16(payload[5])
	answerCount := uint16(payload[6])<<8 | uint16(payload[7])
	authorityCount := uint16(payload[8])<<8 | uint16(payload[9])
	additionalCount := uint16(payload[10])<<8 | uint16(payload[11])

	// Extract flag components
	qr := (flags >> 15) & 0x01     // Query/Response bit
	opcode := (flags >> 11) & 0x0F // Opcode (4 bits)
	aa := (flags >> 10) & 0x01     // Authoritative Answer
	tc := (flags >> 9) & 0x01      // Truncation
	rd := (flags >> 8) & 0x01      // Recursion Desired
	ra := (flags >> 7) & 0x01      // Recursion Available
	z := (flags >> 4) & 0x07       // Reserved (must be 0)
	rcode := flags & 0x0F          // Response code

	// Validation checks

	// 1. Reserved bits (Z) should be 0
	if z != 0 {
		return nil
	}

	// 2. Opcode must be valid (0-6)
	if opcode > 6 {
		return nil
	}

	// 3. Response code must be valid (0-15, but typically 0-10)
	if rcode > 15 {
		return nil
	}

	// 4. Question count validation
	if questionCount == 0 && qr == 0 {
		// Query must have at least one question
		return nil
	}
	if questionCount > 100 {
		// Unreasonably high question count
		return nil
	}

	// 5. Answer count validation for responses
	if qr == 1 && answerCount > 100 {
		// Unreasonably high answer count
		return nil
	}

	// 6. Check total record count is reasonable
	totalRecords := uint32(questionCount) + uint32(answerCount) +
		uint32(authorityCount) + uint32(additionalCount)
	if totalRecords > 200 {
		return nil
	}

	// 7. For queries, typically no answers/authority records
	if qr == 0 && (answerCount > 0 || authorityCount > 0) {
		return nil
	}

	// Extract metadata
	metadata := map[string]interface{}{
		"transaction_id":      uint16(payload[0])<<8 | uint16(payload[1]),
		"is_response":         qr == 1,
		"opcode":              d.opcodeToString(opcode),
		"authoritative":       aa == 1,
		"truncated":           tc == 1,
		"recursion_desired":   rd == 1,
		"recursion_available": ra == 1,
		"rcode":               d.rcodeToString(rcode),
		"questions":           questionCount,
		"answers":             answerCount,
		"authority":           authorityCount,
		"additional":          additionalCount,
	}

	// Store query or correlate response
	transactionID := uint16(payload[0])<<8 | uint16(payload[1])
	if ctx.Flow != nil {
		if qr == 0 {
			// This is a query - store it
			queryKey := fmt.Sprintf("dns_query_%d", transactionID)
			ctx.Flow.Metadata[queryKey] = DNSQuery{
				TransactionID: transactionID,
				QuestionCount: questionCount,
				Timestamp:     ctx.Packet.Metadata().Timestamp,
			}
		} else {
			// This is a response - try to correlate with query
			queryKey := fmt.Sprintf("dns_query_%d", transactionID)
			if queryData, ok := ctx.Flow.Metadata[queryKey]; ok {
				if query, ok := queryData.(DNSQuery); ok {
					responseTime := ctx.Packet.Metadata().Timestamp.Sub(query.Timestamp)
					metadata["query_response_time_ms"] = responseTime.Milliseconds()
					metadata["correlated_query"] = true
					// Clean up the query
					delete(ctx.Flow.Metadata, queryKey)
				}
			}
		}
	}

	// Calculate confidence
	confidence := d.calculateConfidence(ctx, metadata, flags)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{53})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{53})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "DNS",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

// calculateConfidence determines confidence level for DNS detection
func (d *DNSSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, flags uint16) float64 {
	indicators := []signatures.Indicator{}

	// Valid header structure (passed all validation checks)
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_header",
		Weight:     0.5,
		Confidence: signatures.ConfidenceHigh,
	})

	// Reasonable question count
	if qCount, ok := metadata["questions"].(uint16); ok && qCount > 0 && qCount < 10 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "reasonable_questions",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// Standard opcode (QUERY = 0)
	if opcode, ok := metadata["opcode"].(string); ok && opcode == "QUERY" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "standard_query",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// UDP transport (DNS is typically UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.1,
			Confidence: signatures.ConfidenceLow,
		})
	}

	return signatures.ScoreDetection(indicators)
}

// opcodeToString converts DNS opcode to string
func (d *DNSSignature) opcodeToString(opcode uint16) string {
	opcodes := map[uint16]string{
		0: "QUERY",
		1: "IQUERY",
		2: "STATUS",
		3: "Reserved",
		4: "NOTIFY",
		5: "UPDATE",
		6: "DSO",
	}
	if s, ok := opcodes[opcode]; ok {
		return s
	}
	return "Unknown"
}

// rcodeToString converts DNS response code to string
func (d *DNSSignature) rcodeToString(rcode uint16) string {
	rcodes := map[uint16]string{
		0:  "NOERROR",
		1:  "FORMERR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		4:  "NOTIMP",
		5:  "REFUSED",
		6:  "YXDOMAIN",
		7:  "YXRRSET",
		8:  "NXRRSET",
		9:  "NOTAUTH",
		10: "NOTZONE",
	}
	if s, ok := rcodes[rcode]; ok {
		return s
	}
	return "Unknown"
}

// DNSQuery stores information about a DNS query for response correlation
type DNSQuery struct {
	TransactionID uint16
	QuestionCount uint16
	Timestamp     time.Time
}
