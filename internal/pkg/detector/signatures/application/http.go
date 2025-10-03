package application

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// HTTPSignature detects HTTP protocol
type HTTPSignature struct {
	methods       []string
	statusPrefixes []string
}

// NewHTTPSignature creates a new HTTP signature detector
func NewHTTPSignature() *HTTPSignature {
	return &HTTPSignature{
		methods: []string{
			"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
			"PATCH ", "TRACE ", "CONNECT ",
		},
		statusPrefixes: []string{
			"HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2.0 ", "HTTP/2 ",
		},
	}
}

func (h *HTTPSignature) Name() string {
	return "HTTP Detector"
}

func (h *HTTPSignature) Protocols() []string {
	return []string{"HTTP"}
}

func (h *HTTPSignature) Priority() int {
	return 80 // High priority for common protocol
}

func (h *HTTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (h *HTTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 16 {
		return nil
	}

	// Check for HTTP request methods
	for _, method := range h.methods {
		if bytes.HasPrefix(ctx.Payload, []byte(method)) {
			return h.detectRequest(ctx)
		}
	}

	// Check for HTTP response
	for _, statusPrefix := range h.statusPrefixes {
		if bytes.HasPrefix(ctx.Payload, []byte(statusPrefix)) {
			return h.detectResponse(ctx)
		}
	}

	return nil
}

func (h *HTTPSignature) detectRequest(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	payloadStr := string(ctx.Payload[:min(500, len(ctx.Payload))])
	lines := strings.Split(payloadStr, "\r\n")

	if len(lines) == 0 {
		return nil
	}

	// Parse request line: METHOD /path HTTP/version
	requestLine := lines[0]
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 3 {
		return nil
	}

	method := parts[0]
	path := parts[1]
	version := parts[2]

	// Validate HTTP version
	if !strings.HasPrefix(version, "HTTP/") {
		return nil
	}

	metadata := map[string]interface{}{
		"type":    "request",
		"method":  method,
		"path":    path,
		"version": version,
	}

	// Extract common headers
	headers := h.extractHeaders(lines[1:])
	if host, ok := headers["Host"]; ok {
		metadata["host"] = host
	}
	if userAgent, ok := headers["User-Agent"]; ok {
		metadata["user_agent"] = userAgent
	}
	if contentType, ok := headers["Content-Type"]; ok {
		metadata["content_type"] = contentType
	}

	// Calculate confidence based on indicators
	indicators := []signatures.Indicator{
		{Name: "method", Weight: 0.4, Confidence: 1.0},
		{Name: "version", Weight: 0.3, Confidence: 1.0},
	}

	if _, hasHost := headers["Host"]; hasHost {
		indicators = append(indicators, signatures.Indicator{
			Name: "host_header", Weight: 0.3, Confidence: 1.0,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{80, 8080, 8000, 3000})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{80, 8080, 8000, 3000})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "HTTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (h *HTTPSignature) detectResponse(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	payloadStr := string(ctx.Payload[:min(500, len(ctx.Payload))])
	lines := strings.Split(payloadStr, "\r\n")

	if len(lines) == 0 {
		return nil
	}

	// Parse status line: HTTP/version status_code reason
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}

	version := parts[0]
	statusCode := parts[1]
	reason := ""
	if len(parts) >= 3 {
		reason = parts[2]
	}

	metadata := map[string]interface{}{
		"type":        "response",
		"version":     version,
		"status_code": statusCode,
	}

	if reason != "" {
		metadata["reason"] = reason
	}

	// Extract common headers
	headers := h.extractHeaders(lines[1:])
	if server, ok := headers["Server"]; ok {
		metadata["server"] = server
	}
	if contentType, ok := headers["Content-Type"]; ok {
		metadata["content_type"] = contentType
	}
	if contentLength, ok := headers["Content-Length"]; ok {
		metadata["content_length"] = contentLength
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "version", Weight: 0.5, Confidence: 1.0},
		{Name: "status_code", Weight: 0.5, Confidence: 1.0},
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{80, 8080, 8000, 3000})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{80, 8080, 8000, 3000})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "HTTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (h *HTTPSignature) extractHeaders(lines []string) map[string]string {
	headers := make(map[string]string)

	for _, line := range lines {
		if line == "" {
			break // End of headers
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}

	return headers
}
