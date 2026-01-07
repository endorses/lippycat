//go:build cli || hunter || tap || all

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HTTP methods (RFC 7231 + common extensions)
var validMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"CONNECT": true,
	"OPTIONS": true,
	"TRACE":   true,
	"PATCH":   true,
}

// Common HTTP status reasons
var statusReasons = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	206: "Partial Content",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	429: "Too Many Requests",
	500: "Internal Server Error",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

// Regex patterns for parsing
var (
	// Request line: METHOD PATH HTTP/VERSION
	requestLineRegex = regexp.MustCompile(`^([A-Z]+)\s+([^\s]+)\s+HTTP/(\d\.\d)\s*$`)
	// Status line: HTTP/VERSION STATUS REASON
	statusLineRegex = regexp.MustCompile(`^HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$`)
	// Header line: Name: Value
	headerRegex = regexp.MustCompile(`^([A-Za-z0-9\-]+):\s*(.*)$`)
)

// Parser parses HTTP requests and responses.
type Parser struct{}

// NewParser creates a new HTTP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts HTTP metadata from a packet.
// Returns nil if the packet is not an HTTP request or response.
func (p *Parser) Parse(packet gopacket.Packet) *types.HTTPMetadata {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || len(tcp.Payload) < 10 {
		return nil
	}

	return p.ParsePayload(tcp.Payload)
}

// ParsePayload parses HTTP metadata from raw payload bytes.
func (p *Parser) ParsePayload(payload []byte) *types.HTTPMetadata {
	if len(payload) < 10 {
		return nil
	}

	// Find the first line (request line or status line)
	idx := bytes.IndexByte(payload, '\n')
	if idx == -1 || idx > 8192 {
		return nil
	}

	firstLine := strings.TrimRight(string(payload[:idx]), "\r")

	// Try to parse as request
	if metadata := p.parseRequestLine(firstLine); metadata != nil {
		p.parseHeaders(payload[idx+1:], metadata)
		return metadata
	}

	// Try to parse as response
	if metadata := p.parseStatusLine(firstLine); metadata != nil {
		p.parseHeaders(payload[idx+1:], metadata)
		return metadata
	}

	return nil
}

// parseRequestLine parses an HTTP request line.
func (p *Parser) parseRequestLine(line string) *types.HTTPMetadata {
	matches := requestLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	method := matches[1]
	if !validMethods[method] {
		return nil
	}

	path := matches[2]
	version := matches[3]

	// Extract query string if present
	queryString := ""
	if qIdx := strings.Index(path, "?"); qIdx != -1 {
		queryString = path[qIdx+1:]
		path = path[:qIdx]
	}

	return &types.HTTPMetadata{
		Type:        "request",
		IsServer:    false,
		Method:      method,
		Path:        path,
		Version:     "HTTP/" + version,
		QueryString: queryString,
		Headers:     make(map[string]string),
	}
}

// parseStatusLine parses an HTTP response status line.
func (p *Parser) parseStatusLine(line string) *types.HTTPMetadata {
	matches := statusLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	version := matches[1]
	statusCode, err := strconv.Atoi(matches[2])
	if err != nil || statusCode < 100 || statusCode > 599 {
		return nil
	}

	statusReason := matches[3]
	if statusReason == "" {
		if reason, ok := statusReasons[statusCode]; ok {
			statusReason = reason
		}
	}

	return &types.HTTPMetadata{
		Type:         "response",
		IsServer:     true,
		Version:      "HTTP/" + version,
		StatusCode:   statusCode,
		StatusReason: statusReason,
		Headers:      make(map[string]string),
	}
}

// parseHeaders parses HTTP headers from payload after the first line.
func (p *Parser) parseHeaders(payload []byte, metadata *types.HTTPMetadata) {
	reader := bufio.NewReader(bytes.NewReader(payload))

	for i := 0; i < 100; i++ { // Limit header count
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// End of headers
			break
		}

		matches := headerRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := strings.ToLower(matches[1])
		value := matches[2]

		// Store in headers map
		metadata.Headers[name] = value

		// Extract common headers
		switch name {
		case "host":
			metadata.Host = value
		case "server":
			metadata.Server = value
		case "content-type":
			metadata.ContentType = value
		case "content-length":
			if cl, err := strconv.ParseInt(value, 10, 64); err == nil {
				metadata.ContentLength = cl
			}
		case "user-agent":
			metadata.UserAgent = value
		case "authorization":
			metadata.HasAuth = true
		}
	}
}

// ParseLine parses a single HTTP line (request, response, or header).
// Returns true if the line was successfully parsed.
func (p *Parser) ParseLine(line string, metadata *types.HTTPMetadata, isFromServer bool) bool {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return false
	}

	// Try to parse as request line (client)
	if !isFromServer {
		if reqMeta := p.parseRequestLine(line); reqMeta != nil {
			*metadata = *reqMeta
			return true
		}
	}

	// Try to parse as status line (server)
	if isFromServer {
		if respMeta := p.parseStatusLine(line); respMeta != nil {
			*metadata = *respMeta
			return true
		}
	}

	// Try to parse as header
	matches := headerRegex.FindStringSubmatch(line)
	if matches != nil {
		name := strings.ToLower(matches[1])
		value := matches[2]

		if metadata.Headers == nil {
			metadata.Headers = make(map[string]string)
		}
		metadata.Headers[name] = value

		// Extract common headers
		switch name {
		case "host":
			metadata.Host = value
		case "server":
			metadata.Server = value
		case "content-type":
			metadata.ContentType = value
		case "content-length":
			if cl, err := strconv.ParseInt(value, 10, 64); err == nil {
				metadata.ContentLength = cl
			}
		case "user-agent":
			metadata.UserAgent = value
		case "authorization":
			metadata.HasAuth = true
		}
		return true
	}

	return false
}

// FormatInfo returns a formatted info string for display.
func (p *Parser) FormatInfo(metadata *types.HTTPMetadata) string {
	if metadata.Type == "request" {
		info := fmt.Sprintf("%s %s", metadata.Method, metadata.Path)
		if metadata.Host != "" {
			info = fmt.Sprintf("%s %s%s", metadata.Method, metadata.Host, metadata.Path)
		}
		return info
	}

	// Response
	return fmt.Sprintf("%d %s", metadata.StatusCode, metadata.StatusReason)
}

// HTTPMetadata is an alias for convenience in this package.
type HTTPMetadata = types.HTTPMetadata

// IsHTTPRequest returns true if the metadata represents a request.
func IsHTTPRequest(metadata *types.HTTPMetadata) bool {
	return metadata.Type == "request"
}

// IsHTTPResponse returns true if the metadata represents a response.
func IsHTTPResponse(metadata *types.HTTPMetadata) bool {
	return metadata.Type == "response"
}
