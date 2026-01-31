package processor

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SIP port constants
const (
	SIPPort    = 5060
	SIPPortTLS = 5061
)

// detectSIP checks if a UDP payload contains a SIP message and processes it.
func (p *Processor) detectSIP(packet gopacket.Packet, udp *layers.UDP, payload []byte) *ProcessResult {
	if len(payload) == 0 {
		return nil
	}

	// Check if payload looks like a SIP message
	if !isSIPMessage(payload) {
		return nil
	}

	// Parse SIP headers
	headers, body := parseSIPHeaders(payload)
	callID := headers["call-id"]
	if callID == "" {
		return nil
	}

	// Validate Call-ID for security
	if err := validateCallID(callID); err != nil {
		logger.Debug("Invalid Call-ID rejected",
			"error", err,
			"source", "voip_processor")
		return nil
	}

	// Check if this packet matches the application filter (if set)
	// If filter is set and packet doesn't match, don't track this call
	if p.appFilter != nil && !p.appFilter.MatchPacket(packet) {
		// Check if this call is already being tracked (subsequent SIP messages for matched calls)
		p.mu.RLock()
		_, exists := p.calls[callID]
		p.mu.RUnlock()
		if !exists {
			// New call that doesn't match filter - don't track it
			return nil
		}
		// Existing call - continue processing (allow BYE, ACK, etc.)
	}

	// Get or create call state
	_ = p.getOrCreateCall(callID)

	// Detect SIP method
	method := detectSIPMethod(payload)

	// Extract Content-Type header
	contentType := headers["content-type"]

	// Extract metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              headers["from"],
		To:                headers["to"],
		FromTag:           extractTagFromHeader(headers["from"]),
		ToTag:             extractTagFromHeader(headers["to"]),
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            method,
		ResponseCode:      extractSIPResponseCode(payload),
		SDPBody:           body,
		ContentType:       contentType,
	}

	// For MESSAGE method, extract body with size limit for LI compliance
	if method == "MESSAGE" && body != "" {
		metadata.Body = extractMessageBody(body)
	}

	// Extract 3GPP IMS headers (P-Access-Network-Info, P-Visited-Network-ID)
	if pani := headers["p-access-network-info"]; pani != "" {
		metadata.AccessType, metadata.BSSID, metadata.CellID, metadata.LocalIP, metadata.AccessParams = parseAccessNetworkInfo(pani)
	}
	if pvni := headers["p-visited-network-id"]; pvni != "" {
		metadata.VisitedNetworkID = parseVisitedNetworkID(pvni)
	}

	// Update call state
	p.updateCallState(callID, method, metadata)

	// Extract RTP ports from SDP if present
	if strings.Contains(body, "m=audio") {
		ports := extractRTPPortsFromSDP(body)
		for _, port := range ports {
			p.registerRTPPort(callID, port)
		}
	}

	// Build protobuf metadata
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          extractUserFromSIPURI(metadata.From),
			ToUser:            extractUserFromSIPURI(metadata.To),
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           extractFullSIPURI(metadata.From),
			ToUri:             extractFullSIPURI(metadata.To),
			Method:            metadata.Method,
			ResponseCode:      metadata.ResponseCode,
			PAssertedIdentity: metadata.PAssertedIdentity,
			VisitedNetworkId:  metadata.VisitedNetworkID,
		},
	}

	// Add AccessNetworkInfo if present
	if metadata.AccessType != "" {
		pbMetadata.Sip.AccessNetworkInfo = &data.AccessNetworkInfo{
			AccessType: metadata.AccessType,
			Bssid:      metadata.BSSID,
			CellId:     metadata.CellID,
			LocalIp:    metadata.LocalIP,
			Parameters: metadata.AccessParams,
		}
	}

	return &ProcessResult{
		IsVoIP:       true,
		PacketType:   PacketTypeSIP,
		CallID:       callID,
		Metadata:     pbMetadata,
		CallMetadata: metadata,
	}
}

// isSIPMessage checks if payload looks like a SIP message.
func isSIPMessage(payload []byte) bool {
	// SIP messages must have at least one line
	if len(payload) < 10 {
		return false
	}

	// Find first line
	nlIdx := bytes.IndexByte(payload, '\n')
	if nlIdx == -1 {
		nlIdx = len(payload)
	}
	if nlIdx > 0 && payload[nlIdx-1] == '\r' {
		nlIdx--
	}

	firstLine := payload[:nlIdx]

	// SIP responses start with SIP/2.0
	if bytes.HasPrefix(firstLine, []byte("SIP/2.0")) {
		return true
	}

	// SIP requests must contain "SIP/2.0" somewhere
	if !bytes.Contains(firstLine, []byte("SIP/2.0")) {
		return false
	}

	// Check for valid SIP methods at the beginning
	return bytes.HasPrefix(firstLine, []byte("INVITE ")) ||
		bytes.HasPrefix(firstLine, []byte("BYE ")) ||
		bytes.HasPrefix(firstLine, []byte("ACK ")) ||
		bytes.HasPrefix(firstLine, []byte("OPTIONS ")) ||
		bytes.HasPrefix(firstLine, []byte("REGISTER ")) ||
		bytes.HasPrefix(firstLine, []byte("CANCEL ")) ||
		bytes.HasPrefix(firstLine, []byte("PRACK ")) ||
		bytes.HasPrefix(firstLine, []byte("SUBSCRIBE ")) ||
		bytes.HasPrefix(firstLine, []byte("NOTIFY ")) ||
		bytes.HasPrefix(firstLine, []byte("PUBLISH ")) ||
		bytes.HasPrefix(firstLine, []byte("INFO ")) ||
		bytes.HasPrefix(firstLine, []byte("REFER ")) ||
		bytes.HasPrefix(firstLine, []byte("MESSAGE ")) ||
		bytes.HasPrefix(firstLine, []byte("UPDATE "))
}

// parseSIPHeaders parses SIP headers from payload.
func parseSIPHeaders(payload []byte) (map[string]string, string) {
	// Limit input size for security
	const maxSize = 65536
	if len(payload) > maxSize {
		payload = payload[:maxSize]
	}

	headers := make(map[string]string)
	lines := bytes.Split(payload, []byte("\n"))

	var bodyStart bool
	var bodyBuilder strings.Builder
	var isFirstLine = true
	var headerCount int
	const maxHeaders = 100

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			bodyStart = true
			continue
		}
		if !bodyStart {
			// Skip the first line (SIP request/response line)
			if isFirstLine {
				isFirstLine = false
				continue
			}

			if headerCount >= maxHeaders {
				break
			}

			key, val := parseHeaderLine(trimmed)
			if key != "" {
				headers[key] = val
				headerCount++
			}
		} else {
			bodyBuilder.Write(trimmed)
			bodyBuilder.WriteByte('\n')
		}
	}

	return headers, bodyBuilder.String()
}

// parseHeaderLine parses a single header line.
func parseHeaderLine(line []byte) (string, string) {
	idx := bytes.IndexByte(line, ':')
	if idx == -1 {
		return "", ""
	}

	keyBytes := bytes.TrimSpace(line[:idx])
	if len(keyBytes) == 0 {
		return "", ""
	}

	key := strings.ToLower(string(keyBytes))
	key = normalizeHeaderName(key)

	valBytes := bytes.TrimSpace(line[idx+1:])
	return key, string(valBytes)
}

// normalizeHeaderName converts SIP compact header names to full form.
func normalizeHeaderName(compact string) string {
	switch compact {
	case "i":
		return "call-id"
	case "f":
		return "from"
	case "t":
		return "to"
	case "v":
		return "via"
	case "c", "m":
		return "contact"
	case "l":
		return "content-length"
	case "x":
		return "expires"
	case "s":
		return "subject"
	case "k":
		return "supported"
	case "r":
		return "refer-to"
	case "b":
		return "referred-by"
	case "j":
		return "reject-contact"
	case "d":
		return "request-disposition"
	case "u":
		return "allow-events"
	case "o":
		return "event"
	case "a":
		return "accept-contact"
	case "n":
		return "in-reply-to"
	case "p":
		return "p-access-network-info"
	default:
		return compact
	}
}

// detectSIPMethod extracts the SIP method from the first line.
func detectSIPMethod(payload []byte) string {
	// Find first line
	nlIdx := bytes.IndexByte(payload, '\n')
	if nlIdx == -1 {
		nlIdx = len(payload)
	}
	firstLine := string(bytes.TrimSpace(payload[:nlIdx]))

	// SIP response
	if strings.HasPrefix(firstLine, "SIP/2.0") {
		return "RESPONSE"
	}

	// SIP request - extract method
	spaceIdx := strings.Index(firstLine, " ")
	if spaceIdx > 0 {
		return firstLine[:spaceIdx]
	}

	return ""
}

// extractSIPResponseCode extracts the response code from a SIP response.
func extractSIPResponseCode(payload []byte) uint32 {
	if len(payload) < 12 {
		return 0
	}

	if !bytes.HasPrefix(payload, []byte("SIP/2.0 ")) {
		return 0
	}

	codeStart := 8
	if len(payload) < codeStart+3 {
		return 0
	}

	code := uint32(0)
	for i := 0; i < 3; i++ {
		digit := payload[codeStart+i]
		if digit < '0' || digit > '9' {
			return 0
		}
		code = code*10 + uint32(digit-'0')
	}

	return code
}

// extractUserFromSIPURI extracts the username from a SIP URI.
func extractUserFromSIPURI(uri string) string {
	start := strings.Index(uri, "sip:")
	if start == -1 {
		start = strings.Index(uri, "sips:")
		if start == -1 {
			return ""
		}
		start += 5
	} else {
		start += 4
	}

	end := strings.Index(uri[start:], "@")
	if end == -1 {
		return ""
	}

	return uri[start : start+end]
}

// extractFullSIPURI extracts the full SIP URI from a header value.
func extractFullSIPURI(header string) string {
	start := strings.Index(header, "<")
	if start != -1 {
		end := strings.Index(header[start:], ">")
		if end != -1 {
			return header[start+1 : start+end]
		}
	}

	sipStart := strings.Index(header, "sip:")
	if sipStart == -1 {
		sipStart = strings.Index(header, "sips:")
		if sipStart == -1 {
			return ""
		}
	}

	uri := header[sipStart:]
	for i, ch := range uri {
		if ch == ' ' || ch == ';' || ch == '\r' || ch == '\n' || ch == '>' {
			return uri[:i]
		}
	}

	return uri
}

// extractTagFromHeader extracts the tag parameter from a SIP header.
func extractTagFromHeader(header string) string {
	tagStart := strings.Index(strings.ToLower(header), ";tag=")
	if tagStart == -1 {
		return ""
	}

	valueStart := tagStart + 5
	if valueStart >= len(header) {
		return ""
	}

	value := header[valueStart:]
	for i, ch := range value {
		if ch == ';' || ch == ' ' || ch == '\r' || ch == '\n' || ch == '>' {
			return value[:i]
		}
	}

	return value
}

// validateCallID validates a Call-ID for security.
func validateCallID(callID string) error {
	const maxCallIDLength = 1024
	if len(callID) > maxCallIDLength {
		return errCallIDTooLong
	}

	// Check for dangerous characters
	for _, ch := range callID {
		if ch == '\x00' || ch == '\n' || ch == '\r' {
			return errCallIDInvalidChars
		}
	}

	return nil
}

var (
	errCallIDTooLong      = &callIDError{"call-id too long"}
	errCallIDInvalidChars = &callIDError{"call-id contains invalid characters"}
)

// MaxMessageBodySize is the maximum size of MESSAGE body to extract (64KB).
// This prevents excessive memory usage while capturing SMS-over-IMS content.
const MaxMessageBodySize = 65536

// extractMessageBody extracts the body of a SIP MESSAGE with size limit.
func extractMessageBody(body string) string {
	if len(body) <= MaxMessageBodySize {
		return body
	}
	return body[:MaxMessageBodySize]
}

type callIDError struct {
	msg string
}

func (e *callIDError) Error() string {
	return e.msg
}

// parseAccessNetworkInfo parses the P-Access-Network-Info header (3GPP TS 24.229).
// Format: <access-type> [; <parameter>=<value>]*
// Examples:
//   - IEEE-802.11; i-wlan-node-id=00:11:22:33:44:55
//   - 3GPP-E-UTRAN; utran-cell-id-3gpp=23415001234567890
//   - 3GPP-E-UTRAN-FDD; cgi-3gpp=23415001234567890
//   - 3GPP-NR; ncgi=23415001234567890
//   - 3GPP-GERAN; cgi-3gpp=234150012345; local-time-zone=+0100
func parseAccessNetworkInfo(headerValue string) (accessType, bssid, cellID, localIP string, params map[string]string) {
	if headerValue == "" {
		return "", "", "", "", nil
	}

	// Split on semicolons to get access type and parameters
	parts := strings.Split(headerValue, ";")
	if len(parts) == 0 {
		return "", "", "", "", nil
	}

	accessType = strings.TrimSpace(parts[0])
	if accessType == "" {
		return "", "", "", "", nil
	}

	params = make(map[string]string)

	// Parse parameters
	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if param == "" {
			continue
		}

		// Split on first '=' only
		eqIdx := strings.Index(param, "=")
		if eqIdx == -1 {
			// Parameter without value (flag)
			params[strings.ToLower(param)] = ""
			continue
		}

		key := strings.TrimSpace(strings.ToLower(param[:eqIdx]))
		value := strings.TrimSpace(param[eqIdx+1:])

		// Remove quotes if present
		value = strings.Trim(value, "\"")

		params[key] = value

		// Extract specific fields based on parameter name
		switch key {
		case "i-wlan-node-id":
			// WiFi BSSID (MAC address)
			bssid = value
		case "cgi-3gpp", "utran-cell-id-3gpp", "ecgi", "ncgi":
			// Cell ID (various formats for different radio technologies)
			cellID = value
		case "local-ip":
			// UE local IP address
			localIP = value
		}
	}

	return accessType, bssid, cellID, localIP, params
}

// parseVisitedNetworkID parses the P-Visited-Network-ID header (3GPP TS 24.229).
// Format: <network-id> (may be quoted)
// Examples:
//   - "Visited Network Name"
//   - visited.network.example.com
func parseVisitedNetworkID(headerValue string) string {
	if headerValue == "" {
		return ""
	}

	// Remove leading/trailing whitespace
	value := strings.TrimSpace(headerValue)

	// Remove quotes if present
	value = strings.Trim(value, "\"")

	return value
}
