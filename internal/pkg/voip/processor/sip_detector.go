package processor

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
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
	return p.detectSIPWithCompletion(packet, udp, payload, true)
}

func (p *Processor) detectSIPWithCompletion(packet gopacket.Packet, udp *layers.UDP, payload []byte, completeTerminal bool) *ProcessResult {
	if len(payload) == 0 {
		return nil
	}

	opts := sharedsip.ParseOptions{Timestamp: packet.Metadata().Timestamp}
	if net := packet.NetworkLayer(); net != nil {
		opts.SourceIP, opts.DestinationIP = net.NetworkFlow().Src().String(), net.NetworkFlow().Dst().String()
	}
	if udp != nil {
		opts.SourcePort, opts.DestinationPort = uint16(udp.SrcPort), uint16(udp.DstPort)
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		opts.SourcePort, opts.DestinationPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
	}
	event, err := sharedsip.Parse(payload, opts)
	if err != nil {
		return nil
	}
	headers, body := event.Headers, string(event.Body)
	callID := event.CallID
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

	// Check if this packet matches the application filter (if set).
	// The verdict is carried on the result so callers do not re-match the packet.
	var filterEvaluated, filterMatched bool
	var filterIDs []string
	if p.appFilter != nil {
		filterEvaluated = true
		if p.needFilterIDs {
			filterMatched, filterIDs = p.appFilter.MatchPacketWithIDs(packet)
		} else {
			filterMatched = p.appFilter.MatchPacket(packet)
		}
	}

	// If filter is set and packet doesn't match, don't track this call
	if filterEvaluated {
		p.mu.RLock()
		_, previouslySelected := p.calls[callID]
		p.mu.RUnlock()
		if !p.selectionPolicy.Select(callregistry.SelectionInput{
			FilterConfigured:   true,
			DirectMatch:        filterMatched,
			PreviouslySelected: previouslySelected,
		}) {
			// New call that doesn't match filter - don't track it, but report the
			// verdict so the caller can drop the packet without matching again.
			return &ProcessResult{
				PacketType:      PacketTypeSIP,
				CallID:          callID,
				CallIDs:         []string{callID},
				FilterEvaluated: true,
			}
		}
	}

	// Get or create call state
	_ = p.getOrCreateCall(callID)

	// Detect SIP method
	method := event.Method

	// Extract Content-Type header
	contentType := headers["content-type"]

	// Extract metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              headers["from"],
		To:                headers["to"],
		FromTag:           event.FromTag,
		ToTag:             event.ToTag,
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            method,
		CSeqMethod:        event.CSeqMethod,
		ResponseCode:      uint32(event.ResponseCode),
		SDPBody:           string(event.SDP),
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
	if strings.Contains(string(event.SDP), "m=audio") {
		ports := extractRTPPortsFromSDP(string(event.SDP))
		for _, port := range ports {
			p.registerRTPPort(callID, port)
		}
	}

	// A final response to dialog termination is the ownership boundary for RTP
	// associations. Do this independently of per-call PCAP monitoring: tap mode
	// may legitimately run without PCAP output enabled.
	if completeTerminal && isTerminalDialogResponse(metadata) {
		p.CompleteCall(callID)
	}

	// Build protobuf metadata
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          event.FromUser,
			ToUser:            event.ToUser,
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           event.FromURI,
			ToUri:             event.ToURI,
			Method:            metadata.Method,
			CseqMethod:        metadata.CSeqMethod,
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
		IsVoIP:          true,
		PacketType:      PacketTypeSIP,
		CallID:          callID,
		CallIDs:         []string{callID},
		Metadata:        pbMetadata,
		CallMetadata:    metadata,
		FilterEvaluated: filterEvaluated,
		FilterMatched:   filterMatched,
		FilterIDs:       filterIDs,
	}
}

func isTerminalDialogResponse(metadata *CallMetadata) bool {
	if metadata == nil || metadata.ResponseCode < 200 {
		return false
	}
	return metadata.CSeqMethod == "BYE" || metadata.CSeqMethod == "CANCEL"
}

// isSIPMessage checks if payload looks like a SIP message.
func isSIPMessage(payload []byte) bool {
	nlIdx := bytes.IndexByte(payload, '\n')
	if nlIdx == -1 {
		nlIdx = len(payload)
	}
	if nlIdx > 0 && payload[nlIdx-1] == '\r' {
		nlIdx--
	}

	return sharedsip.IsStartLine(string(payload[:nlIdx]))
}

// parseSIPHeaders parses SIP headers from payload.
func parseSIPHeaders(payload []byte) (map[string]string, string) {
	if event, err := sharedsip.Parse(payload, sharedsip.ParseOptions{}); err == nil {
		return event.Headers, string(event.Body)
	}
	return map[string]string{}, ""
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
	if full, ok := sharedsip.CompactHeaders[compact]; ok {
		return full
	}
	return compact
}

// detectSIPMethod extracts the SIP method from the first line.
func detectSIPMethod(payload []byte) string {
	if event, err := sharedsip.Parse(payload, sharedsip.ParseOptions{}); err == nil {
		return event.Method
	}
	return ""
}

// extractCSeqMethod returns the method token from a CSeq header value.
// SIP CSeq is "<sequence-number> <method>" (RFC 3261 §8.1.1.5), e.g.
// "1 INVITE" -> "INVITE". Returns "" when the value is empty or malformed.
// The method recovers the originating transaction method of a SIP response,
// which the status line does not carry — letting a call first observed via
// a response still be classified.
func extractCSeqMethod(cseq string) string {
	return sharedsip.CSeqMethod(cseq)
}

// extractSIPResponseCode extracts the response code from a SIP response.
func extractSIPResponseCode(payload []byte) uint32 {
	if event, err := sharedsip.Parse(payload, sharedsip.ParseOptions{}); err == nil {
		return uint32(event.ResponseCode)
	}
	return 0
}

// extractUserFromSIPURI extracts the username from a SIP URI.
func extractUserFromSIPURI(uri string) string {
	return sharedsip.User(sharedsip.URI(uri))
}

// extractFullSIPURI extracts the full SIP URI from a header value.
func extractFullSIPURI(header string) string {
	return sharedsip.URI(header)
}

// extractTagFromHeader extracts the tag parameter from a SIP header.
func extractTagFromHeader(header string) string {
	return sharedsip.Tag(header)
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
