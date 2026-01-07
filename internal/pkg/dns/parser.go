package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Parser extracts DNS metadata from packets.
type Parser struct{}

// NewParser creates a new DNS parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts DNS metadata from a packet.
// Returns nil if the packet is not a DNS packet or parsing fails.
func (p *Parser) Parse(packet gopacket.Packet) *types.DNSMetadata {
	// Try to get DNS layer from gopacket
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil
	}

	metadata := &types.DNSMetadata{
		TransactionID:      dns.ID,
		IsResponse:         dns.QR,
		Opcode:             opcodeToString(dns.OpCode),
		ResponseCode:       rcodeToString(dns.ResponseCode),
		Authoritative:      dns.AA,
		Truncated:          dns.TC,
		RecursionDesired:   dns.RD,
		RecursionAvailable: dns.RA,
		QuestionCount:      dns.QDCount,
		AnswerCount:        dns.ANCount,
		AuthorityCount:     dns.NSCount,
		AdditionalCount:    dns.ARCount,
	}

	// Parse first question (most DNS queries have exactly one)
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		metadata.QueryName = string(q.Name)
		metadata.QueryType = dnsTypeToString(q.Type)
		metadata.QueryClass = dnsClassToString(q.Class)
	}

	// Parse answers
	if len(dns.Answers) > 0 {
		metadata.Answers = make([]types.DNSAnswer, 0, len(dns.Answers))
		for _, a := range dns.Answers {
			answer := types.DNSAnswer{
				Name:  string(a.Name),
				Type:  dnsTypeToString(a.Type),
				Class: dnsClassToString(a.Class),
				TTL:   a.TTL,
				Data:  formatAnswerData(a),
			}
			metadata.Answers = append(metadata.Answers, answer)
		}
	}

	return metadata
}

// ParseRaw parses DNS from raw payload bytes (without gopacket).
// This is useful for processing already-extracted payloads.
func (p *Parser) ParseRaw(payload []byte) *types.DNSMetadata {
	if len(payload) < 12 {
		return nil
	}

	// Parse DNS header
	txnID := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	nsCount := binary.BigEndian.Uint16(payload[8:10])
	arCount := binary.BigEndian.Uint16(payload[10:12])

	// Extract flag components
	qr := (flags >> 15) & 0x01
	opcode := layers.DNSOpCode((flags >> 11) & 0x0F)
	aa := (flags >> 10) & 0x01
	tc := (flags >> 9) & 0x01
	rd := (flags >> 8) & 0x01
	ra := (flags >> 7) & 0x01
	rcode := layers.DNSResponseCode(flags & 0x0F)

	metadata := &types.DNSMetadata{
		TransactionID:      txnID,
		IsResponse:         qr == 1,
		Opcode:             opcodeToString(opcode),
		ResponseCode:       rcodeToString(rcode),
		Authoritative:      aa == 1,
		Truncated:          tc == 1,
		RecursionDesired:   rd == 1,
		RecursionAvailable: ra == 1,
		QuestionCount:      qdCount,
		AnswerCount:        anCount,
		AuthorityCount:     nsCount,
		AdditionalCount:    arCount,
	}

	// Parse question section
	offset := 12
	if qdCount > 0 && offset < len(payload) {
		name, newOffset := parseDomainName(payload, offset)
		if newOffset > 0 && newOffset+4 <= len(payload) {
			metadata.QueryName = name
			qType := binary.BigEndian.Uint16(payload[newOffset : newOffset+2])
			qClass := binary.BigEndian.Uint16(payload[newOffset+2 : newOffset+4])
			metadata.QueryType = dnsTypeToString(layers.DNSType(qType))
			metadata.QueryClass = dnsClassToString(layers.DNSClass(qClass))
			offset = newOffset + 4
		}
	}

	// Parse answer section
	if anCount > 0 && offset < len(payload) {
		metadata.Answers = make([]types.DNSAnswer, 0, int(anCount))
		for i := uint16(0); i < anCount && offset < len(payload); i++ {
			answer, newOffset := parseResourceRecord(payload, offset)
			if newOffset <= offset {
				break
			}
			metadata.Answers = append(metadata.Answers, answer)
			offset = newOffset
		}
	}

	return metadata
}

// parseDomainName parses a DNS domain name from the payload.
// Returns the name and the new offset, or empty string and -1 on error.
func parseDomainName(payload []byte, offset int) (string, int) {
	var parts []string
	maxJumps := 10 // Prevent infinite loops from malformed packets
	jumps := 0
	originalOffset := offset
	jumped := false

	for offset < len(payload) {
		length := int(payload[offset])

		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		// Handle compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(payload) {
				return "", -1
			}
			pointer := int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			jumps++
			if jumps > maxJumps {
				return "", -1
			}
			continue
		}

		offset++
		if offset+length > len(payload) {
			return "", -1
		}
		parts = append(parts, string(payload[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, "."), originalOffset
}

// parseResourceRecord parses a DNS resource record from the payload.
func parseResourceRecord(payload []byte, offset int) (types.DNSAnswer, int) {
	answer := types.DNSAnswer{}

	name, newOffset := parseDomainName(payload, offset)
	if newOffset < 0 || newOffset+10 > len(payload) {
		return answer, offset
	}
	answer.Name = name
	offset = newOffset

	rrType := binary.BigEndian.Uint16(payload[offset : offset+2])
	rrClass := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(payload[offset+4 : offset+8])
	rdLength := binary.BigEndian.Uint16(payload[offset+8 : offset+10])

	answer.Type = dnsTypeToString(layers.DNSType(rrType))
	answer.Class = dnsClassToString(layers.DNSClass(rrClass))
	answer.TTL = ttl

	offset += 10
	if offset+int(rdLength) > len(payload) {
		return answer, offset
	}

	// Parse RDATA based on type
	rdata := payload[offset : offset+int(rdLength)]
	answer.Data = formatRData(layers.DNSType(rrType), rdata, payload)

	return answer, offset + int(rdLength)
}

// formatRData formats resource record data based on type.
func formatRData(rrType layers.DNSType, rdata []byte, fullPayload []byte) string {
	switch rrType {
	case layers.DNSTypeA:
		if len(rdata) == 4 {
			return net.IP(rdata).String()
		}
	case layers.DNSTypeAAAA:
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		// These contain a domain name
		name, _ := parseDomainName(fullPayload, len(fullPayload)-len(rdata))
		if name != "" {
			return name
		}
		return string(rdata)
	case layers.DNSTypeMX:
		if len(rdata) > 2 {
			priority := binary.BigEndian.Uint16(rdata[0:2])
			name, _ := parseDomainName(fullPayload, len(fullPayload)-len(rdata)+2)
			return fmt.Sprintf("%d %s", priority, name)
		}
	case layers.DNSTypeTXT:
		return string(rdata)
	case layers.DNSTypeSOA:
		// SOA has complex format, just show length
		return fmt.Sprintf("<SOA %d bytes>", len(rdata))
	}
	return fmt.Sprintf("<data %d bytes>", len(rdata))
}

// formatAnswerData formats the answer data from a gopacket DNS resource record.
func formatAnswerData(a layers.DNSResourceRecord) string {
	switch a.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return a.IP.String()
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		return string(a.CNAME)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", a.MX.Preference, string(a.MX.Name))
	case layers.DNSTypeTXT:
		var parts []string
		for _, txt := range a.TXTs {
			parts = append(parts, string(txt))
		}
		return strings.Join(parts, " ")
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s %s", string(a.SOA.MName), string(a.SOA.RName))
	default:
		return fmt.Sprintf("<data %d bytes>", len(a.Data))
	}
}

// opcodeToString converts DNS opcode to string.
func opcodeToString(opcode layers.DNSOpCode) string {
	switch opcode {
	case layers.DNSOpCodeQuery:
		return "QUERY"
	case layers.DNSOpCodeIQuery:
		return "IQUERY"
	case layers.DNSOpCodeStatus:
		return "STATUS"
	case layers.DNSOpCodeNotify:
		return "NOTIFY"
	case layers.DNSOpCodeUpdate:
		return "UPDATE"
	default:
		return fmt.Sprintf("OPCODE%d", opcode)
	}
}

// rcodeToString converts DNS response code to string.
func rcodeToString(rcode layers.DNSResponseCode) string {
	switch rcode {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	case layers.DNSResponseCodeYXDomain:
		return "YXDOMAIN"
	case layers.DNSResponseCodeYXRRSet:
		return "YXRRSET"
	case layers.DNSResponseCodeNXRRSet:
		return "NXRRSET"
	case layers.DNSResponseCodeNotAuth:
		return "NOTAUTH"
	case layers.DNSResponseCodeNotZone:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

// dnsTypeToString converts DNS record type to string.
func dnsTypeToString(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// dnsClassToString converts DNS class to string.
func dnsClassToString(c layers.DNSClass) string {
	switch c {
	case layers.DNSClassIN:
		return "IN"
	case layers.DNSClassCS:
		return "CS"
	case layers.DNSClassCH:
		return "CH"
	case layers.DNSClassHS:
		return "HS"
	case layers.DNSClassAny:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// formatDNSInfo creates a human-readable DNS info string.
func formatDNSInfo(metadata *types.DNSMetadata) string {
	if metadata.IsResponse {
		if len(metadata.Answers) > 0 {
			return metadata.QueryType + " " + metadata.QueryName + " -> " + metadata.Answers[0].Data
		}
		return metadata.QueryType + " " + metadata.QueryName + " " + metadata.ResponseCode
	}
	return metadata.QueryType + " " + metadata.QueryName + "?"
}
