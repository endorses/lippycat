package eventanalysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
)

func ReverseFlow(flow *events.FlowTuple) {
	flow.SourceAddress, flow.DestinationAddress = flow.DestinationAddress, flow.SourceAddress
	flow.SourcePort, flow.DestinationPort = flow.DestinationPort, flow.SourcePort
}
func MapTLS(env events.Envelope, m *data.TLSMetadata) events.TLSEvent {
	if m.IsServer {
		ReverseFlow(&env.Flow)
	}
	e := events.NewTLSEvent(env)
	e.Version, e.ServerName = m.Version, m.Sni
	if m.SelectedCipher != 0 {
		e.Cipher = fmt.Sprintf("0x%04x", m.SelectedCipher)
	}
	if len(m.SupportedGroups) > 0 {
		e.Curve = fmt.Sprintf("0x%04x", m.SupportedGroups[0])
	}
	if len(m.AlpnProtocols) > 0 {
		e.NextProtocol = m.AlpnProtocols[0]
	}
	e.Established = m.CorrelatedPeer || strings.EqualFold(m.HandshakeType, "ServerHello")
	e.JA3, e.JA3S, e.JA4 = m.Ja3, m.Ja3S, m.Ja4
	return e
}
func MapHTTP(env events.Envelope, m *data.HTTPMetadata, headers bool) events.HTTPEvent {
	if m.IsServer || strings.EqualFold(m.Type, "response") {
		ReverseFlow(&env.Flow)
	}
	e := events.NewHTTPEvent(env)
	e.TransactionDepth = 1
	e.Method, e.Host, e.Version, e.UserAgent = m.Method, m.Host, m.Version, m.UserAgent
	e.URI = m.Path
	if m.QueryString != "" {
		e.URI += "?" + m.QueryString
	}
	if m.ContentLength > 0 {
		if m.IsServer || strings.EqualFold(m.Type, "response") {
			e.ResponseBodyLength = uint64(m.ContentLength)
		} else {
			e.RequestBodyLength = uint64(m.ContentLength)
		}
	}
	e.StatusCode, e.StatusMessage = uint16(m.StatusCode), m.StatusReason
	if headers {
		e.Headers = make(map[string][]string, len(m.Headers))
		for k, v := range m.Headers {
			e.Headers[k] = []string{v}
		}
		e.Referrer, e.Origin = m.Headers["referer"], m.Headers["origin"]
	}
	return e
}
func MapDNS(env events.Envelope, m *data.DNSMetadata) events.DNSEvent {
	if m.IsResponse {
		ReverseFlow(&env.Flow)
	}
	e := events.NewDNSEvent(env)
	e.IsResponse = m.IsResponse
	e.TransactionID = uint16(m.TransactionId)
	if m.CorrelatedQuery && m.QueryResponseTimeMs > 0 {
		e.RTT = time.Duration(m.QueryResponseTimeMs) * time.Millisecond
	}
	e.Query, e.QClass, e.QType, e.RCode = m.QueryName, dnsClass(m.QueryClass), dnsType(m.QueryType), dnsRCode(m.ResponseCode)
	e.Authoritative, e.Truncated = m.Authoritative, m.Truncated
	e.RecursionDesired, e.RecursionAvailable = m.RecursionDesired, m.RecursionAvailable
	for _, a := range m.Answers {
		e.Answers = append(e.Answers, a.Data)
		e.TTLs = append(e.TTLs, time.Duration(a.Ttl)*time.Second)
	}
	e.Rejected = strings.EqualFold(m.ResponseCode, "REFUSED")
	return e
}
func dnsClass(v string) uint16 {
	if strings.EqualFold(v, "IN") {
		return 1
	}
	return 0
}
func dnsType(v string) uint16 {
	return map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "OPT": 41, "ANY": 255}[strings.ToUpper(v)]
}
func dnsRCode(v string) uint16 {
	return map[string]uint16{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5, "YXDOMAIN": 6, "YXRRSET": 7, "NXRRSET": 8, "NOTAUTH": 9, "NOTZONE": 10}[strings.ToUpper(v)]
}
