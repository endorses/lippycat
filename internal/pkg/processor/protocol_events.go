//go:build processor || tap || all

package processor

import (
	"fmt"
	"mime"
	"net/netip"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

func (p *Processor) emitProtocolEvents(batchSource string, packets []*data.CapturedPacket) {
	if p.eventDispatcher == nil {
		return
	}
	for _, packet := range packets {
		if packet == nil || packet.Metadata == nil {
			continue
		}
		meta := packet.Metadata
		flow, err := flowTuple(meta)
		if err != nil {
			logger.Debug("Skipping protocol event with invalid flow metadata", "source_id", batchSource, "error", err)
			continue
		}
		timestamp := time.Unix(0, packet.TimestampNs)
		if packet.TimestampNs == 0 {
			timestamp = time.Now()
		}
		scope := events.CaptureScopeFull
		if len(packet.MatchedFilterIds) > 0 {
			scope = events.CaptureScopeFiltered
		}
		env := events.Envelope{Timestamp: timestamp, NodeID: batchSource, Flow: flow, CaptureScope: scope, Partial: scope == events.CaptureScopeFiltered}
		env, err = p.flowIdentity.Enrich(env)
		if err != nil {
			logger.Warn("Failed to assign protocol event flow identity", "error", err)
			continue
		}
		if meta.Dns != nil {
			dnsEvent := mapDNSEvent(env, meta.Dns)
			p.eventDispatcher.Enqueue(dnsEvent)
		}
		if meta.Email != nil {
			smtpEvent := events.NewSMTPEvent(env)
			smtpEvent.MailFrom = meta.Email.MailFrom
			smtpEvent.Recipients = append([]string(nil), meta.Email.RcptTo...)
			smtpEvent.Subject = meta.Email.Subject
			smtpEvent.MessageID = meta.Email.MessageId
			p.eventDispatcher.Enqueue(smtpEvent)
			p.emitSMTPFiles(env, meta.Email)
		}
		if meta.Tls != nil {
			p.eventDispatcher.Enqueue(mapTLSEvent(env, meta.Tls))
		}
		if meta.Http != nil {
			p.eventDispatcher.Enqueue(mapHTTPEvent(env, meta.Http, p.config.LogConfig != nil && p.config.LogConfig.IncludeHTTPHeaders))
			p.emitHTTPFile(env, meta.Http)
		}
	}
}

func (p *Processor) emitSMTPFiles(env events.Envelope, meta *data.EmailMetadata) {
	if p.fileAnalyzer == nil || p.config.LogConfig == nil || !p.config.LogConfig.IncludeEmailBodyPreview || len(meta.BodyPreview) == 0 || !strings.HasPrefix(strings.ToLower(meta.ContentType), "multipart/") {
		return
	}
	items, err := fileanalysis.SMTPAttachments([]byte(meta.BodyPreview), meta.ContentType, p.config.LogConfig.FileMaxSize)
	if err != nil {
		logger.Debug("Skipping malformed SMTP MIME body", "error", err)
		return
	}
	for _, item := range items {
		item.Envelope, item.TotalBytes, item.Truncated = env, uint64(len(item.Content)), item.Truncated || meta.BodyTruncated
		ev, content, err := p.fileAnalyzer.Analyze(item)
		if err != nil {
			logger.Warn("Failed to analyze SMTP attachment", "error", err)
			continue
		}
		p.eventDispatcher.Enqueue(ev)
		if content != nil {
			p.eventDispatcher.Enqueue(*content)
		}
	}
}

func (p *Processor) emitHTTPFile(env events.Envelope, meta *data.HTTPMetadata) {
	if p.fileAnalyzer == nil || len(meta.BodyPreview) == 0 || !(meta.IsServer || strings.EqualFold(meta.Type, "response")) {
		return
	}
	reverseFlow(&env.Flow)
	filename := ""
	if disposition := meta.Headers["content-disposition"]; disposition != "" {
		if _, params, err := mime.ParseMediaType(disposition); err == nil {
			filename = params["filename"]
		}
	}
	ev, content, err := p.fileAnalyzer.Analyze(fileanalysis.Observation{Envelope: env, Source: "HTTP", Filename: filename, ContentType: meta.ContentType, ContentEncoding: meta.Headers["content-encoding"], Content: meta.BodyPreview, TotalBytes: meta.BodySize, Truncated: meta.BodyTruncated})
	if err != nil {
		logger.Warn("Failed to analyze HTTP file", "error", err)
		return
	}
	p.eventDispatcher.Enqueue(ev)
	if content != nil {
		p.eventDispatcher.Enqueue(*content)
	}
}

func mapTLSEvent(env events.Envelope, meta *data.TLSMetadata) events.TLSEvent {
	// A ServerHello travels responder-to-originator; ssl.log retains the
	// connection's client/originator orientation.
	if meta.IsServer {
		reverseFlow(&env.Flow)
	}
	ev := events.NewTLSEvent(env)
	ev.Version, ev.ServerName = meta.Version, meta.Sni
	if meta.SelectedCipher != 0 {
		ev.Cipher = fmt.Sprintf("0x%04x", meta.SelectedCipher)
	}
	if len(meta.SupportedGroups) > 0 {
		ev.Curve = fmt.Sprintf("0x%04x", meta.SupportedGroups[0])
	}
	if len(meta.AlpnProtocols) > 0 {
		ev.NextProtocol = meta.AlpnProtocols[0]
	}
	ev.Established = meta.CorrelatedPeer || strings.EqualFold(meta.HandshakeType, "ServerHello")
	ev.JA3, ev.JA3S, ev.JA4 = meta.Ja3, meta.Ja3S, meta.Ja4
	return ev
}

func mapHTTPEvent(env events.Envelope, meta *data.HTTPMetadata, includeHeaders bool) events.HTTPEvent {
	if meta.IsServer || strings.EqualFold(meta.Type, "response") {
		reverseFlow(&env.Flow)
	}
	ev := events.NewHTTPEvent(env)
	ev.Method, ev.Host, ev.Version, ev.UserAgent = meta.Method, meta.Host, meta.Version, meta.UserAgent
	ev.URI = meta.Path
	if meta.QueryString != "" {
		ev.URI += "?" + meta.QueryString
	}
	if meta.ContentLength > 0 {
		if meta.IsServer {
			ev.ResponseBodyLength = uint64(meta.ContentLength)
		} else {
			ev.RequestBodyLength = uint64(meta.ContentLength)
		}
	}
	ev.StatusCode, ev.StatusMessage = uint16(meta.StatusCode), meta.StatusReason // #nosec G115 -- protobuf HTTP status is parser validated
	if includeHeaders {
		ev.Headers = make(map[string][]string, len(meta.Headers))
		for key, value := range meta.Headers {
			ev.Headers[key] = []string{value}
		}
		ev.Referrer, ev.Origin = meta.Headers["referer"], meta.Headers["origin"]
	}
	return ev
}

func reverseFlow(flow *events.FlowTuple) {
	flow.SourceAddress, flow.DestinationAddress = flow.DestinationAddress, flow.SourceAddress
	flow.SourcePort, flow.DestinationPort = flow.DestinationPort, flow.SourcePort
}

func flowTuple(meta *data.PacketMetadata) (events.FlowTuple, error) {
	src, err := netip.ParseAddr(meta.SrcIp)
	if err != nil {
		return events.FlowTuple{}, fmt.Errorf("source IP %q: %w", meta.SrcIp, err)
	}
	dst, err := netip.ParseAddr(meta.DstIp)
	if err != nil {
		return events.FlowTuple{}, fmt.Errorf("destination IP %q: %w", meta.DstIp, err)
	}
	var protocol uint8
	switch strings.ToLower(meta.Transport) {
	case "tcp":
		protocol = 6
	case "udp":
		protocol = 17
	case "icmp":
		protocol = 1
	case "icmpv6", "icmp6":
		protocol = 58
	default:
		return events.FlowTuple{}, fmt.Errorf("unsupported transport %q", meta.Transport)
	}
	return events.FlowTuple{Protocol: protocol, SourceAddress: src, DestinationAddress: dst, SourcePort: uint16(meta.SrcPort), DestinationPort: uint16(meta.DstPort)}, nil
}

func mapDNSEvent(env events.Envelope, meta *data.DNSMetadata) events.DNSEvent {
	// Zeek's id.orig_* identifies the querying endpoint.
	if meta.IsResponse {
		env.Flow.SourceAddress, env.Flow.DestinationAddress = env.Flow.DestinationAddress, env.Flow.SourceAddress
		env.Flow.SourcePort, env.Flow.DestinationPort = env.Flow.DestinationPort, env.Flow.SourcePort
	}
	ev := events.NewDNSEvent(env)
	ev.TransactionID = uint16(meta.TransactionId)
	if meta.CorrelatedQuery && meta.QueryResponseTimeMs > 0 {
		ev.RTT = time.Duration(meta.QueryResponseTimeMs) * time.Millisecond
	}
	ev.Query, ev.QClass, ev.QType, ev.RCode = meta.QueryName, dnsClassCode(meta.QueryClass), dnsTypeCode(meta.QueryType), dnsRCode(meta.ResponseCode)
	ev.Authoritative, ev.Truncated = meta.Authoritative, meta.Truncated
	ev.RecursionDesired, ev.RecursionAvailable = meta.RecursionDesired, meta.RecursionAvailable
	for _, answer := range meta.Answers {
		ev.Answers = append(ev.Answers, answer.Data)
		ev.TTLs = append(ev.TTLs, time.Duration(answer.Ttl)*time.Second)
	}
	ev.Rejected = strings.EqualFold(meta.ResponseCode, "REFUSED")
	return ev
}

func dnsClassCode(value string) uint16 {
	if strings.EqualFold(value, "IN") {
		return 1
	}
	return 0
}
func dnsTypeCode(value string) uint16 {
	return map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "OPT": 41, "ANY": 255}[strings.ToUpper(value)]
}
func dnsRCode(value string) uint16 {
	return map[string]uint16{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5, "YXDOMAIN": 6, "YXRRSET": 7, "NXRRSET": 8, "NOTAUTH": 9, "NOTZONE": 10}[strings.ToUpper(value)]
}
