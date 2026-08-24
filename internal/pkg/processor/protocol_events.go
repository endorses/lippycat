//go:build processor || tap || all

package processor

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
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
		env := events.Envelope{Timestamp: timestamp, NodeID: batchSource, Flow: flow, CaptureScope: events.CaptureScopeFull}
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
		}
	}
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
