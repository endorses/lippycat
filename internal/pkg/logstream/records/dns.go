package records

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// DNS maps a normalized DNS event to the canonical dns.log schema.
func DNS(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.DNSEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected DNS event, got %T", event)
	}
	env := ev.Envelope()
	record, err := logstream.NewRecord("dns",
		env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort,
		env.Flow.DestinationAddress, env.Flow.DestinationPort, protocolName(env.Flow.Protocol),
		ev.TransactionID, optionalDuration(ev.RTT), ev.Query, ev.QClass, dnsClassName(ev.QClass),
		ev.QType, dnsTypeName(ev.QType), ev.RCode, dnsRCodeName(ev.RCode),
		ev.Authoritative, ev.Truncated, ev.RecursionDesired, ev.RecursionAvailable, ev.Z,
		ev.Answers, ev.TTLs, ev.Rejected, env.CommunityID, env.NodeID,
	)
	return record, err == nil, err
}

func optionalDuration(value interface{ Nanoseconds() int64 }) any {
	if value.Nanoseconds() == 0 {
		return logstream.Unset
	}
	return value
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	default:
		return fmt.Sprintf("%d", protocol)
	}
}

func dnsClassName(value uint16) any {
	if value == 0 {
		return logstream.Unset
	}
	if value == 1 {
		return "C_INTERNET"
	}
	return fmt.Sprintf("%d", value)
}

func dnsTypeName(value uint16) any {
	names := map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}
	if value == 0 {
		return logstream.Unset
	}
	if name := names[value]; name != "" {
		return name
	}
	return fmt.Sprintf("%d", value)
}

func dnsRCodeName(value uint16) string {
	names := []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}
	if int(value) < len(names) {
		return names[value]
	}
	return strings.ToUpper(fmt.Sprintf("RCODE%d", value))
}
