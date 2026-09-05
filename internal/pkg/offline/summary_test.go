//go:build tui || all

package offline

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestSummaryFilterParity(t *testing.T) {
	fields := []string{"src", "srcip", "dst", "dstip", "srcport", "dstport", "protocol", "info", "node", "nodeid", "interface", "length", "len", "voip", "sip", "rtp", "dns", "tls", "http", "email", "sip.user", "sip.from", "sip.to", "sip.callid", "sip.method", "sip.codec", "sip.fromtag", "sip.totag", "sip.imsi", "sip.imei", "sip.status", "rtp.seq", "rtp.sequence", "rtp.ssrc", "dns.query", "dns.name", "dns.type", "dns.ttl", "dns.latency", "tls.sni", "tls.ja3", "http.host", "http.path", "http.method", "http.status", "http.contentlength", "sip.unknown", "rtp.unknown", "dns.unknown", "tls.unknown", "http.unknown", "email.unknown", "unknown", "SRC"}
	full := types.PacketDisplay{SrcIP: "192.168.1.10", DstIP: "2001:db8::1", SrcPort: "5060", DstPort: "443", Protocol: "SIP", Transport: 17, Length: 1234, Info: "INVITE From: <sip:Alice@example.org>", NodeID: "edge-01", Interface: "eth0", RawData: []byte{1, 2, 3},
		VoIPData: &types.VoIPMetadata{User: "Alice", From: "sip:Alice@example.org", To: "Bob", CallID: "call-1", Method: "INVITE", Codec: "PCMU", FromTag: "f", ToTag: "t", IMSI: "1234", IMEI: "5678", Status: 200, IsRTP: true, SequenceNum: 23, SSRC: 42, Headers: map[string]string{"large": "excluded"}, RawSIP: []byte{4}},
		DNSData:  &types.DNSMetadata{QueryName: "example.org", QueryType: "AAAA", QueryResponseTimeMs: 12, Answers: []types.DNSAnswer{{TTL: 60}, {TTL: 900}}},
		TLSData:  &types.TLSMetadata{SNI: "example.org", JA3Fingerprint: "abc"},
		HTTPData: &types.HTTPMetadata{Host: "example.org", Path: "/hello", Method: "GET", StatusCode: 200, ContentLength: 456}, EmailData: &types.EmailMetadata{BodyPreview: "excluded"}}
	emptyMetadata := types.PacketDisplay{VoIPData: &types.VoIPMetadata{}, DNSData: &types.DNSMetadata{}, TLSData: &types.TLSMetadata{}, HTTPData: &types.HTTPMetadata{}, EmailData: &types.EmailMetadata{}}
	records := []types.PacketDisplay{{}, full, emptyMetadata, {Protocol: "SIP", Info: "INVITE From: <sip:Alice@example.org>", NodeID: "Local"}, {Protocol: "RTP"}, {Protocol: "TCP", NodeID: ""}}
	var predicates []filters.Filter
	for _, field := range fields {
		predicates = append(predicates, filters.NewTextFilter("alice", []string{field}), filters.NewTextFilter("", []string{field}))
		for _, op := range []string{">0", "<1", ">=0", "<=23", "=0", "==200"} {
			f, err := filters.NewNumericComparisonFilter(field, op)
			if err != nil {
				t.Fatal(err)
			}
			predicates = append(predicates, f)
		}
	}
	predicates = append(predicates, filters.NewTextFilter("5060", nil), filters.NewTextFilter("ALICE", nil), filters.NewTextFilter("5060", []string{"src"}), filters.NewTextFilter("443", []string{"dst"}), filters.NewCallStateFilter("active"))
	for _, kind := range []string{"voip", "dns", "tls", "http", "email", "unknown"} {
		predicates = append(predicates, filters.NewMetadataFilter(kind))
	}
	for _, field := range []string{"user", "from", "to", "method", "callid", "codec", "fromtag", "totag", "unknown"} {
		for _, value := range []string{"alice", "Ali*", "*ice", "*lic*", "INVITE", "*"} {
			predicates = append(predicates, filters.NewVoIPFilter(field, value))
		}
	}
	for _, node := range []string{"*", "Local", "edge-*", "*-01", "edge-*-01"} {
		predicates = append(predicates, filters.NewNodeFilter(node))
	}
	for _, expr := range []string{"tcp", "udp", "icmp", "port 5060", "src port 5060", "dst port 443", "host 192.168.1", "net 192.168.0.0/16", "src net 192.168", "ip", "unsupported expression"} {
		f, err := filters.NewBPFFilter(expr)
		if err != nil {
			t.Fatal(err)
		}
		predicates = append(predicates, f)
	}
	for i, p := range records {
		s := NewSummary(PacketID(i), p)
		for _, field := range fields {
			if s.GetStringField(field) != p.GetStringField(field) || s.GetNumericField(field) != p.GetNumericField(field) || s.HasField(field) != p.HasField(field) {
				t.Fatalf("record %d field %s differs", i, field)
			}
		}
		chain := filters.NewFilterChain()
		for _, f := range predicates {
			if f.Match(s) != f.Match(p) {
				t.Fatalf("record %d filter %s differs", i, f.String())
			}
			for _, op := range []filters.BooleanOperator{filters.OpAND, filters.OpOR, filters.OpNOT} {
				b := filters.NewBooleanFilter(op, f, filters.NewMetadataFilter("voip"), "")
				if b.Match(s) != b.Match(p) {
					t.Fatalf("record %d boolean %s differs", i, b.String())
				}
			}
			chain.Add(f)
			if chain.Match(s) != chain.Match(p) {
				t.Fatalf("record %d stacked filters differ", i)
			}
		}
		for chain.RemoveLast() {
			if chain.Match(s) != chain.Match(p) {
				t.Fatalf("record %d filter removal differs", i)
			}
		}
	}
	// Projection must survive mutations of analyzer-owned metadata and raw bytes.
	s := NewSummary(1, full)
	full.VoIPData.User = "changed"
	full.DNSData.Answers[0].TTL = 999
	full.HTTPData.StatusCode = 500
	if s.GetStringField("sip.user") != "Alice" || s.GetNumericField("dns.ttl") != 60 || s.GetNumericField("http.status") != 200 {
		t.Fatal("summary aliases analyzer metadata")
	}
	if s.packet.RawData != nil || s.packet.VoIPData.Headers != nil || s.packet.VoIPData.RawSIP != nil || len(s.packet.DNSData.Answers) != 1 || s.packet.EmailData.BodyPreview != "" {
		t.Fatal("summary retains detail-only data")
	}
}
