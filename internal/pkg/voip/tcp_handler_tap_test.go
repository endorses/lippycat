//go:build tap || all

package voip

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// targetSubstringFilter is a minimal ApplicationFilter test double. It matches a
// packet when the target string appears anywhere in the packet's application
// (SIP) payload. This mirrors how the real hunter.ApplicationFilter matches on
// the SIP identity headers of the specific message, and — crucially — lets the
// test assert that matching operates on THIS message's synthesized packet, not
// on some other buffered packet of the flow.
type targetSubstringFilter struct {
	target string
	// seen records the application payloads the filter was asked to match,
	// in order, so the test can confirm each message was evaluated on its own.
	seen []string
}

func (f *targetSubstringFilter) MatchPacket(pkt gopacket.Packet) bool {
	var payload string
	if app := pkt.ApplicationLayer(); app != nil {
		payload = string(app.LayerContents())
	}
	f.seen = append(f.seen, payload)
	return strings.Contains(payload, f.target)
}

// testNetFlow builds an IPv4 network-layer flow for the given dotted-quad IPs.
func testNetFlow(t *testing.T, src, dst string) gopacket.Flow {
	t.Helper()
	srcIP := layers.NewIPEndpoint(mustIP(t, src))
	dstIP := layers.NewIPEndpoint(mustIP(t, dst))
	return gopacket.NewFlow(layers.EndpointIPv4, srcIP.Raw(), dstIP.Raw())
}

func mustIP(t *testing.T, s string) []byte {
	t.Helper()
	ip := parseTestIPv4(s)
	if ip == nil {
		t.Fatalf("invalid test IP %q", s)
	}
	return ip
}

func parseTestIPv4(s string) []byte {
	var b [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	for i, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return nil
		}
		b[i] = byte(n)
	}
	return b[:]
}

// drainForwarded collects all InjectedPackets currently queued on ch.
func drainForwarded(ch <-chan source.InjectedPacket) []source.InjectedPacket {
	var out []source.InjectedPacket
	for {
		select {
		case p := <-ch:
			out = append(out, p)
		default:
			return out
		}
	}
}

func mtMessage(callID, toUser string) []byte {
	return []byte(
		"MESSAGE sip:" + toUser + "@ims.example SIP/2.0\r\n" +
			"Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK" + callID + "\r\n" +
			"From: <sip:smsc@ims.example>;tag=a" + callID + "\r\n" +
			"To: <sip:" + toUser + "@ims.example>\r\n" +
			"P-Called-Party-ID: <sip:" + toUser + "@ims.example>\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: 1 MESSAGE\r\n" +
			"Content-Type: application/vnd.3gpp.sms\r\n" +
			"Content-Length: 3\r\n" +
			"\r\n" +
			"abc")
}

func moMessage(callID, fromUser string) []byte {
	return []byte(
		"MESSAGE sip:smsc@ims.example SIP/2.0\r\n" +
			"Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK" + callID + "\r\n" +
			"From: <sip:" + fromUser + "@ims.example>;tag=b" + callID + "\r\n" +
			"To: <sip:smsc@ims.example>\r\n" +
			"P-Asserted-Identity: <sip:" + fromUser + "@ims.example>\r\n" +
			"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: 1 MESSAGE\r\n" +
			"Content-Type: application/vnd.3gpp.sms\r\n" +
			"Content-Length: 3\r\n" +
			"\r\n" +
			"xyz")
}

// TestTapHandler_MultipleMessagesEachForwarded verifies that on one persistent
// TCP connection carrying several SIP MESSAGEs with different Call-IDs, EACH
// message that matches the target is matched+forwarded as its own unit — not
// just the first — and non-matching messages are dropped. It also verifies that
// an MO leg (target only in From/P-Asserted-Identity) is matched, and that no
// message is double-forwarded.
func TestTapHandler_MultipleMessagesEachForwarded(t *testing.T) {
	const target = "31600000000" // the surveilled subscriber

	ch := make(chan source.InjectedPacket, 16)
	filter := &targetSubstringFilter{target: target}
	h := NewTapTCPHandler(ch)
	h.SetApplicationFilter(filter)

	netFlow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	const src = "10.0.0.1:5060"
	const dst = "10.0.0.2:5060"

	type msg struct {
		callID    string
		bytes     []byte
		wantMatch bool
	}
	msgs := []msg{
		{"call-mt-1", mtMessage("call-mt-1", target), true},           // MT to target
		{"call-other", mtMessage("call-other", "31699999999"), false}, // not target
		{"call-mo-2", moMessage("call-mo-2", target), true},           // MO from target
		{"call-mt-3", mtMessage("call-mt-3", target), true},           // MT to target
		{"call-mo-4", moMessage("call-mo-4", target), true},           // MO from target
	}

	wantForwarded := 0
	for _, m := range msgs {
		got := h.HandleSIPMessage(m.bytes, m.callID, src, dst, netFlow)
		if got != m.wantMatch {
			t.Errorf("HandleSIPMessage(%s) = %v, want %v", m.callID, got, m.wantMatch)
		}
		if m.wantMatch {
			wantForwarded++
		}
	}

	forwarded := drainForwarded(ch)
	if len(forwarded) != wantForwarded {
		t.Fatalf("forwarded %d messages, want %d", len(forwarded), wantForwarded)
	}

	// Each forwarded packet must carry its OWN message's Call-ID (no cross-talk),
	// and the synthesized packet's application payload must equal that message.
	seenCallIDs := map[string]int{}
	for _, p := range forwarded {
		if p.Metadata == nil || p.Metadata.Sip == nil {
			t.Fatalf("forwarded packet missing SIP metadata")
		}
		cid := p.Metadata.Sip.CallId
		seenCallIDs[cid]++

		app := p.PacketInfo.Packet.ApplicationLayer()
		if app == nil {
			t.Fatalf("forwarded packet for %s has no application layer", cid)
		}
		payload := string(app.LayerContents())
		if !strings.Contains(payload, "Call-ID: "+cid) {
			t.Errorf("forwarded packet for %s does not carry its own SIP payload", cid)
		}
		if !strings.Contains(payload, target) {
			t.Errorf("forwarded packet for %s does not contain target identity", cid)
		}
	}

	// No message double-forwarded.
	for cid, n := range seenCallIDs {
		if n != 1 {
			t.Errorf("Call-ID %s forwarded %d times, want exactly 1", cid, n)
		}
	}
	// All matching Call-IDs present.
	for _, m := range msgs {
		if m.wantMatch && seenCallIDs[m.callID] != 1 {
			t.Errorf("matching message %s was not forwarded", m.callID)
		}
	}

	// The filter must have been evaluated once per message (on that message's
	// own synthesized packet), not just on the first.
	if len(filter.seen) != len(msgs) {
		t.Errorf("filter evaluated %d times, want %d (once per message)", len(filter.seen), len(msgs))
	}
}

// TestTapHandler_MOLegMatchesFromAndPAI verifies an MO leg whose target appears
// only in From / P-Asserted-Identity (never in To) is matched and forwarded.
func TestTapHandler_MOLegMatchesFromAndPAI(t *testing.T) {
	const target = "31600000000"

	ch := make(chan source.InjectedPacket, 4)
	filter := &targetSubstringFilter{target: target}
	h := NewTapTCPHandler(ch)
	h.SetApplicationFilter(filter)

	netFlow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	msg := moMessage("call-mo", target)

	if !h.HandleSIPMessage(msg, "call-mo", "10.0.0.1:5060", "10.0.0.2:5060", netFlow) {
		t.Fatal("MO leg (target in From/P-Asserted-Identity) was not matched")
	}
	forwarded := drainForwarded(ch)
	if len(forwarded) != 1 {
		t.Fatalf("MO leg forwarded %d packets, want 1", len(forwarded))
	}
	// The forwarded synthesized packet must preserve the P-Access-Network-Info
	// (cell-ID location) that only the MO leg carries.
	app := forwarded[0].PacketInfo.Packet.ApplicationLayer()
	if app == nil || !strings.Contains(string(app.LayerContents()), "P-Access-Network-Info") {
		t.Error("MO leg forwarding lost the P-Access-Network-Info header")
	}
}

// TestBuildSIPPacketInfo verifies the synthesized packet round-trips: correct
// 5-tuple and an application payload equal to the original SIP message.
func TestBuildSIPPacketInfo(t *testing.T) {
	netFlow := testNetFlow(t, "192.0.2.10", "192.0.2.20")
	sip := mtMessage("rt-1", "31600000000")

	pkt, ok := buildSIPPacketInfo(sip, "192.0.2.10:5060", "192.0.2.20:5062", netFlow, time.Unix(0, 0))
	if !ok {
		t.Fatal("buildSIPPacketInfo returned ok=false")
	}

	ipLayer := pkt.Packet.NetworkLayer()
	if ipLayer == nil {
		t.Fatal("synthesized packet has no network layer")
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		t.Fatalf("network layer is %T, want *layers.IPv4", ipLayer)
	}
	if ip.SrcIP.String() != "192.0.2.10" || ip.DstIP.String() != "192.0.2.20" {
		t.Errorf("IPs = %s->%s, want 192.0.2.10->192.0.2.20", ip.SrcIP, ip.DstIP)
	}

	tcpLayer := pkt.Packet.TransportLayer()
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		t.Fatalf("transport layer is %T, want *layers.TCP", tcpLayer)
	}
	if uint16(tcp.SrcPort) != 5060 || uint16(tcp.DstPort) != 5062 {
		t.Errorf("ports = %d->%d, want 5060->5062", tcp.SrcPort, tcp.DstPort)
	}

	app := pkt.Packet.ApplicationLayer()
	if app == nil {
		t.Fatal("synthesized packet has no application layer")
	}
	if string(app.LayerContents()) != string(sip) {
		t.Error("synthesized application payload does not equal the SIP message")
	}
}

func TestEndpointPort(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
		ok   bool
	}{
		{"10.0.0.1:5060", 5060, true},
		{"2001:db8::1:5061", 5061, true}, // IPv6 unbracketed (getEndpoints form)
		{"[2001:db8::1]:5062", 5062, true},
		{"10.0.0.1", 0, false},
		{"10.0.0.1:", 0, false},
		{"10.0.0.1:notaport", 0, false},
	}
	for _, c := range cases {
		got, ok := endpointPort(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("endpointPort(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
