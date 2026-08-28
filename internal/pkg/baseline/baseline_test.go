package baseline

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type protocolEvent struct {
	Protocol   string   `json:"protocol"`
	SourcePCAP string   `json:"source_pcap"`
	Timestamp  string   `json:"timestamp"`
	SrcIP      string   `json:"src_ip"`
	DstIP      string   `json:"dst_ip"`
	SrcPort    string   `json:"src_port"`
	DstPort    string   `json:"dst_port"`
	Info       string   `json:"info"`
	Modes      []string `json:"modes"`
}

type perCallFixture struct {
	SourcePCAP  string `json:"source_pcap"`
	CallID      string `json:"call_id"`
	PacketCount int    `json:"packet_count"`
	LinkType    string `json:"link_type"`
	Packets     []struct {
		Timestamp       string          `json:"timestamp"`
		FiveTuple       json.RawMessage `json:"five_tuple"`
		SIP             json.RawMessage `json:"sip"`
		PayloadSHA256   string          `json:"payload_sha256"`
		CallAssociation string          `json:"call_association"`
	} `json:"packets"`
}

func readFixture(t *testing.T, name string, dst any) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolEventGoldenFixtures(t *testing.T) {
	var events []protocolEvent
	readFixture(t, "protocol-events.json", &events)
	wantProtocols := map[string]bool{"DNS": false, "TLS": false, "HTTP": false, "SMTP": false, "SIP": false}
	for _, event := range events {
		if _, ok := wantProtocols[event.Protocol]; !ok {
			t.Fatalf("unexpected protocol %q", event.Protocol)
		}
		wantProtocols[event.Protocol] = true
		if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
			t.Errorf("%s timestamp: %v", event.Protocol, err)
		}
		if event.SourcePCAP == "" || event.SrcIP == "" || event.DstIP == "" || event.SrcPort == "" || event.DstPort == "" || event.Info == "" {
			t.Errorf("%s has an incomplete observable event", event.Protocol)
		}
		for _, mode := range []string{"sniff", "watch-live", "watch-file"} {
			found := false
			for _, got := range event.Modes {
				found = found || got == mode
			}
			if !found {
				t.Errorf("%s is missing %s baseline", event.Protocol, mode)
			}
		}
	}
	for protocol, found := range wantProtocols {
		if !found {
			t.Errorf("missing %s fixture", protocol)
		}
	}
}

func TestPerCallPCAPSemanticFixture(t *testing.T) {
	var fixture perCallFixture
	readFixture(t, "per-call-pcap.json", &fixture)
	if fixture.SourcePCAP == "" || fixture.CallID == "" || fixture.LinkType == "" || fixture.PacketCount != len(fixture.Packets) {
		t.Fatal("incomplete per-call PCAP fixture header")
	}
	for i, packet := range fixture.Packets {
		if _, err := time.Parse(time.RFC3339Nano, packet.Timestamp); err != nil {
			t.Errorf("packet %d timestamp: %v", i, err)
		}
		if len(packet.FiveTuple) == 0 || packet.CallAssociation != fixture.CallID {
			t.Errorf("packet %d has incomplete flow/call association", i)
		}
		digest, err := hex.DecodeString(packet.PayloadSHA256)
		if err != nil || len(digest) != 32 {
			t.Errorf("packet %d has invalid SHA-256 digest", i)
		}
	}
}
