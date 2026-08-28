package baseline

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type protocolEvent struct {
	Protocol    string   `json:"protocol"`
	CLIProtocol string   `json:"cli_protocol"`
	CLIInfo     string   `json:"cli_info"`
	SourcePCAP  string   `json:"source_pcap"`
	Timestamp   string   `json:"timestamp"`
	SrcIP       string   `json:"src_ip"`
	DstIP       string   `json:"dst_ip"`
	SrcPort     string   `json:"src_port"`
	DstPort     string   `json:"dst_port"`
	Info        string   `json:"info"`
	Modes       []string `json:"modes"`
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
		if event.SourcePCAP == "" || event.SrcIP == "" || event.DstIP == "" || event.SrcPort == "" || event.DstPort == "" || event.Info == "" || event.CLIProtocol == "" || event.CLIInfo == "" {
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
