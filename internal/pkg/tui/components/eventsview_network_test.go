//go:build tui || all

package components

import (
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/stretchr/testify/require"
)

func networkPresentationEvents() []events.Event {
	env := events.Envelope{Timestamp: time.Unix(100, 0), EventID: "network-event", UID: "flow-uid", NodeID: "sensor", CaptureScope: events.CaptureScopeFiltered, Partial: true,
		Flow: events.FlowTuple{SourceAddress: netip.MustParseAddr("192.0.2.10"), DestinationAddress: netip.MustParseAddr("192.0.2.20"), SourcePort: 49152, DestinationPort: 123, Protocol: 17}}
	dhcp := events.NewDHCPEvent(env)
	dhcp.MessageType, dhcp.TransactionID = 2, 42
	dhcp.Hostname = "example\nhost"
	dhcp.ClientIdentifier = []byte{0, 255, 128}
	dhcp.Association = events.AssociationAmbiguous
	ntp := events.NewNTPEvent(env)
	ntp.Version, ntp.Mode, ntp.Poll, ntp.Precision = 4, 4, -1, -18
	ntp.RootDelay = -32768
	ntp.Transmit.Raw = 0xffffffff80000001
	ntp.Association = events.AssociationUnique
	host := events.NewKnownHostEvent(env)
	host.Host, host.Evidence = env.Flow.SourceAddress, events.EvidenceUDPBidirectional
	service := events.NewKnownServiceEvent(env)
	service.Host, service.Port, service.Transport, service.Protocol, service.Evidence = env.Flow.DestinationAddress, 123, 17, "ntp", events.EvidenceNTPExchange
	return []events.Event{dhcp, ntp, host, service}
}

func TestNetworkEventDetailsUseCanonicalFields(t *testing.T) {
	streams := []string{"dhcp", "ntp", "known_hosts", "known_services"}
	wants := []map[string]string{
		{"message_type": "2", "transaction_id": "42", "client_identifier": "00ff80", "hostname": "example host", "association": "ambiguous"},
		{"poll": "-1", "precision": "-18", "root_delay_raw": "-32768", "transmit_raw": "ffffffff80000001", "association": "unique"},
		{"host": "192.0.2.10", "evidence": "udp_bidirectional"},
		{"host": "192.0.2.20", "port": "123", "transport": "udp", "service": "ntp", "evidence": "ntp_exchange"},
	}
	for i, event := range networkPresentationEvents() {
		t.Run(string(event.Kind()), func(t *testing.T) {
			schema, ok := logschema.ByName(streams[i])
			require.True(t, ok)
			positions := make(map[string]int)
			for index, field := range schema.Fields {
				positions[field.Name] = index
			}
			actual := make(map[string]string)
			previous := -1
			for _, field := range eventFields(event) {
				position, present := positions[field.Name]
				require.True(t, present)
				require.Greater(t, position, previous, "canonical field order")
				previous = position
				actual[field.Name] = field.Value
			}
			for name, want := range wants[i] {
				require.Equal(t, want, actual[name], name)
			}
			require.Equal(t, "true", actual["partial"])
			require.Equal(t, "filtered", actual["capture_scope"])
			require.NotEmpty(t, eventSummary(event))
			require.NotEqual(t, "📋", eventKindIcon(event.Kind()))
			view := NewEventsView()
			content := view.renderEventDetailsContent(EventItem{Event: event}, 100)
			require.Contains(t, content, eventKindSectionTitle(event.Kind()))
			for name, want := range wants[i] {
				require.Contains(t, content, want, name)
			}
		})
	}
}

func TestNetworkEventRenderingRemainsReadOnly(t *testing.T) {
	for _, event := range networkPresentationEvents() {
		t.Run(string(event.Kind()), func(t *testing.T) {
			view := NewEventsView()
			view.SetEvents([]EventItem{{Event: event}})
			view.PrepareLayout(140, 15, 100, 20)
			view.ScrollDetailsToBottom()
			before := *view
			before.items = append([]EventItem(nil), view.items...)
			for range 3 {
				view.RenderTimeline(140, 15, true)
				view.RenderDetails(100, 20, true)
				view.RenderTimeline(80, 10, false)
				require.Equal(t, before, *view)
			}
			if dhcp, ok := event.(events.DHCPEvent); ok {
				require.Equal(t, "example\nhost", dhcp.Hostname)
				require.Equal(t, []byte{0, 255, 128}, dhcp.ClientIdentifier)
			}
		})
	}
}
