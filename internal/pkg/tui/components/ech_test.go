//go:build tui || all

package components

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestTLSStatisticsAndDetailsQualifyObservationAvailability(t *testing.T) {
	view := NewStatisticsView()
	view.SetSize(100, 30)
	view.SetSelectedProtocol("HTTPS/TLS")
	require.False(t, view.HasProtocolStats())
	view.SetTLSObservations(TLSObservationStats{Rows: 4, ClientHellos: 3, ECHOffered: 2, Unavailable: 1})
	require.True(t, view.HasProtocolStats())
	rendered := view.renderProtocolStats()
	require.Contains(t, rendered, "2 / 3")
	require.Contains(t, rendered, "retained canonical TLS events")
	require.Contains(t, rendered, "without ClientHello evidence: 1")
	for _, tc := range []struct {
		observed, offered bool
		text              string
	}{{false, false, "unknown"}, {true, false, "not offered"}, {true, true, "offered"}} {
		panel := NewDetailsPanel()
		panel.SetPacket(&types.PacketDisplay{TLSData: &types.TLSMetadata{ClientHelloObserved: tc.observed, ECHOffered: tc.offered}})
		require.Contains(t, panel.renderContent(), tc.text)
	}
	unknown := events.NewTLSEvent(events.Envelope{})
	for _, field := range eventFields(unknown) {
		if strings.HasPrefix(field.Name, "ech_") || field.Name == "client_hello_count" {
			require.Equal(t, "-", field.Value)
		}
	}
}
