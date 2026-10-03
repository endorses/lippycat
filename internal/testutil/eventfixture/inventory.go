package eventfixture

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

// InventoryMessages observes one associated unicast NTP exchange between two
// endpoints. Inventory emits as soon as the reply confirms the exchange.
func InventoryMessages() ([]capture.PacketInfo, error) {
	packets, err := NetworkMessages()
	if err != nil {
		return nil, err
	}
	return packets[3:], nil
}

func InventoryPolicy() *eventconfig.Config {
	policy := eventconfig.Default()
	policy.Inventory.Enabled = true
	policy.Inventory.LocalCIDRs = []string{"192.0.2.0/24"}
	return &policy
}

func AssertInventory(t testing.TB, input []events.Event) []events.Event {
	t.Helper()
	var got []events.Event
	for _, event := range input {
		if event.Kind() == events.KindKnownHost || event.Kind() == events.KindKnownService {
			got = append(got, event)
		}
	}
	require.Len(t, got, 3, "one exchange establishes two hosts and one service, once")
	hosts := map[string]bool{}
	ids := map[string]bool{}
	services := 0
	for _, event := range got {
		env := event.Envelope()
		require.True(t, events.HasValidDeliveryIdentity(env))
		require.NotEmpty(t, env.UID)
		require.NotEmpty(t, env.CommunityID)
		require.False(t, ids[env.EventID])
		ids[env.EventID] = true
		require.Equal(t, got[0].Envelope().UID, env.UID)
		require.Equal(t, uint8(17), env.Flow.Protocol)
		require.Equal(t, "192.0.2.20", env.Flow.SourceAddress.String())
		require.Equal(t, "192.0.2.123", env.Flow.DestinationAddress.String())
		require.Equal(t, uint16(40000), env.Flow.SourcePort)
		require.Equal(t, uint16(123), env.Flow.DestinationPort)
		switch e := event.(type) {
		case events.KnownHostEvent:
			hosts[e.Host.String()] = true
			require.Equal(t, events.EvidenceUDPBidirectional, e.Evidence)
		case events.KnownServiceEvent:
			services++
			require.Equal(t, "192.0.2.123", e.Host.String())
			require.Equal(t, uint16(123), e.Port)
			require.Equal(t, uint8(17), e.Transport)
			require.Equal(t, "ntp", e.Protocol)
			require.Equal(t, events.EvidenceNTPExchange, e.Evidence)
		}
	}
	require.Equal(t, map[string]bool{"192.0.2.20": true, "192.0.2.123": true}, hosts)
	require.Equal(t, 1, services)
	return got
}
