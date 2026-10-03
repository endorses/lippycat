package eventfixture

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

// AssertNetworkMessages checks the shared fixture's semantic contract across
// production entry points while allowing each path to own its source identity.
func AssertNetworkMessages(t testing.TB, input []events.Event) []events.Event {
	t.Helper()
	var got []events.Event
	for _, e := range input {
		if e.Kind() == events.KindDHCP || e.Kind() == events.KindNTP {
			got = append(got, e)
		}
	}
	require.Len(t, got, 5)
	ids := map[string]bool{}
	for _, e := range got {
		env := e.Envelope()
		require.True(t, events.HasValidDeliveryIdentity(env))
		require.NotEmpty(t, env.UID)
		require.NotEmpty(t, env.CommunityID)
		require.False(t, ids[env.EventID], "observed retransmissions need distinct delivery IDs")
		ids[env.EventID] = true
	}
	d := got[0].(events.DHCPEvent)
	require.Equal(t, uint8(1), d.MessageType)
	require.Equal(t, uint32(0x12345678), d.TransactionID)
	require.Equal(t, []byte{0, 255, 1}, d.ClientIdentifier)
	require.Equal(t, []byte{3, 6}, d.ParameterRequestList)
	require.Equal(t, events.AssociationRequest, d.Association)
	require.Equal(t, "0.0.0.0", d.Envelope().Flow.SourceAddress.String())
	require.Equal(t, "255.255.255.255", d.Envelope().Flow.DestinationAddress.String())
	offer := got[1].(events.DHCPEvent)
	require.Equal(t, uint8(2), offer.MessageType)
	require.Equal(t, events.AssociationUnique, offer.Association)
	require.Equal(t, "192.0.2.20", offer.OfferedAddress.String())
	require.Equal(t, "192.0.2.1", offer.ServerIdentifier.String())
	require.NotEmpty(t, offer.AssociationID)
	require.NotEqual(t, d.Envelope().UID, offer.Envelope().UID)
	retry := got[2].(events.DHCPEvent)
	require.Equal(t, d.TransactionID, retry.TransactionID)
	require.Equal(t, d.ClientIdentifier, retry.ClientIdentifier)
	req := got[3].(events.NTPEvent)
	resp := got[4].(events.NTPEvent)
	require.Equal(t, uint8(3), req.Mode)
	require.Equal(t, int8(-20), req.Precision)
	require.Equal(t, uint64(0xee43fc0080000000), req.Transmit.Raw)
	require.Equal(t, events.AssociationRequest, req.Association)
	require.Equal(t, uint8(4), resp.Mode)
	require.Equal(t, uint8(2), resp.Stratum)
	require.Equal(t, req.Transmit.Raw, resp.Origin.Raw)
	require.Equal(t, events.AssociationUnique, resp.Association)
	require.NotEmpty(t, resp.AssociationID)
	require.False(t, resp.Transmit.Time.IsZero())
	return got
}
