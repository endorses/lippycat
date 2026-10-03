package events

import (
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

func TestNetworkEventIdentityAndRetry(t *testing.T) {
	p, err := NewOfflineProducer("sensor", OfflineSession{InputIdentity: "fixture", AnalysisProfile: "network-v1"})
	require.NoError(t, err)
	input := []Event{NewDHCPEvent(Envelope{}), NewNTPEvent(Envelope{}), NewKnownHostEvent(Envelope{}), NewKnownServiceEvent(Envelope{})}
	for i, event := range input {
		assigned := p.Assign(event)
		require.True(t, HasValidDeliveryIdentity(assigned.Envelope()))
		require.Equal(t, uint64(i+1), assigned.Envelope().EventSequence)
		require.Equal(t, assigned, p.Assign(assigned))
		require.False(t, isNilEvent(assigned))
	}
	require.True(t, isNilEvent((*DHCPEvent)(nil)))
	require.True(t, isNilEvent((*NTPEvent)(nil)))
	require.True(t, isNilEvent((*KnownHostEvent)(nil)))
	require.True(t, isNilEvent((*KnownServiceEvent)(nil)))
}

func TestDHCPCloneOwnsMutableFields(t *testing.T) {
	ev := NewDHCPEvent(Envelope{Provenance: SourceProvenance{ProcessorNodeIDs: []string{"relay"}}})
	lease := uint32(0)
	ev.HardwareAddress = []byte{1, 2}
	ev.ClientIdentifier = []byte{0, 255}
	ev.ParameterRequestList = []byte{3, 6}
	ev.LeaseSeconds = &lease
	ev.Routers = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	ev.DNSServers = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	copy := ev.Clone()
	copy.HardwareAddress[0] = 9
	copy.ClientIdentifier[0] = 9
	copy.ParameterRequestList[0] = 9
	*copy.LeaseSeconds = 42
	copy.Routers[0] = netip.Addr{}
	copy.DNSServers[0] = netip.Addr{}
	copy.EventEnvelope.Provenance.ProcessorNodeIDs[0] = "other"
	require.Equal(t, byte(1), ev.HardwareAddress[0])
	require.Zero(t, ev.ClientIdentifier[0])
	require.Equal(t, byte(3), ev.ParameterRequestList[0])
	require.Zero(t, *ev.LeaseSeconds)
	require.True(t, ev.Routers[0].IsValid())
	require.True(t, ev.DNSServers[0].IsValid())
	require.Equal(t, "relay", ev.Envelope().Provenance.ProcessorNodeIDs[0])
}
