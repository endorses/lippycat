package capture

import (
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
)

type scopedTestInstaller struct{ testFilterInstaller }

func (scopedTestInstaller) CaptureScope(name string) uint32 {
	if name == "other" {
		return 1
	}
	return 0
}
func TestAdmissionDomainsIsolateFragmentsAndESPCaches(t *testing.T) {
	base := NewIPv4Defragmenter()
	states, err := newCaptureDomainStates([]pcaptypes.PcapInterface{&mockPcapInterface{name: "signal"}, &mockPcapInterface{name: "media"}, &mockPcapInterface{name: "other"}}, scopedTestInstaller{}, base, NewIPv6Defragmenter())
	require.NoError(t, err)
	require.Len(t, states, 2)
	frames := udpFragmentFrames(t, false, 5060, []byte("INVITE sip:alice@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	first := gopacket.NewPacket(frames[0], layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	second := gopacket.NewPacket(frames[1], layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	packet, err := states[0].ipv4.DefragIPv4(first)
	require.NoError(t, err)
	require.Nil(t, packet)
	packet, err = states[1].ipv4.DefragIPv4(second)
	require.NoError(t, err)
	require.Nil(t, packet, "different observation domains must not complete each other's datagram")
	packet, err = states[0].ipv4.DefragIPv4(second)
	require.NoError(t, err)
	require.NotNil(t, packet, "interfaces within one domain share reassembly")
	states[0].esp.Store(42, layers.IPProtocolUDP)
	_, ok := states[1].esp.Load(42)
	require.False(t, ok)
	snapshot := sumIPv4Defrag([]*IPv4Defragmenter{states[0].ipv4, states[1].ipv4})
	require.EqualValues(t, 3, snapshot.ObservedFragments)
	require.EqualValues(t, 1, snapshot.CompletedDatagrams)
}
