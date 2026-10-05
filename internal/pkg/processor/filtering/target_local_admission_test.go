package filtering

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestAdmissionIPSelectorsUpdateApplicationWithoutCaptureRestart(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "udp and not port 53", ApplicationIPSelectors: true})
	kernel := &mockBPFUpdater{}
	app := &mockAppFilterUpdater{}
	target.SetBPFUpdater(kernel)
	target.SetApplicationFilter(app)
	_, err := target.ApplyFilter(&management.Filter{Id: "sip", Type: management.FilterType_FILTER_SIP_USER, Pattern: "selected", Enabled: true})
	require.NoError(t, err)
	baseline := kernel.FilterCount()
	for _, pattern := range []string{"192.0.2.2", "192.0.2.0/24"} {
		_, err = target.ApplyFilter(&management.Filter{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true})
		require.NoError(t, err)
		require.Equal(t, baseline, kernel.FilterCount())
		require.Equal(t, "udp and not port 53", kernel.LastFilter())
		require.Len(t, app.GetFilters(), 2)
		require.Equal(t, pattern, app.GetFilters()[0].Pattern)
	}
	_, err = target.RemoveFilter("ip")
	require.NoError(t, err)
	require.Equal(t, baseline, kernel.FilterCount())
	require.Len(t, app.GetFilters(), 1)
	_, err = target.ApplyFilter(&management.Filter{Id: "explicit", Type: management.FilterType_FILTER_BPF, Pattern: "not port 54", Enabled: true})
	require.NoError(t, err)
	require.Greater(t, kernel.FilterCount(), baseline, "explicit capture policy still follows its capture boundary")
	require.Contains(t, kernel.LastFilter(), "not port 54")
}

// Disabled admission implements IP selection through classic BPF; opt-in
// admission routes IP selection to the application/controller while preserving
// exactly the same explicit port restrictions. Payload narrowing is tested in
// the kernel program separately, rather than assumed equivalent here.
func TestIPSelectorRoutingPreservesExplicitPortPacketPredicate(t *testing.T) {
	for _, applicationSelectors := range []bool{false, true} {
		t.Run(fmt.Sprint(applicationSelectors), func(t *testing.T) {
			target := NewLocalTarget(LocalTargetConfig{BaseBPF: "udp and (port 5060 or portrange 4000-4999)", ApplicationIPSelectors: applicationSelectors})
			kernel, app := &mockBPFUpdater{}, &mockAppFilterUpdater{}
			target.SetBPFUpdater(kernel)
			target.SetApplicationFilter(app)
			_, err := target.ApplyFilter(&management.Filter{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.2", Enabled: true})
			require.NoError(t, err)
			predicate, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, kernel.LastFilter())
			require.NoError(t, err)
			for _, tc := range []struct {
				destination string
				port        uint16
				want        bool
			}{
				{"192.0.2.2", 5060, true}, {"192.0.2.2", 4100, true}, {"192.0.2.2", 6000, false},
				{"198.51.100.2", 4100, applicationSelectors}, {"198.51.100.2", 6000, false},
			} {
				ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
				ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP(tc.destination)}
				udp := &layers.UDP{SrcPort: 7000, DstPort: layers.UDPPort(tc.port)}
				require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
				buf := gopacket.NewSerializeBuffer()
				require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload("ordinary UDP")))
				require.Equal(t, tc.want, predicate.Matches(gopacket.CaptureInfo{CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()), "destination=%s port=%d", tc.destination, tc.port)
			}
			if applicationSelectors {
				require.Len(t, app.GetFilters(), 1)
			} else {
				require.Empty(t, app.GetFilters())
			}
		})
	}
}
