//go:build hunter || all

package capture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

func TestProcessorListExclusionsPreserveUnrelatedTraffic(t *testing.T) {
	m := New(Config{Processors: []failover.Endpoint{{Address: "192.0.2.10:443"}, {Address: "[2001:db8::1]:8443"}}}, context.Background())
	filter := m.buildProcessorPortExclusionFilter()
	bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, filter)
	require.NoError(t, err)
	packet := func(destination string, port uint16, udp bool) []byte {
		t.Helper()
		ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.20"), DstIP: net.ParseIP(destination), Protocol: layers.IPProtocolTCP}
		var transport gopacket.SerializableLayer
		if udp {
			ip.Protocol = layers.IPProtocolUDP
			u := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(port)}
			require.NoError(t, u.SetNetworkLayerForChecksum(ip))
			transport = u
		} else {
			tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(port), SYN: true}
			require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
			transport = tcp
		}
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, transport))
		return buffer.Bytes()
	}
	for _, tc := range []struct {
		address string
		port    uint16
		udp     bool
		capture bool
	}{{"192.0.2.10", 443, false, false}, {"192.0.2.11", 443, false, true}, {"192.0.2.10", 8443, false, true}, {"192.0.2.10", 443, true, true}} {
		data := packet(tc.address, tc.port, tc.udp)
		require.Equal(t, tc.capture, bpf.Matches(gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, data), "destination %s:%d udp=%v", tc.address, tc.port, tc.udp)
	}
}

func TestProcessorDNSExclusionRefreshAndFailure(t *testing.T) {
	endpoint := failover.Endpoint{Address: "relay.example:443"}
	address := netip.MustParseAddr("192.0.2.10")
	var lookupErr error
	m := New(Config{Processors: []failover.Endpoint{endpoint}, ResolveProcessor: func(ctx context.Context, host string) ([]netip.Addr, error) {
		require.Equal(t, "relay.example", host)
		if lookupErr != nil {
			return nil, lookupErr
		}
		return []netip.Addr{address}, nil
	}}, context.Background())
	require.NoError(t, m.PrepareProcessor(context.Background(), endpoint, nil))
	require.Contains(t, m.buildProcessorPortExclusionFilter(), "host 192.0.2.10")
	address = netip.MustParseAddr("192.0.2.11")
	require.NoError(t, m.PrepareProcessor(context.Background(), endpoint, nil))
	require.Contains(t, m.buildProcessorPortExclusionFilter(), "host 192.0.2.11")
	require.NotContains(t, m.buildProcessorPortExclusionFilter(), "192.0.2.10")
	lookupErr = errors.New("unavailable DNS")
	require.ErrorContains(t, m.PrepareProcessor(context.Background(), endpoint, nil), "unavailable DNS")
	require.Contains(t, m.buildProcessorPortExclusionFilter(), "host 192.0.2.11")
}
