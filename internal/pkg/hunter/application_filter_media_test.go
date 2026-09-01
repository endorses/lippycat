//go:build hunter || tap || all

package hunter

import (
	"net"
	"sync"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestMatchPacketLevelWithIDs(t *testing.T) {
	tests := []struct {
		name   string
		ipv6   bool
		filter string
		wantID string
		want   bool
	}{
		{name: "IPv4 source", filter: "192.0.2.10", wantID: "v4", want: true},
		{name: "IPv4 miss", filter: "203.0.113.9", want: false},
		{name: "IPv6 destination", ipv6: true, filter: "2001:db8:2::20", wantID: "v6", want: true},
		{name: "IPv6 miss", ipv6: true, filter: "2001:db8:3::30", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			af, err := NewApplicationFilter(nil)
			require.NoError(t, err)
			af.UpdateFilters([]*management.Filter{{Id: tt.wantID, Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: tt.filter}})
			matched, ids := af.MatchPacketLevelWithIDs(mediaScopePacket(t, tt.ipv6, rtpPayloadContainingSIPIdentity()))
			require.Equal(t, tt.want, matched)
			if tt.want {
				require.Equal(t, []string{tt.wantID}, ids)
			} else {
				require.Empty(t, ids)
			}
		})
	}
}

func TestMatchPacketLevelWithIDsNoFilterPolicyIsGlobal(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	packet := mediaScopePacket(t, false, rtpPayloadContainingSIPIdentity())
	matched, ids := af.MatchPacketLevelWithIDs(packet)
	require.True(t, matched)
	require.Empty(t, ids)
	af.SetNoFilterPolicy(NoFilterPolicyDeny)
	matched, ids = af.MatchPacketLevelWithIDs(packet)
	require.False(t, matched)
	require.Empty(t, ids)

	af.UpdateFilters([]*management.Filter{{Id: "identity", Type: management.FilterType_FILTER_SIP_USER, Pattern: "synthetic-user"}})
	af.SetNoFilterPolicy(NoFilterPolicyAllow)
	matched, ids = af.MatchPacketLevelWithIDs(packet)
	require.False(t, matched, "configured out-of-scope filters must disable the no-filter allowance")
	require.Empty(t, ids)
}

func TestClassifiedMediaSkipsIdentityMatchingInFullAPIs(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	filters := make([]*management.Filter, 0, 400)
	for i := 0; i < 100; i++ {
		filters = append(filters,
			&management.Filter{Id: "sip", Type: management.FilterType_FILTER_SIP_USER, Pattern: "synthetic-user"},
			&management.Filter{Id: "phone", Type: management.FilterType_FILTER_PHONE_NUMBER, Pattern: "15550102000"},
			&management.Filter{Id: "imsi", Type: management.FilterType_FILTER_IMSI, Pattern: "001010000001234"},
			&management.Filter{Id: "imei", Type: management.FilterType_FILTER_IMEI, Pattern: "990000000001234"},
		)
	}
	af.UpdateFilters(filters)
	for _, payload := range [][]byte{rtpPayloadContainingSIPIdentity(), {0x80, 200, 0, 1, 0, 0, 0, 1}} {
		packet := mediaScopePacket(t, false, payload)
		classification := af.detector.Detect(packet)
		require.NotNil(t, classification)
		require.Contains(t, []string{"RTP", "RTCP"}, classification.Protocol)
		require.False(t, af.MatchPacket(packet))
		matched, ids := af.MatchPacketWithIDs(packet)
		require.False(t, matched)
		require.Empty(t, ids)
		matched, ids = af.MatchPacketLevelWithIDs(packet)
		require.False(t, matched)
		require.Empty(t, ids)
	}
}

func TestConcurrentFullAndPacketLevelMatchingDuringFilterUpdates(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	media := mediaScopePacket(t, false, rtpPayloadContainingSIPIdentity())
	sip := mediaScopePacket(t, false, []byte("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:synthetic-user@example.invalid>\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: synthetic-call\r\nContent-Length: 0\r\n\r\n"))
	filterSets := [][]*management.Filter{
		{{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.10"}},
		{{Id: "sip", Type: management.FilterType_FILTER_SIP_USER, Pattern: "synthetic-user"}},
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			af.UpdateFilters(filterSets[i%len(filterSets)])
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			af.MatchPacket(sip)
			af.MatchPacketWithIDs(sip)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			af.MatchPacketLevelWithIDs(media)
		}
	}()
	wg.Wait()
}

func rtpPayloadContainingSIPIdentity() []byte {
	return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte("INVITE sip:synthetic-user@example.invalid SIP/2.0\r\nFrom: <sip:synthetic-user@example.invalid>\r\n\r\n")...)
}

func mediaScopePacket(t *testing.T, ipv6 bool, payload []byte) gopacket.Packet {
	t.Helper()
	udp := &layers.UDP{SrcPort: 16384, DstPort: 20000}
	var network gopacket.NetworkLayer
	var serializable gopacket.SerializableLayer
	var first gopacket.LayerType
	if ipv6 {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8:1::10"), DstIP: net.ParseIP("2001:db8:2::20")}
		network, serializable, first = ip, ip, layers.LayerTypeIPv6
	} else {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(198, 51, 100, 20)}
		network, serializable, first = ip, ip, layers.LayerTypeIPv4
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(network))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializable, udp, gopacket.Payload(payload)))
	return gopacket.NewPacket(buffer.Bytes(), first, gopacket.Default)
}
