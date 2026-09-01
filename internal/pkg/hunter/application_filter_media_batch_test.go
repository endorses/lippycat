//go:build hunter || tap || all

package hunter

import (
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// TestApplicationFilterMatchBatchSkipsIdentityMatchingForMedia covers the
// batch-specific extraction path. The media payloads deliberately contain a
// syntactically valid SIP identity header after their binary protocol header;
// classification, rather than an incidental parse miss, must keep them out of
// SIP identity matching.
func TestApplicationFilterMatchBatchSkipsIdentityMatchingForMedia(t *testing.T) {
	filter, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	filter.UpdateFilters([]*management.Filter{{
		Id:      "synthetic-sip-user",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "synthetic-target",
	}})

	rtpPayload := make([]byte, 172)
	rtpPayload[0] = 0x80
	rtpPayload[1] = 0x00
	rtpPayload[2], rtpPayload[3] = 0, 1
	rtpPayload[4], rtpPayload[5], rtpPayload[6], rtpPayload[7] = 0, 0, 1, 0x40
	rtpPayload[8], rtpPayload[9], rtpPayload[10], rtpPayload[11] = 0x12, 0x34, 0x56, 0x78
	copy(rtpPayload[12:], "\r\nFrom: <sip:synthetic-target@example.invalid>\r\n\r\n")

	// The centralized detector currently reports this minimal RTCP sender
	// report through its RTP classification path.
	rtcpPayload := []byte{0x80, 200, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	packets := []gopacket.Packet{
		serializeMediaBatchPacket(t, 10000, 20000, rtpPayload),
		serializeMediaBatchPacket(t, 10001, 20001, rtcpPayload),
		serializeMediaBatchPacket(t, 5060, 5060, []byte("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:synthetic-target@example.invalid>\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: synthetic-call\r\nContent-Length: 0\r\n\r\n")),
	}

	for i := 0; i < 2; i++ {
		classification := filter.detector.Detect(packets[i])
		require.NotNil(t, classification)
		require.Contains(t, []string{"RTP", "RTCP"}, classification.Protocol, "packet %d", i)
	}

	require.Equal(t, []bool{false, false, true}, filter.MatchBatch(packets))
}

func TestApplicationFilterMatchBatchHonorsNonVoIPFilters(t *testing.T) {
	filter, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	filter.UpdateFilters([]*management.Filter{{
		Id:      "synthetic-source",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.0.2.10",
	}})

	packet := serializeMediaBatchPacket(t, 10000, 20000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	require.Equal(t, []bool{true}, filter.MatchBatch([]gopacket.Packet{packet}))
}

func serializeMediaBatchPacket(t *testing.T, srcPort, dstPort layers.UDPPort, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip,
		udp,
		gopacket.Payload(payload),
	))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
