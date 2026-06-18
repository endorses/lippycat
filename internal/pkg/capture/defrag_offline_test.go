package capture

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fragFrame serializes one Ethernet/IPv6/IPv6Fragment frame carrying a raw
// fragment payload.
func fragFrame(t *testing.T, src, dst net.IP, id uint32, offsetUnits uint16, more bool, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolIPv6Fragment,
		SrcIP:      src,
		DstIP:      dst,
	}
	// IPv6 Fragment extension header (8 bytes): gopacket's IPv6Fragment is not
	// a SerializableLayer, so build it by hand.
	//   [0] next header  [1] reserved
	//   [2:4] fragment offset (13 bits) << 3 | M flag (bit 0)
	//   [4:8] identification
	fragHdr := make([]byte, 8)
	fragHdr[0] = byte(layers.IPProtocolUDP)
	moreBit := uint16(0)
	if more {
		moreBit = 1
	}
	binary.BigEndian.PutUint16(fragHdr[2:4], (offsetUnits<<3)|moreBit)
	binary.BigEndian.PutUint32(fragHdr[4:8], id)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip6, gopacket.Payload(append(fragHdr, payload...))))
	return buf.Bytes()
}

// TestReadAllPacketsFromDevice_ReassemblesIPv6Fragments verifies that the
// offline capture path reassembles a fragmented IPv6 UDP/SIP datagram so the
// SDP body (which lands in the second fragment) is available to downstream
// detection. This is the offline analogue of the live-path defrag and the fix
// for RTP-only calls caused by fragmented SIP INVITE/200 OK over IPv6.
func TestReadAllPacketsFromDevice_ReassemblesIPv6Fragments(t *testing.T) {
	src := net.ParseIP("2a03:9ec0:fc81::1b")
	dst := net.ParseIP("2a03:9ec0::8c")

	// SIP INVITE whose SDP (c=/m=) sits past the first-fragment boundary.
	headers := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2a03:9ec0:fc81::1b]:5060\r\n" +
		"Call-ID: frag-test-call-id-9988\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		strings.Repeat("X-Pad: padding-to-push-sdp-into-second-fragment\r\n", 30)
	sdp := "\r\nv=0\r\no=- 1 1 IN IP6 2a03:9ec0:fc81::1f\r\n" +
		"c=IN IP6 2a03:9ec0:fc81::1f\r\nm=audio 41024 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n"
	sip := headers + sdp

	// Build the UDP datagram (8-byte header + SIP payload).
	udp := make([]byte, 8+len(sip))
	binary.BigEndian.PutUint16(udp[0:2], 5060)
	binary.BigEndian.PutUint16(udp[2:4], 5060)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], sip)

	// Split on an 8-byte boundary, before the SDP, so the SDP is in fragment 2.
	splitAt := (8 + len(headers) - 40) &^ 7 // multiple of 8, inside the headers
	require.Greater(t, splitAt, 0)
	require.Equal(t, 0, splitAt%8)
	first, second := udp[:splitAt], udp[splitAt:]

	id := uint32(0xC0FFEE)
	frame1 := fragFrame(t, src, dst, id, 0, true, first)
	frame2 := fragFrame(t, src, dst, id, uint16(splitAt/8), false, second)

	// Write both fragment frames to a temp pcap.
	tmp, err := os.CreateTemp(t.TempDir(), "frag-*.pcap")
	require.NoError(t, err)
	w := pcapgo.NewWriter(tmp)
	require.NoError(t, w.WriteFileHeader(65536, layers.LinkTypeEthernet))
	now := time.Now()
	for _, fr := range [][]byte{frame1, frame2} {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     now,
			CaptureLength: len(fr),
			Length:        len(fr),
		}, fr))
	}
	_, err = tmp.Seek(0, io.SeekStart)
	require.NoError(t, err)

	// Read through the production offline path.
	dev := pcaptypes.CreateOfflineInterface(tmp)
	packets, err := readAllPacketsFromDevice(dev, "")
	require.NoError(t, err)

	// Exactly one reassembled UDP/SIP packet should carry the full SDP.
	var reassembled int
	for _, p := range packets {
		udpLayer := p.Packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		full := string(udpLayer.LayerPayload())
		if !strings.Contains(full, "frag-test-call-id-9988") {
			continue
		}
		reassembled++
		assert.Contains(t, full, "m=audio 41024", "SDP media line must survive reassembly")
		assert.Contains(t, full, "c=IN IP6 2a03:9ec0:fc81::1f", "SDP connection line must survive reassembly")
		assert.Equal(t, len(sip), len(full), "reassembled payload should equal the original SIP message")
	}
	assert.Equal(t, 1, reassembled, "expected exactly one reassembled SIP datagram")
}
