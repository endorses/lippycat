package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
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

func TestOfflineCursorIPv6FragmentCaptureLengths(t *testing.T) {
	for _, extension := range []string{"plain", "hop-by-hop"} {
		for _, truncation := range []string{"none", "first", "final"} {
			t.Run(extension+"/"+truncation, func(t *testing.T) {
				udp := make([]byte, 40)
				binary.BigEndian.PutUint16(udp[0:2], 4000)
				binary.BigEndian.PutUint16(udp[2:4], 4001)
				binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
				copy(udp[8:], bytes.Repeat([]byte{'x'}, len(udp)-8))
				src, dst := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
				frames := [][]byte{
					fragFrame(t, src, dst, 42, 0, true, udp[:16]),
					fragFrame(t, src, dst, 42, 2, false, udp[16:]),
				}
				if extension == "hop-by-hop" {
					for i, frame := range frames {
						const ipOffset = 14
						const payloadOffset = ipOffset + 40
						withExtension := append([]byte(nil), frame[:payloadOffset]...)
						// Eight-byte hop-by-hop header followed by the fragment
						// header; the remaining option bytes are Pad1 options.
						withExtension = append(withExtension, byte(layers.IPProtocolIPv6Fragment), 0, 0, 0, 0, 0, 0, 0)
						withExtension = append(withExtension, frame[payloadOffset:]...)
						withExtension[ipOffset+6] = byte(layers.IPProtocolIPv6HopByHop)
						binary.BigEndian.PutUint16(withExtension[ipOffset+4:], uint16(len(withExtension)-payloadOffset))
						frames[i] = withExtension
					}
				}
				var out bytes.Buffer
				writer := pcapgo.NewWriter(&out)
				require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
				for i, frame := range frames {
					wireLength := len(frame)
					if truncation == "first" && i == 0 {
						frame = frame[:len(frame)-8]
					} else if truncation == "final" && i == 1 {
						frame = frame[:len(frame)-5]
					}
					require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{
						Timestamp: time.Unix(int64(100+i), 0), CaptureLength: len(frame), Length: wireLength,
					}, frame))
				}
				cursor, err := cursorFromBytes(t, out.Bytes())
				require.NoError(t, err)
				packet, err := cursor.Next(context.Background())
				if truncation != "none" {
					require.ErrorContains(t, err, "truncated IPv6 fragment")
					require.ErrorContains(t, err, cursor.path)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, packet.Packet.Layer(layers.LayerTypeUDP))
				require.Equal(t, udp[8:], packet.Packet.Layer(layers.LayerTypeUDP).LayerPayload())
				require.Equal(t, time.Unix(101, 0).UTC(), packet.Packet.Metadata().Timestamp)
				_, err = cursor.Next(context.Background())
				require.ErrorIs(t, err, io.EOF)
			})
		}
	}
}

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

func TestOfflineMergeFragmentCompletionTimestampAndSourceIsolation(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	base := time.Unix(100, 0).UTC()
	writeFragments := func(payload string, first, last time.Time) string {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:2], 5060)
		binary.BigEndian.PutUint16(udp[2:4], 5060)
		binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
		copy(udp[8:], payload)
		frames := [][]byte{
			fragFrame(t, src, dst, 42, 0, true, udp[:16]),
			fragFrame(t, src, dst, 42, 2, false, udp[16:]),
		}
		name := filepath.Join(t.TempDir(), "same.pcap")
		file, err := os.Create(name)
		require.NoError(t, err)
		writer := pcapgo.NewWriter(file)
		require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for i, timestamp := range []time.Time{first, last} {
			require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(frames[i]), Length: len(frames[i])}, frames[i]))
		}
		require.NoError(t, file.Close())
		return name
	}
	// Identical fragment keys from distinct sources must never share state.
	first := writeFragments("first---payload1", base, base.Add(4*time.Second))
	second := writeFragments("second--payload2", base.Add(time.Second), base.Add(2*time.Second))
	ordinary := writeTimestampedTestPCAP(t, []time.Time{base.Add(3 * time.Second)})
	var got []PacketInfo
	err := RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, first, second, ordinary), "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet)
		}
	})
	require.NoError(t, err)
	require.Len(t, got, 3)
	for i, packet := range got {
		require.Equal(t, base.Add(time.Duration(i+2)*time.Second), packet.Packet.Metadata().Timestamp)
	}
	require.Equal(t, second, got[0].SourcePath)
	require.Equal(t, first, got[2].SourcePath)
	require.Equal(t, "second--payload2", string(got[0].Packet.Layer(layers.LayerTypeUDP).LayerPayload()))
	require.Equal(t, "first---payload1", string(got[2].Packet.Layer(layers.LayerTypeUDP).LayerPayload()))
	require.Equal(t, len(got[0].Packet.Data()), got[0].Packet.Metadata().CaptureLength)
}
