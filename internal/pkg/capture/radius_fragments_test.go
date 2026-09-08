package capture

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Exercise the actual loop used by live capture with an offline libpcap handle.
func runFragmentCapture(t *testing.T, packets [][]byte, linkType layers.LinkType, options ...CaptureOptions) []PacketInfo {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fragments.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(f)
	require.NoError(t, writer.WriteFileHeader(65535, linkType))
	for i, raw := range packets {
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 123000), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	require.NoError(t, f.Close())
	handle, err := pcap.OpenOffline(path)
	require.NoError(t, err)
	defer handle.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buffer := NewPacketBuffer(ctx, len(packets)+1)
	defer buffer.Close()
	captureFromInterface(ctx, &mockPcapInterface{name: "fragment-mirror", handle: handle}, "", buffer, NewIPv4Defragmenter(), NewIPv6Defragmenter(), newTelemetryCollector(nil), &sync.Mutex{}, options...)
	buffer.CloseInputs()
	var result []PacketInfo
	for info := range buffer.Receive() {
		result = append(result, info)
	}
	return result
}

func udpFragmentFrames(t *testing.T, ipv6 bool, port uint16, payload []byte) [][]byte {
	t.Helper()
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], port)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	var result [][]byte
	for i, part := range [][]byte{udp[:24], udp[24:]} {
		b := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if ipv6 {
			ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolIPv6Fragment, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
			fragment := make([]byte, 8)
			fragment[0] = byte(layers.IPProtocolUDP)
			binary.BigEndian.PutUint32(fragment[4:], 42)
			if i == 0 {
				fragment[3] = 1
			} else {
				binary.BigEndian.PutUint16(fragment[2:], 24)
			}
			require.NoError(t, gopacket.SerializeLayers(b, opts, ip, gopacket.Payload(append(fragment, part...))))
		} else {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, Id: 42, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
			if i == 0 {
				ip.Flags = layers.IPv4MoreFragments
			} else {
				ip.FragOffset = 3
			}
			require.NoError(t, gopacket.SerializeLayers(b, opts, ip, gopacket.Payload(part)))
		}
		result = append(result, append([]byte(nil), b.Bytes()...))
	}
	return result
}

func TestRADIUSLiveCapturePreservesFragments(t *testing.T) {
	message := make([]byte, 20)
	message[0] = 1
	message[1] = 7
	message = append(message, 1, 7, 'a', 'l', 'i', 'c', 'e')
	binary.BigEndian.PutUint16(message[2:], uint16(len(message)))
	for _, ipv6 := range []bool{false, true} {
		for _, port := range []uint16{1812, 2812} {
			for _, reverse := range []bool{false, true} {
				frames := udpFragmentFrames(t, ipv6, port, message)
				if reverse {
					frames[0], frames[1] = frames[1], frames[0]
				}
				captured := runFragmentCapture(t, frames, layers.LinkTypeRaw)
				require.Len(t, captured, 2)
				observer, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "capture-test"}, port)
				require.NoError(t, err)
				for i, info := range captured {
					require.Equal(t, frames[i], info.Packet.Data())
					// libpcap maps LINKTYPE_RAW (101) to the platform DLT_RAW (12).
					require.Contains(t, []layers.LinkType{layers.LinkTypeRaw, layers.LinkType(12)}, info.LinkType)
					require.Equal(t, time.Unix(1700000000+int64(i), 123000), info.Packet.Metadata().Timestamp)
					require.Equal(t, len(frames[i]), info.Packet.Metadata().CaptureLength)
					require.Nil(t, observer.Process(info.Packet, info.LinkType, info.Interface, nil))
				}
				validation, correlation := observer.Stats()
				observer.Close()
				require.EqualValues(t, 2, validation.Fragmented)
				require.Zero(t, correlation.Requests)
			}
		}
	}
}

func TestLiveCaptureVoIPFragmentReassemblyOptIn(t *testing.T) {
	payload := []byte("INVITE sip:alice@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	for _, ipv6 := range []bool{false, true} {
		frames := udpFragmentFrames(t, ipv6, 5060, payload)
		for _, option := range []CaptureOptions{{ReassembleIPFragments: true}, {ReassembleIPFragmentsWhen: func() bool { return true }}} {
			captured := runFragmentCapture(t, frames, layers.LinkTypeRaw, option)
			require.Len(t, captured, 1)
			udp, ok := captured[0].Packet.TransportLayer().(*layers.UDP)
			require.True(t, ok)
			require.Equal(t, payload, udp.Payload)
		}
		captured := runFragmentCapture(t, frames, layers.LinkTypeRaw, CaptureOptions{ReassembleIPFragments: true, ReassembleIPFragmentsWhen: func() bool { return false }})
		require.Len(t, captured, 2)
		for i := range frames {
			require.Equal(t, frames[i], captured[i].Packet.Data())
		}
	}
}

func TestRADIUSLiveCaptureAcceptanceFragments(t *testing.T) {
	f, err := os.Open("../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var frames [][]byte
	for {
		raw, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		frames = append(frames, raw)
	}
	require.NoError(t, f.Close())
	require.Len(t, frames, 26)
	captured := runFragmentCapture(t, frames, reader.LinkType())
	require.Len(t, captured, len(frames))
	for i, info := range captured {
		require.Equal(t, frames[i], info.Packet.Data(), "record %d", i+1)
	}
	observer, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "acceptance"})
	require.NoError(t, err)
	defer observer.Close()
	// The last two records are an incomplete IPv4 first fragment and an IPv6
	// atomic fragment. Neither may disappear or become an admissible observation.
	for _, info := range captured[24:] {
		require.Nil(t, observer.Process(info.Packet, info.LinkType, info.Interface, nil))
	}
	validation, correlation := observer.Stats()
	require.EqualValues(t, 2, validation.Fragmented)
	require.Zero(t, correlation.Requests)
}
