package eventanalysis

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/stretchr/testify/require"
)

func echHello() []byte {
	hello := testClientHello()
	// Empty extensions vector is at the end of this controlled fixture.
	binary.BigEndian.PutUint16(hello[len(hello)-2:], 7)
	hello = append(hello, 0xfe, 0x0d, 0, 3, 0, 1, 2)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	size := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(size>>16), byte(size>>8), byte(size)
	return hello
}

func TestECHCanonicalCountsAcrossProducerModes(t *testing.T) {
	for _, captured := range []bool{false, true} {
		name := "local-tap-sniff-offline"
		if captured {
			name = "processor-packet-mode"
		}
		t.Run(name, func(t *testing.T) {
			r, dispatcher, sink := testRuntime(t, 64)
			defer r.Close()
			source := Source{NodeID: "authority", CaptureSource: "fixture"}
			base := time.Unix(100, 0)
			observe := func(info capture.PacketInfo) {
				t.Helper()
				if captured {
					raw := &data.CapturedPacket{Data: info.Packet.Data(), TimestampNs: info.Packet.Metadata().Timestamp.UnixNano(), LinkType: uint32(info.LinkType), Metadata: protocolmeta.Enrich(info.Packet, nil, false)}
					require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{raw}))
				} else {
					require.NoError(t, r.ObservePacket(source, info))
				}
			}
			observe(tcpPacket(t, 40000, 443, 1000, true, nil, base))
			hello := echHello()
			// Split both TLS records and TCP segments. Retry the first segment.
			a := append([]byte{22, 3, 1, 0, 20}, hello[5:25]...)
			b := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(hello)-25))
			b = append(b, hello[25:]...)
			first := tcpPacket(t, 40000, 443, 1001, false, a, base.Add(time.Second))
			observe(first)
			observe(first)
			require.Zero(t, r.Stats().TLSClientHelloCount)
			observe(tcpPacket(t, 40000, 443, 1001+uint32(len(a)), false, b, base.Add(2*time.Second)))
			// A second valid hello at a new stream position is another observation,
			// even on the same connection; TCP replay of the same bytes is not.
			plain := testClientHello()
			seq := 1001 + uint32(len(a)+len(b))
			joined := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(plain)+len(hello)-10))
			joined = append(joined, plain[5:]...)
			joined = append(joined, hello[5:]...)
			observe(tcpPacket(t, 40000, 443, seq, false, joined, base.Add(3*time.Second)))
			observe(tcpPacket(t, 40000, 443, seq, false, joined, base.Add(4*time.Second)))
			r.EOF()
			require.NoError(t, dispatcher.Close(context.Background()))
			require.Equal(t, uint64(3), r.Stats().TLSClientHelloCount)
			require.Equal(t, uint64(2), r.Stats().TLSECHOfferedCount)
			var total, offered uint64
			for _, event := range sink.events {
				if event, ok := event.(events.TLSEvent); ok {
					total += event.ClientHelloCount
					offered += event.ECHOfferedCount
				}
			}
			require.Equal(t, uint64(3), total)
			require.Equal(t, uint64(2), offered)
		})
	}
}

func TestECHLegacyMetadataAndServerOnlyStayUnknown(t *testing.T) {
	for _, metadata := range []*data.TLSMetadata{
		{HandshakeType: "ClientHello", Ja3: "legacy", EchOffered: true},
		{HandshakeType: "ServerHello", IsServer: true},
		{HandshakeType: "Certificate"},
	} {
		event := MapTLS(events.Envelope{}, metadata)
		require.Zero(t, event.ClientHelloCount)
		require.Zero(t, event.ECHOfferedCount)
	}
}
