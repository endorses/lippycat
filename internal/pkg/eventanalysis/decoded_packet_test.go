package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/stretchr/testify/require"
)

func TestDecodedPacketMatchesTransportedAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    uint16
		payload []byte
	}{
		{"http", 80, []byte("GET /reuse HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{"http nonstandard port", 18080, []byte("GET /reuse HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{"tls", 443, testClientHello()},
		{"smtp", 25, []byte("MAIL FROM:<alice@example.test>\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Unix(100, 0)
			packets := []capture.PacketInfo{
				tcpPacket(t, 40000, tc.port, 1000, true, nil, base),
				tcpPacket(t, 40000, tc.port, 1001, false, tc.payload, base.Add(time.Second)),
				tcpPacketFlags(t, 40000, tc.port, 1001+uint32(len(tc.payload)), false, true, nil, base.Add(2*time.Second)),
			}
			observe := func(local bool) []events.Event {
				r, d, sink := testRuntime(t, 32)
				defer r.Close()
				source := Source{NodeID: "node", CaptureSource: "pcap", InputFile: "fixture.pcap", InterfaceName: "fixture"}
				for _, info := range packets {
					if local {
						require.NoError(t, r.ObservePacket(source, info))
					} else {
						require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{{
							Data: info.Packet.Data(), TimestampNs: info.Packet.Metadata().Timestamp.UnixNano(),
							LinkType: uint32(info.LinkType), Metadata: protocolmeta.Enrich(info.Packet, nil, false),
						}}))
					}
				}
				r.EOF()
				require.NoError(t, d.Close(context.Background()))
				// Flow UIDs and live producer sessions are deliberately random.
				for i, event := range sink.events {
					env := event.Envelope()
					env.UID, env.EventID, env.ProducerSessionID = "", "", ""
					switch e := event.(type) {
					case events.HTTPEvent:
						e.EventEnvelope = env
						sink.events[i] = e
					case events.TLSEvent:
						e.EventEnvelope = env
						sink.events[i] = e
					case events.SMTPEvent:
						e.EventEnvelope = env
						sink.events[i] = e
					case events.ConnEvent:
						e.EventEnvelope = env
						sink.events[i] = e
					default:
						t.Fatalf("unexpected event %T", event)
					}
				}
				return sink.events
			}
			transported := observe(false)
			require.GreaterOrEqual(t, len(transported), 2)
			require.Equal(t, transported, observe(true))
		})
	}
}
