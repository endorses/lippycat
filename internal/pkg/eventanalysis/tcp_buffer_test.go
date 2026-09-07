package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestRuntimeTLSFramesAfterDrainingBuffer(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 32)
	defer r.Close()
	base := time.Unix(100, 0)
	source := Source{NodeID: "node", CaptureSource: "fixture"}
	require.NoError(t, r.ObservePacket(source, tcpPacket(t, 40000, 443, 1000, true, nil, base)))
	hello := testClientHello()
	application := []byte{23, 3, 3, 0, 3, 1, 2, 3}
	seq := uint32(1001)
	// The first handshake and application record drain their buffers. The next
	// handshake spans callbacks, exercising reuse followed by partial retention.
	for i, payload := range [][]byte{hello, application, hello[:7], hello[7:]} {
		require.NoError(t, r.ObservePacket(source, tcpPacket(t, 40000, 443, seq, false, payload, base.Add(time.Duration(i+1)*time.Second))))
		seq += uint32(len(payload))
	}
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))
	var tlsEvents []events.TLSEvent
	for _, event := range sink.events {
		if tlsEvent, ok := event.(events.TLSEvent); ok {
			tlsEvents = append(tlsEvents, tlsEvent)
		}
	}
	require.Len(t, tlsEvents, 2)
	require.Equal(t, "TLS 1.2", tlsEvents[0].Version)
	require.Equal(t, base.Add(time.Second), tlsEvents[0].Envelope().Timestamp)
	require.Equal(t, base.Add(4*time.Second), tlsEvents[1].Envelope().Timestamp)
	tlsEvents[1].EventEnvelope = tlsEvents[0].EventEnvelope
	require.Equal(t, tlsEvents[0], tlsEvents[1])
}

func BenchmarkTLSApplicationBufferReuse(b *testing.B) {
	frame := make([]byte, 16389)
	frame[0], frame[1], frame[2], frame[3] = 23, 3, 3, 64
	s := &applicationStream{}
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.buffer = append(s.buffer, frame...)
		s.parseTLS()
	}
}
