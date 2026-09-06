package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestBorrowedPacketBytesDoNotEscapeReassembly(t *testing.T) {
	hello := testClientHello()
	base := time.Unix(100, 0)
	run := func(poison bool) events.TLSEvent {
		r, d, sink := testRuntime(t, 32)
		defer r.Close()
		source := Source{NodeID: "node", CaptureSource: "pcap", InputFile: "fixture"}
		// The tail is queued before the middle arrives. Both the parser's
		// partial prefix and the assembler's queued bytes outlive callbacks.
		for i, part := range []struct {
			seq     uint32
			syn     bool
			payload []byte
		}{
			{1000, true, nil},
			{1001, false, hello[:7]},
			{1021, false, hello[20:]},
			{1008, false, hello[7:20]},
		} {
			info := tcpPacket(t, 40000, 443, part.seq, part.syn, part.payload, base.Add(time.Duration(i)*time.Second))
			require.NoError(t, r.ObservePacket(source, info))
			if poison {
				clear(info.Packet.Data())
			}
		}
		r.EOF()
		require.NoError(t, d.Close(context.Background()))
		var found []events.TLSEvent
		for _, ev := range sink.events {
			if tls, ok := ev.(events.TLSEvent); ok {
				tls.EventEnvelope.UID = ""
				tls.EventEnvelope.EventID = ""
				tls.EventEnvelope.ProducerSessionID = ""
				found = append(found, tls)
			}
		}
		require.Len(t, found, 1)
		return found[0]
	}
	require.Equal(t, run(false), run(true))
}
