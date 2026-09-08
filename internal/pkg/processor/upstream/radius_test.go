package upstream

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type radiusRecordingStream struct {
	detectingStream
	received chan *data.PacketBatch
}

func (s *radiusRecordingStream) Send(b *data.PacketBatch) error {
	wire, err := proto.Marshal(b)
	if err != nil {
		return err
	}
	out := &data.PacketBatch{}
	if err := proto.Unmarshal(wire, out); err != nil {
		return err
	}
	s.received <- out
	return nil
}
func TestRADIUSUpstreamPreservesCaptureOrigin(t *testing.T) {
	f, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	raw, ci, err := r.ReadPacketData()
	require.NoError(t, err)
	scope := radius.CaptureScope{OriginNodeID: "original", SourceID: "mirror", Epoch: [16]byte{1}}
	o, _, err := radius.DecodePacket(raw, r.LinkType(), ci, scope, radius.Identity{Epoch: scope.Epoch, Sequence: 1})
	require.NoError(t, err)
	packet := &data.CapturedPacket{Data: raw, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(r.LinkType()), Radius: grpcadapter.RADIUSToProto(o)}
	in := &data.PacketBatch{HunterId: "relay", Sequence: 5, Packets: []*data.CapturedPacket{packet}}
	var forwarded atomic.Uint64
	m := NewManager(Config{OutboundQueueSize: 2}, &forwarded)
	stream := &radiusRecordingStream{received: make(chan *data.PacketBatch, 1)}
	generation := startTestGeneration(m, stream, 2)
	defer stopTestGeneration(generation)
	m.Forward(in)
	select {
	case out := <-stream.received:
		require.True(t, proto.Equal(in, out))
		validated, err := grpcadapter.RADIUSFromProto(out.Packets[0])
		require.NoError(t, err)
		require.Equal(t, scope, validated.Scope)
		require.Equal(t, raw, validated.Packet)
		require.Equal(t, r.LinkType(), validated.Capture.LinkType)
	case <-time.After(time.Second):
		t.Fatal("upstream packet missing")
	}
}
