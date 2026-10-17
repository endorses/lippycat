//go:build hunter || all

package packetforwarding

import (
	"io"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type recordingCaptureSend struct {
	grpc.ClientStream
	messages []*data.ReliablePacketMessage
}

func (s *recordingCaptureSend) Recv() (*data.ReliablePacketControl, error) { return nil, io.EOF }

func (s *recordingCaptureSend) Send(message *data.ReliablePacketMessage) error {
	s.messages = append(s.messages, message)
	return nil
}

func TestConnectionBacklogIsNeverCurrentCaptureAuthority(t *testing.T) {
	raw := &recordingCaptureSend{}
	id := &data.RawPacketIdentity{SourceId: "hunter", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "processor", AckScope: "receiver"}
	stream := &Stream{ReliablePacketService_StreamReliablePacketsClient: raw, identity: id, backlogThrough: 2}
	batch := &data.PacketBatch{HunterId: id.SourceId, ProducerSessionId: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: 2, Packets: []*data.CapturedPacket{{Data: []byte{1}, ObservationDomain: 7, ObservationDomainKnown: true}}}
	digest, err := packetreceipt.BatchDigest(batch)
	require.NoError(t, err)
	require.NoError(t, stream.Send(batch))
	require.False(t, raw.messages[0].CurrentCapture)
	batch.Sequence = 3
	require.NoError(t, stream.Send(batch))
	require.True(t, raw.messages[1].CurrentCapture)
	stream.backlogThrough = 3 // A replacement connection observes this pending batch.
	require.NoError(t, stream.Send(batch))
	require.False(t, raw.messages[2].CurrentCapture)
	batch.Sequence = 2
	after, err := packetreceipt.BatchDigest(batch)
	require.NoError(t, err)
	require.Equal(t, digest, after, "live/backlog classification must not mutate custody receipt identity or packet provenance")
}
