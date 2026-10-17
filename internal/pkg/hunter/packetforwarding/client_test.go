//go:build hunter || all

package packetforwarding

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type stalledRawSend struct {
	grpc.ClientStream
	ctx context.Context
}

func (s stalledRawSend) Send(*data.ReliablePacketMessage) error {
	<-s.ctx.Done()
	return s.ctx.Err()
}
func (s stalledRawSend) Recv() (*data.ReliablePacketControl, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func TestStalledRawSendCancelsRPCWithoutRetiringOrigin(t *testing.T) {
	for _, losses := range []bool{false, true} {
		t.Run(map[bool]string{false: "batch", true: "loss"}[losses], func(t *testing.T) {
			config := packetspool.Config{Directory: filepath.Join(t.TempDir(), "spool"), SourceID: "hunter", DestinationID: "central", AckScope: "central", Protection: "private", MaxRecords: 1, Policy: packetspool.DropNew}
			require.NoError(t, packetspool.Initialize(config))
			spool, err := packetspool.Open(config)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, spool.Close()) })
			_, err = spool.Enqueue(&data.PacketBatch{HunterId: "hunter", Packets: []*data.CapturedPacket{{Data: []byte{1}}}})
			require.NoError(t, err)
			if losses {
				_, err = spool.Enqueue(&data.PacketBatch{HunterId: "hunter", Packets: []*data.CapturedPacket{{Data: []byte{2}}}})
				require.NoError(t, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			id := spool.Identity()
			stream := &Stream{ReliablePacketService_StreamReliablePacketsClient: stalledRawSend{ctx: ctx}, spool: spool, identity: &data.RawPacketIdentity{SourceId: id.SourceID, ProducerSessionId: id.SessionID, CaptureEpoch: id.CaptureEpoch, DestinationId: id.DestinationID, AckScope: id.AckScope}, cancel: cancel}
			done := make(chan error, 1)
			go func() {
				_, err := stream.SendNext(ctx, func(context.Context) error { return nil }, 10*time.Millisecond)
				done <- err
			}()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(3 * time.Second):
				t.Fatal("stalled send did not release its RPC")
			}
			require.Equal(t, 1, spool.Status().PendingRecords)
			require.Zero(t, spool.Status().AckedSequence)
		})
	}
}
