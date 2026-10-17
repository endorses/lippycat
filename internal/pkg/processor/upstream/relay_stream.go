package upstream

import (
	"context"
	"fmt"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc"
)

// relayStream keeps origin batches intact while authenticating the immediate
// hop separately. One sender owns Send and CloseSend after generation commit.
type relayStream struct {
	data.RelayDataService_StreamRelayPacketsClient
	relayID string
}

func (s *relayStream) Send(batch *data.PacketBatch) error {
	return s.RelayDataService_StreamRelayPacketsClient.Send(&data.RelayPacketMessage{RelayId: s.relayID, ProtocolVersion: 1, Batch: batch})
}

func openRelayStream(ctx context.Context, conn *grpc.ClientConn, relayID string) (upstreamStream, error) {
	stream, err := data.NewRelayDataServiceClient(conn).StreamRelayPackets(ctx)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			if closeErr := stream.CloseSend(); closeErr != nil {
				logger.Error("Close rejected relay stream", "error", closeErr)
			}
		}
	}()
	if err := stream.Send(&data.RelayPacketMessage{RelayId: relayID, ProtocolVersion: 1}); err != nil {
		return nil, fmt.Errorf("send relay open: %w", err)
	}
	ack, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("relay open rejected: %w", err)
	}
	if ack.GetAckSequence() != 0 {
		return nil, fmt.Errorf("relay open returned unexpected acknowledgment %d", ack.GetAckSequence())
	}
	ready = true
	return &relayStream{RelayDataService_StreamRelayPacketsClient: stream, relayID: relayID}, nil
}
