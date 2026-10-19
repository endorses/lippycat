//go:build processor || tap || all

package processor

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unnegotiatedEvidenceBatch(source string) *data.PacketBatch {
	return &data.PacketBatch{HunterId: source, Sequence: 1, TimestampNs: time.Now().UnixNano(), Packets: []*data.CapturedPacket{{Data: make([]byte, 64), TimestampNs: time.Now().UnixNano(), CaptureLength: 64, OriginalLength: 64, LinkType: 1, LearnedCaptureEvidence: &evidence.LearnedCaptureEvidence{Version: 1, Overflow: true}}}}
}
func TestTypedDirectEvidenceRequiresAuthenticatedReadiness(t *testing.T) {
	for _, offer := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-no-offer", true: "typed-offer"}[offer], func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0"})
			require.NoError(t, err)
			_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{HunterId: "hunter.test"})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := data.NewDataServiceClient(relayTestConnection(t, p, "hunter.test")).StreamPackets(ctx)
			require.NoError(t, err)
			open := &data.PacketBatch{HunterId: "hunter.test"}
			if offer {
				open.LearnedEvidenceVersions = []uint32{1}
			}
			require.NoError(t, stream.Send(open))
			ready, err := stream.Recv()
			require.NoError(t, err)
			if offer {
				require.Equal(t, []uint32{1}, ready.LearnedEvidenceVersions)
			} else {
				require.Empty(t, ready.LearnedEvidenceVersions)
				require.NoError(t, stream.Send(unnegotiatedEvidenceBatch("hunter.test")))
				_, err = stream.Recv()
				require.Equal(t, codes.FailedPrecondition, status.Code(err))
				require.Zero(t, p.packetsReceived.Load())
			}
		})
	}
}
func TestTypedRelayEvidenceCannotBypassReadiness(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", RelayOrigins: map[string][]string{"relay.test": {"edge"}}})
	require.NoError(t, err)
	require.NoError(t, p.downstreamManager.Register("relay.test", "127.0.0.1:1", "test"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := data.NewRelayDataServiceClient(relayTestConnection(t, p, "relay.test")).StreamRelayPackets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1}))
	ready, err := stream.Recv()
	require.NoError(t, err)
	require.Empty(t, ready.LearnedEvidenceVersions)
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1, Batch: unnegotiatedEvidenceBatch("edge")}))
	_, err = stream.Recv()
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, p.packetsReceived.Load())
}
func TestTypedReliableEvidenceRefusedBeforeCustodyWithoutOffer(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	config := reliableMediaConfiguration(t, pki, certificate, key)
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	address := serveRelayTestProcessor(t, p, pair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "central", AckScope: "central"}
	stream := openReliableMediaStream(t, ctx, address, pki, id)
	batch := unnegotiatedEvidenceBatch(id.SourceId)
	batch.ProducerSessionId = id.ProducerSessionId
	batch.CaptureEpoch = id.CaptureEpoch
	require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch}))
	_, err = stream.Recv()
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	pending, err := p.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Empty(t, pending)
}
