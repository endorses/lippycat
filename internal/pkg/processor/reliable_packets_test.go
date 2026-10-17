//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

func TestCentralRawReceiptSurvivesAlternativeRelaysAndDeduplicatesBeforeAnalysis(t *testing.T) {
	pki := newRelayTestPKI(t)
	centralPair, certificate, key := pki.identity(t, "central")
	store := packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "central", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxRecords: 16, MaxSessions: 4, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(store))
	central, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", TLSEnabled: true, TLSClientAuth: true, TLSCertFile: certificate, TLSKeyFile: key, TLSCAFile: pki.caFile, RelayOrigins: map[string][]string{"relay-a": {"edge-a"}, "relay-b": {"edge-a"}}, PacketCustody: PacketCustodyConfig{Enabled: true, Store: store, AuthorityID: "central", SigningCertificate: certificate, SigningKey: key}})
	require.NoError(t, err)
	address := serveRelayTestProcessor(t, central, centralPair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	central.startPacketCustody(ctx)
	out := central.subscriberManager.Add("durable-monitor")
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	id := &data.RawPacketIdentity{SourceId: "edge-a", ProducerSessionId: "durable-session", CaptureEpoch: "capture-epoch", DestinationId: "central", AckScope: "central"}
	batch := &data.PacketBatch{HunterId: "edge-a", ProducerSessionId: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: 1, TimestampNs: time.Now().UnixNano(), Packets: []*data.CapturedPacket{{Data: make([]byte, 64), CaptureLength: 64, OriginalLength: 64, LinkType: 1, InterfaceName: "eth0", TimestampNs: time.Now().UnixNano()}}}
	for index, relayID := range []string{"relay-a", "relay-b"} {
		pair, certificate, key := pki.identity(t, relayID)
		relay, err := newTestProcessor(t, Config{ProcessorID: relayID, ListenAddr: "127.0.0.1:0", UpstreamAddr: address, TLSEnabled: true, TLSClientAuth: true, TLSCAFile: pki.caFile, TLSCertFile: certificate, TLSKeyFile: key})
		require.NoError(t, err)
		relayAddress := serveRelayTestProcessor(t, relay, pair, pki.pool)
		require.NoError(t, relay.upstreamManager.Start())
		require.Eventually(t, relay.upstreamManager.IsConnected, 5*time.Second, 5*time.Millisecond)
		pair, _, _ = pki.identity(t, "edge-a")
		conn, err := grpc.NewClient(relayAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
		require.NoError(t, err)
		_, err = management.NewManagementServiceClient(conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: "edge-a"})
		require.NoError(t, err)
		stream, err := data.NewReliablePacketServiceClient(conn).StreamReliablePackets(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id}))
		ready, err := stream.Recv()
		require.NoError(t, err)
		require.NoError(t, verifier.Verify(ready.Receipt, id, nil))
		require.Zero(t, ready.Receipt.Sequence)
		require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch}))
		receipt, err := stream.Recv()
		require.NoError(t, err)
		require.NoError(t, verifier.Verify(receipt.Receipt, id, batch))
		forged := proto.Clone(receipt.Receipt).(*data.RawPacketReceipt)
		forged.Sequence++
		require.Error(t, verifier.Verify(forged, id, nil))
		if index == 0 {
			select {
			case got := <-out:
				require.Equal(t, batch.Packets[0].Data, got.Packets[0].Data)
				require.Equal(t, id.ProducerSessionId, got.ProducerSessionId)
			case <-ctx.Done():
				t.Fatal("durably accepted raw packet not drained")
			}
		} else {
			pending, err := central.packetCustody.store.Pending(1)
			require.NoError(t, err)
			// Duplicate ingress has no pending second dispatch and the analysis
			// counter is unchanged, even though a second route returned a receipt.
			require.Empty(t, pending)
			require.Equal(t, uint64(1), central.packetsReceived.Load())
		}
		require.NoError(t, stream.CloseSend())
		require.NoError(t, conn.Close())
		require.NoError(t, relay.Shutdown())
	}
}
