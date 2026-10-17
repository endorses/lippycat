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
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

func reliableMediaConfiguration(t *testing.T, pki relayTestPKI, certificate, key string) Config {
	t.Helper()
	store := packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "central", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxRecords: 16, MaxSessions: 4, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(store))
	return Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t), TLSEnabled: true, TLSClientAuth: true, TLSCertFile: certificate, TLSKeyFile: key, TLSCAFile: pki.caFile,
		PacketCustody: PacketCustodyConfig{Enabled: true, Store: store, AuthorityID: "central", SigningCertificate: certificate, SigningKey: key},
		MediaRules:    MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []MediaSourceMapping{{HunterID: "hunter-a", Interface: "capture0", Domain: 7, HunterDomain: 1}}},
	}
}
func reliableMediaSelector(t *testing.T, p *Processor) {
	t.Helper()
	_, err := p.updateManagedFilter(&management.Filter{Id: "local-alice", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	require.Empty(t, p.filterManager.GetForHunter("hunter-a"))
}
func openReliableMediaStream(t *testing.T, ctx context.Context, address string, pki relayTestPKI, id *data.RawPacketIdentity) data.ReliablePacketService_StreamReliablePacketsClient {
	t.Helper()
	pair, _, _ := pki.identity(t, id.SourceId)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	registered, err := management.NewManagementServiceClient(conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: id.SourceId})
	require.NoError(t, err)
	require.True(t, registered.Accepted)
	stream, err := data.NewReliablePacketServiceClient(conn).StreamReliablePackets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id}))
	ready, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, ready.Receipt)
	require.Zero(t, ready.Receipt.Sequence)
	return stream
}
func reliableMediaBatch(t *testing.T, id *data.RawPacketIdentity, sequence uint64) *data.PacketBatch {
	t.Helper()
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-current", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	envelope := centralEnvelope(t, id.SourceId, invite, false)
	envelope.Source.ObservationDomain = 1
	envelope.Source.ObservationDomainKnown = true
	batch := &source.PacketBatch{SourceID: id.SourceId, ProducerSessionID: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: sequence, TimestampNs: time.Now().UnixNano()}
	batch.Envelopes = append(batch.Envelopes, envelope)
	projected, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	return projected
}
func sendReliableMediaBatch(t *testing.T, stream data.ReliablePacketService_StreamReliablePacketsClient, verifier *packetreceipt.Verifier, id *data.RawPacketIdentity, batch *data.PacketBatch, current bool) {
	t.Helper()
	require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch, CurrentCapture: current}))
	response, err := stream.Recv()
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(response.Receipt, id, batch))
	require.Equal(t, batch.Sequence, response.Receipt.Sequence)
}
func waitReliableMediaDrain(t *testing.T, p *Processor, out <-chan *data.PacketBatch, batch *data.PacketBatch, processed uint64) {
	t.Helper()
	select {
	case received := <-out:
		require.Equal(t, batch.Sequence, received.Sequence)
		require.Equal(t, batch.Packets[0].Data, received.Packets[0].Data)
		require.Equal(t, "hunter-a", received.HunterId)
		require.Equal(t, "capture0", received.Packets[0].InterfaceName)
		require.True(t, received.Packets[0].ObservationDomainKnown)
		require.EqualValues(t, 1, received.Packets[0].ObservationDomain)
	case <-time.After(5 * time.Second):
		t.Fatal("durably accepted capture was not delivered")
	}
	require.Eventually(t, func() bool { return p.packetCustody.replayed.Load() == processed }, 5*time.Second, time.Millisecond)
	pending, err := p.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestReliableMediaBacklogCannotGainCurrentAuthorityByDuplicate(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	config := reliableMediaConfiguration(t, pki, certificate, key)
	central, err := newTestProcessor(t, config)
	require.NoError(t, err)
	reliableMediaSelector(t, central)
	address := serveRelayTestProcessor(t, central, pair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	observer := central.subscriberManager.Add("raw-evidence")
	id := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "central", AckScope: "central"}
	stream := openReliableMediaStream(t, ctx, address, pki, id)
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	backlog := reliableMediaBatch(t, id, 1)
	sendReliableMediaBatch(t, stream, verifier, id, backlog, false)
	sendReliableMediaBatch(t, stream, verifier, id, backlog, true)
	require.EqualValues(t, 1, central.packetCustody.duplicates.Load())
	require.Zero(t, central.packetsReceived.Load(), "pending backlog has not been dispatched")
	require.Empty(t, central.mediaControl.store.Snapshot().Rules)
	central.packetCustody.currentMu.Lock()
	proofs := len(central.packetCustody.current)
	central.packetCustody.currentMu.Unlock()
	require.Zero(t, proofs, "a duplicate's changed CurrentCapture flag cannot upgrade accepted authority")
	central.startPacketCustody(ctx)
	waitReliableMediaDrain(t, central, observer, backlog, 1)
	require.Empty(t, central.mediaControl.store.Snapshot().Rules, "fresh timestamps alone cannot turn reliable backlog into current call selection")
	current := reliableMediaBatch(t, id, 2)
	sendReliableMediaBatch(t, stream, verifier, id, current, true)
	waitReliableMediaDrain(t, central, observer, current, 2)
	rules := central.mediaControl.store.Snapshot().Rules
	require.NotEmpty(t, rules)
	require.Equal(t, []string{"local-alice"}, rules[0].Call.FilterIDs)
	require.Contains(t, rules[0].Scope, mediarules.Scope{HunterID: "hunter-a", Domain: 1})
	require.Empty(t, central.filterManager.GetForHunter("hunter-a"))
	require.EqualValues(t, 2, central.packetsReceived.Load(), "receipt replay does not add another raw processing attempt")
	central.packetCustody.currentMu.Lock()
	proofs = len(central.packetCustody.current)
	central.packetCustody.currentMu.Unlock()
	require.Zero(t, proofs, "processed current proofs are released")
	require.NoError(t, stream.CloseSend())
}

func TestReliableMediaRestartRetainsPendingCaptureWithoutCurrentProof(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	config := reliableMediaConfiguration(t, pki, certificate, key)
	original, err := newTestProcessor(t, config)
	require.NoError(t, err)
	reliableMediaSelector(t, original)
	address := serveRelayTestProcessor(t, original, pair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "central", AckScope: "central"}
	stream := openReliableMediaStream(t, ctx, address, pki, id)
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	accepted := reliableMediaBatch(t, id, 1)
	sendReliableMediaBatch(t, stream, verifier, id, accepted, true)
	pending, err := original.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	original.packetCustody.currentMu.Lock()
	proofs := len(original.packetCustody.current)
	original.packetCustody.currentMu.Unlock()
	require.Equal(t, 1, proofs)
	require.Zero(t, original.packetsReceived.Load(), "worker intentionally has not accepted processing ownership")
	require.NoError(t, stream.CloseSend())
	require.NoError(t, original.Shutdown())
	restarted, err := newTestProcessor(t, config)
	require.NoError(t, err)
	require.Empty(t, restarted.packetCustody.current, "volatile authority must not be reconstructed from the persisted record")
	require.Empty(t, restarted.filterManager.GetForHunter("hunter-a"))
	address = serveRelayTestProcessor(t, restarted, pair, pki.pool)
	reopened := openReliableMediaStream(t, ctx, address, pki, id)
	sendReliableMediaBatch(t, reopened, verifier, id, accepted, true)
	require.Empty(t, restarted.packetCustody.current, "even a pending duplicate cannot upgrade recovered authority")
	require.EqualValues(t, 1, restarted.packetCustody.duplicates.Load())
	observer := restarted.subscriberManager.Add("recovered-raw-evidence")
	restarted.startPacketCustody(ctx)
	waitReliableMediaDrain(t, restarted, observer, accepted, 1)
	require.Empty(t, restarted.mediaControl.store.Snapshot().Rules)
	require.Empty(t, restarted.mediaControl.tracker.Snapshot())
	require.EqualValues(t, 1, restarted.packetsReceived.Load())
	require.NoError(t, reopened.CloseSend())
}

func TestReliableMediaCurrentProofUsesFullReceiptIdentity(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	central, err := newTestProcessor(t, reliableMediaConfiguration(t, pki, certificate, key))
	require.NoError(t, err)
	reliableMediaSelector(t, central)
	address := serveRelayTestProcessor(t, central, pair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	historicalID := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "central", AckScope: "receiver"}
	currentID := proto.Clone(historicalID).(*data.RawPacketIdentity)
	currentID.AckScope = "central"
	batch := reliableMediaBatch(t, historicalID, 1)
	historicalStream := openReliableMediaStream(t, ctx, address, pki, historicalID)
	sendReliableMediaBatch(t, historicalStream, verifier, historicalID, batch, false)
	require.NoError(t, historicalStream.CloseSend())
	currentStream := openReliableMediaStream(t, ctx, address, pki, currentID)
	sendReliableMediaBatch(t, currentStream, verifier, currentID, batch, true)
	require.NoError(t, currentStream.CloseSend())

	pending, err := central.packetCustody.store.Pending(2)
	require.NoError(t, err)
	require.Len(t, pending, 2, "receipt acknowledgement scopes identify distinct durable records")
	scopes := map[string]bool{}
	for _, record := range pending {
		scopes[record.Identity.AckScope] = true
		require.EqualValues(t, 1, record.Batch.Sequence)
	}
	require.Equal(t, map[string]bool{"receiver": true, "central": true}, scopes)
	require.Zero(t, central.packetCustody.duplicates.Load(), "different acknowledgement scopes are not receipt retries")
	historicalKey := captureRecordKey(historicalID, batch.Sequence)
	currentKey := captureRecordKey(currentID, batch.Sequence)
	require.NotEqual(t, historicalKey, currentKey)
	central.packetCustody.currentMu.Lock()
	historicalProof := central.packetCustody.current[historicalKey]
	currentProof := central.packetCustody.current[currentKey]
	proofs := len(central.packetCustody.current)
	central.packetCustody.currentMu.Unlock()
	require.False(t, historicalProof, "a current record in a different acknowledgement scope cannot upgrade historical authority")
	require.True(t, currentProof)
	require.Equal(t, 1, proofs)
	require.Empty(t, central.mediaControl.store.Snapshot().Rules, "pending records have not reached current selection")
	otherDestination := proto.Clone(historicalID).(*data.RawPacketIdentity)
	otherDestination.DestinationId = "other-central"
	require.NotEqual(t, historicalKey, captureRecordKey(otherDestination, batch.Sequence), "destination identity also isolates current proof")
}
