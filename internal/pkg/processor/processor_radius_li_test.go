//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestRADIUSStreamSourceRequiresVerifiedCertificateIdentity(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"hunter.example.invalid"}}
	for _, test := range []struct {
		name   string
		state  tls.ConnectionState
		source string
		want   bool
	}{
		{"verified", tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, "hunter.example.invalid", true},
		{"unverified", tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, "hunter.example.invalid", false},
		{"wrong origin", tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, "other.example.invalid", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: test.state}})
			require.Equal(t, test.want, radiusStreamSourceTrusted(ctx, test.source))
		})
	}
	require.False(t, radiusStreamSourceTrusted(context.Background(), "hunter"))
}

func TestRADIUSProcessorAdmissionRequiresInternalOriginTrust(t *testing.T) {
	packets := radiusOutputFixtures(t)
	p := &Processor{config: Config{ProcessorID: "test"}}
	p.liManager = li.NewManager(li.ManagerConfig{Enabled: true}, nil)
	p.normalizeRADIUS("hunter", packets)
	o, err := grpcadapter.RADIUSFromProto(packets[0])
	require.NoError(t, err)
	o.Scope.OperatorScope = "operator"
	o.Scope.ProfileRevision = "v1"
	var username string
	for _, a := range o.Message.Attributes {
		if a.Type == 1 {
			username = string(a.Value)
		}
	}
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	task := &li.InterceptTask{XID: uuid.New(), Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: username}}, DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{did}, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}
	require.NoError(t, p.liManager.ActivateTask(task))
	active, err := p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	fm := li.NewFilterManager(nil)
	filters, err := fm.CreateFiltersForTask(active)
	require.NoError(t, err)
	require.Len(t, filters, 1)
	group, ok := fm.LookupRADIUSGroup(filters[0])
	require.True(t, ok)
	ref, matched, err := group.Match(o)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, active.ActivationGeneration, ref.TaskGeneration)
	o.Direct = []radius.AttributionReference{ref}
	packets[0].Radius = grpcadapter.RADIUSToProto(o)
	got := 0
	p.liManager.SetPacketProcessor(func(_ *li.InterceptTask, _ *types.PacketDisplay) { got++ })
	display := &types.PacketDisplay{RawData: o.Packet, Timestamp: o.Capture.Timestamp, Protocol: "RADIUS"}
	batch := source.FromProtoBatch(&data.PacketBatch{HunterId: o.Scope.OriginNodeID, Packets: packets})
	p.processLIRADIUSPacket(display, packets[0], batch)
	require.Zero(t, got)
	batch.RADIUSSourceTrusted = true
	batch.SourceID = "wrong"
	p.processLIRADIUSPacket(display, packets[0], batch)
	require.Zero(t, got)
	batch.SourceID = o.Scope.OriginNodeID
	p.processLIRADIUSPacket(display, packets[0], batch)
	require.Equal(t, 1, got)
	wire, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	restored := source.FromProtoBatch(wire)
	require.False(t, restored.RADIUSSourceTrusted)
}

func TestRADIUSInitializedProcessorDoesNotUseVoIPEncoder(t *testing.T) {
	p, err := New(Config{ProcessorID: "radius-encoder-test", ListenAddr: "localhost:0", MaxHunters: 1, LIEnabled: true})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	packets := radiusOutputFixtures(t)
	p.normalizeRADIUS("hunter", packets)
	observation, err := grpcadapter.RADIUSFromProto(packets[0])
	require.NoError(t, err)
	observation.Scope.OperatorScope = "operator"
	observation.Scope.ProfileRevision = "v1"
	var username string
	for _, attribute := range observation.Message.Attributes {
		if attribute.Type == 1 {
			username = string(attribute.Value)
		}
	}
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	task := &li.InterceptTask{XID: uuid.New(), Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: username}}, DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{did}, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}
	require.NoError(t, p.liManager.ActivateTask(task))
	task, err = p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	filters := li.NewFilterManager(nil)
	ids, err := filters.CreateFiltersForTask(task)
	require.NoError(t, err)
	group, ok := filters.LookupRADIUSGroup(ids[0])
	require.True(t, ok)
	ref, matched, err := group.Match(observation)
	require.NoError(t, err)
	require.True(t, matched)
	observation.Direct = []radius.AttributionReference{ref}
	packet := &types.PacketDisplay{RawData: observation.Packet, Timestamp: observation.Capture.Timestamp, Protocol: "SIP", VoIPData: &types.VoIPMetadata{Method: "INVITE", CallID: "spurious", From: "sip:a@example.test", To: "sip:b@example.test"}}
	before := p.getLIEncodingStats()
	p.liManager.ProcessPacketWithProvenance(packet, li.PacketFilterProvenance{RADIUS: observation, RADIUSTrusted: true})
	require.Equal(t, uint64(1), p.liManager.Stats().PacketsMatched)
	after := p.getLIEncodingStats()
	require.Equal(t, before.X2Errors+1, after.X2Errors, "missing durable correlation storage must fail closed")
	require.Equal(t, before.X2Encoded, after.X2Encoded)
	require.Equal(t, before.X3Encoded, after.X3Encoded)
	require.Equal(t, "spurious", packet.VoIPData.CallID)
}

// These callback tests exercise lifecycle checks before potentially expensive
// allocation/encoding. The fake must never be called for stale authorization.
type radiusForbiddenAllocator struct {
	t      *testing.T
	closed bool
}

func (a *radiusForbiddenAllocator) Allocate(*radius.Observation) (uint64, error) {
	a.t.Fatal("unauthorized allocation")
	return 0, nil
}
func (a *radiusForbiddenAllocator) Close() error { a.closed = true; return nil }

func TestRADIUSDeliveryRejectsStaleGenerationAndShutdown(t *testing.T) {
	p := &Processor{config: Config{ProcessorID: "radius-lifecycle"}}
	p.liManager = li.NewManager(li.ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	task := &li.InterceptTask{XID: uuid.New(), Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "alice@example.test"}}, DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{did}, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}
	require.NoError(t, p.liManager.ActivateTask(task))
	active, err := p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	allocator := &radiusForbiddenAllocator{t: t}
	p.radiusLIAllocator = allocator
	stale := *active
	stale.ActivationGeneration++
	p.deliverLIRADIUS(&stale, &radius.Observation{})
	require.EqualValues(t, 1, p.radiusLIStats.StaleGeneration)
	p.closeLIRADIUS()
	require.True(t, allocator.closed)
	p.deliverLIRADIUS(active, &radius.Observation{})
	require.Nil(t, p.radiusLIAllocator, "shutdown must not reopen allocator")
	require.NoError(t, p.liManager.DeactivateTask(task.XID))
	p.deliverLIRADIUS(active, &radius.Observation{})
}
