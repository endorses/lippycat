//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capturegrant"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

// These fixtures exercise the hunter production boundary. Processor-side task
// provisioning and historical LI delivery remain separate integration tests.
type reliableGrantFixture struct {
	*reliableVoIPBoundaryFixture
	publisher      *mediarules.Store
	control        mediarules.Control
	service        *wire.Service
	genericService *learnedwire.Service
	typed          bool
	snapshot       *management.SignedPolicySnapshot
	rule           mediarules.Rule
}

func reliableGrantDiagnosticAdapter() core.Adapter {
	return core.Adapter{ID: "diagnostic", Version: 1, Validate: func(b core.Binding) error {
		if string(b.Context) != "diagnostic-v1" {
			return core.ErrInvalid
		}
		return nil
	}, Authorize: func(b core.Binding) error {
		if len(b.Intents) != 1 || b.Intents[0].ID != "diagnostic-request" {
			return core.ErrAuthority
		}
		return nil
	}}
}

func newReliableGrantFixture(t *testing.T, until time.Time) *reliableGrantFixture {
	t.Helper()
	return newReliableGrantFixtureForOwner(t, until, "li", 1)
}
func newReliableGrantFixtureForOwner(t *testing.T, until time.Time, owner string, batchSize int) *reliableGrantFixture {
	t.Helper()
	return newReliableGrantFixtureForProtocol(t, until, owner, batchSize, false)
}
func newReliableGrantFixtureForProtocol(t *testing.T, until time.Time, owner string, batchSize int, typed bool) *reliableGrantFixture {
	t.Helper()
	g := &reliableGrantFixture{typed: typed}
	g.reliableVoIPBoundaryFixture = newReliableVoIPBoundaryFixture(t, func(f *reliableVoIPBoundaryFixture, server *grpc.Server, cfg *Config) {
		if owner == "shared" {
			shared := f.policyConfig
			shared.Owner = "shared"
			sharedDir := filepath.Join(t.TempDir(), "shared-private")
			require.NoError(t, os.Mkdir(sharedDir, 0700))
			shared.StateFile = filepath.Join(sharedDir, "shared-policy.state")
			require.NoError(t, filterpolicy.Initialize(shared))
			var err error
			f.verifier, err = filterpolicy.NewVerifier(shared)
			require.NoError(t, err)
			f.policyConfig = shared
			shared.SigningKeyFile = ""
			cfg.FilterPolicy = shared
		}
		now := time.Now()
		policy := &management.PolicySnapshot{ProtocolVersion: 2, Domain: f.policyConfig.Domain, AuthorityId: f.policyConfig.AuthorityID, OwnerKind: "li", Revision: 1, CaptureAuthority: []byte("opaque-consumer-authorization"), ValidFromNs: now.Add(-time.Minute).UnixNano(), ValidUntilNs: until.UnixNano(), AllowOfflineCapture: true, SourceIds: []string{"edge"}, SelectionGrants: []*management.CaptureSelectionGrant{{Id: "opaque-selection-reference", Revision: 1, ProcessorId: "receiver", Scopes: []*management.CaptureSelectionScope{{HunterId: "edge", Domain: 0}}, NotBeforeNs: now.Add(-time.Minute).UnixNano(), ExpiresAtNs: until.UnixNano(), Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA}}}
		policy.OwnerKind = owner
		if owner == "shared" {
			policy.CaptureAuthority = nil
		}
		var err error
		g.snapshot, err = f.verifier.SignSnapshot(f.signer, policy)
		require.NoError(t, err)
		f.policy.current = g.snapshot
		settings, err := (mediarules.Settings{}).Normalize()
		require.NoError(t, err)
		if typed {
			// Register the same independent adapter at publication and capture. Its
			// ordinary intent must never inherit the LI media grant's authority.
			cfg.LearnedAdapters = []core.Adapter{reliableGrantDiagnosticAdapter()}
		}
		g.publisher, err = mediarules.NewWithAdapters(settings.StoreConfig("receiver", "", nil, nil), cfg.LearnedAdapters...)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, g.publisher.Close()) })
		g.rule = currentMediaRule()
		g.rule.Call = mediarules.CallAssociation{CallID: "centrally-selected-call", Lifetime: callregistry.Lifetime{Session: 17, Generation: 3}, FromTag: "from", ToTag: "to", SelectionRevision: 1, CapturePolicyRevision: 1, SelectionGrants: []mediarules.SelectionRef{{ID: "opaque-selection-reference", Revision: 1}}}
		g.rule.NotBefore = now.Add(-time.Second)
		g.rule.ExpiresAt = until
		signedRule, err := f.verifier.SignMediaRule(f.signer, wire.EncodeRule(g.rule))
		require.NoError(t, err)
		g.rule, err = wire.DecodeRule(signedRule)
		require.NoError(t, err)
		g.control, err = g.publisher.StartSession("receiver", g.rule.Session)
		require.NoError(t, err)
		require.NoError(t, g.publisher.ApplySnapshot(g.control, 1, []mediarules.Rule{g.rule}))
		g.service, err = wire.NewService(g.publisher, wire.Limits{MaxMessageBytes: settings.MaxMessageBytes, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxRules: settings.MaxRules}, 4, func(ctx context.Context, hunterID string) error {
			remote, ok := peer.FromContext(ctx)
			if !ok || hunterID != "edge" {
				return fmt.Errorf("unexpected source")
			}
			return verifiedMediaIssuer(remote, "edge")
		})
		require.NoError(t, err)
		management.RegisterMediaControlServiceServer(server, g.service)
		if typed {

			g.genericService, err = learnedwire.NewService(g.publisher.Core(), learnedwire.Limits{MaxMessageBytes: settings.MaxMessageBytes, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxRules: settings.MaxRules}, 4, func(ctx context.Context, hunterID string) error {
				remote, ok := peer.FromContext(ctx)
				if !ok || hunterID != "edge" {
					return fmt.Errorf("unexpected source")
				}
				return verifiedMediaIssuer(remote, "edge")
			})
			require.NoError(t, err)
			learnedpb.RegisterLearnedControlServiceServer(server, g.genericService)
		}
		cfg.BatchSize = batchSize
		if batchSize > 1 {
			cfg.BatchTimeout = time.Hour
		}
		cfg.VoIPMediaPolicy = "processor"
		cfg.VoIPSignallingPolicy = "none"
		cfg.MediaRules = mediarules.Settings{Enabled: true, ProcessorID: "receiver"}
		cfg.VoIPInterfaceDomains = map[string]mediaadmission.DomainID{"protected-interface": 0, "other-domain": 1}
	})
	require.Eventually(t, func() bool {
		if typed {
			application := g.genericService.Application("edge")
			return application != nil && application.Synchronized && application.ActiveBindings == 1
		}
		application := g.service.Application("edge")
		return application != nil && application.Synchronized && application.ActiveRules == 1
	}, 5*time.Second, 5*time.Millisecond)
	return g
}
func grantBoundaryMedia(t *testing.T, port uint16) capture.PacketInfo {
	return boundaryTransportPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4}, false, 40000, port)
}
func sendAndDrainGrantCapture(t *testing.T, f *reliableVoIPBoundaryFixture, packet capture.PacketInfo) {
	t.Helper()
	expected := f.h.statsCollector.GetCaptured() + 1
	f.send(t, packet)
	// Captured increments under the producer boundary. Once observed, acquiring
	// that boundary waits for this exact packet's processing callback to finish.
	require.Eventually(t, func() bool { return f.h.statsCollector.GetCaptured() >= expected }, time.Second, time.Millisecond)
	require.NoError(t, f.h.packetProducer.WithCaptureBoundary(func() error { return nil }))
}
func (g *reliableGrantFixture) stopHunter(t *testing.T) {
	t.Helper()
	g.cancel()
	require.NoError(t, <-g.done)
	g.stopped = true
	require.NoError(t, g.h.Close())
}
func assertGrantBatch(t *testing.T, g *reliableGrantFixture, batch *data.PacketBatch, expectedPolicy uint64) {
	t.Helper()
	require.Equal(t, "edge", batch.HunterId)
	require.Len(t, batch.Packets, 1)
	p := batch.Packets[0]
	require.Equal(t, []string{"opaque-selection-reference"}, p.MatchedFilterIds)
	require.Empty(t, p.DirectMatchedFilterIds)
	require.Equal(t, p.MatchedFilterIds, p.InheritedMatchedFilterIds)
	require.True(t, p.ObservationDomainKnown)
	require.Zero(t, p.ObservationDomain)
	require.Equal(t, "protected-interface", p.InterfaceName)
	signed := &management.SignedPolicySnapshot{}
	require.NoError(t, proto.Unmarshal(batch.SignedCapturePolicy, signed))
	require.NoError(t, g.verifier.Verify(signed))
	require.Equal(t, expectedPolicy, signed.Snapshot.Revision)
	require.Empty(t, signed.Snapshot.Filters)
	proof := p.CaptureSelectionProof
	if g.typed {
		require.Empty(t, proof, "typed capture emits one evidence representation")
		require.NoError(t, learnedwire.ValidateEvidence(p.LearnedCaptureEvidence, learnedwire.DefaultEvidenceLimits))
		require.Len(t, p.LearnedCaptureEvidence.Candidates, 1)
		candidate := p.LearnedCaptureEvidence.Candidates[0]
		require.Equal(t, "voip", candidate.AdapterId)
		require.Equal(t, g.rule.Call.CallID, candidate.SubjectId)
		require.Equal(t, "17:3", candidate.SubjectIncarnation)
		proof = candidate.GetLegacyMediaRule()
	} else {
		require.Nil(t, p.LearnedCaptureEvidence)
	}
	rule := &management.MediaRule{}
	require.NoError(t, proto.Unmarshal(proof, rule))
	require.NoError(t, g.verifier.VerifyMediaRule(rule))
	require.Equal(t, "centrally-selected-call", rule.Call.CallId)
	require.Equal(t, uint64(3), rule.Call.RegistryGeneration)
	packet := gopacket.NewPacket(p.Data, layers.LinkType(p.LinkType), gopacket.Default)
	require.NoError(t, capturegrant.ValidateRule(signed.Snapshot, rule, "edge", p.ObservationDomain, packet, time.Unix(0, p.TimestampNs)))
	require.Equal(t, wire.EncodeRule(g.rule).Call.RegistrySession, rule.Call.RegistrySession)
}

func TestGrantOnlyReliableHunterExactMediaPolicyReplacementAndWithdrawal(t *testing.T) {
	g := newReliableGrantFixture(t, time.Now().Add(time.Minute))
	require.Empty(t, g.h.filterManager.GetFilters(), "capture grants cannot create target-bearing matchers")
	exported, err := proto.Marshal(g.snapshot)
	require.NoError(t, err)
	require.NotContains(t, string(exported), "alice")
	require.NotContains(t, string(exported), "sip_user")
	require.False(t, g.h.filterManager.CaptureSelectionAllowed([]string{"opaque-selection-reference"}))
	g.send(t, grantBoundaryMedia(t, 45000))
	g.waitAck(t, 1)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, grantBoundaryMedia(t, 46000))
	wrongDomain := grantBoundaryMedia(t, 45000)
	wrongDomain.Interface = "other-domain"
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, wrongDomain)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, boundaryPacket(t, boundarySIP("unselected-signalling", true), false, 5060))
	require.Equal(t, uint64(1), g.h.packetSpool.Status().LastSequence, "grant cannot authorize unrelated endpoint or SIP")
	replacement := proto.Clone(g.snapshot.Snapshot).(*management.PolicySnapshot)
	replacement.Revision = 2
	replacement.SelectionGrants[0].Revision = 2
	signed, err := g.verifier.SignSnapshot(g.signer, replacement)
	require.NoError(t, err)
	g.policy.publish(signed)
	require.Eventually(t, func() bool { return g.h.filterManager.EffectiveCapturePolicyRevision() == 2 }, 5*time.Second, time.Millisecond)
	_, selected := g.h.mediaRules.ResolveMedia(grantBoundaryMedia(t, 45000).Packet, "protected-interface")
	require.False(t, selected, "old media rule cannot inherit a replacement grant")
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, grantBoundaryMedia(t, 45000))
	require.Equal(t, uint64(1), g.h.packetSpool.Status().LastSequence)
	next := g.rule
	next.Revision = 2
	next.Call.CapturePolicyRevision = 2
	next.Call.SelectionGrants = []mediarules.SelectionRef{{ID: "opaque-selection-reference", Revision: 2}}
	signedRule, err := g.verifier.SignMediaRule(g.signer, wire.EncodeRule(next))
	require.NoError(t, err)
	next, err = wire.DecodeRule(signedRule)
	require.NoError(t, err)
	require.NoError(t, g.publisher.ApplyDelta(g.control, 2, []mediarules.Rule{next}, nil))
	require.Eventually(t, func() bool {
		_, ok := g.h.mediaRules.ResolveMedia(grantBoundaryMedia(t, 45000).Packet, "protected-interface")
		return ok
	}, time.Second, time.Millisecond)
	g.send(t, grantBoundaryMedia(t, 45000))
	g.waitAck(t, 2)
	require.NoError(t, g.publisher.ApplyDelta(g.control, 3, nil, []string{next.ID}))
	require.Eventually(t, func() bool { return len(g.h.mediaRules.store.ActiveRules()) == 0 }, time.Second, time.Millisecond)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, grantBoundaryMedia(t, 45000))
	require.Equal(t, uint64(2), g.h.packetSpool.Status().LastSequence)
	replacement.Revision = 3
	replacement.SelectionGrants = nil
	signed, err = g.verifier.SignSnapshot(g.signer, replacement)
	require.NoError(t, err)
	g.policy.publish(signed)
	require.Eventually(t, func() bool { return g.h.filterManager.EffectiveCapturePolicyRevision() == 3 }, 5*time.Second, time.Millisecond)
	require.False(t, g.h.filterManager.CaptureAllowed(time.Now()))
	g.stopHunter(t)
	g.server.Stop()
	require.NoError(t, g.receiver.Shutdown())
	custody, err := packetreceipt.Open(g.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assertGrantBatch(t, g, pending[0].Batch, 1)
	assertGrantBatch(t, g, pending[1].Batch, 2)
	assertEncryptedCaptureFiles(t, g.origin)
	assertEncryptedCaptureFiles(t, g.store.Directory)
}

func TestGrantOnlyReliableHunterOfflineExpiryRestartReplaysOriginalProof(t *testing.T) {
	for _, typed := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed-%t", typed), func(t *testing.T) { grantOnlyReliableHunterOfflineExpiryRestartReplaysOriginalProof(t, typed) })
	}
}
func grantOnlyReliableHunterOfflineExpiryRestartReplaysOriginalProof(t *testing.T, typed bool) {
	g := newReliableGrantFixtureForProtocol(t, time.Now().Add(3*time.Second), "li", 1, typed)
	if typed {
		require.Nil(t, g.service.Application("edge"), "generic control must be selected when supported")
		stream := g.h.connectionManager.GetStream()
		accepted, ok := stream.(interface{ LearnedEvidenceVersions() []uint32 })
		require.True(t, ok)
		require.Equal(t, []uint32{1}, accepted.LearnedEvidenceVersions())
	}
	g.send(t, grantBoundaryMedia(t, 45000))
	g.waitAck(t, 1)
	g.server.Stop()
	require.Eventually(t, func() bool {
		if typed {
			return g.genericService.Application("edge") == nil
		}
		return g.service.Application("edge") == nil
	}, time.Second, time.Millisecond)

	require.Eventually(t, func() bool {
		state := g.h.connectionManager.Status()
		return state.State == "waiting"
	}, time.Second, time.Millisecond, "observe an actual failed route attempt before capturing offline")
	require.True(t, g.h.filterManager.CaptureAllowed(time.Now()), "signed offline permission preserves bounded media capture")
	offline := grantBoundaryMedia(t, 45000)
	_, selected := g.h.mediaRules.ResolveMedia(offline.Packet, offline.Interface)
	require.True(t, selected, "disconnected rule: status=%+v rules=%d current=%d allowed=%t typed=%t", g.h.mediaRules.store.Status(), len(g.h.mediaRules.store.ActiveRules()), g.h.filterManager.EffectiveCapturePolicyRevision(), g.h.filterManager.CaptureAllowed(time.Now()), g.h.filterManager.CaptureMediaRuleAllowed(wire.EncodeRule(g.rule), offline.Packet, 0, time.Now()))
	g.send(t, offline)

	require.Eventually(t, func() bool { s := g.h.packetSpool.Status(); return s.LastSequence == 2 && s.PendingRecords == 1 }, time.Second, time.Millisecond)
	retained, err := g.h.packetSpool.BatchesAfter(1, 4)
	require.NoError(t, err)
	require.Len(t, retained, 1)
	assertGrantBatch(t, g, retained[0], 1)
	require.Equal(t, offline.Packet.Metadata().Timestamp.UnixNano(), retained[0].Packets[0].TimestampNs)
	if typed {
		exactProof, err := proto.Marshal(wire.EncodeRule(g.rule))
		require.NoError(t, err)
		require.Equal(t, exactProof, retained[0].Packets[0].LearnedCaptureEvidence.Candidates[0].GetLegacyMediaRule())
	}
	original := proto.Clone(retained[0]).(*data.PacketBatch)
	identity := g.h.packetSpool.Identity()
	require.Eventually(t, func() bool { return !g.h.filterManager.CaptureAllowed(time.Now()) }, 5*time.Second, 5*time.Millisecond)
	_, ok := g.h.mediaRules.ResolveMedia(grantBoundaryMedia(t, 45000).Packet, "protected-interface")
	require.False(t, ok, "disconnected rule expiry cannot renew media capture")
	config := g.h.config
	g.stopHunter(t)
	// A fresh signed withdrawal permits control/replay after restart, while it
	// supplies no current matcher or media capture authority.
	withdrawal := proto.Clone(g.snapshot.Snapshot).(*management.PolicySnapshot)
	withdrawal.Revision = 2
	withdrawal.SelectionGrants = nil
	withdrawal.ValidFromNs = time.Now().Add(-time.Second).UnixNano()
	withdrawal.ValidUntilNs = time.Now().Add(time.Minute).UnixNano()
	current, err := g.verifier.SignSnapshot(g.signer, withdrawal)
	require.NoError(t, err)
	g.policy.publish(current)
	// Retire the entire issuing epoch, not merely the binding. Retained
	// signed capture facts must remain replayable without live learned state.
	previousSession := g.rule.Session
	nextSession := previousSession
	nextSession.Generation++
	g.control, err = g.publisher.StartSession("receiver", nextSession)
	require.NoError(t, err)
	require.NoError(t, g.publisher.ApplySnapshot(g.control, 1, nil))
	require.NotEqual(t, previousSession, g.publisher.Status().Session)
	require.Empty(t, g.publisher.ActiveRules())
	pair, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	require.NoError(t, err)
	encoded, err := os.ReadFile(config.TLSCAFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(encoded))
	listener, err := net.Listen("tcp", config.Processors[0].Address)
	require.NoError(t, err)
	restarted := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterManagementServiceServer(restarted, g.receiver)
	data.RegisterReliablePacketServiceServer(restarted, g.receiver)
	management.RegisterFilterPolicyServiceServer(restarted, g.policy)
	management.RegisterMediaControlServiceServer(restarted, g.service)
	if typed {
		learnedpb.RegisterLearnedControlServiceServer(restarted, g.genericService)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- restarted.Serve(listener) }()
	t.Cleanup(func() { restarted.Stop(); require.NoError(t, <-serveDone) })
	g.h, err = New(config)
	require.NoError(t, err)
	require.Equal(t, identity, g.h.packetSpool.Identity())
	require.False(t, g.h.filterManager.CaptureAllowed(time.Now()), "cached expired grant cannot restart capture")
	require.NoError(t, g.h.captureManager.PrepareBuffer())
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.done = make(chan error, 1)
	g.stopped = false
	go func() { g.done <- g.h.Start(ctx) }()
	g.waitAck(t, 2)
	require.Eventually(t, func() bool { return g.h.filterManager.EffectiveCapturePolicyRevision() == 2 }, 5*time.Second, time.Millisecond)
	require.False(t, g.h.filterManager.CaptureAllowed(time.Now()))
	require.Empty(t, g.h.mediaRules.store.ActiveRules())
	require.Equal(t, uint64(2), g.h.packetSpool.Status().LastSequence, "replay never creates a new raw capture record")
	g.stopHunter(t)
	restarted.Stop()
	require.NoError(t, g.receiver.Shutdown())
	custody, err := packetreceipt.Open(g.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	require.True(t, proto.Equal(original, pending[1].Batch), "restart replay preserves exact original signed policy, proof, capture time and source")
	assertGrantBatch(t, g, pending[1].Batch, 1)
}

func TestSharedOwnerGrantProducerChecksOriginalCaptureAndSealAuthority(t *testing.T) {
	g := newReliableGrantFixtureForOwner(t, time.Now().Add(3*time.Second), "shared", 8)
	proof, err := proto.Marshal(wire.EncodeRule(g.rule))
	require.NoError(t, err)
	backdated := grantBoundaryMedia(t, 45000)
	backdated.Packet.Metadata().Timestamp = g.rule.NotBefore.Add(-time.Millisecond)
	_, live := g.h.mediaRules.ResolveMedia(backdated.Packet, backdated.Interface)
	require.True(t, live, "live endpoint resolution alone does not validate original capture time")
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, backdated)
	g.h.packetProducer.SendBatch()
	require.Zero(t, g.h.packetSpool.Status().LastSequence, "shared-owner producer must reject pre-rule capture before raw sealing")
	valid := grantBoundaryMedia(t, 45000)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, valid)
	g.h.packetProducer.SendBatch()
	g.waitAck(t, 1)
	// Replacement keeps ordinary capture unleased while invalidating the exact
	// old grant reference and its frozen capture proof.
	replacement := proto.Clone(g.snapshot.Snapshot).(*management.PolicySnapshot)
	replacement.Revision = 2
	replacement.SelectionGrants[0].Revision = 2
	signed, err := g.verifier.SignSnapshot(g.signer, replacement)
	require.NoError(t, err)
	g.policy.publish(signed)
	require.Eventually(t, func() bool { return g.h.filterManager.EffectiveCapturePolicyRevision() == 2 }, time.Second, time.Millisecond)
	require.ErrorContains(t, g.h.ForwardPacketWithCaptureSelectionProof(grantBoundaryMedia(t, 45000).Packet, nil, "protected-interface", layers.LinkTypeEthernet, nil, []string{"opaque-selection-reference"}, proof, nil), "capture authority")
	next := g.rule
	next.Revision = 2
	next.Call.CapturePolicyRevision = 2
	next.Call.SelectionGrants = []mediarules.SelectionRef{{ID: "opaque-selection-reference", Revision: 2}}
	signedRule, err := g.verifier.SignMediaRule(g.signer, wire.EncodeRule(next))
	require.NoError(t, err)
	next, err = wire.DecodeRule(signedRule)
	require.NoError(t, err)
	require.NoError(t, g.publisher.ApplyDelta(g.control, 2, []mediarules.Rule{next}, nil))
	require.Eventually(t, func() bool {
		_, ok := g.h.mediaRules.ResolveMedia(grantBoundaryMedia(t, 45000).Packet, "protected-interface")
		return ok
	}, time.Second, time.Millisecond)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, grantBoundaryMedia(t, 45000))
	g.h.packetProducer.SendBatch()
	g.waitAck(t, 2)
	require.NoError(t, g.publisher.ApplyDelta(g.control, 3, nil, []string{next.ID}))
	require.Eventually(t, func() bool { return len(g.h.mediaRules.store.ActiveRules()) == 0 }, time.Second, time.Millisecond)
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, grantBoundaryMedia(t, 45000))
	g.h.packetProducer.SendBatch()
	require.Equal(t, uint64(2), g.h.packetSpool.Status().LastSequence, "withdrawn media owner cannot supply fresh capture proof")
	// Exercise the producer's own typed proof check at seal, independently of a
	// resolver callback: this valid signed packet waits in the real batch until
	// its grant expires. Ordinary shared capture remains allowed throughout.
	proof, err = proto.Marshal(wire.EncodeRule(next))
	require.NoError(t, err)
	queued := grantBoundaryMedia(t, 45000)
	require.NoError(t, g.h.ForwardPacketWithCaptureSelectionProof(queued.Packet, nil, queued.Interface, queued.LinkType, nil, []string{"opaque-selection-reference"}, proof, nil))
	require.Equal(t, uint64(2), g.h.packetSpool.Status().LastSequence)
	require.Eventually(t, func() bool {
		return !g.h.filterManager.CaptureMediaRuleAllowed(wire.EncodeRule(next), queued.Packet, 0, queued.Packet.Metadata().Timestamp)
	}, 5*time.Second, 5*time.Millisecond)
	require.True(t, g.h.filterManager.CaptureAllowed(time.Now()), "ordinary shared capture has no media-grant lease")
	g.h.packetProducer.SendBatch()
	require.Equal(t, uint64(2), g.h.packetSpool.Status().LastSequence, "expired proof cannot be sealed merely because ordinary capture remains allowed")
	replacement.ProtocolVersion = 1
	replacement.Revision = 3
	replacement.SelectionGrants = nil
	replacement.ValidFromNs = 0
	replacement.ValidUntilNs = 0
	replacement.SourceIds = nil
	replacement.AllowOfflineCapture = false
	signed, err = g.verifier.SignSnapshot(g.signer, replacement)
	require.NoError(t, err)
	g.policy.publish(signed)
	require.Eventually(t, func() bool { return g.h.filterManager.EffectiveCapturePolicyRevision() == 3 }, time.Second, time.Millisecond)
	require.ErrorContains(t, g.h.ForwardPacketWithCaptureSelectionProof(grantBoundaryMedia(t, 45000).Packet, nil, "protected-interface", layers.LinkTypeEthernet, nil, []string{"opaque-selection-reference"}, proof, nil), "capture authority")
	g.stopHunter(t)
	g.server.Stop()
	require.NoError(t, g.receiver.Shutdown())
	custody, err := packetreceipt.Open(g.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assertGrantBatch(t, g, pending[0].Batch, 1)
	assertGrantBatch(t, g, pending[1].Batch, 2)
}

// A valid generic binding and a global MEDIA lease are deliberately independent
// authorities. Exercise the real producer so neither admission nor sealing can
// mistake the former for a grant to capture arbitrary subscriber/diagnostic UDP.
func TestDiagnosticBindingCannotBroadenLIOnlyMediaGrant(t *testing.T) {
	for _, owner := range []string{"li", "shared"} {
		t.Run(owner, func(t *testing.T) {
			g := newReliableGrantFixtureForProtocol(t, time.Now().Add(time.Minute), owner, 1, true)
			g.send(t, grantBoundaryMedia(t, 45000))
			g.waitAck(t, 1)
			binding := core.Binding{ID: "diagnostic-binding", Session: g.rule.Session, Revision: 2, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: "diagnostic-subject", Incarnation: "request-1"}, AttributionContext: "diagnostic", Intents: []core.IntentRef{{ID: "diagnostic-request", Revision: 1}}, Scope: []core.Scope{{HunterID: "edge", Domain: 0}}, Selectors: []core.Selector{{Address: g.rule.Endpoints[0].Key.Addr, Port: 47000, Protocol: core.UDP, Direction: core.Destination}}, Context: []byte("diagnostic-v1"), NotBefore: time.Now().Add(-time.Second), ExpiresAt: g.rule.ExpiresAt}
			require.NoError(t, g.publisher.Core().ApplyDelta(g.control, 2, []core.Binding{binding}, nil))
			require.Eventually(t, func() bool {
				application := g.genericService.Application("edge")
				return application != nil && application.Synchronized && application.ActiveBindings == 2
			}, time.Second, time.Millisecond)
			packet := boundaryTransportPacket(t, []byte("independent-diagnostic-payload"), false, 48000, 47000)
			candidates := g.h.mediaRules.runtime.Match(packet.Packet, packet.Interface)
			require.False(t, candidates.Overflow)
			require.Len(t, candidates.Bindings, 1)
			require.Equal(t, "diagnostic", candidates.Bindings[0].AdapterID)
			require.Empty(t, candidates.Bindings[0].Proof)
			require.True(t, g.h.filterManager.CaptureAllowed(time.Now()), "global MEDIA lease is still valid during independent diagnostic selection")
			sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, packet)
			if owner == "li" {
				require.Equal(t, uint64(1), g.h.packetSpool.Status().LastSequence, "reference-only binding cannot broaden a media-only LI grant")
			} else {
				g.waitAck(t, 2)
			}
			// Rejection must not disable valid signed media on the same actual source.
			g.send(t, grantBoundaryMedia(t, 45000))
			expected := uint64(2)
			if owner == "shared" {
				expected = 3
			}
			g.waitAck(t, expected)
			g.stopHunter(t)
			g.server.Stop()
			require.NoError(t, g.receiver.Shutdown())
			custody, err := packetreceipt.Open(g.store)
			require.NoError(t, err)
			defer func() { require.NoError(t, custody.Close()) }()
			pending, err := custody.Pending(32)
			require.NoError(t, err)
			require.Len(t, pending, int(expected))
			assertGrantBatch(t, g, pending[0].Batch, 1)
			assertGrantBatch(t, g, pending[len(pending)-1].Batch, 1)
			if owner == "shared" {
				ordinary := pending[1].Batch.Packets[0]
				require.Empty(t, ordinary.CaptureSelectionProof)
				require.Empty(t, ordinary.MatchedFilterIds)
				require.Empty(t, ordinary.InheritedMatchedFilterIds)
				require.Len(t, ordinary.LearnedCaptureEvidence.Candidates, 1)
				candidate := ordinary.LearnedCaptureEvidence.Candidates[0]
				require.Equal(t, "diagnostic", candidate.AdapterId)
				require.Equal(t, "diagnostic-subject", candidate.SubjectId)
				require.True(t, candidate.GetReferenceOnly())
				require.Empty(t, candidate.GetLegacyMediaRule())
			}
		})
	}
}

// Overflow must stop the actual mixed-adapter producer before it can fall back
// to the legacy VoIP resolver and silently discard the other associations.
func TestRemoteMixedCandidateOverflowCannotFallBackToLegacyMedia(t *testing.T) {
	g := newReliableGrantFixtureForProtocol(t, time.Now().Add(time.Minute), "li", 1, true)
	g.send(t, grantBoundaryMedia(t, 45000))
	g.waitAck(t, 1)
	const diagnosticCount = 65
	bindings := make([]core.Binding, 0, diagnosticCount)
	for index := range diagnosticCount {
		bindings = append(bindings, core.Binding{ID: fmt.Sprintf("overflow-diagnostic-%d", index), Session: g.rule.Session, Revision: 2, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: fmt.Sprintf("diagnostic-subject-%d", index), Incarnation: "request-1"}, AttributionContext: "diagnostic", Intents: []core.IntentRef{{ID: "diagnostic-request", Revision: 1}}, Scope: []core.Scope{{HunterID: "edge", Domain: 0}}, Selectors: []core.Selector{{Address: g.rule.Endpoints[0].Key.Addr, Port: g.rule.Endpoints[0].Key.Port, Protocol: core.UDP, Direction: core.Either}}, Context: []byte("diagnostic-v1"), NotBefore: time.Now().Add(-time.Second), ExpiresAt: g.rule.ExpiresAt})
	}
	require.NoError(t, g.publisher.Core().ApplyDelta(g.control, 2, bindings, nil))
	require.Eventually(t, func() bool {
		application := g.genericService.Application("edge")
		return application != nil && application.Synchronized && application.ActiveBindings == diagnosticCount+1
	}, time.Second, time.Millisecond)
	require.Len(t, g.h.mediaRules.store.Core().ActiveRules(), diagnosticCount+1)
	packet := grantBoundaryMedia(t, 45000)
	facts, ok := core.PacketFacts(packet.Packet, 0)
	require.True(t, ok)
	// The compatibility view excludes independent adapters. It demonstrates that
	// the old VoIP-only fallback could still claim a unique valid signed owner.
	legacy := g.h.mediaRules.store.Resolve(mediaadmission.EndpointKey{Addr: facts.Source.Address, Port: facts.Source.Port}, mediaadmission.EndpointKey{Addr: facts.Destination.Address, Port: facts.Destination.Port})
	require.True(t, legacy.Resolved, "VoIP considered alone has one exact owner")
	require.NotNil(t, legacy.Rule)
	require.Equal(t, g.rule.Call.CallID, legacy.Call.CallID)
	require.True(t, g.h.filterManager.CaptureMediaRuleAllowed(wire.EncodeRule(*legacy.Rule), packet.Packet, 0, packet.Packet.Metadata().Timestamp), "legacy signed VoIP authority alone would accept this RTP")
	before := g.h.mediaRules.store.Core().Status().CandidateOverflows
	sendAndDrainGrantCapture(t, g.reliableVoIPBoundaryFixture, packet)
	require.Greater(t, g.h.mediaRules.store.Core().Status().CandidateOverflows, before, "the actual remote producer must report its complete candidate-set overflow")
	require.Equal(t, uint64(1), g.h.packetSpool.Status().LastSequence, "overflow cannot emit either truncated typed evidence or legacy field16 fallback")
	require.Zero(t, g.h.packetSpool.Status().PendingRecords)
	g.stopHunter(t)
	g.server.Stop()
	require.NoError(t, g.receiver.Shutdown())
	custody, err := packetreceipt.Open(g.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 1, "overflow never reaches receiver custody")
	assertGrantBatch(t, g, pending[0].Batch, 1)
	require.Empty(t, pending[0].Batch.Packets[0].CaptureSelectionProof)
	require.NotNil(t, pending[0].Batch.Packets[0].LearnedCaptureEvidence)
}
