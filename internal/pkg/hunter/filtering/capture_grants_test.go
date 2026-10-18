//go:build hunter || all

package filtering

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func grantTestPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 45000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return packet
}
func TestCaptureGrantRequiresSignedMediaProofWithoutGrantingFilterOrSignallingMembership(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	snapshot := f.sign(t, 1, true).Snapshot
	snapshot.ProtocolVersion = 2
	snapshot.Filters = nil
	now := time.Now()
	snapshot.SelectionGrants = []*management.CaptureSelectionGrant{{Id: "opaque", Revision: 3, ProcessorId: "processor", Scopes: []*management.CaptureSelectionScope{{HunterId: "edge", Domain: 0}}, NotBeforeNs: snapshot.ValidFromNs, ExpiresAtNs: snapshot.ValidUntilNs, Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA}}
	signed, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
	require.NoError(t, err)
	f.install(t, signed)
	require.True(t, f.manager.CaptureAllowed(time.Now()))
	require.False(t, f.manager.CaptureSelectionAllowed([]string{"opaque"}), "grant references never become direct or SIP matching membership")
	rule := &management.MediaRule{Id: "rule", Session: &management.MediaRuleSession{ProcessorId: "processor", Generation: 1}, Revision: 1, Call: &management.MediaRuleCall{CallId: "call", RegistrySession: 1, RegistryGeneration: 1, SelectionRevision: 1, CapturePolicyRevision: 1, SelectionGrants: []*management.CaptureSelectionRef{{Id: "opaque", Revision: 3}}}, Scopes: []*management.MediaRuleScope{{HunterId: "edge", Domain: 0}}, Endpoints: []*management.MediaRuleEndpoint{{Address: "192.0.2.2", Port: 45000}}, NotBeforeNs: now.Add(-time.Second).UnixNano(), ExpiresAtNs: now.Add(30 * time.Second).UnixNano()}
	rule, err = f.manager.sharedPolicy.state.Verifier().SignMediaRule(f.signer, rule)
	require.NoError(t, err)
	packet := grantTestPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	at := packet.Metadata().Timestamp
	require.True(t, f.manager.CaptureMediaRuleAllowed(rule, packet, 0, at))
	require.False(t, f.manager.CaptureMediaRuleAllowed(rule, packet, 1, at))
	require.False(t, f.manager.CaptureMediaRuleAllowed(rule, grantTestPacket(t, []byte("INVITE sip:a@example SIP/2.0\r\n")), 0, at))
	proof, err := proto.Marshal(rule)
	require.NoError(t, err)
	env := pipeline.NewDecodedPacketEnvelope(packet, layers.LinkTypeRaw)
	env.CaptureSelectionProof = proof
	env.Source.ObservationDomainKnown = true
	env.InheritedMatchedFilterIDs = []string{"opaque"}
	env.MatchedFilterIDs = []string{"opaque"}
	require.True(t, f.manager.CaptureSelectionProofAllowed(env))
	env.DirectMatchedFilterIDs = []string{"opaque"}
	require.False(t, f.manager.CaptureSelectionProofAllowed(env))
	env.DirectMatchedFilterIDs = nil
	bad := proto.Clone(rule).(*management.MediaRule)
	bad.Call.SelectionGrants[0].Revision++
	require.False(t, f.manager.CaptureMediaRuleAllowed(bad, packet, 0, at))
	snapshot.Revision = 2
	snapshot.SelectionGrants[0].Revision++
	replacement, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
	require.NoError(t, err)
	f.install(t, replacement)
	require.False(t, f.manager.CaptureSelectionProofAllowed(env), "new lease cannot retag original proof")
	snapshot.Revision = 3
	snapshot.SelectionGrants = nil
	snapshot.Filters = nil
	withdrawn, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
	require.NoError(t, err)
	f.install(t, withdrawn)
	require.False(t, f.manager.CaptureAllowed(time.Now()))
}

type captureGrantBoundary struct {
	snapshots     [][]byte
	ordinaryCalls int
}

func (c *captureGrantBoundary) ApplyCaptureSnapshot(encoded []byte, apply func() error) error {
	if err := apply(); err != nil {
		return err
	}
	c.snapshots = append(c.snapshots, append([]byte(nil), encoded...))
	return nil
}
func (c *captureGrantBoundary) ApplyPolicyChange(apply func() error) error {
	c.ordinaryCalls++
	return apply()
}

type sharedGrantFixture struct {
	manager  *Manager
	verifier *filterpolicy.Verifier
	signer   crypto.Signer
	snapshot *management.SignedPolicySnapshot
	rule     *management.MediaRule
	packet   gopacket.Packet
}

func newSharedGrantFixture(t *testing.T, offline bool, coordinator PolicyChangeCoordinator) *sharedGrantFixture {
	t.Helper()
	cfg, key := policyfixture.Config(t)
	v, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	cfg.SigningKeyFile = ""
	m := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.NoError(t, m.InitializeSharedPolicy(cfg, []string{"bpf"}))
	t.Cleanup(func() { require.NoError(t, m.CloseSharedPolicy()) })
	if coordinator != nil {
		m.SetPolicyChangeCoordinator(coordinator)
	}
	now := time.Now()
	snapshot, err := v.SignSnapshot(key, &management.PolicySnapshot{ProtocolVersion: 2, OwnerKind: "shared", Domain: cfg.Domain, AuthorityId: cfg.AuthorityID, Revision: 1, ValidFromNs: now.Add(-time.Minute).UnixNano(), ValidUntilNs: now.Add(time.Minute).UnixNano(), SourceIds: []string{"edge"}, AllowOfflineCapture: offline, SelectionGrants: []*management.CaptureSelectionGrant{{Id: "opaque", Revision: 3, ProcessorId: "processor", Scopes: []*management.CaptureSelectionScope{{HunterId: "edge", Domain: 0}}, NotBeforeNs: now.Add(-time.Minute).UnixNano(), ExpiresAtNs: now.Add(time.Minute).UnixNano(), Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA}}})
	require.NoError(t, err)
	rule, err := v.SignMediaRule(key, &management.MediaRule{Id: "rule", Session: &management.MediaRuleSession{ProcessorId: "processor", Generation: 1}, Revision: 1, Call: &management.MediaRuleCall{CallId: "call", RegistrySession: 1, RegistryGeneration: 1, SelectionRevision: 1, CapturePolicyRevision: 1, SelectionGrants: []*management.CaptureSelectionRef{{Id: "opaque", Revision: 3}}}, Scopes: []*management.MediaRuleScope{{HunterId: "edge", Domain: 0}}, Endpoints: []*management.MediaRuleEndpoint{{Address: "192.0.2.2", Port: 45000}}, NotBeforeNs: now.Add(-time.Second).UnixNano(), ExpiresAtNs: now.Add(30 * time.Second).UnixNano()})
	require.NoError(t, err)
	return &sharedGrantFixture{manager: m, verifier: v, signer: key, snapshot: snapshot, rule: rule, packet: grantTestPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})}
}
func (f *sharedGrantFixture) allowed() bool {
	return f.manager.CaptureMediaRuleAllowed(f.rule, f.packet, 0, f.packet.Metadata().Timestamp)
}
func TestSharedOwnerGrantInstallationAndLegacyReplacementUseSignedProducerBoundary(t *testing.T) {
	for _, version := range []uint32{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			boundary := &captureGrantBoundary{}
			f := newSharedGrantFixture(t, true, boundary)
			require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{f.snapshot}))
			require.True(t, f.allowed())
			require.Len(t, boundary.snapshots, 1)
			require.True(t, bytes.Equal(boundary.snapshots[0], f.manager.EffectiveCapturePolicy()))
			require.False(t, f.manager.CaptureMediaRuleAllowed(f.rule, f.packet, 1, time.Now()), "generic grant retains exact source domain")
			withdrawal := &management.PolicySnapshot{ProtocolVersion: version, OwnerKind: "shared", Domain: f.snapshot.Snapshot.Domain, AuthorityId: f.snapshot.Snapshot.AuthorityId, Revision: 2, Filters: []*management.Filter{{Id: "shared/capture/ordinary", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}}}
			signed, err := f.verifier.SignSnapshot(f.signer, withdrawal)
			require.NoError(t, err)
			require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{signed}))
			require.True(t, f.allowed(), "staged reconnect policy waits for existing producer drain boundary")
			require.NoError(t, f.manager.ApplyPendingInitialE())
			require.False(t, f.allowed())
			require.Len(t, boundary.snapshots, 2)
			require.Zero(t, boundary.ordinaryCalls)
			installed := &management.SignedPolicySnapshot{}
			require.NoError(t, proto.Unmarshal(boundary.snapshots[1], installed))
			require.True(t, proto.Equal(signed, installed))
			require.Equal(t, "shared/capture/ordinary", f.manager.GetFilters()[0].Id)
			require.True(t, f.manager.CaptureAllowed(time.Now().Add(24*time.Hour)), "ordinary shared matching remains unleased after grant withdrawal")
		})
	}
}
func TestSharedOwnerGrantOfflinePermissionAndStickyRollback(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(fmt.Sprint(offline), func(t *testing.T) {
			f := newSharedGrantFixture(t, offline, nil)
			require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{f.snapshot}))
			require.True(t, f.allowed())
			f.manager.PolicyDisconnected()
			require.Equal(t, offline, f.allowed())
		})
	}
	f := newSharedGrantFixture(t, true, nil)
	require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{f.snapshot}))
	require.True(t, f.allowed())
	lease := &f.manager.sharedPolicy.lease
	lease.mu.Lock()
	lease.lastWall = time.Now().Add(time.Hour).UnixNano()
	lease.mu.Unlock()
	require.False(t, f.allowed())
	lease.mu.Lock()
	lease.lastWall = 0
	lease.mu.Unlock()
	require.False(t, f.allowed(), "catching up the clock cannot revive a faulted grant")
	renewed := proto.Clone(f.snapshot.Snapshot).(*management.PolicySnapshot)
	renewed.Revision = 2
	signed, err := f.verifier.SignSnapshot(f.signer, renewed)
	require.NoError(t, err)
	require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{signed}))
	rule := proto.Clone(f.rule).(*management.MediaRule)
	rule.Call.CapturePolicyRevision = 2
	f.rule, err = f.verifier.SignMediaRule(f.signer, rule)
	require.NoError(t, err)
	require.True(t, f.allowed(), "fresh signed policy and exact new proof reconcile rollback")
	lease.mu.Lock()
	lease.deadline = time.Now().Add(-time.Second)
	lease.mu.Unlock()
	require.False(t, f.allowed(), "monotonic lease deadline independently bounds ordinary-owner media grants")
}
func TestSharedOwnerGrantsRejectEventCoordinatorWithoutProofBoundary(t *testing.T) {
	f := newSharedGrantFixture(t, true, &recordingPolicyCoordinator{})
	err := f.manager.InitializePolicy(t.Context(), snapshotConnection{f.snapshot})
	require.ErrorContains(t, err, "preserves signed capture proof")
	require.False(t, f.allowed())
	require.False(t, f.manager.SharedStartupReady())
}
