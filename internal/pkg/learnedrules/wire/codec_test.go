package wire

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	pb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func capabilities() []*pb.LearnedCapability {
	return []*pb.LearnedCapability{{AdapterId: "diagnostic", ContextVersion: 1, EndpointSelectorVersions: []uint32{1}, EvidenceVersions: []uint32{1}}}
}
func diagnosticRegistry(t *testing.T) *learnedrules.Registry {
	t.Helper()
	registry, err := learnedrules.NewRegistry(learnedrules.Adapter{ID: "diagnostic", Version: 1, Validate: func(b learnedrules.Binding) error {
		if string(b.Context) != "session-v1" {
			return learnedrules.ErrInvalid
		}
		return nil
	}, Authorize: func(b learnedrules.Binding) error {
		if len(b.Intents) != 1 || b.Intents[0].ID != "request-1" {
			return learnedrules.ErrAuthority
		}
		return nil
	}})
	require.NoError(t, err)
	return registry
}
func testStore(t *testing.T, source string) *learnedrules.Store {
	t.Helper()
	config := learnedrules.Config{ProcessorID: "processor", HunterID: source, MaxRules: 16, MaxBytes: 65536, MaxEndpoints: 64, MaxEndpointsPerRule: 4, MaxSubscribers: 4, SubscriptionBuffer: 8, MaxLifetime: time.Hour, Registry: diagnosticRegistry(t)}
	if source != "" {
		config.Domains = []learnedrules.DomainID{0}
	}
	store, err := learnedrules.New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store
}
func testBinding(index int) learnedrules.Binding {
	now := time.Now()
	return learnedrules.Binding{ID: fmt.Sprintf("binding-%d", index), Session: learnedrules.Session{ProcessorID: "processor", Generation: 1}, Revision: learnedrules.Revision(index + 7), AdapterID: "diagnostic", ContextVersion: 1, Subject: learnedrules.Subject{ID: "endpoint-investigation", Incarnation: "instance-1"}, AttributionContext: "diagnostic-session", Intents: []learnedrules.IntentRef{{ID: "request-1", Revision: 1}}, EvidenceRefs: []string{"trusted-request"}, Scope: []learnedrules.Scope{{HunterID: "hunter", Domain: 0}}, Selectors: []learnedrules.Selector{{Address: netip.MustParseAddr("192.0.2.1"), Port: uint16(4000 + index), Protocol: learnedrules.UDP, Direction: learnedrules.Either}}, Context: []byte("session-v1"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
}

var testLimits = Limits{MaxMessageBytes: 512, MaxSnapshotBytes: 8192, MaxRules: 16}

func frame(t *testing.T, bindings []learnedrules.Binding, revision uint64) []*pb.LearnedRuleUpdate {
	t.Helper()
	chunks, err := SnapshotChunks(learnedrules.Session{ProcessorID: "processor", Generation: 1}, learnedrules.Revision(revision), bindings, testLimits)
	require.NoError(t, err)
	for i, c := range chunks {
		c.SubscriptionId = "subscription-1"
		if i == 0 {
			c.Capabilities = capabilities()
		}
	}
	return chunks
}

func TestSnapshotStagesAtomicallyAndPreservesBindingRevision(t *testing.T) {
	store := testStore(t, "hunter")
	receiver, err := NewReceiver(store, "processor", testLimits, capabilities())
	require.NoError(t, err)
	bindings := []learnedrules.Binding{testBinding(0), testBinding(1), testBinding(2)}
	chunks := frame(t, bindings, 1)
	require.Greater(t, len(chunks), 1)
	for i, chunk := range chunks {
		require.NoError(t, receiver.Apply(chunk))
		if i < len(chunks)-1 {
			require.Empty(t, store.ActiveRules())
			require.False(t, store.Status().Ready)
		}
	}
	require.Len(t, store.ActiveRules(), 3)
	require.Equal(t, bindings[0].Revision, store.ActiveRules()[0].Revision)
	require.NoError(t, receiver.Apply(&pb.LearnedRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(bindings[0].Session), Revision: 2, SubscriptionId: "subscription-1", RemovedIds: []string{bindings[0].ID}}))
	require.Len(t, store.ActiveRules(), 2)
}
func TestBindingCodecOwnsBytesAndRejectsNarrowing(t *testing.T) {
	binding := testBinding(0)
	binding.Proof = []byte("exact-original-proof")
	encoded := EncodeBinding(binding)
	binding.Context[0] = 'X'
	binding.Proof[0] = 'X'
	decoded, err := DecodeBinding(encoded)
	require.NoError(t, err)
	encoded.Context[0] = 'Y'
	encoded.Proof[0] = 'Y'
	require.Equal(t, "session-v1", string(decoded.Context))
	require.Equal(t, "exact-original-proof", string(decoded.Proof))
	for _, mutate := range []func(*pb.LearnedBinding){func(b *pb.LearnedBinding) { b.Selectors[0].Port = 65536 }, func(b *pb.LearnedBinding) { b.Selectors[0].Protocol = 273 }, func(b *pb.LearnedBinding) { b.Selectors[0].Direction = 256 }, func(b *pb.LearnedBinding) { b.Selectors[0].Address = "::ffff:192.0.2.1" }, func(b *pb.LearnedBinding) { b.Selectors[0].Qualifier = &pb.LearnedQualifier{Id: "", Version: 1} }, func(b *pb.LearnedBinding) { b.Scopes[0] = nil }} {
		bad := EncodeBinding(testBinding(0))
		mutate(bad)
		_, err := DecodeBinding(bad)
		require.Error(t, err)
	}
}
func TestReceiverRefusesUnsupportedCapabilitiesAndEpochChanges(t *testing.T) {
	for _, mutate := range []func(*pb.LearnedRuleUpdate){func(u *pb.LearnedRuleUpdate) { u.Bindings[0].AdapterId = "other" }, func(u *pb.LearnedRuleUpdate) { u.Bindings[0].ContextVersion = 2 }, func(u *pb.LearnedRuleUpdate) {
		u.Bindings[0].Selectors[0].Qualifier = &pb.LearnedQualifier{Id: "unknown", Version: 1}
	}, func(u *pb.LearnedRuleUpdate) { u.Capabilities[0].EvidenceVersions = []uint32{2} }, func(u *pb.LearnedRuleUpdate) { u.Session.ProcessorId = "forged" }} {
		store := testStore(t, "hunter")
		r, err := NewReceiver(store, "processor", testLimits, capabilities())
		require.NoError(t, err)
		u := frame(t, []learnedrules.Binding{testBinding(0)}, 1)[0]
		mutate(u)
		require.Error(t, r.Apply(u))
		require.Empty(t, store.ActiveRules())
	}
	store := testStore(t, "hunter")
	r, err := NewReceiver(store, "processor", testLimits, capabilities())
	require.NoError(t, err)
	u := frame(t, nil, 1)[0]
	require.NoError(t, r.Apply(u))
	u.Session.Generation = 2
	require.ErrorIs(t, r.Apply(u), learnedrules.ErrSession)
}
func TestStagedCapacityAndReconnectRejectOldCallbacks(t *testing.T) {
	store := testStore(t, "hunter")
	limits := testLimits
	limits.MaxRules = 1
	r, err := NewReceiver(store, "processor", limits, capabilities())
	require.NoError(t, err)
	chunks := frame(t, []learnedrules.Binding{testBinding(0), testBinding(1)}, 1)
	chunks[0].SnapshotEnd = false
	chunks[0].Bindings = chunks[0].Bindings[:1]
	require.NoError(t, r.Apply(chunks[0]))
	end := &pb.LearnedRuleUpdate{ProtocolVersion: Version, Session: chunks[0].Session, Revision: 1, SubscriptionId: "subscription-1", SnapshotEnd: true, Bindings: []*pb.LearnedBinding{EncodeBinding(testBinding(1))}}
	require.ErrorIs(t, r.Apply(end), learnedrules.ErrCapacity)
	require.Empty(t, store.ActiveRules())
	replacement, err := NewReceiver(store, "processor", testLimits, capabilities())
	require.NoError(t, err)
	require.NoError(t, replacement.Apply(frame(t, nil, 1)[0]))
	require.Error(t, r.Apply(frame(t, nil, 2)[0]))
	require.Empty(t, store.ActiveRules())
}
func TestEvidenceTypedMixedProofAndIndependentWireVector(t *testing.T) {
	b := testBinding(0)
	ordinary := Candidate(b)
	b.ID = "protected"
	b.Proof = []byte{0x0a, 0x01, 'x'}
	protected := Candidate(b)
	e := &evidence.LearnedCaptureEvidence{Version: 1, Candidates: []*evidence.LearnedCandidate{ordinary, protected}}
	require.NoError(t, ValidateEvidence(e, DefaultEvidenceLimits))
	require.True(t, ReferenceMatches(protected, b))
	b.Subject.Incarnation = "reused"
	require.False(t, ReferenceMatches(protected, b))
	decoded := &evidence.LearnedCaptureEvidence{}
	require.NoError(t, proto.Unmarshal([]byte{0x08, 0x01, 0x18, 0x01}, decoded))
	require.Equal(t, uint32(1), decoded.Version)
	require.True(t, decoded.Overflow)
	require.NoError(t, ValidateEvidence(decoded, DefaultEvidenceLimits))
	protected.GetLegacyMediaRule()[0] = 0xff
	require.Equal(t, byte(0x0a), b.Proof[0])
	bad := proto.Clone(e).(*evidence.LearnedCaptureEvidence)
	bad.Candidates[0].Proof = nil
	require.Error(t, ValidateEvidence(bad, DefaultEvidenceLimits))
	bad = proto.Clone(e).(*evidence.LearnedCaptureEvidence)
	bad.Candidates[0].Proof = &evidence.LearnedCandidate_ReferenceOnly{ReferenceOnly: false}
	require.Error(t, ValidateEvidence(bad, DefaultEvidenceLimits))
	bad = proto.Clone(e).(*evidence.LearnedCaptureEvidence)
	bad.Candidates = append(bad.Candidates, bad.Candidates[0])
	require.Error(t, ValidateEvidence(bad, DefaultEvidenceLimits))
	// Two revisions of one binding are competing immutable claims, not two
	// independent subjects that may be resolved by arrival order.
	bad = proto.Clone(e).(*evidence.LearnedCaptureEvidence)
	duplicate := proto.Clone(bad.Candidates[0]).(*evidence.LearnedCandidate)
	duplicate.BindingRevision++
	bad.Candidates = append(bad.Candidates, duplicate)
	require.Error(t, ValidateEvidence(bad, DefaultEvidenceLimits))
	bad = proto.Clone(e).(*evidence.LearnedCaptureEvidence)
	bad.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	require.ErrorIs(t, ValidateEvidence(bad, DefaultEvidenceLimits), learnedrules.ErrUnsupported)
}
func TestFallbackOnlyExplicitUnsupportedExactVoIP(t *testing.T) {
	require.True(t, LegacyFallbackAllowed(status.Error(codes.Unimplemented, "old server"), true))
	require.False(t, LegacyFallbackAllowed(status.Error(codes.Unimplemented, "unknown adapter"), false))
	for _, c := range []codes.Code{codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition, codes.ResourceExhausted, codes.Unavailable} {
		require.False(t, LegacyFallbackAllowed(status.Error(c, "no downgrade"), true))
	}
}

func TestImmutableBindingAcrossDistinctSourceDomains(t *testing.T) {
	binding := testBinding(0)
	binding.Scope = append(binding.Scope, learnedrules.Scope{HunterID: "other-source", Domain: 9})
	binding.Selectors = append(binding.Selectors, learnedrules.Selector{Domain: 9, Address: netip.MustParseAddr("198.51.100.2"), Port: 7000, Protocol: learnedrules.TCP, Direction: learnedrules.Either})
	limits := Limits{MaxMessageBytes: 2048, MaxSnapshotBytes: 4096, MaxRules: 16}
	store := testStore(t, "hunter")
	receiver, err := NewReceiver(store, "processor", limits, capabilities())
	require.NoError(t, err)
	chunks, err := SnapshotChunks(binding.Session, 1, []learnedrules.Binding{binding}, limits)
	require.NoError(t, err)
	chunks[0].SubscriptionId = "scope-isolated"
	chunks[0].Capabilities = capabilities()
	require.NoError(t, receiver.Apply(chunks[0]))
	installed := store.ActiveRules()[0]
	require.Equal(t, EncodeBinding(binding), EncodeBinding(installed))
	packet := learnedrules.Packet{Domain: 9, Protocol: learnedrules.TCP, Source: learnedrules.Endpoint{Address: binding.Selectors[1].Address, Port: 7000}, Destination: learnedrules.Endpoint{Address: netip.MustParseAddr("198.51.100.3"), Port: 443}}
	require.Empty(t, store.Match(packet, 4).Bindings, "foreign source scope is not local capture permission")
}

func TestExplicitTransportCapabilitiesRefuseUnsupportedSelectors(t *testing.T) {
	caps := capabilities()
	tcp := testBinding(0)
	tcp.Selectors[0].Protocol = learnedrules.TCP
	require.NoError(t, ValidateCapabilities(caps))
	require.True(t, Supports(caps, tcp), "the original v1 capability contract supports UDP and TCP")
	caps[0].SupportedProtocols = []uint32{17}
	require.NoError(t, ValidateCapabilities(caps))
	require.False(t, Supports(caps, tcp))
	require.True(t, Supports(caps, testBinding(0)))
	for _, invalid := range [][]uint32{{1}, {6, 6}, {6, 17, 6}} {
		caps[0].SupportedProtocols = invalid
		require.Error(t, ValidateCapabilities(caps))
	}
}

func TestCapabilitiesRefuseUnrepresentablePacketEvidenceBeforeInstallation(t *testing.T) {
	binding := testBinding(0)
	binding.AdapterID = "voip"
	protectedCaps := capabilities()
	protectedCaps[0].AdapterId = "voip"
	binding.Proof = make([]byte, 300<<10)
	require.True(t, Supports(protectedCaps, binding), "valid legacy artifact sizes above the initial 256KiB draft limit remain representable")
	for _, test := range []struct {
		name   string
		change func(*learnedrules.Binding)
	}{
		{"proof", func(b *learnedrules.Binding) { b.Proof = make([]byte, DefaultEvidenceLimits.MaxProofBytes+1) }},
		{"envelope", func(b *learnedrules.Binding) { b.Proof = make([]byte, DefaultEvidenceLimits.MaxBytes) }},
		{"subject", func(b *learnedrules.Binding) {
			b.Subject.ID = strings.Repeat("x", DefaultEvidenceLimits.MaxStringBytes+1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := learnedrules.CloneBinding(binding)
			test.change(&candidate)
			require.False(t, Supports(protectedCaps, candidate))
		})
	}
	store := testStore(t, "hunter")
	receiver, err := NewReceiver(store, "processor", Limits{MaxMessageBytes: 4 << 20, MaxSnapshotBytes: 4 << 20, MaxRules: 16}, capabilities())
	require.NoError(t, err)
	binding = testBinding(0)
	binding.Subject.ID = strings.Repeat("x", DefaultEvidenceLimits.MaxStringBytes+1)
	update := &pb.LearnedRuleUpdate{ProtocolVersion: 1, Session: EncodeSession(binding.Session), Revision: 1, SnapshotBegin: true, SnapshotEnd: true, SubscriptionId: "unrepresentable", Capabilities: capabilities(), Bindings: []*pb.LearnedBinding{EncodeBinding(binding)}}
	require.ErrorIs(t, receiver.Apply(update), learnedrules.ErrUnsupported)
	require.False(t, store.Status().Ready)
	require.Empty(t, store.ActiveRules())
}

func TestNonVoIPBindingCannotBorrowLegacyMediaProofCapability(t *testing.T) {
	binding := testBinding(0)
	binding.Proof = []byte("another adapter cannot claim a media artifact")
	require.False(t, EvidenceRepresentable(binding))
	require.False(t, Supports(capabilities(), binding))
	store := testStore(t, "hunter")
	receiver, err := NewReceiver(store, "processor", testLimits, capabilities())
	require.NoError(t, err)
	update := frame(t, []learnedrules.Binding{binding}, 1)[0]
	require.ErrorIs(t, receiver.Apply(update), learnedrules.ErrUnsupported)
	require.False(t, store.Status().Ready)
	binding.Proof = nil
	require.True(t, Supports(capabilities(), binding), "ordinary reference-only diagnostics remain supported")
}
