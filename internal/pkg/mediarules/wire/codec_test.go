package wire

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func testStore(t *testing.T) *mediarules.Store {
	t.Helper()
	store, err := mediarules.New(mediarules.Config{ProcessorID: "processor", HunterID: "hunter", Domains: []mediaadmission.DomainID{0},
		MaxRules: 16, MaxBytes: 32768, MaxEndpoints: 32, MaxEndpointsPerRule: 4, MaxSubscribers: 2,
		SubscriptionBuffer: 2, MaxLifetime: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store
}

func testRule(index int) mediarules.Rule {
	now := time.Now()
	return mediarules.Rule{ID: fmt.Sprintf("rule-%d", index), Session: mediarules.Session{ProcessorID: "processor", Generation: 1}, Revision: 1,
		Call: mediarules.CallAssociation{CallID: fmt.Sprintf("call-%d", index), Lifetime: callregistry.Lifetime{Session: 1, Generation: uint64(index + 1)},
			FromTag: "from", ToTag: "to", SelectionRevision: 1, FilterIDs: []string{"selected"}},
		Scope:     []mediarules.Scope{{HunterID: "hunter", Domain: 0}},
		Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Addr: netip.MustParseAddr("192.0.2.1"), Port: uint16(4000 + index)}, Kind: mediarules.RTP}},
		NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
}

var testLimits = Limits{MaxMessageBytes: 240, MaxSnapshotBytes: 4096, MaxRules: 16}

func TestChunkedSnapshotPublishesOnlyAtEndAndRemovesRules(t *testing.T) {
	store := testStore(t)
	receiver, err := NewReceiver(store, "processor", testLimits)
	require.NoError(t, err)
	rules := []mediarules.Rule{testRule(0), testRule(1), testRule(2)}
	chunks, err := SnapshotChunks(rules[0].Session, 1, rules, testLimits)
	require.NoError(t, err)
	require.Greater(t, len(chunks), 1)
	for index, chunk := range chunks {
		require.LessOrEqual(t, proto.Size(chunk), testLimits.MaxMessageBytes)
		require.NoError(t, receiver.Apply(chunk))
		if index != len(chunks)-1 {
			require.False(t, store.Status().Ready)
			require.Empty(t, store.ActiveRules())
		}
	}
	require.Len(t, store.ActiveRules(), 3)
	require.NoError(t, receiver.Apply(&management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(rules[0].Session), Revision: 2, RemovedIds: []string{rules[0].ID}}))
	require.Len(t, store.ActiveRules(), 2)
	require.False(t, store.Resolve(rules[0].Endpoints[0].Key, rules[0].Endpoints[0].Key).Resolved)
}

func TestReceiverRejectsForgedIssuerAndDiscontinuousDelta(t *testing.T) {
	store := testStore(t)
	receiver, err := NewReceiver(store, "processor", testLimits)
	require.NoError(t, err)
	rule := testRule(0)
	chunks, err := SnapshotChunks(rule.Session, 1, []mediarules.Rule{rule}, testLimits)
	require.NoError(t, err)
	forged := proto.Clone(chunks[0]).(*management.MediaRuleUpdate)
	forged.Session.ProcessorId = "other-processor"
	require.ErrorIs(t, receiver.Apply(forged), mediarules.ErrAuthority)
	require.False(t, store.Status().Ready)
	for _, chunk := range chunks {
		require.NoError(t, receiver.Apply(chunk))
	}
	require.ErrorIs(t, receiver.Apply(&management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(rule.Session), Revision: 3, RemovedIds: []string{rule.ID}}), mediarules.ErrRevision)
	require.Len(t, store.ActiveRules(), 1, "a missing revision must not partially mutate installed rules")
}

func TestNewReceiverInvalidatesOldConnectionCallbacks(t *testing.T) {
	store := testStore(t)
	rule := testRule(0)
	chunks, err := SnapshotChunks(rule.Session, 1, []mediarules.Rule{rule}, testLimits)
	require.NoError(t, err)
	old, err := NewReceiver(store, "processor", testLimits)
	require.NoError(t, err)
	for _, chunk := range chunks {
		require.NoError(t, old.Apply(chunk))
	}
	next, err := NewReceiver(store, "processor", testLimits)
	require.NoError(t, err)
	require.Empty(t, store.ActiveRules(), "a new connection must wait for its own authoritative snapshot")
	require.ErrorIs(t, old.Apply(&management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(rule.Session), Revision: 2, RemovedIds: []string{rule.ID}}), mediarules.ErrSession)
	for _, chunk := range chunks {
		require.NoError(t, next.Apply(chunk))
	}
	require.Len(t, store.ActiveRules(), 1)
}

func TestWireRejectsTruncatedEndpointsAndOversizedStaging(t *testing.T) {
	rule := testRule(0)
	for _, port := range []uint32{0, 65536, ^uint32(0)} {
		encoded := EncodeRule(rule)
		encoded.Endpoints[0].Port = port
		_, err := DecodeRule(encoded)
		require.ErrorIs(t, err, mediarules.ErrInvalid)
	}
	encoded := EncodeRule(rule)
	encoded.Endpoints[0].Kind = -1
	_, err := DecodeRule(encoded)
	require.ErrorIs(t, err, mediarules.ErrInvalid)
	encoded = EncodeRule(rule)
	encoded.Scopes[0] = nil
	_, err = DecodeRule(encoded)
	require.ErrorIs(t, err, mediarules.ErrScope)
	_, err = SnapshotChunks(rule.Session, 1, []mediarules.Rule{rule}, Limits{MaxMessageBytes: 32, MaxSnapshotBytes: 4096, MaxRules: 1})
	require.ErrorIs(t, err, mediarules.ErrCapacity)

	store := testStore(t)
	limits := testLimits
	limits.MaxRules = 1
	receiver, err := NewReceiver(store, "processor", limits)
	require.NoError(t, err)
	first := &management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(rule.Session), Revision: 1, SnapshotBegin: true, Rules: []*management.MediaRule{EncodeRule(rule)}}
	require.NoError(t, receiver.Apply(first))
	second := &management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(rule.Session), Revision: 1, SnapshotEnd: true, Rules: []*management.MediaRule{EncodeRule(testRule(1))}}
	require.ErrorIs(t, receiver.Apply(second), mediarules.ErrCapacity)
	require.Empty(t, store.ActiveRules())
}

func TestCapturePolicyRevisionRoundTrip(t *testing.T) {
	rule := testRule(0)
	rule.Call.CapturePolicyRevision = 42
	encoded := EncodeRule(rule)
	decoded, err := DecodeRule(encoded)
	require.NoError(t, err)
	require.Equal(t, rule.Call.CapturePolicyRevision, decoded.Call.CapturePolicyRevision)
}
