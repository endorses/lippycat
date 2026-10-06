package admission

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestReplayWindowSequentialCallsReleaseSeparateCapacity(t *testing.T) {
	b, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	cfg := b.cfg.Limits
	cfg.ReplayGuardCapacity = 2
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	b.cfg.Metadata = store
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("synthetic-sequential-%d", i)
		invite, _, _ := reliableSequence(id)
		request, answer := recoveryAtSequence(invite, "caller", "INVITE", uint64(i+1))
		require.NoError(t, submitDerivation(t, b, registry, request))
		require.NoError(t, submitDerivation(t, b, registry, answer))
		assertDerivationState(t, b, controller, mediaadmission.FailureClosed, false)
		call, ok := registry.Call(id)
		require.True(t, ok)
		b.OnCallEnded(call, callregistry.EndReason("completed"))
		b.mu.Lock()
		// Advance the maintenance clock to model independent calls separated
		// by the configured protection horizon without wall-clock sleeping.
		b.expireLifetimeProofLocked(time.Now().Add(cfg.ReplayWindow))
		b.mu.Unlock()
		require.Zero(t, store.Stats().ReplayContexts)
		require.Zero(t, store.Stats().SelectedContexts)
	}
}

func TestReplayWindowBoundaryAndExplicitLifetime(t *testing.T) {
	b, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 10, Generation: 1}, derivations: map[derivationSide]*derivationState{
		{sender: "from", peer: "to", initiator: "from"}: {cseq: 12, method: "INVITE"},
	}}
	require.NoError(t, b.rememberLifetimeLocked("synthetic-reuse", old))
	hash := lifetimeInitiatorHash("synthetic-reuse", "from")
	due := b.proofHistory.initiators[hash].expires
	b.expireLifetimeProofLocked(due.Add(-time.Nanosecond))
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 10, Generation: 2}}
	key := mediaadmission.DialogKey{CallID: "synthetic-reuse", FromTag: "from", CSeq: 12, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, b.checkKeyLifetimeLocked(current, key))
	b.expireLifetimeProofLocked(due)
	// Unbound identical wire evidence is deliberately indistinguishable after
	// the supported window. Explicit old generation evidence remains rejected.
	require.True(t, b.checkKeyLifetimeLocked(current, key))
	require.True(t, b.canConfirmedLifetimeLocked(current, key))
	key.LifetimeSession, key.LifetimeGeneration = old.lifetime.Session, old.lifetime.Generation
	require.False(t, b.checkKeyLifetimeLocked(current, key))
	require.False(t, b.canConfirmedLifetimeLocked(current, key))
}

func TestReplayUnrecordedRetirementExtendsFiniteDomainProtection(t *testing.T) {
	b, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	cfg := b.cfg.Limits
	cfg.ReplayGuardCapacity = 1
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	b.cfg.Metadata = store
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}, contextLost: true}
	require.NoError(t, b.rememberLifetimeLocked("synthetic-first", old))
	require.ErrorIs(t, b.rememberLifetimeLocked("synthetic-overflow", old), mediaadmission.ErrCapacity)
	firstDeadline := b.proofHistory.blockedUntil
	require.ErrorIs(t, b.rememberLifetimeLocked("synthetic-overflow-again", old), mediaadmission.ErrCapacity)
	require.False(t, b.proofHistory.blockedUntil.Before(firstDeadline))
	require.Equal(t, uint64(2), b.proofHistory.unrecorded)
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}, known: true}
	b.selected["synthetic-unrelated"] = current
	key := mediaadmission.DialogKey{CallID: "synthetic-unrelated", FromTag: "from", CSeq: 5, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, b.checkKeyLifetimeLocked(current, key))
	require.False(t, current.lifetimeAmbiguous, "capacity pressure is independently expiring")
	current.unknown = true
	b.expireLifetimeProofLocked(b.proofHistory.blockedUntil)
	require.True(t, b.proofHistory.blockedUntil.IsZero())
	require.True(t, current.replayBlockedUntil.IsZero())
	require.True(t, current.unknown, "discarded observations require fresh complete evidence")
	require.True(t, b.checkKeyLifetimeLocked(current, key))
}
