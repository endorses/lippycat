package admission

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func pressureFixture(t *testing.T, policy mediaadmission.FailurePolicy) (*Bridge, *callregistry.Core, *mediaadmission.Controller) {
	t.Helper()
	b, r, c := retirementFixture(t, mediaadmission.ModeEnforce, policy)
	cfg := b.cfg.Limits
	cfg.ReplayGuardCapacity = 2
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	b.cfg.Metadata = store
	b.cfg.Limits.ReplayGuardCapacity = 2
	return b, r, c
}
func exhaustReplay(t *testing.T, b *Bridge, r *callregistry.Core) {
	t.Helper()
	for _, id := range []string{"synthetic-guard", "synthetic-overflow"} {
		request, response := recoveryAtSequence(offer(id), "caller", "INVITE", 1)
		_ = submitDerivation(t, b, r, request)
		_ = submitDerivation(t, b, r, response)
		require.True(t, r.Remove(id, callregistry.EndCompleted))
	}
	require.True(t, time.Now().Before(b.proofHistory.blockedUntil))
}
func expirePressure(t *testing.T, b *Bridge) {
	t.Helper()
	b.mu.Lock()
	b.expireLifetimeProofLocked(b.proofHistory.blockedUntil)
	b.mu.Unlock()
	require.NoError(t, b.retrySelected())
}
func TestReplayPressureProofFreeAndRetainedRetransmissionsDoNotPoison(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			b, r, c := pressureFixture(t, policy)
			request, response := recoveryAtSequence(offer("synthetic-healthy"), "caller", "INVITE", 1)
			require.NoError(t, submitDerivation(t, b, r, request))
			require.NoError(t, submitDerivation(t, b, r, response))
			exhaustReplay(t, b, r)
			for _, method := range []string{"INFO", "OPTIONS"} {
				message := request
				message.SDP = nil
				message.Method = method
				message.CSeqMethod = method
				message.CSeqNumber = 2
				message.Headers = map[string]string{"cseq": "2 " + method}
				message.ToTag = response.ToTag
				_ = submitDerivation(t, b, r, message)
			}
			_ = submitDerivation(t, b, r, request)
			_ = submitDerivation(t, b, r, response)
			b.mu.Lock()
			state := b.selected[request.CallID]
			require.False(t, state.replayEvidenceMissing)
			require.Nil(t, state.quarantine)
			b.mu.Unlock()
			expirePressure(t, b)
			assertDerivationState(t, b, c, policy, false)
			retirementOwns(t, r, request.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
		})
	}
}
func TestReplayPressureIncompleteProofExpiresAndRequiresFreshExchange(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			b, r, _ := pressureFixture(t, policy)
			exhaustReplay(t, b, r)
			request, _ := recoveryAtSequence(offer("synthetic-incomplete"), "caller", "INVITE", 1)
			_ = submitDerivation(t, b, r, request)
			b.mu.Lock()
			state := b.selected[request.CallID]
			require.NotNil(t, state.quarantine)
			expires := state.quarantineExpires
			b.expireLifetimeProofLocked(b.proofHistory.blockedUntil)
			require.True(t, state.unknown)
			require.True(t, state.replayEvidenceMissing)
			b.expireLifetimeProofLocked(expires)
			require.Nil(t, state.quarantine)
			require.Zero(t, b.cfg.Metadata.Stats().SelectedContexts)
			b.mu.Unlock()
			fresh, answer := recoveryAtSequence(request, "caller", "INVITE", 2)
			_ = submitDerivation(t, b, r, fresh)
			require.NoError(t, submitDerivation(t, b, r, answer))
			require.Zero(t, b.Stats().UnknownDerivations)
		})
	}
}
func TestReplayPressureQuarantineExhaustionIsBounded(t *testing.T) {
	b, r, _ := pressureFixture(t, mediaadmission.FailureClosed)
	exhaustReplay(t, b, r)
	cfg := b.cfg.Limits
	cfg.PendingDialogCapacity = 1
	cfg.PendingBytes = 4096
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	// Replay history remains accounted in its old store only for this fixture;
	// reset after clearing it before switching the descriptor-budget store.
	b.mu.Lock()
	deadline := b.proofHistory.blockedUntil
	require.NoError(t, b.releaseLifetimeProofLocked())
	b.cfg.Metadata = store
	b.proofHistory.blockedUntil = deadline
	b.mu.Unlock()
	request, response := recoveryAtSequence(offer("synthetic-bounded"), "caller", "INVITE", 1)
	_ = submitDerivation(t, b, r, request)
	_ = submitDerivation(t, b, r, response)
	b.mu.Lock()
	state := b.selected[request.CallID]
	require.True(t, state.quarantine.contextLost)
	require.LessOrEqual(t, store.Stats().SelectedContexts, 1)
	b.expireLifetimeProofLocked(deadline)
	require.True(t, state.unknown)
	b.expireLifetimeProofLocked(state.quarantineExpires)
	require.Nil(t, state.quarantine)
	require.Zero(t, store.Stats().SelectedContexts)
	b.mu.Unlock()
}
func TestReplayPressureRepeatedDeadlineDoesNotRenewQuarantine(t *testing.T) {
	b, r, _ := pressureFixture(t, mediaadmission.FailureClosed)
	exhaustReplay(t, b, r)
	request, response := recoveryAtSequence(offer("synthetic-repeated"), "caller", "INVITE", 1)
	_ = submitDerivation(t, b, r, request)
	_ = submitDerivation(t, b, r, response)
	b.mu.Lock()
	state := b.selected[request.CallID]
	expiry := state.quarantineExpires
	b.proofHistory.blockedUntil = expiry.Add(time.Second)
	b.mu.Unlock()
	_ = submitDerivation(t, b, r, response)
	b.mu.Lock()
	require.Equal(t, expiry, state.quarantineExpires)
	b.expireLifetimeProofLocked(expiry)
	require.Nil(t, state.quarantine)
	require.True(t, state.replayEvidenceMissing)
	require.True(t, state.unknown)
	b.mu.Unlock()
}
func TestReplayPressureExplicitOldLifetimeRejectedAndSurvivingGuardBlocksQuarantine(t *testing.T) {
	b, r, _ := pressureFixture(t, mediaadmission.FailureClosed)
	exhaustReplay(t, b, r)
	request, response := recoveryAtSequence(offer("synthetic-guarded-active"), "caller", "INVITE", 1)
	_ = submitDerivation(t, b, r, request)
	_ = submitDerivation(t, b, r, response)
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.selected[request.CallID]
	old := mediaadmission.DialogKey{CallID: request.CallID, FromTag: request.FromTag, LifetimeSession: state.lifetime.Session, LifetimeGeneration: state.lifetime.Generation + 1, CSeq: 99, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, b.observeSelectedRecordLocked(state, mediaadmission.MetadataRecord{Key: old, Complete: true}))
	// A separately surviving exact guard must still reject the quarantined
	// exchange even when global storage pressure has reached its deadline.
	deadline := b.proofHistory.blockedUntil
	for hash := range b.proofHistory.initiators {
		delete(b.proofHistory.initiators, hash)
	}
	b.proofHistory.initiators[lifetimeInitiatorHash(request.CallID, request.FromTag)] = retiredInitiatorProof{lifetime: callregistry.Lifetime{Session: state.lifetime.Session, Generation: state.lifetime.Generation + 1}, maximum: 1, expires: deadline.Add(time.Second)}
	b.expireLifetimeProofLocked(deadline)
	require.True(t, state.replayEvidenceMissing)
	require.True(t, state.unknown)
}

func TestReplayPressureCachedPrePressureProofDoesNotRepairIncompleteQuarantine(t *testing.T) {
	b, r, _ := pressureFixture(t, mediaadmission.FailureClosed)
	first, accepted := recoveryAtSequence(offer("synthetic-cached"), "caller", "INVITE", 1)
	require.NoError(t, submitDerivation(t, b, r, first))
	require.NoError(t, submitDerivation(t, b, r, accepted))
	exhaustReplay(t, b, r)
	incomplete, _ := recoveryAtSequence(first, "caller", "INVITE", 2)
	_ = submitDerivation(t, b, r, incomplete)
	b.mu.Lock()
	state := b.selected[first.CallID]
	b.expireLifetimeProofLocked(b.proofHistory.blockedUntil)
	require.True(t, state.replayEvidenceMissing)
	b.mu.Unlock()
	_ = submitDerivation(t, b, r, first)
	_ = submitDerivation(t, b, r, accepted)
	b.mu.Lock()
	require.True(t, state.replayEvidenceMissing)
	require.True(t, state.unknown)
	b.mu.Unlock()
	fresh, response := recoveryAtSequence(first, "caller", "INVITE", 3)
	_ = submitDerivation(t, b, r, fresh)
	require.NoError(t, submitDerivation(t, b, r, response))
	require.Zero(t, b.Stats().UnknownDerivations)
}

func TestReplayPressureReliableCompleteExchangeRemainsQuarantinedUntilDeadline(t *testing.T) {
	b, r, c := pressureFixture(t, mediaadmission.FailureClosed)
	exhaustReplay(t, b, r)
	invite, response, prack := reliableSequence("synthetic-quarantined-reliable")
	_ = submitDerivation(t, b, r, invite)
	_ = submitDerivation(t, b, r, response)
	_ = submitDerivation(t, b, r, prack)
	final := response
	final.ResponseCode = 200
	final.SDP = nil
	final.Headers = map[string]string{"cseq": "1 INVITE"}
	_ = submitDerivation(t, b, r, final)
	require.Equal(t, 1, b.Stats().UnknownDerivations)
	require.Empty(t, r.CallIDsForEndpoint("192.0.2.1:10000"))
	expirePressure(t, b)
	assertDerivationState(t, b, c, mediaadmission.FailureClosed, false)
	retirementOwns(t, r, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
}

func TestReplayPressureDelayedOfferACKCompleteExchangeRecovers(t *testing.T) {
	b, r, c := pressureFixture(t, mediaadmission.FailureClosed)
	exhaustReplay(t, b, r)
	invite := offer("synthetic-quarantined-delayed")
	invite.SDP = nil
	invite.Headers = map[string]string{"cseq": "1 INVITE"}
	response := invite
	response.Method = "RESPONSE"
	response.ResponseCode = 200
	response.ToTag = "peer"
	response.SDP = derivationSDP("192.0.2.2", 20000, false)
	ack := invite
	ack.Method = "ACK"
	ack.CSeqMethod = "ACK"
	ack.ToTag = "peer"
	ack.ViaBranch = "ack-separate"
	ack.Headers = map[string]string{"cseq": "1 ACK"}
	ack.SDP = derivationSDP("192.0.2.1", 10000, false)
	_ = submitDerivation(t, b, r, invite)
	_ = submitDerivation(t, b, r, response)
	_ = submitDerivation(t, b, r, ack)
	require.Equal(t, 1, b.Stats().UnknownDerivations)
	require.Empty(t, r.CallIDsForEndpoint("192.0.2.1:10000"))
	expirePressure(t, b)
	assertDerivationState(t, b, c, mediaadmission.FailureClosed, false)
	retirementOwns(t, r, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
}

func TestReplayPressureCannotDiscardIndependentUnboundedHeaderConflict(t *testing.T) {
	b, r, _ := pressureFixture(t, mediaadmission.FailureClosed)
	first, accepted := recoveryAtSequence(offer("synthetic-independent-conflict"), "caller", "INVITE", 1)
	require.NoError(t, submitDerivation(t, b, r, first))
	require.NoError(t, submitDerivation(t, b, r, accepted))
	exhaustReplay(t, b, r)
	malformed, _ := recoveryAtSequence(first, "caller", "INVITE", 2)
	malformed.ToTag = accepted.ToTag
	malformed.ReliableHeaderEvidence.Conflicts = sip.ReliableHeaderConflicts{CSeq: true}
	malformed.ReliableHeaderEvidence.CSeqBoundsValid = false
	_ = submitDerivation(t, b, r, malformed)
	b.mu.Lock()
	state := b.selected[first.CallID]
	b.expireLifetimeProofLocked(b.proofHistory.blockedUntil)
	b.expireLifetimeProofLocked(state.quarantineExpires)
	b.mu.Unlock()
	fresh, response := recoveryAtSequence(first, "caller", "INVITE", 3)
	_ = submitDerivation(t, b, r, fresh)
	_ = submitDerivation(t, b, r, response)
	require.Equal(t, 1, b.Stats().UnknownDerivations, "missing pressure proof must not erase unbounded contradictory evidence")
}
