package admission

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func receiptFixture(t *testing.T) (*Bridge, *callregistry.Core, *replayTestClock) {
	t.Helper()
	clock := &replayTestClock{}
	clock.set(time.Now())
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled, cfg.Mode, cfg.FailurePolicy, cfg.RetryInterval = true, mediaadmission.ModeEnforce, mediaadmission.FailureClosed, time.Hour
	cfg.ReplayGuardCapacity, cfg.ReplayGuardBytes = 2, 4096
	cfg.ReplayWindow, cfg.PendingTTL, cfg.PendingDialogCapacity = time.Second, time.Minute, 4
	b, r, _ := retirementConfiguredFixture(t, cfg, clock.now)
	return b, r, clock
}
func loseReceiptStaging(t *testing.T, b *Bridge, clock *replayTestClock, id, kind string) {
	t.Helper()
	if kind == "eviction" {
		for i := range 6 {
			extra := offer(fmt.Sprintf("synthetic-receipt-eviction-%d", i))
			require.NoError(t, b.ObserveValidatedReceipt(&extra))
		}
		require.NotZero(t, b.cfg.Metadata.Stats().Evicted)
		clock.set(clock.now().Add(b.cfg.Limits.ReplayWindow))
	} else {
		clock.set(clock.now().Add(b.cfg.Limits.ReplayWindow + b.cfg.Limits.PendingTTL + time.Nanosecond))
	}
	b.cfg.Metadata.Expire(clock.now())
	require.Empty(t, b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, id, clock.now()))
	b.mu.Lock()
	b.expireLifetimeProofLocked(clock.now())
	b.mu.Unlock()
}
func TestReceiptProvenanceSurvivesStagingLoss(t *testing.T) {
	for _, kind := range []string{"ttl", "eviction"} {
		for _, receipt := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/receipt-%v", kind, receipt), func(t *testing.T) {
				b, r, clock := receiptFixture(t)
				retireObservationPair(t, b, r, "synthetic-receipt-guard")
				request, response := retireObservationPair(t, b, r, "synthetic-receipt-retired")
				if receipt {
					require.NoError(t, b.ObserveValidatedReceipt(&request))
					require.NoError(t, b.ObserveValidatedReceipt(&response))
				} else {
					require.NoError(t, b.ObserveValidated(request))
					require.NoError(t, b.ObserveValidated(response))
				}
				loseReceiptStaging(t, b, clock, request.CallID, kind)
				r.Upsert(callregistry.Call{CallID: request.CallID})
				_ = b.Selected(request)
				_ = b.Selected(response)
				snapshot, ok := r.EndpointSnapshot(request.CallID)
				require.True(t, ok)
				require.Empty(t, snapshot.Endpoints, "same original observation cannot be restamped after staging loss")
				require.Equal(t, 1, b.Stats().UnknownDerivations)
				// A new receipt for identical wire evidence after expiry is distinct.
				_ = submitDerivation(t, b, r, request)
				require.NoError(t, submitDerivation(t, b, r, response))
				retirementOwns(t, r, request.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
			})
		}
	}
}
func TestReceiptProvenanceRetainsHistoryInvalidationWithoutStaging(t *testing.T) {
	for _, kind := range []string{"ttl", "eviction"} {
		t.Run(kind, func(t *testing.T) {
			b, r, clock := receiptFixture(t)
			retireObservationPair(t, b, r, "synthetic-receipt-guard")
			retireObservationPair(t, b, r, "synthetic-receipt-overflow")
			request, response := recoveryAtSequence(offer("synthetic-receipt-genuine"), "caller", "INVITE", 1)
			require.NoError(t, b.ObserveValidatedReceipt(&request))
			require.NoError(t, b.ObserveValidatedReceipt(&response))
			retireObservationPair(t, b, r, "synthetic-receipt-history-loss")
			loseReceiptStaging(t, b, clock, request.CallID, kind)
			r.Upsert(callregistry.Call{CallID: request.CallID})
			_ = b.Selected(request)
			_ = b.Selected(response)
			snapshot, ok := r.EndpointSnapshot(request.CallID)
			require.True(t, ok)
			require.Empty(t, snapshot.Endpoints)
			require.Equal(t, 1, b.Stats().UnknownDerivations)
		})
	}
}
func TestReceiptProvenancePreservesHigherWatermarkAndFreshTimestamps(t *testing.T) {
	b, r, clock := receiptFixture(t)
	retired, _ := retireObservationPair(t, b, r, "synthetic-receipt-watermark")
	request, response := recoveryAtSequence(retired, "caller", "INVITE", 7)
	request.Timestamp = clock.now()
	response.Timestamp = clock.now()
	require.NoError(t, b.ObserveValidatedReceipt(&request))
	require.NoError(t, b.ObserveValidatedReceipt(&response))
	loseReceiptStaging(t, b, clock, request.CallID, "ttl")
	r.Upsert(callregistry.Call{CallID: request.CallID})
	_ = b.Selected(request)
	require.NoError(t, b.Selected(response))
	require.Zero(t, b.Stats().UnknownDerivations)
	// Repeated receipts may reuse canonical staging keys; their actual capture
	// timestamp still binds the result and must not cause a false mismatch.
	for i := range 2 {
		repeated := request
		repeated.Timestamp = clock.now().Add(time.Duration(i+1) * time.Millisecond)
		require.NoError(t, b.ObserveValidatedReceipt(&repeated))
		require.NoError(t, b.Selected(repeated))
	}
	retireObservationPair(t, b, r, "synthetic-receipt-new-guard")
	retireObservationPair(t, b, r, "synthetic-receipt-new-overflow")
	ack := request
	ack.SDP = nil
	ack.Method = "ACK"
	ack.CSeqMethod = "ACK"
	ack.Headers = map[string]string{"cseq": "7 ACK"}
	ack.ToTag = response.ToTag
	ack.ViaBranch = "separate-ack"
	for i := range 2 {
		ack.Timestamp = clock.now().Add(time.Duration(i+1) * time.Millisecond)
		require.NoError(t, b.ObserveValidatedReceipt(&ack))
		_ = b.Selected(ack)
	}
	require.Zero(t, b.Stats().UnknownDerivations)
}
func TestReceiptProvenanceRejectsScopeAndEvidenceMutation(t *testing.T) {
	for _, kind := range []string{"scope", "sdp", "timestamp"} {
		t.Run(kind, func(t *testing.T) {
			b, r, clock := receiptFixture(t)
			request, response := recoveryAtSequence(offer("synthetic-receipt-bound"), "caller", "INVITE", 1)
			require.NoError(t, b.ObserveValidatedReceipt(&request))
			require.NoError(t, b.ObserveValidatedReceipt(&response))
			b.cfg.Metadata.Expire(clock.now().Add(b.cfg.Limits.PendingTTL))
			switch kind {
			case "scope":
				other, _, _ := receiptFixture(t)
				require.NoError(t, other.ObserveValidatedReceipt(&request))
				require.NoError(t, other.ObserveValidatedReceipt(&response))
			case "sdp":
				request.SDP = derivationSDP("192.0.2.9", 50000, false)
			case "timestamp":
				request.Timestamp = clock.now().Add(time.Hour)
			}
			r.Upsert(callregistry.Call{CallID: request.CallID})
			_ = b.Selected(request)
			_ = b.Selected(response)
			require.Equal(t, 1, b.Stats().UnknownDerivations)
			require.Empty(t, r.CallIDsForEndpoint("192.0.2.9:50000"))
		})
	}
}
func TestReceiptlessProofFreeMessagePreservesRetainedProof(t *testing.T) {
	b, r, _ := receiptFixture(t)
	request, response := recoveryAtSequence(offer("synthetic-receipt-healthy"), "caller", "INVITE", 1)
	require.NoError(t, submitDerivation(t, b, r, request))
	require.NoError(t, submitDerivation(t, b, r, response))
	ack := request
	ack.SDP = nil
	ack.Method = "ACK"
	ack.CSeqMethod = "ACK"
	ack.Headers = map[string]string{"cseq": "1 ACK"}
	ack.ToTag = response.ToTag
	ack.ViaBranch = "separate-ack"
	require.NoError(t, b.Selected(ack))
	require.Zero(t, b.Stats().UnknownDerivations)
}
