package admission

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func derivationSDP(address string, port int, partial bool) []byte {
	body := fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 0\r\n", address, port)
	if partial {
		body += "m=audio invalid RTP/AVP 0\r\n"
	}
	return []byte(body)
}

func submitDerivation(t *testing.T, bridge *Bridge, registry *callregistry.Core, message pipeline.SIPResult) error {
	t.Helper()
	observed := bridge.ObserveValidated(message)
	if _, exists := registry.Call(message.CallID); !exists {
		registry.Upsert(callregistry.Call{CallID: message.CallID})
	}
	return errors.Join(observed, bridge.Selected(message))
}

func assertDerivationState(t *testing.T, bridge *Bridge, controller *mediaadmission.Controller, policy mediaadmission.FailurePolicy, unknown bool) {
	t.Helper()
	state := mediaadmission.StateEnforcing
	count := 0
	if unknown {
		count = 1
		state = mediaadmission.StateDegradedOpen
		if policy == mediaadmission.FailureClosed {
			state = mediaadmission.StateDegradedClosed
		}
	}
	require.Equal(t, count, bridge.Stats().UnknownDerivations)
	require.Equal(t, state, controller.Status()[0].State)
	if !unknown {
		require.Zero(t, controller.Status()[0].PendingUpdates)
	}
}

func assertDerivationMedia(t *testing.T, bridge *Bridge, callID string, endpoints ...string) {
	t.Helper()
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	state := bridge.selected[callID]
	require.NotNil(t, state)
	want := make(map[mediaadmission.EndpointKey]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		key, err := parseEndpoint(bridge.cfg.Domain, endpoint)
		require.NoError(t, err)
		want[key] = struct{}{}
	}
	require.Equal(t, want, state.mediaSet)
}

func TestDerivationOppositeAnswerRequiresSameSideRepair(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, maps, controller := recoveryFixture(t, policy, nil)
			initial := offer("opposite-answer")
			initial.SDP = derivationSDP("192.0.2.1", 10000, true)
			require.Error(t, submitDerivation(t, bridge, registry, initial))
			assertDerivationState(t, bridge, controller, policy, true)
			require.Equal(t, 2, maps.count())
			answer := initial
			answer.Method, answer.ResponseCode, answer.ToTag = "200", 200, "to"
			answer.SDP = derivationSDP("192.0.2.2", 20000, false)
			require.Error(t, submitDerivation(t, bridge, registry, answer))
			assertDerivationState(t, bridge, controller, policy, true)
			require.Equal(t, 4, maps.count())
			require.Equal(t, initial.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
			require.Equal(t, initial.CallID, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:30000", "192.0.2.1:30002").CallID)
			repair := initial
			repair.ToTag, repair.CSeqNumber, repair.ViaBranch = "to", 2, "repair"
			repair.SDP = derivationSDP("192.0.2.1", 30002, false)
			require.NoError(t, submitDerivation(t, bridge, registry, repair))
			assertDerivationState(t, bridge, controller, policy, false)
			assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:30002", "192.0.2.1:30003", "192.0.2.2:20000", "192.0.2.2:20001")
			// An old answer and the old partial request cannot undo a newer offer.
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			initial.ToTag = "to"
			require.Error(t, submitDerivation(t, bridge, registry, initial))
			assertDerivationState(t, bridge, controller, policy, false)
			assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:30002", "192.0.2.1:30003", "192.0.2.2:20000", "192.0.2.2:20001")
		})
	}
}

func TestDerivationMissingRequestRepairsOnlyExactLateOffer(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	request := offer("missing-request")
	answer := request
	answer.Method, answer.ResponseCode, answer.ToTag = "200", 200, "to"
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.Error(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
	require.NoError(t, submitDerivation(t, bridge, registry, request))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
	assertDerivationMedia(t, bridge, request.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
}

func TestDerivationInvalidTransactionCannotRepair(t *testing.T) {
	for _, invalid := range []string{"missing-branch", "wrong-cseq-header", "untagged-higher-request"} {
		t.Run(invalid, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			initial := offer(invalid)
			initial.SDP = derivationSDP("192.0.2.1", 10000, true)
			if invalid != "untagged-higher-request" {
				initial.ToTag = "to"
			}
			require.Error(t, submitDerivation(t, bridge, registry, initial))
			repair := initial
			repair.CSeqNumber, repair.ViaBranch = 2, "repair"
			repair.SDP = derivationSDP("192.0.2.1", 20000, false)
			switch invalid {
			case "missing-branch":
				repair.ViaBranch = ""
			case "wrong-cseq-header":
				repair.Headers = map[string]string{"cseq": "7 INVITE"}
			}
			require.Error(t, submitDerivation(t, bridge, registry, repair))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
		})
	}
}

func TestDerivationDelayedOfferResolvesWithACKAnswer(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	request := offer("delayed-offer")
	request.SDP = nil
	require.Error(t, submitDerivation(t, bridge, registry, request))
	answer := request
	answer.Method, answer.ResponseCode, answer.ToTag = "200", 200, "to"
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.Error(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
	ack := request
	ack.Method, ack.CSeqMethod, ack.ToTag, ack.ViaBranch = "ACK", "ACK", "to", "ack-branch"
	ack.SDP = derivationSDP("192.0.2.1", 10000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, ack))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
	assertDerivationMedia(t, bridge, request.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
}

func TestDerivationRejectedUpdatePreservesPriorAndRejectsLateSuccess(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	initial := offer("rejected-update")
	initial.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	update := initial
	update.CSeqNumber, update.ViaBranch = 2, "update"
	update.SDP = derivationSDP("192.0.2.1", 30000, true)
	require.Error(t, submitDerivation(t, bridge, registry, update))
	failure := update
	failure.Method, failure.ResponseCode, failure.SDP = "486", 486, nil
	failure.ViaBranch = "unrelated"
	require.Error(t, submitDerivation(t, bridge, registry, failure))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	failure.ViaBranch = update.ViaBranch
	require.NoError(t, submitDerivation(t, bridge, registry, failure))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:10000", "192.0.2.1:10001")
	late := failure
	late.Method, late.ResponseCode = "200", 200
	late.SDP = derivationSDP("192.0.2.2", 40000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, late))
	// A retransmitted failed offer is still a parse error, but its derivation
	// does not become current again merely because it was observed late.
	require.Error(t, submitDerivation(t, bridge, registry, update))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:10000", "192.0.2.1:10001")
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:40000", "").CallID)
}

func TestDerivationRequestInitiatorsHaveIndependentSequences(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	initial := offer("independent-sequences")
	initial.CSeqNumber, initial.ToTag = 50, "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	reverse := initial
	reverse.FromTag, reverse.ToTag, reverse.CSeqNumber, reverse.ViaBranch = "to", "from", 1, "reverse"
	reverse.SDP = derivationSDP("192.0.2.2", 20000, true)
	require.Error(t, submitDerivation(t, bridge, registry, reverse))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
	forward := initial
	forward.CSeqNumber, forward.ViaBranch = 51, "forward"
	forward.SDP = derivationSDP("192.0.2.1", 30000, false)
	require.Error(t, submitDerivation(t, bridge, registry, forward))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
	reverse.CSeqNumber, reverse.ViaBranch = 2, "reverse-repair"
	reverse.SDP = derivationSDP("192.0.2.2", 40000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, reverse))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
}

func TestDerivationConflictingRetransmissionStaysUnknown(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	initial := offer("conflicting-retransmission")
	initial.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	conflict := initial
	conflict.SDP = derivationSDP("192.0.2.1", 20000, false)
	require.Error(t, submitDerivation(t, bridge, registry, conflict))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	require.Error(t, submitDerivation(t, bridge, registry, initial))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	conflict.CSeqNumber, conflict.ViaBranch = 2, "repair"
	require.NoError(t, submitDerivation(t, bridge, registry, conflict))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
}

func TestDerivationContextCapacityLossIsBoundedUntilRetirement(t *testing.T) {
	for _, limit := range []string{"contexts", "bytes", "endpoints"} {
		t.Run(limit, func(t *testing.T) { testDerivationContextCapacity(t, limit) })
	}
}

func testDerivationContextCapacity(t *testing.T, limit string) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, mediaadmission.FailureClosed, time.Hour
	switch limit {
	case "contexts":
		cfg.PendingDialogCapacity = 1
	case "bytes":
		// Admit one descriptor, then exhaust the shared pool on its answer.
		cfg.PendingBytes, _ = derivationCost(derivationSide{"replacement", "peer", "replacement", false}, &derivationState{
			branch: "replacement", method: "INVITE", endpoints: make([]mediaadmission.EndpointKey, 2),
		})
	case "endpoints":
		cfg.PendingEndpointCapacity = 2
	}
	maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	check(t, err)
	store, err := mediaadmission.NewMetadataStore(cfg)
	check(t, err)
	registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
	bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
	check(t, err)
	t.Cleanup(func() { registry.Close(); check(t, bridge.Close()); check(t, controller.Close(context.Background())) })
	initial := offer("context-capacity")
	initial.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	answer := initial
	answer.Method, answer.ResponseCode = "200", 200
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.Error(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, cfg.FailurePolicy, true)
	for i := uint64(2); i < 10; i++ {
		answer.CSeqNumber = i
		require.Error(t, submitDerivation(t, bridge, registry, answer))
	}
	bridge.mu.Lock()
	count, bytes, endpoints := bridge.derivationCount, bridge.derivationBytes, bridge.derivationEndpoints
	bridge.mu.Unlock()
	require.LessOrEqual(t, count, cfg.PendingDialogCapacity)
	require.LessOrEqual(t, bytes, cfg.PendingBytes)
	require.LessOrEqual(t, endpoints, cfg.PendingEndpointCapacity)
	registry.Remove(initial.CallID, callregistry.EndCompleted)
	check(t, bridge.retrySelected())
	bridge.mu.Lock()
	count, bytes, endpoints = bridge.derivationCount, bridge.derivationBytes, bridge.derivationEndpoints
	bridge.mu.Unlock()
	require.Zero(t, count)
	require.Zero(t, bytes)
	require.Zero(t, endpoints)
	assertDerivationState(t, bridge, controller, cfg.FailurePolicy, false)
	reused := offer(initial.CallID)
	reused.FromTag, reused.ToTag, reused.ViaBranch = "replacement", "peer", "replacement"
	require.NoError(t, submitDerivation(t, bridge, registry, reused))
	assertDerivationState(t, bridge, controller, cfg.FailurePolicy, false)
}

func TestDerivationConcurrentRetransmissionsAndLifetimeReuse(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	initial := offer("concurrent-reuse")
	initial.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	answer := initial
	answer.Method, answer.ResponseCode = "200", 200
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	errors := make(chan error, 160)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		message := initial
		if worker%2 != 0 {
			message = answer
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				errors <- submitDerivation(t, bridge, registry, message)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
	registry.Remove(initial.CallID, callregistry.EndCompleted)
	check(t, bridge.retrySelected())
	replacement := offer(initial.CallID)
	replacement.FromTag, replacement.ToTag, replacement.ViaBranch = "new-from", "new-to", "new-branch"
	replacement.SDP = derivationSDP("192.0.2.3", 30000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, replacement))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.3:30000", "192.0.2.3:30001")
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
}

func TestDerivationInactiveAndInitialRejectionResolveUnknown(t *testing.T) {
	for _, repair := range []string{"inactive", "rejection"} {
		t.Run(repair, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			initial := offer("resolve-" + repair)
			initial.ToTag = "to"
			initial.SDP = derivationSDP("192.0.2.1", 10000, true)
			require.Error(t, submitDerivation(t, bridge, registry, initial))
			resolved := initial
			if repair == "inactive" {
				resolved.CSeqNumber, resolved.ViaBranch = 2, "inactive"
				resolved.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\na=inactive\r\n")
			} else {
				resolved.Method, resolved.ResponseCode, resolved.SDP = "486", 486, nil
			}
			require.NoError(t, submitDerivation(t, bridge, registry, resolved))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			assertDerivationMedia(t, bridge, initial.CallID)
			if repair == "rejection" {
				late := initial
				late.Method, late.ResponseCode = "200", 200
				late.SDP = derivationSDP("192.0.2.9", 40000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, late))
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
				assertDerivationMedia(t, bridge, initial.CallID)
				require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:40000", "").CallID)
			}
		})
	}
}

func TestDerivationRepeatedMediaMovesBoundContextsAndIgnoreFreshStaleEndpoint(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	message := offer("media-moves")
	message.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, message))
	for i := uint64(2); i <= 21; i++ {
		message.CSeqNumber, message.ViaBranch = i, fmt.Sprintf("move-%02d", i)
		// Reuse a bounded endpoint set so this checks context history rather
		// than deliberately exhausting the registry's separate endpoint budget.
		port := 10000 + int(i%8)*2
		message.SDP = derivationSDP("192.0.2.1", port, false)
		require.NoError(t, submitDerivation(t, bridge, registry, message))
		assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
		assertDerivationMedia(t, bridge, message.CallID, fmt.Sprintf("192.0.2.1:%d", port), fmt.Sprintf("192.0.2.1:%d", port+1))
		bridge.mu.Lock()
		count, endpoints := bridge.derivationCount, bridge.derivationEndpoints
		var predecessors int
		for _, state := range bridge.selected[message.CallID].derivations {
			if state.previous != nil {
				predecessors++
			}
		}
		bridge.mu.Unlock()
		require.Equal(t, 1, count)
		require.Equal(t, 4, endpoints, "current media and one rollback predecessor are bounded")
		require.Equal(t, 1, predecessors)
	}
	stale := message
	stale.CSeqNumber, stale.ViaBranch = 3, "move-03"
	stale.SDP = derivationSDP("192.0.2.9", 60000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, stale))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
	assertDerivationMedia(t, bridge, message.CallID, "192.0.2.1:10010", "192.0.2.1:10011")
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:60000", "").CallID)
}

func TestDerivationBodylessRequestCannotBecomeConflictingSameCSeqOffer(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	request := offer("bodyless-conflict")
	request.ToTag, request.SDP = "to", nil
	require.Error(t, submitDerivation(t, bridge, registry, request))
	request.SDP = derivationSDP("192.0.2.1", 10000, false)
	require.Error(t, submitDerivation(t, bridge, registry, request))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
}

func TestDerivationSelectedSnapshotCannotBorrowReusedLifetime(t *testing.T) {
	var source *pausedSnapshotRegistry
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, func(core *callregistry.Core) Registry {
		source = &pausedSnapshotRegistry{Core: core, entered: make(chan struct{}), release: make(chan struct{})}
		return source
	})
	initial := offer("paused-reuse")
	initial.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, initial))
	source.armed.Store(true)
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(source.release) }) })
	done := make(chan error, 1)
	go func() { done <- bridge.Selected(initial) }()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("selected endpoint snapshot was not reached")
	}
	registry.Remove(initial.CallID, callregistry.EndCompleted)
	replacement := offer(initial.CallID)
	replacement.FromTag, replacement.ToTag, replacement.ViaBranch = "new-from", "new-to", "new-branch"
	replacement.SDP = derivationSDP("192.0.2.3", 30000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, replacement))
	release.Do(func() { close(source.release) })
	require.NoError(t, <-done)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.3:30000", "192.0.2.3:30001")
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
}
