//go:build processor || tap || all

package processor

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCallLifecycleIncarnationAcrossReuse(t *testing.T) {
	for _, mode := range []string{"restart", "expired admission", "expired invite", "capacity eviction"} {
		t.Run(mode, func(t *testing.T) {
			r := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: time.Hour, TombstoneLimit: 1})
			first, err := r.Admit("reused")
			require.NoError(t, err)
			first.Release()
			require.NotEqual(t, uuid.Nil, first.Incarnation())
			require.Equal(t, uuid.Version(4), first.Incarnation().Version())
			require.Equal(t, uuid.RFC4122, first.Incarnation().Variant())
			var event CallFinalizationEvent
			r.Subscribe(func(value CallFinalizationEvent) { event = value })
			require.True(t, r.Finalize("reused", CallFinalizationProtocolComplete).Finalized)
			require.Equal(t, first.Incarnation(), event.CallIncarnation)
			require.Equal(t, first.Generation(), event.Generation)
			require.Equal(t, first.Incarnation(), r.tombstones["reused"].incarnation)

			var second *CallAdmission
			switch mode {
			case "restart":
				second, err = r.RestartInvite("reused")
			case "expired admission":
				r.tombstones["reused"].finalizedAt = time.Now().Add(-2 * time.Hour)
				second, err = r.Admit("reused")
			case "expired invite":
				r.tombstones["reused"].finalizedAt = time.Now().Add(-2 * time.Hour)
				require.False(t, r.IsFinalized("reused"))
				second, err = r.StartInviteAfterExpiry("reused")
			case "capacity eviction":
				require.True(t, r.Finalize("other", CallFinalizationManual).Finalized)
				second, err = r.Admit("reused")
			}
			require.NoError(t, err)
			defer second.Release()
			require.NotEqual(t, first.Incarnation(), second.Incarnation())
			require.NotEqual(t, uuid.Nil, second.Incarnation())
			require.Greater(t, second.Generation(), first.Generation())
			require.False(t, r.FinalizeGeneration("reused", first.Generation(), CallFinalizationIdleTimeout).Finalized)
			_, err = r.AdmitGeneration("reused", first.Generation())
			require.Error(t, err)
			current, err := r.AdmitGeneration("reused", second.Generation())
			require.NoError(t, err)
			require.Equal(t, second.Incarnation(), current.Incarnation())
			current.Release()
		})
	}
}

type countedCallEntropy struct {
	bytes atomic.Int64
}

func (r *countedCallEntropy) Read(p []byte) (int, error) {
	n, err := rand.Read(p)
	r.bytes.Add(int64(n))
	return n, err
}

func TestCallLifecycleConcurrentAdmissionsShareIncarnation(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	entropy := &countedCallEntropy{}
	r.entropy = entropy
	const count = 64
	admissions := make(chan *CallAdmission, count)
	var workers sync.WaitGroup
	for range count {
		workers.Go(func() {
			admission, err := r.Admit("one-call")
			if err != nil {
				t.Error(err)
				return
			}
			admissions <- admission
		})
	}
	workers.Wait()
	close(admissions)
	require.Len(t, admissions, count)
	var identity uuid.UUID
	var generation uint64
	for admission := range admissions {
		if identity == uuid.Nil {
			identity, generation = admission.Incarnation(), admission.Generation()
		}
		require.Equal(t, identity, admission.Incarnation())
		require.Equal(t, generation, admission.Generation())
		admission.Release()
	}
	require.Equal(t, int64(16), entropy.bytes.Load(), "new identity must not be generated per packet")
	var event CallFinalizationEvent
	r.Subscribe(func(value CallFinalizationEvent) { event = value })
	require.True(t, r.Finalize("one-call", CallFinalizationProtocolComplete).Finalized)
	require.Equal(t, identity, event.CallIncarnation)
	require.Equal(t, int64(16), entropy.bytes.Load(), "finalization of an existing call needs no entropy")

	other := NewCallLifecycleRegistry(CallLifecycleConfig{})
	another, err := other.Admit("one-call")
	require.NoError(t, err)
	defer another.Release()
	require.Equal(t, generation, another.Generation(), "local numbering can restart")
	require.NotEqual(t, identity, another.Incarnation(), "new registry cannot link a reused Call-ID to old history")
}

func TestCallLifecycleCompletionBeforeAdmissionHasIncarnation(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	var event CallFinalizationEvent
	r.Subscribe(func(value CallFinalizationEvent) { event = value })
	result := r.Finalize("early-completion", CallFinalizationProtocolComplete)
	require.True(t, result.Finalized)
	require.NoError(t, result.Err)
	require.NotEqual(t, uuid.Nil, event.CallIncarnation)
	require.Equal(t, uint64(1), event.Generation)
	first := event.CallIncarnation
	require.False(t, r.Finalize("early-completion", CallFinalizationProtocolComplete).Finalized)
	require.Equal(t, first, event.CallIncarnation)

	var absent *CallAdmission
	require.Equal(t, uuid.Nil, absent.Incarnation())
	require.Equal(t, uuid.Nil, (&CallAdmission{}).Incarnation())
}

func TestCallLifecycleEntropyFailureDoesNotPublishIdentity(t *testing.T) {
	for _, mode := range []string{"admit", "restart", "expired admit", "expired invite", "finalize", "expired finalize"} {
		t.Run(mode, func(t *testing.T) {
			r := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: time.Hour})
			if mode != "admit" && mode != "finalize" {
				require.True(t, r.Finalize("call", CallFinalizationProtocolComplete).Finalized)
				if mode != "restart" {
					r.tombstones["call"].finalizedAt = time.Now().Add(-2 * time.Hour)
				}
				if mode == "expired invite" {
					require.False(t, r.IsFinalized("call"))
				}
			}
			generation := r.nextGeneration
			oldTombstone := r.tombstones["call"]
			fault := errors.New("injected entropy failure")
			// A short read must not be padded or turned into a fallback UUID.
			r.entropy = io.MultiReader(bytes.NewReader([]byte{1, 2, 3}), iotest.ErrReader(fault))
			var callbacks int
			r.Subscribe(func(CallFinalizationEvent) { callbacks++ })
			var err error
			switch mode {
			case "admit", "expired admit":
				_, err = r.Admit("call")
			case "restart":
				_, err = r.RestartInvite("call")
			case "expired invite":
				_, err = r.StartInviteAfterExpiry("call")
			case "finalize", "expired finalize":
				result := r.Finalize("call", CallFinalizationProtocolComplete)
				require.False(t, result.Finalized)
				err = result.Err
			}
			require.ErrorIs(t, err, ErrCallLifecycleIdentity)
			require.ErrorIs(t, err, fault)
			require.ErrorIs(t, r.Err(), fault)
			require.Equal(t, generation, r.nextGeneration)
			require.Same(t, oldTombstone, r.tombstones["call"])
			require.Empty(t, r.active)
			require.Empty(t, r.finalizing)
			require.Zero(t, r.totalInflight)
			require.Zero(t, callbacks)
			r.entropy = rand.Reader
			_, err = r.Admit("different-call")
			require.ErrorIs(t, err, fault, "a repaired reader must not silently reopen a faulted owner")
			require.ErrorIs(t, r.Finalize("different-call", CallFinalizationManual).Err, fault)
			r.ShutdownAndWait()
		})
	}
}

func TestCallLifecycleIdentityFaultStillDrainsExistingCalls(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	finalizing, err := r.Admit("finalizing")
	require.NoError(t, err)
	shutdown, err := r.Admit("shutdown")
	require.NoError(t, err)
	r.entropy = iotest.ErrReader(io.ErrUnexpectedEOF)
	_, err = r.Admit("fault")
	require.ErrorIs(t, err, ErrCallLifecycleIdentity)
	_, err = r.AdmitGeneration("finalizing", finalizing.Generation())
	require.ErrorIs(t, err, ErrCallLifecycleIdentity)
	var event CallFinalizationEvent
	r.Subscribe(func(value CallFinalizationEvent) { event = value })
	finalized := make(chan CallFinalizationResult, 1)
	go func() { finalized <- r.Finalize("finalizing", CallFinalizationProtocolComplete) }()
	require.Eventually(t, func() bool { return r.IsFinalized("finalizing") }, time.Second, time.Millisecond)
	closed := make(chan struct{})
	go func() { r.ShutdownAndWait(); close(closed) }()
	finalizing.Release()
	select {
	case result := <-finalized:
		require.True(t, result.Finalized)
		require.NoError(t, result.Err)
	case <-time.After(time.Second):
		t.Fatal("identity failure prevented existing call cleanup")
	}
	require.Equal(t, finalizing.Incarnation(), event.CallIncarnation)
	shutdown.Release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("identity failure stranded shutdown references")
	}
}

func TestCallLifecycleGenerationExhaustionCannotRecycleIdentity(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	r.nextGeneration = ^uint64(0)
	_, err := r.Admit("overflow")
	require.ErrorIs(t, err, ErrCallLifecycleIdentity)
	require.Equal(t, ^uint64(0), r.nextGeneration)
	require.Empty(t, r.active)
}

func TestCallFinalizationIdentityFailureReachesOutputOwner(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	r.entropy = iotest.ErrReader(io.ErrUnexpectedEOF)
	manager, err := NewPcapWriterManagerWithLifecycle(&PcapWriterConfig{}, r)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	result, err := manager.FinalizeCall("early", CallFinalizationProtocolComplete)
	require.ErrorIs(t, err, ErrCallLifecycleIdentity)
	require.ErrorIs(t, result.Err, io.ErrUnexpectedEOF)
	require.False(t, result.Finalized)
	require.Empty(t, manager.finalizationWaiters)
	monitor := &CallCompletionMonitor{lifecycle: r}
	require.False(t, monitor.finalizeCall("another-early", CallFinalizationProtocolComplete))
	require.ErrorIs(t, r.Err(), io.ErrUnexpectedEOF)
}
