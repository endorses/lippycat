//go:build processor || tap || all

package processor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallLifecycleCompletionBeforeAdmission(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	result := r.Finalize("synthetic-call", CallFinalizationProtocolComplete)
	require.True(t, result.Finalized)

	_, err := r.Admit("synthetic-call")
	require.Error(t, err)
	assert.True(t, IsCallFinalized(err))
}

func TestCallLifecycleFinalizationIsIdempotentAndReentrant(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	var callbacks atomic.Uint64
	r.Subscribe(func(event CallFinalizationEvent) {
		callbacks.Add(1)
		assert.False(t, r.Finalize(event.CallID, event.Reason).Finalized)
		_, err := r.Admit(event.CallID)
		assert.True(t, IsCallFinalized(err))
	})

	assert.True(t, r.Finalize("synthetic-call", CallFinalizationManual).Finalized)
	assert.False(t, r.Finalize("synthetic-call", CallFinalizationManual).Finalized)
	assert.Equal(t, uint64(1), callbacks.Load())
}

func TestCallLifecycleTTLAndCapacityReuseHaveFreshGenerations(t *testing.T) {
	t.Run("ttl", func(t *testing.T) {
		r := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: time.Millisecond, TombstoneLimit: 4})
		first, err := r.Admit("reused")
		require.NoError(t, err)
		firstGeneration := first.Generation()
		first.Release()
		require.True(t, r.Finalize("reused", CallFinalizationProtocolComplete).Finalized)
		time.Sleep(2 * time.Millisecond)

		second, err := r.Admit("reused")
		require.NoError(t, err)
		defer second.Release()
		assert.Greater(t, second.Generation(), firstGeneration)
	})

	t.Run("capacity", func(t *testing.T) {
		r := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: time.Hour, TombstoneLimit: 1})
		first, err := r.Admit("reused")
		require.NoError(t, err)
		firstGeneration := first.Generation()
		first.Release()
		r.Finalize("reused", CallFinalizationManual)
		r.Finalize("other", CallFinalizationManual)

		second, err := r.Admit("reused")
		require.NoError(t, err)
		defer second.Release()
		assert.Greater(t, second.Generation(), firstGeneration)
		assert.False(t, r.FinalizeGeneration("reused", firstGeneration, CallFinalizationIdleTimeout).Finalized)
	})
}

func TestCallLifecycleFinalizeWaitsForAdmissionAndRejectsLateWork(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	admission, err := r.Admit("synthetic-call")
	require.NoError(t, err)

	finished := make(chan CallFinalizationResult, 1)
	go func() {
		finished <- r.Finalize("synthetic-call", CallFinalizationProtocolComplete)
	}()

	require.Eventually(t, func() bool { return r.IsFinalized("synthetic-call") }, time.Second, time.Millisecond)
	select {
	case <-finished:
		t.Fatal("finalization returned before admitted work was released")
	default:
	}
	_, err = r.Admit("synthetic-call")
	assert.True(t, IsCallFinalized(err))
	admission.Release()
	assert.True(t, (<-finished).Finalized)
}

func TestCallLifecycleAdmitFinalizeSingleWinner(t *testing.T) {
	for i := 0; i < 100; i++ {
		r := NewCallLifecycleRegistry(CallLifecycleConfig{})
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var admitted atomic.Bool
		go func() {
			defer wg.Done()
			<-start
			admission, err := r.Admit("race")
			if err == nil {
				admitted.Store(true)
				admission.Release()
			} else {
				assert.True(t, IsCallFinalized(err))
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			assert.True(t, r.Finalize("race", CallFinalizationProtocolComplete).Finalized)
		}()
		close(start)
		wg.Wait()
		assert.True(t, r.IsFinalized("race"))
		if admitted.Load() {
			_, err := r.Admit("race")
			assert.True(t, IsCallFinalized(err))
		}
	}
}

func TestCallLifecycleShutdownDrainsWithoutFinalizing(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	var callbacks atomic.Uint64
	r.Subscribe(func(CallFinalizationEvent) { callbacks.Add(1) })
	admission, err := r.Admit("live")
	require.NoError(t, err)

	closed := make(chan struct{})
	go func() {
		r.Shutdown()
		close(closed)
	}()
	require.Eventually(t, func() bool {
		probe, admitErr := r.Admit("new")
		if admitErr == nil {
			probe.Release()
		}
		return errors.Is(admitErr, ErrCallLifecycleShutdown)
	}, time.Second, time.Millisecond)
	select {
	case <-closed:
		t.Fatal("shutdown returned before admitted work drained")
	default:
	}
	admission.Release()
	<-closed
	r.Shutdown()
	assert.False(t, r.IsFinalized("live"))
	assert.Zero(t, callbacks.Load())
}
