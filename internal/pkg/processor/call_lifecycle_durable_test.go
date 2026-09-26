//go:build processor || tap || all

package processor

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequiredCallClosureFailurePropagatesAndStillCleansUp(t *testing.T) {
	r := NewCallLifecycleRegistry(CallLifecycleConfig{})
	first, err := r.Admit("first")
	require.NoError(t, err)
	second, err := r.Admit("second")
	require.NoError(t, err)
	first.Release()
	second.Release()
	failure := errors.New("durable closure uncertain")
	var cleanup, closures int
	r.SubscribeFinalizer(func(event CallFinalizationEvent) error {
		closures++
		require.NotZero(t, event.CallIncarnation)
		_, err := r.AdmitGeneration(event.CallID, event.Generation)
		require.Error(t, err, "closure runs after capture admission has closed")
		return failure
	})
	r.Subscribe(func(CallFinalizationEvent) { cleanup++ })
	result := r.Finalize("first", CallFinalizationManual)
	require.True(t, result.Finalized)
	require.ErrorIs(t, result.Err, failure)
	require.ErrorIs(t, r.Err(), failure)
	_, err = r.Admit("new")
	require.ErrorIs(t, err, failure)
	_, err = r.Admit("second")
	require.ErrorIs(t, err, failure)
	result = r.Finalize("second", CallFinalizationIdleTimeout)
	require.True(t, result.Finalized, "existing incarnations still close despite fault")
	require.ErrorIs(t, result.Err, failure)
	require.Equal(t, 2, cleanup)
	require.Equal(t, 2, closures)
	r.ShutdownAndWait()
}

func TestRequiredCallClosureFailureSurvivesProcessorShutdown(t *testing.T) {
	p, err := New(Config{ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t)})
	require.NoError(t, err)
	failure := errors.New("required closure failed")
	t.Cleanup(func() { require.ErrorIs(t, p.Shutdown(), failure) })
	p.callLifecycle.SubscribeFinalizer(func(CallFinalizationEvent) error { return failure })
	admission, err := p.callLifecycle.Admit("closing")
	require.NoError(t, err)
	admission.Release()
	require.ErrorIs(t, p.callLifecycle.Finalize("closing", CallFinalizationIdleTimeout).Err, failure)
	require.ErrorIs(t, p.Shutdown(), failure, "shutdown cannot report success after a prior required closure fault")
}
