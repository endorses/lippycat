//go:build tui || all

package tui

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCaptureStateStopCaptureReleasesPausedWorker(t *testing.T) {
	state := &CaptureState{pauseSignal: NewPauseSignal()}
	state.pauseSignal.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	state.SetHandle(cancel, done)

	go func() {
		state.pauseSignal.Wait()
		<-ctx.Done()
		close(done)
	}()

	stopped := make(chan bool, 1)
	go func() { stopped <- state.StopCapture() }()

	select {
	case result := <-stopped:
		require.True(t, result)
	case <-time.After(time.Second):
		t.Fatal("StopCapture blocked while the capture worker was paused")
	}
	require.False(t, state.pauseSignal.IsPaused())
}
