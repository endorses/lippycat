//go:build tui || all

package tui

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCaptureStateStopCaptureResumesPausedPipeline(t *testing.T) {
	pause := NewPauseSignal()
	pause.Pause()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	state := &CaptureState{pauseSignal: pause}
	state.SetHandle(cancel, done)

	go func() {
		pause.Wait()
		<-ctx.Done()
		close(done)
	}()

	stopped := make(chan bool, 1)
	go func() {
		stopped <- state.StopCapture()
	}()

	select {
	case result := <-stopped:
		require.True(t, result)
	case <-time.After(time.Second):
		t.Fatal("StopCapture blocked while the capture pipeline was paused")
	}
	require.False(t, pause.IsPaused())
	require.False(t, state.HasActiveCapture())
}
