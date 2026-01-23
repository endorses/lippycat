//go:build tui || all

package tui

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPauseSignal_InitialState(t *testing.T) {
	ps := NewPauseSignal()
	assert.False(t, ps.IsPaused(), "should start in running state")
}

func TestPauseSignal_PauseResume(t *testing.T) {
	ps := NewPauseSignal()

	ps.Pause()
	assert.True(t, ps.IsPaused(), "should be paused after Pause()")

	ps.Resume()
	assert.False(t, ps.IsPaused(), "should be running after Resume()")
}

func TestPauseSignal_DoublePause(t *testing.T) {
	ps := NewPauseSignal()

	ps.Pause()
	ps.Pause() // Should not panic
	assert.True(t, ps.IsPaused())
}

func TestPauseSignal_DoubleResume(t *testing.T) {
	ps := NewPauseSignal()

	ps.Pause()
	ps.Resume()
	ps.Resume() // Should not panic
	assert.False(t, ps.IsPaused())
}

func TestPauseSignal_ChannelClosedWhenPaused(t *testing.T) {
	ps := NewPauseSignal()

	// Channel should block when running
	select {
	case <-ps.C():
		t.Fatal("channel should block when running")
	default:
		// Expected
	}

	ps.Pause()

	// Channel should return immediately when paused (closed)
	select {
	case <-ps.C():
		// Expected - closed channel returns immediately
	default:
		t.Fatal("channel should return immediately when paused")
	}
}

func TestPauseSignal_Wait(t *testing.T) {
	ps := NewPauseSignal()

	// Wait should return immediately when not paused
	done := make(chan struct{})
	go func() {
		ps.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Wait() should return immediately when not paused")
	}
}

func TestPauseSignal_WaitBlocksWhenPaused(t *testing.T) {
	ps := NewPauseSignal()
	ps.Pause()

	done := make(chan struct{})
	go func() {
		ps.Wait()
		close(done)
	}()

	// Should still be blocked after 50ms
	select {
	case <-done:
		t.Fatal("Wait() should block when paused")
	case <-time.After(50 * time.Millisecond):
		// Expected - still blocked
	}

	// Resume and verify it unblocks
	ps.Resume()

	select {
	case <-done:
		// Expected - unblocked after resume
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Wait() should unblock after Resume()")
	}
}

func TestPauseSignal_ConcurrentAccess(t *testing.T) {
	ps := NewPauseSignal()
	var wg sync.WaitGroup

	// Hammer it with concurrent operations
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			ps.Pause()
		}()
		go func() {
			defer wg.Done()
			ps.Resume()
		}()
		go func() {
			defer wg.Done()
			_ = ps.IsPaused()
			_ = ps.C()
		}()
	}

	wg.Wait()
	// Should not panic or deadlock
}
