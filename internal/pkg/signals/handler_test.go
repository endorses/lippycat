package signals

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetupHandler_CancelsContextOnSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := SetupHandler(ctx, cancel)
	defer cleanup()

	// Send SIGTERM to ourselves
	proc, err := os.FindProcess(os.Getpid())
	assert.NoError(t, err)

	err = proc.Signal(syscall.SIGTERM)
	assert.NoError(t, err)

	// Context should be cancelled within a short time
	select {
	case <-ctx.Done():
		// Success - context was cancelled
	case <-time.After(1 * time.Second):
		t.Fatal("Context was not cancelled after signal")
	}
}

func TestSetupHandler_CleansUpOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cleanup := SetupHandler(ctx, cancel)

	// Cancel context immediately
	cancel()

	// Give handler time to clean up
	time.Sleep(100 * time.Millisecond)

	// Cleanup should not panic
	cleanup()
}

func TestSetupHandlerWithCallback_InvokesCallbackOnSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callbackInvoked := false
	callback := func() {
		callbackInvoked = true
		cancel()
	}

	cleanup := SetupHandlerWithCallback(ctx, callback)
	defer cleanup()

	// Send SIGTERM to ourselves
	proc, err := os.FindProcess(os.Getpid())
	assert.NoError(t, err)

	err = proc.Signal(syscall.SIGTERM)
	assert.NoError(t, err)

	// Callback should be invoked within a short time
	select {
	case <-ctx.Done():
		assert.True(t, callbackInvoked, "Callback should have been invoked")
	case <-time.After(1 * time.Second):
		t.Fatal("Callback was not invoked after signal")
	}
}

func TestSetupHandlerWithCallback_CleansUpOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	callbackInvoked := false
	callback := func() {
		callbackInvoked = true
	}

	cleanup := SetupHandlerWithCallback(ctx, callback)

	// Cancel context immediately
	cancel()

	// Give handler time to clean up
	time.Sleep(100 * time.Millisecond)

	// Callback should not have been invoked
	assert.False(t, callbackInvoked, "Callback should not be invoked on context cancellation")

	// Cleanup should not panic
	cleanup()
}

func TestSetupHandler_EarlyCleanupNoPanic(t *testing.T) {
	// This test ensures that calling cleanup() early (before any signal or context cancellation)
	// does not cause a panic. This is the scenario that occurs when a service fails to start
	// (e.g., "address already in use") and cleanup is called via defer.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := SetupHandler(ctx, cancel)

	// Immediately call cleanup without any signal or context cancellation
	// This used to panic due to nil pointer dereference when reading from closed channel
	cleanup()

	// Give the goroutine time to process the closed channel
	time.Sleep(50 * time.Millisecond)

	// If we get here, no panic occurred - test passes
}

func TestSetupHandlerWithCallback_EarlyCleanupNoPanic(t *testing.T) {
	// Same test for the callback variant
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callbackInvoked := false
	callback := func() {
		callbackInvoked = true
	}

	cleanup := SetupHandlerWithCallback(ctx, callback)

	// Immediately call cleanup without any signal or context cancellation
	cleanup()

	// Callback should not have been invoked
	assert.False(t, callbackInvoked, "Callback should not be invoked on early cleanup")
}

func TestWaitForSignal_BlocksUntilSignal(t *testing.T) {
	// This test needs to run in a goroutine since WaitForSignal blocks
	done := make(chan os.Signal, 1)

	go func() {
		sig := WaitForSignal()
		done <- sig
	}()

	// Give WaitForSignal time to set up
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM to ourselves
	proc, err := os.FindProcess(os.Getpid())
	assert.NoError(t, err)

	err = proc.Signal(syscall.SIGTERM)
	assert.NoError(t, err)

	// Should receive the signal
	select {
	case sig := <-done:
		assert.Equal(t, syscall.SIGTERM, sig)
	case <-time.After(1 * time.Second):
		t.Fatal("WaitForSignal did not return after signal")
	}
}
