package voip

import (
	"sync"
	"testing"
)

// TestCallTracker creates an isolated CallTracker for testing
func TestCallTracker(t *testing.T) *CallTracker {
	tracker := NewCallTracker()
	t.Cleanup(func() {
		tracker.Shutdown()
	})
	return tracker
}

// OverrideDefaultTracker temporarily overrides the default tracker for testing
// This should be used sparingly and only when necessary for integration tests
func OverrideDefaultTracker(tracker *CallTracker) func() {
	oldTracker := defaultTracker
	oldOnce := trackerOnce

	trackerOnce = sync.Once{}
	defaultTracker = tracker

	// Return restore function
	return func() {
		defaultTracker = oldTracker
		trackerOnce = oldOnce
	}
}

// ResetDefaultTracker resets the default tracker singleton for testing
// Use this only in package-level test setup/teardown
func ResetDefaultTracker() {
	if defaultTracker != nil {
		defaultTracker.Shutdown()
	}
	defaultTracker = nil
	trackerOnce = sync.Once{}
}
