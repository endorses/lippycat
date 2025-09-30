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

	// Simply set the default tracker directly without touching sync.Once
	defaultTracker = tracker

	// Return restore function
	return func() {
		defaultTracker = oldTracker
		// Note: We don't reset trackerOnce as it's meant to run only once
		// If needed for testing, create a new tracker instance instead
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
