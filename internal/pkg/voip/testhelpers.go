package voip

import "testing"

// TestCallTracker creates an isolated CallTracker for testing
func TestCallTracker(t testing.TB) *CallTracker {
	tracker := NewCallTracker()
	t.Cleanup(func() {
		tracker.Shutdown()
	})
	return tracker
}
