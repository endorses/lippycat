package voip

import (
	"testing"
	"time"
)

func TestSniffCompletionMonitorPrunesClosedCalls(t *testing.T) {
	monitor := NewSniffCompletionMonitor(TestCallTracker(t), &SniffCompletionMonitorConfig{
		GracePeriod:   time.Second,
		CheckInterval: time.Second,
		ClosedCallTTL: time.Minute,
	})

	now := time.Now()
	monitor.closedCalls["expired-call"] = now.Add(-2 * time.Minute)
	monitor.closedCalls["recent-call"] = now.Add(-30 * time.Second)

	pruned := monitor.pruneClosedCalls(now)
	if pruned != 1 {
		t.Fatalf("expected 1 pruned call, got %d", pruned)
	}

	monitor.mu.Lock()
	_, expiredExists := monitor.closedCalls["expired-call"]
	_, recentExists := monitor.closedCalls["recent-call"]
	monitor.mu.Unlock()

	if expiredExists {
		t.Fatal("expected expired call to be pruned")
	}
	if !recentExists {
		t.Fatal("expected recent call to remain")
	}
}
