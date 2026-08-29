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

func TestSniffCompletionMonitorAllowsCallIDReuse(t *testing.T) {
	tracker := TestCallTracker(t)
	defer tracker.Shutdown()
	monitor := NewSniffCompletionMonitor(tracker, nil)
	tracker.SetCompletionMonitor(monitor)

	monitor.closedCalls["reused"] = time.Now()
	call := tracker.GetOrCreateCall("reused", 1)
	if call == nil {
		t.Fatal("expected reused call to be admitted")
	}
	monitor.ScheduleClose("reused")

	monitor.mu.Lock()
	_, pending := monitor.pendingClose["reused"]
	_, closed := monitor.closedCalls["reused"]
	monitor.mu.Unlock()
	if !pending || closed {
		t.Fatalf("expected reused Call-ID to schedule a fresh close: pending=%v closed=%v", pending, closed)
	}
}
