//go:build li

package li

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConflictReportBackoffSchedule(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	state := &conflictReportState{}
	for _, delay := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		state.deferRetry(now)
		require.Equal(t, delay, state.retryDelay)
		require.Equal(t, now.Add(delay), state.retryAt)
		now = state.retryAt
	}
}

func TestConflictReportScheduleServicesOldestPendingTask(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	first, second := reportTestTask(), reportTestTask()
	first.XID = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	second.XID = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	m.queueConflictReport(second)
	m.queueConflictReport(first)
	m.conflictReportMu.Lock()
	defer m.conflictReportMu.Unlock()
	a, b := m.conflictReports[first.XID], m.conflictReports[second.XID]
	require.Same(t, a, m.nextConflictReportLocked(), "equal deadlines have a stable order")
	a.deferRetry(now)
	require.Same(t, b, m.nextConflictReportLocked(), "a failed task cannot overtake unsent work")
	b.deferRetry(now.Add(time.Second))
	require.Same(t, a, m.nextConflictReportLocked())
	a.deferRetry(a.retryAt)
	require.Same(t, b, m.nextConflictReportLocked(), "older due work precedes another retry")
	b.acknowledged = true
	require.Same(t, a, m.nextConflictReportLocked())
	a.acknowledged = true
	require.Nil(t, m.nextConflictReportLocked())
}

func TestConflictReportBackoffEpisodeLifecycle(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	task := reportTestTask()
	m.queueConflictReport(task) // No transport: drive scheduling deterministically.
	state := m.conflictReports[task.XID]
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	state.deferRetry(time.Now())
	state.deferRetry(state.retryAt)
	deadline := state.retryAt
	m.queueConflictReport(cloneInterceptTask(task))
	require.Same(t, state, m.conflictReports[task.XID])
	require.Equal(t, deadline, state.retryAt)
	require.Equal(t, time.Minute, state.retryDelay)
	require.NoError(t, ctx.Err(), "equivalent polls preserve the episode")

	state.acknowledged = true
	changed := cloneInterceptTask(task)
	changed.ActivationGeneration++
	changed.Definition.ConflictDisarmed = true
	changed.Definition.ConflictReason = "expired"
	m.queueConflictReport(changed)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	fresh := m.conflictReports[task.XID]
	require.NotSame(t, state, fresh)
	require.False(t, fresh.acknowledged)
	require.Zero(t, fresh.retryDelay)
	require.True(t, fresh.retryAt.IsZero(), "a new episode is immediately due")

	fresh.deferRetry(time.Now())
	m.Stop()
	restarted := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(restarted.Stop)
	changed.Definition.Restored = true
	restarted.queueConflictReport(changed)
	restored := restarted.conflictReports[task.XID]
	require.Zero(t, restored.retryDelay)
	require.True(t, restored.retryAt.IsZero(), "restoration never inherits retry delay")
	ctx, cancel = context.WithCancel(context.Background())
	restored.cancel = cancel
	restarted.clearConflictReport(task.XID)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.Empty(t, restarted.conflictReports)
}
