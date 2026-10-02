//go:build li

package li

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func reportTestTask() *InterceptTask {
	return &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:synthetic@example.invalid"}},
		DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, ActivationGeneration: 1,
		Definition: TaskDefinitionState{Source: DefinitionPush, Conflict: true}}
}

func reportAcknowledged(m *Manager, xid uuid.UUID) bool {
	m.conflictReportMu.Lock()
	defer m.conflictReportMu.Unlock()
	return m.conflictReports[xid] != nil && m.conflictReports[xid].acknowledged
}

func TestConflictReportRetriesUntilAcknowledgedAndDeduplicates(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	task := reportTestTask()
	var attempts atomic.Int32
	m.conflictReportSend = func(ctx context.Context, xid uuid.UUID, details string) error {
		require.Equal(t, task.XID, xid)
		require.NotContains(t, details, task.Targets[0].Value)
		if attempts.Add(1) == 1 {
			return errors.New("synthetic transport failure")
		}
		return nil
	}
	m.queueConflictReport(task)
	require.Eventually(t, func() bool {
		m.conflictReportMu.Lock()
		defer m.conflictReportMu.Unlock()
		state := m.conflictReports[task.XID]
		if state == nil || state.retryAt.IsZero() {
			return false
		}
		require.False(t, state.acknowledged)
		// Advance the pending attempt without sleeping through the production
		// retry interval. The worker must still issue and acknowledge the retry.
		state.retryAt = time.Time{}
		m.wakeConflictReportsLocked()
		return true
	}, 3*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return reportAcknowledged(m, task.XID) }, 3*time.Second, time.Millisecond)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); m.queueConflictReport(task) }()
	}
	wg.Wait()
	require.EqualValues(t, 2, attempts.Load())
	m.clearConflictReport(task.XID)
	m.conflictReportMu.Lock()
	require.Empty(t, m.conflictReports)
	m.conflictReportMu.Unlock()
}

func TestConflictLateAcknowledgmentCannotResolveNewEpisode(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	task := reportTestTask()
	entered := make(chan int32, 2)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var attempts atomic.Int32
	finished := make(chan struct{})
	m.conflictReportSend = func(ctx context.Context, _ uuid.UUID, _ string) error {
		attempt := attempts.Add(1)
		entered <- attempt
		if attempt == 1 {
			<-release // Model an acknowledgment already in flight at cancellation.
			return nil
		}
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	}
	m.queueConflictReport(task)
	require.EqualValues(t, 1, <-entered)
	next := cloneInterceptTask(task)
	next.ActivationGeneration++
	next.DeliveryType = DeliveryX2Only
	m.queueConflictReport(next)
	once.Do(func() { close(release) })
	select {
	case attempt := <-entered:
		require.EqualValues(t, 2, attempt)
	case <-time.After(3 * time.Second):
		t.Fatal("new conflict episode was lost behind the old acknowledgment")
	}
	require.False(t, reportAcknowledged(m, task.XID))
	m.clearConflictReport(task.XID)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("resolution did not cancel obsolete report work")
	}
}

func TestConflictReportAcknowledgmentDoesNotSurviveRestart(t *testing.T) {
	task := reportTestTask()
	var attempts atomic.Int32
	for range 2 {
		m := NewManager(ManagerConfig{Enabled: true}, nil)
		m.conflictReportSend = func(context.Context, uuid.UUID, string) error { attempts.Add(1); return nil }
		m.queueConflictReport(task)
		require.Eventually(t, func() bool { return reportAcknowledged(m, task.XID) }, 3*time.Second, time.Millisecond)
		m.Stop()
		task.Definition.Restored = true
	}
	require.EqualValues(t, 2, attempts.Load())
}

func TestConflictReportStopCancelsAndJoinsWorker(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	entered, finished := make(chan struct{}), make(chan struct{})
	m.conflictReportSend = func(ctx context.Context, _ uuid.UUID, _ string) error {
		close(entered)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	}
	task := reportTestTask()
	m.queueConflictReport(task)
	<-entered
	m.Stop()
	select {
	case <-finished:
	default:
		t.Fatal("Stop returned before the report worker finished")
	}
	m.queueConflictReport(task)
	m.conflictReportMu.Lock()
	require.Empty(t, m.conflictReports)
	m.conflictReportMu.Unlock()
}
