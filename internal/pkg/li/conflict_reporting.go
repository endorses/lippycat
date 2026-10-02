//go:build li

package li

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

// Conflict state is durable; acknowledgment is deliberately process-local so
// unresolved conflicts are reported again after restart. A single worker and
// timer bound concurrent reporting independently of the number of tasks.
type conflictReportState struct {
	task          *InterceptTask
	acknowledged  bool
	retryAt       time.Time
	cancel        context.CancelFunc
	failureLogged bool
}

const conflictReportRetryInterval = 30 * time.Second
const conflictReportDetails = "Task definition conflict: enforcement restricted to common authorized scope; send an explicit X1 change to resolve"

// Called only for a successfully established conflict, under administration
// ordering. It performs no network I/O and never re-enters administration.
func (m *Manager) queueConflictReport(task *InterceptTask) {
	if task == nil || !task.Definition.Conflict {
		return
	}
	m.conflictReportMu.Lock()
	defer m.conflictReportMu.Unlock()
	if m.stopped.Load() || m.recoveryCtx.Err() != nil {
		return
	}
	if m.conflictReports == nil {
		m.conflictReports = make(map[uuid.UUID]*conflictReportState)
		m.conflictReportWake = make(chan struct{}, 1)
	}
	previous := m.conflictReports[task.XID]
	if previous != nil && previous.task.ActivationGeneration == task.ActivationGeneration &&
		previous.task.Definition.ConflictDisarmed == task.Definition.ConflictDisarmed &&
		previous.task.Definition.ConflictReason == task.Definition.ConflictReason &&
		equivalentTaskDefinition(previous.task, task) {
		return
	}
	if previous != nil && previous.cancel != nil {
		previous.cancel()
	}
	reason := "detected"
	if previous != nil {
		reason = "scope_changed"
	} else if task.Definition.Restored {
		reason = "restored"
	}
	logger.Warn("LI task definition conflict", "xid", task.XID, "reason", reason,
		"disarmed", task.Definition.ConflictDisarmed)
	m.conflictReports[task.XID] = &conflictReportState{task: cloneInterceptTask(task)}
	if !m.conflictReportStarted && (m.x1Client != nil || m.conflictReportSend != nil) {
		m.conflictReportStarted = true
		m.wg.Add(1)
		go m.runConflictReports()
	}
	m.wakeConflictReportsLocked()
}

func (m *Manager) wakeConflictReportsLocked() {
	select {
	case m.conflictReportWake <- struct{}{}:
	default:
	}
}

func (m *Manager) clearConflictReport(xid uuid.UUID) {
	m.conflictReportMu.Lock()
	defer m.conflictReportMu.Unlock()
	if state := m.conflictReports[xid]; state != nil {
		if state.cancel != nil {
			state.cancel()
		}
		delete(m.conflictReports, xid)
		logger.Info("LI task definition conflict cleared", "xid", xid)
		m.wakeConflictReportsLocked()
	}
}

// Synchronizing with queueConflictReport ensures every worker Add precedes
// Stop's Wait, including callers that use a manager before Start.
func (m *Manager) stopConflictReports() {
	m.conflictReportMu.Lock()
	defer m.conflictReportMu.Unlock()
	for _, state := range m.conflictReports {
		if state.cancel != nil {
			state.cancel()
		}
	}
	clear(m.conflictReports)
}

func (m *Manager) runConflictReports() {
	defer m.wg.Done()
	for {
		m.conflictReportMu.Lock()
		if m.recoveryCtx.Err() != nil {
			m.conflictReportMu.Unlock()
			return
		}
		var selected *conflictReportState
		var next time.Time
		now := time.Now()
		for _, state := range m.conflictReports {
			if state.acknowledged {
				continue
			}
			if !state.retryAt.After(now) {
				selected = state
				break
			}
			if next.IsZero() || state.retryAt.Before(next) {
				next = state.retryAt
			}
		}
		if selected == nil {
			m.conflictReportMu.Unlock()
			var timer *time.Timer
			var timeout <-chan time.Time
			if !next.IsZero() {
				timer = time.NewTimer(time.Until(next))
				timeout = timer.C
			}
			select {
			case <-m.recoveryCtx.Done():
			case <-m.conflictReportWake:
			case <-timeout:
			}
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		ctx, cancel := context.WithTimeout(m.recoveryCtx, m.syncAttemptTimeout())
		selected.cancel = cancel
		xid := selected.task.XID
		m.conflictReportMu.Unlock()
		var err error
		if m.conflictReportSend != nil {
			err = m.conflictReportSend(ctx, xid, conflictReportDetails)
		} else {
			err = m.x1Client.ReportTaskWarning(ctx, xid, conflictReportDetails)
		}
		cancel()
		m.conflictReportMu.Lock()
		if m.conflictReports[xid] == selected {
			selected.cancel = nil
			selected.acknowledged = err == nil
			if err == nil {
				logger.Info("LI task definition conflict acknowledged", "xid", xid)
			} else {
				selected.retryAt = time.Now().Add(conflictReportRetryInterval)
				if !selected.failureLogged && m.recoveryCtx.Err() == nil {
					logger.Warn("LI task definition conflict report pending", "xid", xid, "reason", "report_failed")
					selected.failureLogged = true
				}
			}
		}
		m.conflictReportMu.Unlock()
	}
}

// TryLock establishes an actual contended-lock observation for the concurrency
// regression. The optional observer is installed before use and is nil in
// production; no sleep or goroutine scheduling assumption proves contention.
func (m *Manager) lockSnapshotForX1() {
	if m.snapshotMu.TryLock() {
		return
	}
	if m.snapshotWaitHook != nil {
		m.snapshotWaitHook()
	}
	m.snapshotMu.Lock()
}
