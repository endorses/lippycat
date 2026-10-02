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
	retryDelay    time.Duration
	cancel        context.CancelFunc
	failureLogged bool
}

const conflictReportRetryInterval = 30 * time.Second

// The cap is an operational retry policy, not a delivery deadline. Reports keep
// retrying at the cap until the ADMF acknowledges the current conflict episode.
const conflictReportRetryMax = 5 * time.Minute
const conflictReportDetails = "Task definition conflict: enforcement restricted to common authorized scope; send an explicit X1 change to resolve"
const disarmedConflictReportDetails = "Task definition conflict: task disarmed; explicitly deactivate, then activate a complete definition with unchanged protected identity, or use a new XID"

func (s *conflictReportState) deferRetry(now time.Time) {
	if s.retryDelay == 0 {
		s.retryDelay = conflictReportRetryInterval
	} else {
		s.retryDelay = min(2*s.retryDelay, conflictReportRetryMax)
	}
	s.retryAt = now.Add(s.retryDelay)
}

// Earliest-due selection prevents one failing task from starving older work.
// The UUID tie break makes equal deadlines deterministic without another queue.
// Caller holds conflictReportMu.
func (m *Manager) nextConflictReportLocked() *conflictReportState {
	var selected *conflictReportState
	for id, state := range m.conflictReports {
		if state.acknowledged {
			continue
		}
		if selected == nil || state.retryAt.Before(selected.retryAt) ||
			(state.retryAt.Equal(selected.retryAt) && id.String() < selected.task.XID.String()) {
			selected = state
		}
	}
	return selected
}

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
		selected := m.nextConflictReportLocked()
		var next time.Time
		if selected != nil && selected.retryAt.After(time.Now()) {
			next = selected.retryAt
			selected = nil
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
		details := conflictReportDetails
		if selected.task.Definition.ConflictDisarmed {
			details = disarmedConflictReportDetails
		}
		m.conflictReportMu.Unlock()
		var err error
		if m.conflictReportSend != nil {
			err = m.conflictReportSend(ctx, xid, details)
		} else {
			err = m.x1Client.ReportTaskWarning(ctx, xid, details)
		}
		cancel()
		m.conflictReportMu.Lock()
		if m.conflictReports[xid] == selected {
			selected.cancel = nil
			selected.acknowledged = err == nil
			if err == nil {
				logger.Info("LI task definition conflict acknowledged", "xid", xid)
			} else {
				selected.deferRetry(time.Now())
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
