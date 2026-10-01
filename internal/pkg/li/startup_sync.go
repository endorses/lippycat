//go:build li

package li

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

var errStartupSyncUnsupported = errors.New("ADMF GetAllDetails unsupported")

type incompleteStartupSnapshot struct{ taskFailures, destinationFailures int }

func (e *incompleteStartupSnapshot) Error() string {
	return fmt.Sprintf("incomplete ADMF snapshot: %d task failures, %d destination failures", e.taskFailures, e.destinationFailures)
}

// Remote error descriptions and HTTP bodies can contain target definitions.
// Publish operational categories, never that content, in recovery telemetry.
func startupFailureSummary(err error) string {
	var partial *incompleteStartupSnapshot
	var remote *x1.ADMFError
	switch {
	case errors.As(err, &partial):
		return partial.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "ADMF synchronization timed out"
	case errors.Is(err, context.Canceled):
		return "ADMF synchronization canceled"
	case errors.As(err, &remote):
		return fmt.Sprintf("ADMF query rejected (code %d)", remote.ErrorCode)
	default:
		return "ADMF synchronization request or state application failed"
	}
}

func (m *Manager) StartupSyncStatus() StartupSyncStatus {
	if status := m.startupStatus.Load(); status != nil {
		return *status
	}
	return StartupSyncStatus{}
}

func (m *Manager) syncAttemptTimeout() time.Duration {
	if m.config.SyncTimeout > 0 {
		return m.config.SyncTimeout
	}
	return 30 * time.Second
}

// attemptStartupSync serializes query, application, and status publication with
// X1 mutations. A retry must not apply a stale response over a newer X1 request.
// True means another attempt is needed; unsupported and complete are terminal.
func (m *Manager) attemptStartupSync() bool {
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	status := m.StartupSyncStatus()
	if status.State == StartupSyncSucceeded || status.State == StartupSyncUnsupported || m.recoveryCtx.Err() != nil {
		return false
	}
	status.State = StartupSyncPending
	status.Attempts++
	status.LastAttempt = time.Now().UTC()
	m.startupStatus.Store(&status)
	ctx, cancel := context.WithTimeout(m.recoveryCtx, m.syncAttemptTimeout())
	err := m.syncStateFromADMFLocked(ctx)
	cancel()
	// Publish another immutable copy: readers may still hold the pending one.
	result := status
	switch {
	case errors.Is(err, errStartupSyncUnsupported):
		result.State = StartupSyncUnsupported
		result.LastFailure = err.Error()
	case err != nil:
		result.State = StartupSyncRetryableFailure
		result.LastFailure = startupFailureSummary(err)
		logger.Warn("ADMF startup synchronization pending", "attempt", result.Attempts, "failure", result.LastFailure)
	default:
		result.State = StartupSyncSucceeded
		result.RecoveredAt = time.Now().UTC()
		logger.Info("ADMF startup synchronization recovered", "attempts", result.Attempts)
	}
	m.startupStatus.Store(&result)
	return result.State == StartupSyncRetryableFailure
}

// Retry independently of ReconcileInterval, retaining a bounded delay and a
// fresh configured timeout on each attempt. Stop cancels both wait and request.
func (m *Manager) retryStartupSync() {
	defer m.wg.Done()
	backoff := time.Second
	for {
		timer := time.NewTimer(backoff)
		select {
		case <-m.recoveryCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		logger.Info("Retrying ADMF startup synchronization", "attempt", m.StartupSyncStatus().Attempts+1)
		if !m.attemptStartupSync() {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
