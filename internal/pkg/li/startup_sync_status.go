package li

import "time"

// StartupSyncState describes authoritative startup recovery, independently of
// periodic reconciliation and the NE startup notification.
type StartupSyncState string

const (
	StartupSyncPending          StartupSyncState = "pending"
	StartupSyncSucceeded        StartupSyncState = "succeeded"
	StartupSyncUnsupported      StartupSyncState = "unsupported"
	StartupSyncRetryableFailure StartupSyncState = "retryable_failure"
)

type StartupSyncStatus struct {
	State       StartupSyncState
	Attempts    uint64
	LastFailure string
	LastAttempt time.Time
	RecoveredAt time.Time
}
