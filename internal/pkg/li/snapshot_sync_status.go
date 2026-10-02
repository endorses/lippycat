package li

import "time"

// SnapshotFailureLimit bounds diagnostic detail retained for the latest ADMF
// snapshot. Counts and a fingerprint still cover every failure, not just these
// first 32 entries. This is a diagnostic bound, not an authorization limit.
const SnapshotFailureLimit = 32

// SnapshotFailure contains only fixed categories and validated identifiers.
// EntryIndex is zero-based, or -1 for a request/list-level failure.
type SnapshotFailure struct {
	Kind       string
	Category   string
	EntryIndex int
	UUID       string
}

// SnapshotSyncStatus describes the latest startup or periodic snapshot attempt.
// It is independent of the startup retry lifecycle and never includes selectors,
// delivery addresses, malformed identifiers or remote error text.
type SnapshotSyncStatus struct {
	Source                             string
	State                              string
	Attempts                           uint64
	LastAttempt                        time.Time
	TaskFailures                       uint64
	DestinationFailures                uint64
	TotalFailures                      uint64
	Failures                           []SnapshotFailure
	FailuresTruncated                  uint64
	TaskOrphanRemovalSuppressed        bool
	DestinationOrphanRemovalSuppressed bool
	WarningsSuppressed                 uint64
	fingerprint                        [32]byte
}
