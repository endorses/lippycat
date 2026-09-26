//go:build !linux

package securestore

import "errors"

type snapshotRotationHooks struct{}

func rotateSnapshot(SnapshotRotationOptions, SnapshotRotationOwner, *snapshotRotationHooks) (SnapshotRotationResult, error) {
	return SnapshotRotationResult{Outcome: NotCommitted, ExternalBackupsExcluded: true}, &CommitError{Outcome: NotCommitted, Op: "rotate snapshot", Err: errors.New("securestore: snapshot rotation requires Linux atomic publication and allocation")}
}
