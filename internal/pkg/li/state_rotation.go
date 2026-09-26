//go:build li

package li

import "github.com/endorses/lippycat/internal/pkg/securestore"

// StateRotationOptions selects an explicit offline encrypted state operation.
// The existing encrypted RADIUS allocator pin cannot be overridden by rotation.
type StateRotationOptions struct {
	InPlace, Resume bool
	MaxWorkingBytes int64
}

// RotateEncryptedStateStore preserves exact validated administrative bytes,
// including the state incarnation, retained obligations and optional allocator
// pin. It never starts a manager, restores authority or opens an allocator.
// Source and new key configurations are each loaded exactly once.
func RotateEncryptedStateStore(source, destination string, sourceKeys, newKeys securestore.KeyConfig, options StateRotationOptions) (securestore.SnapshotRotationResult, error) {
	failed := securestore.SnapshotRotationResult{Outcome: securestore.NotCommitted, ExternalBackupsExcluded: true}
	oldRing, err := securestore.LoadKeyring(sourceKeys)
	if err != nil {
		return failed, &securestore.CommitError{Outcome: failed.Outcome, Op: "load state rotation source keys", Err: err}
	}
	newRing, err := securestore.LoadKeyring(newKeys)
	if err != nil {
		return failed, &securestore.CommitError{Outcome: failed.Outcome, Op: "load state rotation new key", Err: err}
	}
	return securestore.RotateSnapshot(securestore.SnapshotRotationOptions{
		Source: source, Destination: destination, SourceKeys: oldRing, NewKeys: newRing,
		InPlace: options.InPlace, Resume: options.Resume, MaxWorkingBytes: options.MaxWorkingBytes,
	}, stateRotationOwner())
}

func stateRotationOwner() securestore.SnapshotRotationOwner {
	return securestore.SnapshotRotationOwner{
		Purpose: securestore.AdministrativeState, Object: stateSnapshotObject, MaxPayloadBytes: MaxStateSnapshotBytes,
		Validate: func(payload []byte, store [16]byte, remainingDecodeBytes int64) (securestore.SnapshotValidation, error) {
			state, err := UnmarshalStateSnapshotWithBudget(payload, remainingDecodeBytes)
			if err != nil {
				return securestore.SnapshotValidation{}, err
			}
			if state.Incarnation != store {
				return securestore.SnapshotValidation{}, securestore.ErrBinding
			}
			var result securestore.SnapshotValidation
			if state.RADIUSCorrelationStateFile != "" {
				result.ProtectedPaths = []string{state.RADIUSCorrelationStateFile}
			}
			return result, nil
		},
	}
}
