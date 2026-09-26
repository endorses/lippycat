package filtering

import (
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// RotationOptions selects an explicit offline encrypted snapshot operation.
// MaxWorkingBytes bounds allocated transaction workspace, not decode memory.
type RotationOptions struct {
	InPlace, Resume bool
	MaxWorkingBytes int64
}

// RotateEncryptedFilterStore authenticates and validates every original filter,
// preserving the exact plaintext payload and store identity under a fresh key.
// It does not construct a manager or publish policy. Both key configurations are
// loaded once; the coordinator receives only immutable loaded keyrings.
func RotateEncryptedFilterStore(source, destination string, sourceKeys, newKeys securestore.KeyConfig, options RotationOptions) (securestore.SnapshotRotationResult, error) {
	failed := securestore.SnapshotRotationResult{Outcome: securestore.NotCommitted, ExternalBackupsExcluded: true}
	oldRing, err := securestore.LoadKeyring(sourceKeys)
	if err != nil {
		return failed, &securestore.CommitError{Outcome: failed.Outcome, Op: "load filter rotation source keys", Err: err}
	}
	newRing, err := securestore.LoadKeyring(newKeys)
	if err != nil {
		return failed, &securestore.CommitError{Outcome: failed.Outcome, Op: "load filter rotation new key", Err: err}
	}
	return securestore.RotateSnapshot(securestore.SnapshotRotationOptions{
		Source: source, Destination: destination, SourceKeys: oldRing, NewKeys: newRing,
		InPlace: options.InPlace, Resume: options.Resume, MaxWorkingBytes: options.MaxWorkingBytes,
	}, filterRotationOwner())
}

func filterRotationOwner() securestore.SnapshotRotationOwner {
	return securestore.SnapshotRotationOwner{
		Purpose: securestore.FilterSnapshot, Object: "filters", MaxPayloadBytes: filtercodec.MaxManagedSnapshotBytes,
		Validate: func(payload []byte, _ [16]byte, remainingDecodeBytes int64) (securestore.SnapshotValidation, error) {
			_, err := filtercodec.UnmarshalEncryptedFiltersWithBudget(payload, remainingDecodeBytes)
			return securestore.SnapshotValidation{}, err
		},
	}
}
