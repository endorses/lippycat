package securestore

// SnapshotRotationOptions describes an explicit offline encrypted-source
// operation. Keys are immutable rings already loaded from private files; this
// API never reloads key paths. SourceKeys has the old active key and prior read
// keys; NewKeys contains exactly one fresh active key. Source and destination
// must share a descriptor-identified private parent directory.
type SnapshotRotationOptions struct {
	Source, Destination string
	SourceKeys, NewKeys *Keyring
	InPlace, Resume     bool
	MaxWorkingBytes     int64
}

// SnapshotRotationOwner validates the complete original plaintext without
// changing it or retaining a decoded tree. remainingDecodeBytes is the part of
// one 256 MiB memory ceiling left after all coordinator buffer capacities and
// scratch are charged. Validation must bound its allocations by that allowance.
// Supported payload ceilings are at most 16 MiB for filters and 32 MiB for state.
type SnapshotRotationOwner struct {
	Purpose         Purpose
	Object          string
	MaxPayloadBytes int64
	Validate        func(payload []byte, store [16]byte, remainingDecodeBytes int64) (SnapshotValidation, error)
}

type SnapshotValidation struct {
	// At most four canonical absolute paths, each at most 4096 bytes. These are
	// immutable inputs such as the LI RADIUS allocator pin. Even an absent path
	// reserves its parent identity/basename against operation-file aliasing.
	ProtectedPaths []string
}

type RotationArtifact struct {
	Kind            string
	KeyID           string
	Count           uint64
	AllocatedBytes  int64
	DependencyKnown bool
}

// SnapshotRotationResult reports the snapshot's commitment independently from
// auxiliary progress, usage, cleanup and inventory failures. A committed output
// can still require explicit resume. Inventory consists of bounded aggregate
// categories, never filenames or secret-derived comparison fingerprints.
type SnapshotRotationResult struct {
	Outcome                                                     Outcome
	Complete, ResumeRequired                                    bool
	SourceKeyID, NewKeyID                                       string
	WorkingAllocatedBytes, OldSourceBytes, HistoricalUsageBytes int64
	Artifacts                                                   []RotationArtifact
	InventoryComplete                                           bool
	ExternalBackupsExcluded                                     bool
}

// RotateSnapshot preserves exact validated payload bytes and store incarnation.
// It never activates policy, starts a runtime, modifies an allocator, retires a
// key, or deletes usage history. Errors expose the snapshot Outcome through
// CommitError while retaining any typed auxiliary cause.
func RotateSnapshot(options SnapshotRotationOptions, owner SnapshotRotationOwner) (SnapshotRotationResult, error) {
	return rotateSnapshot(options, owner, nil)
}
