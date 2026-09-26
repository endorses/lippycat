//go:build linux

package securestore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const snapshotRotationMemoryBytes int64 = 256 << 20
const snapshotRotationScratchBytes int64 = 1 << 20

// Hooks are package-private crash/fault boundaries, never a runtime activation
// surface. A hook error stops this invocation; it does not authorize rollback.
type snapshotRotationHooks struct {
	configure func(*Dir)
	workspace func(*RotationWorkspace)
	step      func(string) error
}

type snapshotRotation struct {
	options                                   SnapshotRotationOptions
	owner                                     SnapshotRotationOwner
	hooks                                     *snapshotRotationHooks
	dir                                       *Dir
	locks                                     []*Lock
	names                                     [rotationStageCount]string
	sourceName, destinationName               string
	sourcePath, destinationPath               [32]byte
	parent                                    FileIdentity
	ringCommit                                [32]byte
	store                                     [16]byte
	request                                   snapshotRotationRequest
	token                                     [32]byte
	bootstrap                                 snapshotRotationBootstrap
	progress                                  *snapshotRotationProgress
	predecessorBootstrap, predecessorProgress []byte
	bootstrapBytes, progressBytes             []byte
	payload, candidate                        []byte
	sourceCipher                              []byte
	protected                                 []FileIdentity
	extraProtected                            []*os.File
	sourceIdentity                            FileIdentity
	sourceKeyID                               string
	newLedger                                 bool
	newSeals, newBlocks                       uint64
	fresh, obsoleteProgress, outputSelected   bool
	predecessorPresent                        [2]bool
	workspace                                 *RotationWorkspace
	usage                                     *Usage
	result                                    SnapshotRotationResult
}

func rotateSnapshot(options SnapshotRotationOptions, owner SnapshotRotationOwner, hooks *snapshotRotationHooks) (report SnapshotRotationResult, result error) {
	r := &snapshotRotation{options: options, owner: owner, hooks: hooks, result: SnapshotRotationResult{Outcome: NotCommitted, ExternalBackupsExcluded: true}}
	defer func() {
		if r.workspace != nil {
			r.updateOutcome()
		}
		if r.usage != nil {
			result = errors.Join(result, r.usage.Close())
		}
		if r.workspace != nil {
			result = errors.Join(result, r.workspace.Close())
		}
		for _, file := range r.extraProtected {
			result = errors.Join(result, file.Close())
		}
		for i := len(r.locks) - 1; i >= 0; i-- {
			result = errors.Join(result, r.locks[i].Close())
		}
		if r.dir != nil {
			result = errors.Join(result, r.dir.Close())
		}
		clear(r.payload)
		clear(r.candidate)
		clear(r.sourceCipher)
		if result != nil {
			if r.bootstrapBytes != nil || r.progress != nil || r.workspace != nil {
				r.result.ResumeRequired = true
			}
			r.result.Complete = false
			result = &CommitError{Outcome: r.result.Outcome, Op: "rotate snapshot", Err: result}
		}
		report = r.result
	}()
	if err := r.prepare(); err != nil {
		return r.result, err
	}
	if err := r.authenticate(); err != nil {
		return r.result, err
	}
	if err := r.validatePayload(); err != nil {
		return r.result, err
	}
	if err := r.execute(); err != nil {
		return r.result, err
	}
	return r.result, nil
}
func (r *snapshotRotation) step(name string) error {
	if r.hooks != nil && r.hooks.step != nil {
		return r.hooks.step(name)
	}
	return nil
}
func (r *snapshotRotation) updateOutcome() {
	if r.workspace != nil {
		out := r.workspace.SnapshotOutcome()
		if out == Committed || r.result.Outcome != Committed && out == Uncertain {
			r.result.Outcome = out
		}
	}
}
func rotationPath(path string) (parent, name string, err error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", "", errors.New("securestore: explicit rotation paths required")
	}
	parent, name = ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if err := checkName(name); err != nil {
		return "", "", err
	}
	if strings.HasPrefix(name, ".rotation-") || strings.HasPrefix(name, ".usage-") {
		return "", "", errors.New("securestore: reserved rotation snapshot name")
	}
	return parent, name, nil
}
func rotationNames(purpose Purpose, destination, usage, token string) [rotationStageCount]string {
	var names [rotationStageCount]string
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", purpose, destination)))
	base := hex.EncodeToString(digest[:])
	for s := RotationStage(0); s < rotationStageCount; s++ {
		switch s {
		case RotationBootstrapUninitialized, RotationBootstrapRequired:
			names[s] = ".rotation-bootstrap-" + base
		case RotationUsageZero, RotationUsageReservation0, RotationUsageReservation1, RotationUsageReservation2, RotationUsageReservation3:
			names[s] = usage
		case RotationPlanned, RotationPrepared, RotationComplete:
			names[s] = ".rotation-progress-" + base
		case RotationCandidateStage:
			names[s] = ".rotation-candidate-" + base
		case RotationPublication:
			names[s] = destination
		case RotationPredecessorBootstrapStage:
			names[s] = ".rotation-prev-bootstrap-" + token
		case RotationPredecessorProgressStage:
			names[s] = ".rotation-prev-progress-" + token
		case RotationSourceCatalogStage:
			names[s] = ".rotation-source-catalog-" + token
		}
	}
	return names
}
func (r *snapshotRotation) prepare() error {
	o := r.owner
	ownerLimit := int64(16 << 20)
	if o.Purpose == AdministrativeState {
		ownerLimit = 32 << 20
	}
	if (o.Purpose != FilterSnapshot && o.Purpose != AdministrativeState) || o.Object == "" || len(o.Object) > MaxObjectIDBytes || o.MaxPayloadBytes <= 0 || o.MaxPayloadBytes > ownerLimit || o.MaxPayloadBytes > MaxPlaintextBytes-bindingFixedBytes-int64(len(o.Object)) || o.Validate == nil || r.options.MaxWorkingBytes <= 0 {
		return errors.New("securestore: invalid snapshot rotation contract")
	}
	var err error
	r.ringCommit, err = snapshotRotationRingCommitment(r.options.SourceKeys, r.options.NewKeys)
	if err != nil {
		return err
	}
	r.result.SourceKeyID, r.result.NewKeyID = r.options.SourceKeys.ActiveID(), r.options.NewKeys.ActiveID()
	sourceParent, sourceName, err := rotationPath(r.options.Source)
	if err != nil {
		return err
	}
	targetParent, targetName, err := rotationPath(r.options.Destination)
	if err != nil {
		return err
	}
	// Validate each raw path before canonicalization, even when strings normalize
	// to the same path. Traversed symlinks and invalid ancestors cannot disappear.
	sourceDir, err := OpenDir(sourceParent)
	if err != nil {
		return err
	}
	targetDir, err := OpenDir(targetParent)
	if err != nil {
		return errors.Join(err, sourceDir.Close())
	}
	same, err := sourceDir.SameDirectory(targetDir)
	err = errors.Join(err, targetDir.Close())
	if err != nil || !same {
		return errors.Join(errors.New("securestore: encrypted rotation requires one private parent"), err, sourceDir.Close())
	}
	r.dir = sourceDir
	r.sourceName, r.destinationName = sourceName, targetName
	if (sourceName == targetName) != r.options.InPlace {
		return errors.New("securestore: explicit in-place mode must match source and destination")
	}
	sourceAbs, err := filepath.Abs(r.options.Source)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(r.options.Destination)
	if err != nil {
		return err
	}
	r.sourcePath = sha256.Sum256([]byte(sourceAbs))
	r.destinationPath = sha256.Sum256([]byte(targetAbs))
	dev, ino, err := r.dir.directoryIdentity()
	if err != nil {
		return err
	}
	r.parent = FileIdentity{dev, ino}
	names := []string{sourceName, targetName, r.options.SourceKeys.UsageFileName(), r.options.NewKeys.UsageFileName()}
	sort.Strings(names)
	previous := ""
	for _, name := range names {
		if name == previous {
			continue
		}
		previous = name
		lock, err := r.dir.Lock(name)
		if err != nil {
			return err
		}
		r.locks = append(r.locks, lock)
	}
	if r.hooks != nil && r.hooks.configure != nil {
		r.hooks.configure(r.dir)
	}
	r.names = rotationNames(o.Purpose, targetName, r.options.NewKeys.UsageFileName(), "")
	return r.step("owners")
}
func (r *snapshotRotation) readOptional(name string, limit int64) ([]byte, error) {
	b, err := r.dir.Read(name, limit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}
func (r *snapshotRotation) keyAliases(name string) error {
	id, err := r.dir.FileIdentity(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.options.SourceKeys.UsesFile(id) || r.options.NewKeys.UsesFile(id) {
		return errors.New("securestore: rotation object aliases a key file")
	}
	return nil
}
func (r *snapshotRotation) ledger(ring *Keyring) (bool, uint64, uint64, error) {
	b, err := r.readOptional(ring.UsageFileName(), usageBytes)
	if err != nil || b == nil {
		return false, 0, 0, err
	}
	store, seals, blocks, err := decodeUsage(ring.active, b)
	if err != nil {
		return false, 0, 0, err
	}
	if r.store == [16]byte{} {
		r.store = store
	} else if store != r.store {
		return false, 0, 0, ErrBinding
	}
	return true, seals, blocks, nil
}
