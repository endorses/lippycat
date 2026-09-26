//go:build li

package li

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// StateOfflineOptions requires operators to explicitly choose in-place replacement
// or authenticated resumption. An existing destination is otherwise never replaced.
type StateOfflineOptions struct {
	InPlace bool
	Resume  bool
	// RADIUSStateFile pins the existing allocator when it used a custom path.
	RADIUSStateFile string
}

type stateMigrationIntent struct {
	Version        int    `json:"version"`
	Operation      string `json:"operation"`
	SourcePath     string `json:"source_path_hash"`
	TargetPath     string `json:"target_path_hash"`
	SourceContent  string `json:"source_content_hash"`
	Payload        string `json:"payload_hash"`
	KeyID          string `json:"key_id"`
	RadiusPath     string `json:"radius_path_hash"`
	SourceIdentity string `json:"source_identity_hash"`
	TargetIdentity string `json:"target_identity_hash"`
}

func stateMigrationDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// InitializeEncryptedStateStore initializes an empty encrypted snapshot offline.
// The private destination directory must have been explicitly provisioned.
func InitializeEncryptedStateStore(path string, keys securestore.KeyConfig, options StateOfflineOptions) (securestore.Outcome, error) {
	if options.InPlace {
		return securestore.NotCommitted, errors.New("empty initialization cannot replace an existing store")
	}
	return offlineStateStore("", path, keys, options)
}

// MigrateJSONStateStore is an explicit JSON-to-encrypted offline operation. All
// source records must validate. Different-path migration retains the original;
// it never creates a plaintext backup or activates any filters.
func MigrateJSONStateStore(source, destination string, keys securestore.KeyConfig, options StateOfflineOptions) (securestore.Outcome, error) {
	if source == "" {
		return securestore.NotCommitted, errors.New("JSON migration requires an explicit source path")
	}
	return offlineStateStore(source, destination, keys, options)
}

func offlineStateStore(source, destination string, keys securestore.KeyConfig, options StateOfflineOptions) (out securestore.Outcome, result error) {
	out = securestore.NotCommitted
	defer func() {
		if result != nil {
			result = &securestore.CommitError{Outcome: out, Op: "offline LI state snapshot", Err: result}
		}
	}()
	ring, err := securestore.LoadKeyring(keys)
	if err != nil {
		return out, err
	}
	targetParent, targetName, targetPath, err := stateMigrationPath(destination)
	if err != nil {
		return out, err
	}
	var sourcePath string
	if source != "" {
		_, _, sourcePath, err = stateMigrationPath(source)
		if err != nil {
			return out, err
		}
	}
	samePath := sourcePath != "" && sourcePath == targetPath
	if samePath != options.InPlace {
		return out, errors.New("same-path migration requires explicit in-place mode; different paths must not use in-place mode")
	}
	for _, key := range append([]securestore.KeyRef{keys.Active}, keys.Prior...) {
		_, _, keyPath, err := stateMigrationPath(key.File)
		if err != nil {
			return out, err
		}
		if keyPath == targetPath || sourcePath != "" && keyPath == sourcePath {
			return out, errors.New("LI state migration source, destination, and key files must not alias")
		}
	}
	var target stateMigrationTarget
	var input *securestore.PrivateSource
	var radius *securestore.PrivateSource
	radiusRaw := options.RADIUSStateFile
	if radiusRaw == "" {
		radiusRaw = destination + ".radius-correlation"
		if source != "" {
			radiusRaw = source + ".radius-correlation"
		}
	}
	_, _, radiusPath, err := stateMigrationPath(radiusRaw)
	if err != nil {
		return out, err
	}
	if radiusPath == targetPath || radiusPath == sourcePath {
		return out, errors.New("RADIUS allocator path conflicts with LI state storage")
	}
	for _, key := range append([]securestore.KeyRef{keys.Active}, keys.Prior...) {
		_, _, keyPath, err := stateMigrationPath(key.File)
		if err != nil {
			return out, err
		}
		if keyPath == radiusPath {
			return out, errors.New("RADIUS allocator path conflicts with an encryption key")
		}
	}
	defer func() {
		if input != nil {
			result = errors.Join(result, input.Close())
		}
		if radius != nil {
			result = errors.Join(result, radius.Close())
		}
		result = errors.Join(result, target.discard())
	}()
	target.dir, err = securestore.OpenDir(targetParent)
	if err != nil {
		return out, err
	}
	target.name = targetName
	radius, err = securestore.PreparePrivateSource(radiusRaw)
	if err != nil {
		return out, err
	}
	targetOrder, err := target.dir.LockOrderKey(targetName)
	if err != nil {
		return out, err
	}
	var sourceOrder string
	if samePath {
		// Even equal canonical pathnames must validate every raw source
		// component. Otherwise a source spelling containing symlink/.. could
		// select a different file than the explicit destination spelling.
		sourceRef, err := securestore.PreparePrivateSource(source)
		if err != nil {
			return out, err
		}
		sourceOrder, err = sourceRef.OrderKey()
		err = errors.Join(err, sourceRef.Close())
		if err != nil {
			return out, err
		}
		if sourceOrder != targetOrder {
			return out, errors.New("in-place source and destination descriptors differ")
		}
	}
	if source != "" && !samePath {
		input, err = securestore.PreparePrivateSource(source)
		if err != nil {
			return out, err
		}
		sourceOrder, err = input.OrderKey()
		if err != nil {
			return out, err
		}
		if sourceOrder == targetOrder {
			return out, errors.New("migration source and destination alias; use a single explicit in-place path")
		}
	}
	if err := checkStateMigrationAliases(&target, input, radius, ring); err != nil {
		return out, err
	}
	// All source/destination descriptors exist before taking ownership. Order by
	// device/inode/basename, not pathname spelling; all flock calls are nonblocking.
	if input != nil && sourceOrder < targetOrder {
		if err := input.Acquire(); err != nil {
			return out, err
		}
	}
	target.lock, err = target.dir.Lock(target.name)
	if err != nil {
		return out, err
	}
	if input != nil {
		if err := input.Acquire(); err != nil {
			return out, err
		}
	}
	if err := checkStateMigrationAliases(&target, input, radius, ring); err != nil {
		return out, err
	}
	var rawSource []byte
	if samePath {
		rawSource, err = target.dir.Read(target.name, int64(maxStateEnvelopeBytes))
	} else if input != nil {
		rawSource, err = input.Read(MaxStateSnapshotBytes)
	}
	if err != nil {
		return out, err
	}
	defer clear(rawSource)
	completedInPlace := samePath && options.Resume && bytes.HasPrefix(rawSource, []byte("LCS1"))
	current, readErr := target.dir.Read(target.name, int64(maxStateEnvelopeBytes))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return out, readErr
	}
	if readErr == nil && !samePath && !options.Resume {
		return out, os.ErrExist
	}
	operation := "initialize"
	if source != "" {
		operation = "json-migration"
	}
	bootstrapName := ".state-bootstrap-" + stateMigrationDigest([]byte(target.name))
	intentName := ".state-intent-" + stateMigrationDigest([]byte(target.name))
	bootstrap, err := prepareStateBootstrap(target.dir, bootstrapName, options.Resume)
	if err != nil {
		return out, err
	}
	var plain []byte
	if !completedInPlace {
		plain, err = stateMigrationPayload(rawSource, source != "", bootstrap.store, radiusPath)
		if err != nil {
			return out, err
		}
		defer clear(plain)
	}
	var sourceIdentity string
	if source != "" {
		var identity securestore.FileIdentity
		if samePath {
			identity, err = target.dir.FileIdentity(target.name)
		} else {
			identity, err = input.Identity()
		}
		if err != nil {
			return out, err
		}
		sourceIdentity = stateMigrationDigest([]byte(fmt.Sprintf("%d:%d", identity.Device, identity.Inode)))
	}
	wanted := stateMigrationIntent{Version: 1, Operation: operation,
		SourcePath: stateMigrationDigest([]byte(sourcePath)), TargetPath: stateMigrationDigest([]byte(targetPath)),
		SourceContent: stateMigrationDigest(rawSource), Payload: stateMigrationDigest(plain), KeyID: ring.ActiveID(),
		RadiusPath: stateMigrationDigest([]byte(radiusPath)), SourceIdentity: sourceIdentity, TargetIdentity: stateMigrationDigest([]byte(targetOrder))}
	if !options.Resume {
		if err := bootstrap.create(target.dir, bootstrapName, ring, wanted); err != nil {
			return out, err
		}
	} else if completedInPlace {
		if bootstrap.stage != stateBootstrapLedgerRequired {
			return out, errors.New("encrypted output exists before the required usage boundary")
		}
		// The original plaintext has been replaced; authenticate the retained intent
		// and its bootstrap commitment before accepting the completed output below.
	} else if err := bootstrap.verify(ring, wanted); err != nil {
		return out, err
	}
	if bootstrap.stage == stateBootstrapUninitialized {
		_, intentErr := target.dir.Read(intentName, 16<<10)
		if intentErr == nil || readErr == nil && !samePath {
			return out, errors.New("encrypted intent or output exists before the required ledger boundary")
		}
		if !errors.Is(intentErr, os.ErrNotExist) {
			return out, intentErr
		}
	}
	usage, err := openStateMigrationUsage(target.dir, ring, bootstrap)
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, usage.Close()) }()
	if bootstrap.stage == stateBootstrapUninitialized && (usage.Stats().Invocations != 0 || usage.Stats().Blocks != 0) {
		return out, errors.New("encryption usage exists before the required ledger boundary")
	}
	writer, err := securestore.NewWriter(usage)
	if err != nil {
		return out, err
	}
	if !completedInPlace {
		if err := bootstrap.requireLedger(target.dir, bootstrapName, ring, wanted); err != nil {
			return out, err
		}
	}
	intentBinding := securestore.Binding{Store: usage.StoreID(), Object: "administrative-state/offline-intent/" + stateMigrationDigest([]byte(target.name))}
	intent := wanted
	encodedIntent, intentReadErr := target.dir.Read(intentName, 16<<10)
	if options.Resume && intentReadErr == nil {
		decoded, err := ring.Open(securestore.AdministrativeState, intentBinding, encodedIntent, 8<<10)
		if err != nil {
			return out, fmt.Errorf("resume requires the authenticated original operation intent: %w", err)
		}
		defer clear(decoded)
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&intent); err != nil {
			return out, errors.New("invalid encrypted LI state migration intent")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return out, errors.New("invalid encrypted LI state migration intent framing")
		}
		canonical, err := json.Marshal(intent)
		if err != nil || !bytes.Equal(canonical, decoded) {
			return out, errors.New("encrypted LI state migration intent is not canonical")
		}
		if intent.Version != wanted.Version || intent.Operation != wanted.Operation || intent.SourcePath != wanted.SourcePath || intent.TargetPath != wanted.TargetPath || intent.KeyID != wanted.KeyID || intent.RadiusPath != wanted.RadiusPath || intent.TargetIdentity != wanted.TargetIdentity {
			return out, errors.New("resume source, destination, operation, or key does not match the authenticated intent")
		}
		if !completedInPlace && (intent.SourceContent != wanted.SourceContent || intent.Payload != wanted.Payload || intent.SourceIdentity != wanted.SourceIdentity) {
			return out, errors.New("resume source content does not match the authenticated intent")
		}
		if err := bootstrap.verify(ring, intent); err != nil {
			return out, err
		}
	} else {
		if completedInPlace {
			return out, errors.New("completed in-place resume requires the encrypted original intent")
		}
		if intentReadErr == nil {
			return out, os.ErrExist
		}
		if !errors.Is(intentReadErr, os.ErrNotExist) {
			return out, intentReadErr
		}
		intentData, err := json.Marshal(intent)
		if err != nil {
			return out, errors.New("encode encrypted LI state migration intent")
		}
		defer clear(intentData)
		encoded, err := writer.Seal(securestore.AdministrativeState, intentBinding, intentData)
		if err != nil {
			return out, err
		}
		if _, err := target.dir.Create(intentName, encoded); err != nil {
			return out, err
		}
	}
	binding := securestore.Binding{Store: usage.StoreID(), Object: stateSnapshotObject}
	if options.Resume && readErr == nil && (!samePath || completedInPlace) {
		decoded, err := ring.Open(securestore.AdministrativeState, binding, current, MaxStateSnapshotBytes)
		if err != nil {
			return out, err
		}
		defer clear(decoded)
		if _, err := UnmarshalStateSnapshot(decoded); err != nil {
			return out, err
		}
		if stateMigrationDigest(decoded) != intent.Payload {
			return out, errors.New("existing encrypted snapshot does not match the resumed operation")
		}
		// Re-establish a durable directory boundary after a lost acknowledgement.
		if err := target.dir.Sync(); err != nil {
			return securestore.Uncertain, err
		}
		return securestore.Committed, nil
	}
	encoded, err := writer.Seal(securestore.AdministrativeState, binding, plain)
	if err != nil {
		return out, err
	}
	if samePath {
		return target.dir.Replace(target.name, encoded)
	}
	return target.dir.Create(target.name, encoded)
}

func checkStateMigrationAliases(target *stateMigrationTarget, input, radius *securestore.PrivateSource, ring *securestore.Keyring) error {
	targetID, targetErr := target.dir.FileIdentity(target.name)
	if targetErr != nil && !errors.Is(targetErr, os.ErrNotExist) {
		return targetErr
	}
	if targetErr == nil && ring.UsesFile(targetID) {
		return errors.New("LI state destination aliases an opened encryption key")
	}
	var sourceID securestore.FileIdentity
	if input != nil {
		var err error
		sourceID, err = input.Identity()
		if err != nil {
			return err
		}
		if ring.UsesFile(sourceID) {
			return errors.New("LI state source aliases an opened encryption key")
		}
		if targetErr == nil && sourceID == targetID {
			return errors.New("LI state source and destination are aliased")
		}
	}
	radiusID, radiusErr := radius.Identity()
	if radiusErr != nil && !errors.Is(radiusErr, os.ErrNotExist) {
		return radiusErr
	}
	if radiusErr == nil && (ring.UsesFile(radiusID) || targetErr == nil && targetID == radiusID || input != nil && sourceID == radiusID) {
		return errors.New("RADIUS allocator aliases LI state source, target, or encryption key")
	}
	radiusOrder, err := radius.OrderKey()
	if err != nil {
		return err
	}
	targetOrder, err := target.dir.LockOrderKey(target.name)
	if err != nil {
		return err
	}
	if radiusOrder == targetOrder {
		return errors.New("RADIUS allocator path aliases LI state storage")
	}
	for _, reserved := range []string{ring.UsageFileName(), ".state-bootstrap-" + stateMigrationDigest([]byte(target.name)), ".state-intent-" + stateMigrationDigest([]byte(target.name))} {
		if target.name == reserved {
			return errors.New("LI state snapshot uses a reserved metadata path")
		}
		reservedOrder, err := target.dir.LockOrderKey(reserved)
		if err != nil {
			return err
		}
		if radiusOrder == reservedOrder {
			return errors.New("RADIUS allocator path aliases LI state metadata")
		}
		identity, err := target.dir.FileIdentity(reserved)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if ring.UsesFile(identity) || targetErr == nil && targetID == identity || input != nil && sourceID == identity || radiusErr == nil && radiusID == identity {
			return errors.New("LI state migration metadata aliases a key, source, or snapshot")
		}
	}
	return nil
}

// A migration never acquires or rewrites the separately owned RADIUS allocator.
// Its canonical pinned path is encrypted with the state snapshot instead.
type stateMigrationTarget struct {
	dir  *securestore.Dir
	lock *securestore.Lock
	name string
}

func (t *stateMigrationTarget) discard() error {
	var err error
	if t.lock != nil {
		err = t.lock.Close()
	}
	if t.dir != nil {
		err = errors.Join(err, t.dir.Close())
	}
	return err
}
func stateMigrationPath(path string) (parent, name, absolute string, err error) {
	parent, name, err = stateStorePath(path)
	if err != nil {
		return
	}
	absolute, err = filepath.Abs(path)
	return
}

func stateMigrationPayload(source []byte, migration bool, id [16]byte, radiusPath string) ([]byte, error) {
	var snapshot *StateSnapshot
	if migration {
		var err error
		snapshot, err = DecodeLegacyStateSnapshot(source, uuid.UUID(id))
		if err != nil {
			return nil, err
		}
	} else {
		// No administrative write has occurred. The deterministic epoch permits
		// bootstrap-only resume; the first lifecycle save supplies its own timestamp.
		snapshot = &StateSnapshot{Version: StateSchemaVersion, WrittenAt: time.Unix(0, 0).UTC(), Incarnation: uuid.UUID(id),
			Tasks: []*InterceptTask{}, Destinations: []*StateDestination{}, CleanupNeeded: map[uuid.UUID][]string{}, Generations: map[uuid.UUID]uint64{},
			Intents: []*StateIntent{}, Revocations: []*StateRevocation{}}
	}
	snapshot.RADIUSCorrelationStateFile = radiusPath
	return MarshalStateSnapshot(snapshot)
}
