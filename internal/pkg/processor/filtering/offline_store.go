package filtering

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// OfflineOptions requires operators to explicitly choose in-place replacement
// or authenticated resumption. An existing destination is otherwise never replaced.
type OfflineOptions struct {
	InPlace bool
	Resume  bool
}

type filterStoreIntent struct {
	Version       int    `json:"version"`
	Operation     string `json:"operation"`
	SourcePath    string `json:"source_path_hash"`
	TargetPath    string `json:"target_path_hash"`
	SourceContent string `json:"source_content_hash"`
	Payload       string `json:"payload_hash"`
	KeyID         string `json:"key_id"`
}

func digestString(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// InitializeEncryptedFilterStore initializes an empty encrypted snapshot offline.
// The private destination directory must have been explicitly provisioned.
func InitializeEncryptedFilterStore(path string, keys securestore.KeyConfig, options OfflineOptions) (securestore.Outcome, error) {
	if options.InPlace {
		return securestore.NotCommitted, errors.New("empty initialization cannot replace an existing store")
	}
	return offlineFilterStore("", path, keys, options)
}

// MigrateYAMLFilterStore is an explicit YAML-to-encrypted offline operation. All
// source records must validate. Different-path migration retains the original;
// it never creates a plaintext backup or activates any filters.
func MigrateYAMLFilterStore(source, destination string, keys securestore.KeyConfig, options OfflineOptions) (securestore.Outcome, error) {
	if source == "" {
		return securestore.NotCommitted, errors.New("YAML migration requires an explicit source path")
	}
	return offlineFilterStore(source, destination, keys, options)
}

func offlineFilterStore(source, destination string, keys securestore.KeyConfig, options OfflineOptions) (out securestore.Outcome, result error) {
	out = securestore.NotCommitted
	defer func() {
		if result != nil {
			result = &securestore.CommitError{Outcome: out, Op: "offline managed filter snapshot", Err: result}
		}
	}()
	ring, err := securestore.LoadKeyring(keys)
	if err != nil {
		return out, err
	}
	targetParent, targetName, targetPath, err := storePath(destination)
	if err != nil {
		return out, err
	}
	var sourcePath string
	if source != "" {
		_, _, sourcePath, err = storePath(source)
		if err != nil {
			return out, err
		}
	}
	samePath := sourcePath != "" && sourcePath == targetPath
	if samePath != options.InPlace {
		return out, errors.New("same-path migration requires explicit in-place mode; different paths must not use in-place mode")
	}
	for _, key := range append([]securestore.KeyRef{keys.Active}, keys.Prior...) {
		_, _, keyPath, err := storePath(key.File)
		if err != nil {
			return out, err
		}
		if keyPath == targetPath || sourcePath != "" && keyPath == sourcePath {
			return out, errors.New("filter migration source, destination, and key files must not alias")
		}
	}
	var target snapshotFile
	var input *securestore.PrivateSource
	defer func() {
		if input != nil {
			result = errors.Join(result, input.Close())
		}
		result = errors.Join(result, target.discard())
	}()
	target.dir, err = securestore.OpenDir(targetParent)
	if err != nil {
		return out, err
	}
	target.path, target.name = targetPath, targetName
	targetOrder, err := target.dir.LockOrderKey(targetName)
	if err != nil {
		return out, err
	}
	var sourceOrder string
	if samePath {
		// Validate the raw source spelling even when canonical pathnames are
		// equal. Collapsing symlink/.. must not bypass descriptor traversal.
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
	if err := checkOfflineAliases(&target, input, ring); err != nil {
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
	if err := checkOfflineAliases(&target, input, ring); err != nil {
		return out, err
	}
	var rawSource []byte
	if samePath {
		rawSource, err = target.dir.Read(target.name, maxFilterEnvelopeBytes)
	} else if input != nil {
		rawSource, err = input.Read(filtercodec.MaxManagedSnapshotBytes)
	}
	if err != nil {
		return out, err
	}
	defer clear(rawSource)
	completedInPlace := samePath && options.Resume && bytes.HasPrefix(rawSource, []byte("LCS1"))
	var plain []byte
	if !completedInPlace {
		filters := make(map[string]*management.Filter)
		if source != "" {
			filters, err = filtercodec.UnmarshalManagedYAML(rawSource)
			if err != nil {
				return out, err
			}
		}
		plain, err = filtercodec.MarshalEncryptedFilters(filters)
		if err != nil {
			return out, err
		}
		defer clear(plain)
	}
	current, readErr := target.dir.Read(target.name, maxFilterEnvelopeBytes)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return out, readErr
	}
	if readErr == nil && !samePath && !options.Resume {
		return out, os.ErrExist
	}
	operation := "initialize"
	if source != "" {
		operation = "yaml-migration"
	}
	wanted := filterStoreIntent{Version: 1, Operation: operation,
		SourcePath: digestString([]byte(sourcePath)), TargetPath: digestString([]byte(targetPath)),
		SourceContent: digestString(rawSource), Payload: digestString(plain), KeyID: ring.ActiveID()}
	bootstrapName := ".filter-bootstrap-" + digestString([]byte(target.name))
	intentName := ".filter-intent-" + digestString([]byte(target.name))
	bootstrap, err := openFilterBootstrap(target.dir, bootstrapName, ring, wanted, options.Resume, completedInPlace)
	if err != nil {
		return out, err
	}
	if bootstrap.stage == bootstrapUninitialized {
		_, intentErr := target.dir.Read(intentName, 16<<10)
		if intentErr == nil || readErr == nil && !samePath {
			return out, errors.New("encrypted intent or output exists before the required ledger boundary")
		}
		if !errors.Is(intentErr, os.ErrNotExist) {
			return out, intentErr
		}
	}
	usage, err := openOfflineUsage(target.dir, ring, bootstrap)
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, usage.Close()) }()
	if bootstrap.stage == bootstrapUninitialized && (usage.Stats().Invocations != 0 || usage.Stats().Blocks != 0) {
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
	intentBinding := securestore.Binding{Store: usage.StoreID(), Object: "filters/offline-intent/" + digestString([]byte(target.name))}
	intent := wanted
	encodedIntent, intentReadErr := target.dir.Read(intentName, 16<<10)
	if options.Resume && intentReadErr == nil {
		decoded, err := ring.Open(securestore.FilterSnapshot, intentBinding, encodedIntent, 8<<10)
		if err != nil {
			return out, fmt.Errorf("resume requires the authenticated original operation intent: %w", err)
		}
		defer clear(decoded)
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&intent); err != nil {
			return out, errors.New("invalid encrypted filter migration intent")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return out, errors.New("invalid encrypted filter migration intent framing")
		}
		canonical, err := json.Marshal(intent)
		if err != nil || !bytes.Equal(canonical, decoded) {
			return out, errors.New("encrypted filter migration intent is not canonical")
		}
		if intent.Version != wanted.Version || intent.Operation != wanted.Operation || intent.SourcePath != wanted.SourcePath || intent.TargetPath != wanted.TargetPath || intent.KeyID != wanted.KeyID {
			return out, errors.New("resume source, destination, operation, or key does not match the authenticated intent")
		}
		if !completedInPlace && (intent.SourceContent != wanted.SourceContent || intent.Payload != wanted.Payload) {
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
			return out, errors.New("encode encrypted filter migration intent")
		}
		defer clear(intentData)
		encoded, err := writer.Seal(securestore.FilterSnapshot, intentBinding, intentData)
		if err != nil {
			return out, err
		}
		if _, err := target.dir.Create(intentName, encoded); err != nil {
			return out, err
		}
	}
	binding := securestore.Binding{Store: usage.StoreID(), Object: filterSnapshotObject}
	if options.Resume && readErr == nil && (!samePath || completedInPlace) {
		decoded, err := ring.Open(securestore.FilterSnapshot, binding, current, filtercodec.MaxManagedSnapshotBytes)
		if err != nil {
			return out, err
		}
		defer clear(decoded)
		if _, err := filtercodec.UnmarshalEncryptedFilters(decoded); err != nil {
			return out, err
		}
		if digestString(decoded) != intent.Payload {
			return out, errors.New("existing encrypted snapshot does not match the resumed operation")
		}
		// Re-establish a durable directory boundary after a lost acknowledgement.
		if err := target.dir.Sync(); err != nil {
			return securestore.Uncertain, err
		}
		return securestore.Committed, nil
	}
	encoded, err := writer.Seal(securestore.FilterSnapshot, binding, plain)
	if err != nil {
		return out, err
	}
	if samePath {
		return target.dir.Replace(target.name, encoded)
	}
	return target.dir.Create(target.name, encoded)
}

func checkOfflineAliases(target *snapshotFile, input *securestore.PrivateSource, ring *securestore.Keyring) error {
	targetID, targetErr := target.dir.FileIdentity(target.name)
	if targetErr != nil && !errors.Is(targetErr, os.ErrNotExist) {
		return targetErr
	}
	if targetErr == nil && ring.UsesFile(targetID) {
		return errors.New("filter destination aliases an opened encryption key")
	}
	var sourceID securestore.FileIdentity
	if input != nil {
		var err error
		sourceID, err = input.Identity()
		if err != nil {
			return err
		}
		if ring.UsesFile(sourceID) {
			return errors.New("filter source aliases an opened encryption key")
		}
		if targetErr == nil && sourceID == targetID {
			return errors.New("filter source and destination are aliased")
		}
	}
	for _, reserved := range []string{ring.UsageFileName(), ".filter-bootstrap-" + digestString([]byte(target.name)), ".filter-intent-" + digestString([]byte(target.name))} {
		if target.name == reserved {
			return errors.New("filter snapshot uses a reserved metadata path")
		}
		identity, err := target.dir.FileIdentity(reserved)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if ring.UsesFile(identity) || targetErr == nil && targetID == identity || input != nil && sourceID == identity {
			return errors.New("filter migration metadata aliases a key, source, or snapshot")
		}
	}
	return nil
}
