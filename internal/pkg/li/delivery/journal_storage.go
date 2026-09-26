//go:build li

package delivery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const journalDefaultKeyID = "default"

// journalEnvelopeRecord freezes the existing X2 owner schema independently of
// the envelope version. Later journal schemas require explicit version dispatch.
type journalEnvelopeRecord struct {
	Version int           `json:"version"`
	Record  JournalRecord `json:"record"`
}

// UpgradeLegacyJournal is an explicit offline bootstrap for existing LCX2 v1
// stores. It authenticates the complete source before initializing the fresh
// write-key ledger, then establishes durable ID and sequence checkpoints. Old
// products remain immutable and require their explicitly mapped prior read key.
// Calling again resumes an interrupted bootstrap without resetting reservations.
func UpgradeLegacyJournal(cfg JournalConfig) (securestore.Outcome, error) {
	if cfg.KeyID == "" || cfg.LegacyKeyID == "" || cfg.KeyID == cfg.LegacyKeyID {
		return securestore.NotCommitted, errors.New("offline journal upgrade requires a fresh active key ID and an explicit prior legacy key mapping")
	}
	j, err := openJournal(cfg, true)
	if err != nil {
		return securestore.OutcomeOf(err), err
	}
	if err := j.Close(); err != nil {
		return securestore.Committed, &securestore.CommitError{Outcome: securestore.Committed, Op: "close upgraded journal", Err: err}
	}
	return securestore.Committed, nil
}

func openJournal(cfg JournalConfig, upgrade bool) (_ *Journal, result error) {
	if cfg.MaxBytes <= journalFaultReserve || cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 || cfg.MaxRecords > 1_000_000 {
		return nil, errors.New("invalid X2 journal capacity")
	}
	keyID, legacyID := cfg.KeyID, cfg.LegacyKeyID
	if keyID == "" {
		keyID = journalDefaultKeyID
		if legacyID == "" {
			legacyID = keyID // Original raw-key configuration selects exactly one key.
		}
	}
	ring, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: legacyID})
	if err != nil {
		return nil, err
	}
	if cfg.ValidateKeys != nil {
		if err := cfg.ValidateKeys(ring); err != nil {
			return nil, err
		}
	}
	// The owner queue may be larger; filesystem work has its own fixed ceiling.
	cfg.MaxPending = min(cfg.MaxPending, 4096)
	if err := securestore.EnsureDir(cfg.Dir); err != nil {
		return nil, fmt.Errorf("create X2 journal: %w", err)
	}
	dir, err := securestore.OpenDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	j := &Journal{cfg: cfg, store: dir, keys: ring, entries: make(map[uint64]*journalEntry),
		ops: make(chan journalOperation, cfg.MaxPending), done: make(chan struct{}),
		sequences: make(map[string]journalSequenceEntry), heldByDID: make(map[uuid.UUID]int), wake: make(chan struct{}, 1)}
	defer func() {
		if result != nil {
			result = errors.Join(result, j.closeStorage())
			if upgrade && j.bootstrapTouched {
				result = &securestore.CommitError{Outcome: securestore.Uncertain, Op: "offline journal bootstrap", Err: result}
			}
		}
	}()
	j.lock, err = dir.Lock(".lock")
	if err != nil {
		return nil, fmt.Errorf("lock journal: %w", err)
	}
	// The stable sidecar and this empty data inode cover new and old binaries.
	// Old binaries flock .lock itself; Dir retains that inode lock on creation.
	lockExisted := false
	if _, err := dir.Read(".lock", 0); errors.Is(err, os.ErrNotExist) {
		out, err := dir.Create(".lock", nil)
		if err != nil {
			return nil, journalStorageError(out, err)
		}
	} else if err != nil {
		return nil, err
	} else {
		lockExisted = true
	}
	j.allocationUnit, err = dir.AllocationUnit()
	if err != nil {
		return nil, err
	}
	// Reserve journal/state/usage ownership files, prior ledgers and rewrite space.
	j.faultReserve = max(journalFaultReserve, int64(6+2*len(cfg.ReadKeys))*j.allocationUnit)
	if cfg.MaxBytes <= j.faultReserve {
		return nil, fmt.Errorf("recovered journal exceeds configured capacity: %w", ErrJournalFull)
	}
	j.stats.MaxBytes = cfg.MaxBytes
	j.writeFile = j.writePath
	if _, err := dir.RecoverTemporaries(); err != nil {
		return nil, err
	}
	var products, sequences, temporary []string
	stateFound, ledgerFound := false, false
	metadataCount := 0
	metadataAllocated := int64(0)
	err = dir.WalkEntries(func(name string) error {
		switch {
		case name == ".lock":
			return nil
		case strings.HasPrefix(name, ".securestore-lock-"), strings.HasPrefix(name, ".usage-"):
			size, err := dir.MetadataAllocatedSize(name)
			if err != nil {
				return err
			}
			if size > cfg.MaxBytes-j.faultReserve-metadataAllocated {
				return fmt.Errorf("recovered journal metadata exceeds configured capacity: %w", ErrJournalFull)
			}
			metadataAllocated += size
			ledgerFound = ledgerFound || strings.HasPrefix(name, ".usage-")
			metadataCount++
		case name == ".state":
			stateFound = true
		case strings.HasSuffix(name, ".tmp"):
			if !validLegacyJournalTemp(name) {
				return errors.New("unexpected temporary journal file")
			}
			temporary = append(temporary, name)
			if len(temporary) > cfg.MaxPending+2 {
				return errors.New("too many incomplete journal objects")
			}
		case strings.HasSuffix(name, ".seq"):
			if len(sequences) >= cfg.MaxRecords {
				return errors.New("recovered journal exceeds configured capacity")
			}
			sequences = append(sequences, name)
		case strings.HasSuffix(name, ".x2"):
			id, err := strconv.ParseUint(strings.TrimSuffix(name, ".x2"), 10, 64)
			if err != nil || id == 0 || name != journalRecordName(id) {
				return errors.New("invalid journal record name")
			}
			if len(products) >= cfg.MaxRecords {
				return errors.New("recovered journal exceeds configured capacity")
			}
			products = append(products, name)
		default:
			return errors.New("unexpected journal file")
		}
		if metadataCount > 16 {
			return errors.New("too many journal metadata files")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Existing metadata is charged in addition to the reserve for publication,
	// replacement, and active-ledger growth after this scan.
	j.faultReserve += metadataAllocated
	empty := !lockExisted && metadataCount == 1 && !stateFound && !ledgerFound && len(products) == 0 && len(sequences) == 0 && len(temporary) == 0
	j.usage, err = securestore.OpenUsage(dir, j.keys, [16]byte{})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		j.readOnly = true
		if !empty && !stateFound && len(products) == 0 && len(sequences) == 0 {
			return nil, errors.New("required journal usage ledger is missing from used storage")
		}
		if empty && !upgrade {
			if err := j.initializeUsage(); err != nil {
				return nil, err
			}
		}
	} else {
		if err := j.installWriter(); err != nil {
			return nil, err
		}
	}
	if stateFound {
		data, err := dir.Read(".state", 4096)
		if err != nil {
			return nil, err
		}
		r, err := j.decodeObject(securestore.JournalState, "journal-state", data, 4096)
		if err != nil {
			return nil, fmt.Errorf("recover journal state: %w", err)
		}
		if !validJournalState(r) {
			return nil, errors.New("invalid journal state schema")
		}
		j.next = r.ID
	} else if !j.readOnly && !empty {
		if !upgrade {
			return nil, errors.New("required journal state is missing")
		}
		if usage := j.usage.Stats(); usage.Invocations != 0 || usage.Blocks != 0 {
			return nil, errors.New("missing journal state after encryption usage was reserved")
		}
		j.legacyBootstrapOnly = true
	}
	for _, name := range sequences {
		if err := j.recoverSequence(name); err != nil {
			return nil, err
		}
	}
	for _, name := range products {
		size, err := dir.AllocatedSize(name)
		if err != nil {
			return nil, err
		}
		if size > cfg.MaxBytes-j.faultReserve-j.stats.Bytes {
			return nil, fmt.Errorf("recovered journal exceeds configured capacity: %w", ErrJournalFull)
		}
		id, _ := strconv.ParseUint(strings.TrimSuffix(name, ".x2"), 10, 64) // Validated above.
		rec, err := j.readRecord(id)
		if err != nil {
			return nil, fmt.Errorf("recover journal product: %w", err)
		}
		j.entries[id] = &journalEntry{did: rec.DID, payloadBytes: int64(len(rec.Data)), size: size, held: true, persisted: true}
		j.stats.Bytes += size
		j.stats.Persisted++
		j.stats.Held++
		j.heldByDID[rec.DID]++
		j.next = max(j.next, id)
	}
	j.legacyBootstrapOnly = false
	if upgrade && j.readOnly {
		if empty {
			return nil, errors.New("offline legacy upgrade requires an existing source journal")
		}
		if err := j.initializeUsage(); err != nil {
			return nil, err
		}
	}
	if !j.readOnly {
		// All published records have authenticated before any owner repair writes.
		for _, name := range temporary {
			out, err := dir.Remove(name)
			if err != nil {
				return nil, journalStorageError(out, err)
			}
		}
		if err := j.repairRecoveredCheckpoints(); err != nil {
			return nil, fmt.Errorf("repair recovered journal checkpoints: %w", err)
		}
		if empty || upgrade || !stateFound {
			state, err := j.encodeObject(securestore.JournalState, "journal-state", JournalRecord{ID: j.next})
			if err != nil {
				return nil, err
			}
			if err := j.writeFile(filepath.Join(cfg.Dir, ".state"), state); err != nil {
				return nil, err
			}
		}
	}
	go j.run()
	return j, nil
}

func (j *Journal) initializeUsage() error {
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	out, err := securestore.InitializeUsage(j.store, j.keys, [16]byte(id))
	if out != securestore.NotCommitted {
		j.bootstrapTouched = true
	}
	if err != nil {
		return journalStorageError(out, err)
	}
	j.usage, err = securestore.OpenUsage(j.store, j.keys, [16]byte(id))
	if err != nil {
		return err
	}
	return j.installWriter()
}

func (j *Journal) installWriter() error {
	j.storeID = j.usage.StoreID()
	var err error
	j.writer, err = securestore.NewWriter(j.usage)
	j.readOnly = false
	return err
}

func (j *Journal) closeStorage() error {
	var result error
	if j.usage != nil {
		result = errors.Join(result, j.usage.Close())
	}
	if j.lock != nil {
		result = errors.Join(result, j.lock.Close())
	}
	if j.store != nil {
		result = errors.Join(result, j.store.Close())
	}
	return result
}

func journalRecordName(id uint64) string { return fmt.Sprintf("%020d.x2", id) }
func journalObjectID(id uint64) string   { return strconv.FormatUint(id, 10) }

func validLegacyJournalTemp(name string) bool {
	if name == ".state.tmp" || validSequenceTemp(name) {
		return true
	}
	id, err := strconv.ParseUint(strings.TrimSuffix(name, ".x2.tmp"), 10, 64)
	return err == nil && id != 0 && name == journalRecordName(id)+".tmp"
}

func validJournalState(r JournalRecord) bool {
	return r.DID == uuid.Nil && r.XID == uuid.Nil && r.TaskGeneration == 0 && r.DestinationGeneration == 0 && r.CallGeneration == 0 && r.CallID == "" && r.AdmittedAt.IsZero() && r.CapturedAt.IsZero() && len(r.Data) == 0
}

func journalStorageError(out securestore.Outcome, err error) error {
	if err == nil {
		return nil
	}
	if out != securestore.NotCommitted {
		return &securestore.CommitError{Outcome: out, Op: "mutate journal object", Err: errors.Join(ErrPersistenceUncertain, err)}
	}
	return err
}

func (j *Journal) removeRecord(id uint64) error {
	out, err := j.store.Remove(journalRecordName(id))
	return journalStorageError(out, err)
}

func (j *Journal) readRecord(id uint64) (JournalRecord, error) {
	b, err := j.store.Read(journalRecordName(id), journalMaxRecord)
	if err != nil {
		return JournalRecord{}, err
	}
	r, err := j.decodeObject(securestore.X2Product, journalObjectID(id), b, int(journalMaxRecord)-1024)
	if err == nil && r.ID != id {
		return JournalRecord{}, errors.New("journal identity mismatch")
	}
	return r, err
}

func (j *Journal) encodeObject(p securestore.Purpose, object string, r JournalRecord) ([]byte, error) {
	if j.readOnly || j.writer == nil {
		return nil, ErrJournalMigrationRequired
	}
	plain, err := json.Marshal(journalEnvelopeRecord{Version: 1, Record: r})
	if err != nil {
		return nil, errors.New("encode journal schema")
	}
	defer clear(plain)
	binding := securestore.Binding{Store: j.storeID, Object: object}
	if p == securestore.X2Product {
		return j.writer.Seal(p, binding, plain)
	}
	return j.writer.SealControl(p, binding, plain)
}

func (j *Journal) decodeObject(p securestore.Purpose, object string, b []byte, limit int) (JournalRecord, error) {
	var rec JournalRecord
	if len(b) < 5 || len(b) > int(journalMaxRecord) {
		return rec, errors.New("invalid journal version or truncated record")
	}
	var plain []byte
	var err error
	switch string(b[:4]) {
	case "LCX2":
		if b[4] != 1 || len(b) < 5+12+16+4 {
			return rec, errors.New("invalid journal version or truncated record")
		}
		if crc32.ChecksumIEEE(b[:len(b)-4]) != binary.BigEndian.Uint32(b[len(b)-4:]) {
			return rec, errors.New("journal checksum mismatch")
		}
		plain, err = j.keys.OpenLegacy(b[5:17], b[17:len(b)-4], b[:5], limit)
		if err != nil {
			return rec, err
		}
		defer clear(plain)
		err = decodeJournalJSON(plain, journalRecordFields, &rec)
	case "LCS1":
		if j.legacyBootstrapOnly {
			return rec, errors.New("cannot recover missing journal state from new-format objects")
		}
		if j.readOnly || j.storeID == [16]byte{} {
			return rec, fmt.Errorf("required journal usage ledger is missing: %w", ErrJournalMigrationRequired)
		}
		plain, err = j.keys.Open(p, securestore.Binding{Store: j.storeID, Object: object}, b, limit)
		if err != nil {
			return rec, err
		}
		defer clear(plain)
		var wrapped journalEnvelopeRecord
		err = decodeJournalJSON(plain, journalWrapperFields, &wrapped)
		if err == nil && wrapped.Version != 1 {
			err = errors.New("unsupported journal owner schema version")
		}
		rec = wrapped.Record
	default:
		return rec, errors.New("invalid journal version")
	}
	if err != nil {
		return JournalRecord{}, err
	}
	return rec, nil
}

type journalJSONFields map[string]journalJSONFields

var journalRecordFields = journalJSONFields{"ID": nil, "DID": nil, "XID": nil, "TaskGeneration": nil, "DestinationGeneration": nil, "CallGeneration": nil, "CallID": nil, "AdmittedAt": nil, "CapturedAt": nil, "Data": nil}
var journalWrapperFields = journalJSONFields{"version": nil, "record": journalRecordFields}
var journalSequenceFields = journalJSONFields{"Context": {"PDUType": nil, "XID": nil, "DomainID": nil, "NFID": nil, "IPID": nil, "CorrelationID": nil}, "Next": nil}

// Only these fixed-depth, fixed-field schemas are accepted. Validate duplicate
// keys and containers before the typed decoder can silently overwrite fields.
func decodeJournalJSON(data []byte, fields journalJSONFields, output any) error {
	if !utf8.Valid(data) || !validJournalJSONUnicode(data) {
		return errors.New("invalid journal JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := validateJournalJSONObject(d, fields); err != nil {
		return errors.New("invalid journal JSON schema")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing journal JSON data")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("invalid journal JSON field value")
	}
	return nil
}

// The standard decoder replaces lone UTF-16 surrogates. Reject them before
// decoding so authenticated identities cannot change through lossy conversion.
func validJournalJSONUnicode(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); {
		if data[i] == '"' {
			quoted = !quoted
			i++
			continue
		}
		if !quoted || data[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(data) {
			return false
		}
		if data[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil || value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 6
	}
	return true
}

func validateJournalJSONObject(d *json.Decoder, fields journalJSONFields) error {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("expected object")
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		child, known := fields[name]
		if err != nil || !ok || !known || seen[name] {
			return errors.New("unknown or duplicate field")
		}
		seen[name] = true
		if child != nil {
			if err := validateJournalJSONObject(d, child); err != nil {
				return err
			}
		} else {
			value, err := d.Token()
			if _, container := value.(json.Delim); err != nil || container || (value == nil && name != "Data") {
				return errors.New("expected scalar")
			}
		}
	}
	_, err = d.Token()
	if err != nil || len(seen) != len(fields) {
		return errors.New("missing fields")
	}
	return nil
}
