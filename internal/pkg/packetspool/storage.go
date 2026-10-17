package packetspool

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	data "github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

const stateName = "state.packetspool"
const identityName = "identity.packetspool"
const headerBytes = 48

// Spool is safe for concurrent use. The checkpoint is the sole authority for
// the active immutable files, and is replaced durably before any retirement.
type Spool struct {
	mu                sync.Mutex
	config            Config
	dir               *securestore.Dir
	lock              *securestore.Lock
	usage             *securestore.Usage
	writer            *securestore.Writer
	fs                fileOps
	state             state
	orphans           map[string]struct{}
	uncertain, closed bool
	cleanupErr        error
}

// Initialize is an explicit provisioning operation. It never overwrites an
// existing identity or checkpoint, including evidence of incomplete creation.
// Open never silently initializes a missing identity or encryption ledger.
func Initialize(config Config) (result error) {
	s, err := openStore(config, true)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, s.Close()) }()
	if err := s.dir.WalkEntries(func(name string) error {
		if strings.HasPrefix(name, ".securestore-lock-") {
			return nil
		}
		if s.config.Keys != nil && name == s.config.Keys.UsageFileName() {
			return nil
		}
		return fmt.Errorf("initialize packet spool: directory contains existing object %q", name)
	}); err != nil {
		return err
	}
	if s.config.Protection == Encrypted {
		if _, err := s.dir.Read(s.config.Keys.UsageFileName(), 1024); errors.Is(err, os.ErrNotExist) {
			var store [16]byte
			if _, err := rand.Read(store[:]); err != nil {
				return fmt.Errorf("generate packet spool store identity: %w", err)
			}
			if _, err := securestore.InitializeUsage(s.dir, s.config.Keys, store); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := s.openCrypto(); err != nil {
			return err
		}
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("generate packet spool session: %w", err)
	}
	id := Identity{SourceID: s.config.SourceID, SessionID: hex.EncodeToString(random[:16]), CaptureEpoch: s.config.CaptureEpoch, DestinationID: s.config.DestinationID, AckScope: s.config.AckScope, Protection: s.config.Protection}
	if id.CaptureEpoch == "" {
		id.CaptureEpoch = hex.EncodeToString(random[16:])
	}
	s.state = state{Version: 1, Identity: id}
	identity, err := json.Marshal(id)
	if err != nil {
		return err
	}
	encoded, err := s.protect(identityName, identity, false)
	if err != nil {
		return err
	}
	if _, err := s.fs.create(identityName, encoded); err != nil {
		return err
	}
	checkpoint, err := s.encodeState(s.state)
	if err != nil {
		return err
	}
	_, err = s.fs.create(stateName, checkpoint)
	return err
}

func Open(config Config) (_ *Spool, result error) {
	s, err := openStore(config, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.Close())
		}
	}()
	if s.config.Protection == Encrypted {
		if err := s.openCrypto(); err != nil {
			return nil, err
		}
	}
	identity, err := s.read(identityName, 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read packet spool identity: %w", err)
	}
	var id Identity
	if err := decodeJSON(identity, &id); err != nil {
		return nil, fmt.Errorf("decode packet spool identity: %w", err)
	}
	if !s.matches(id) {
		return nil, ErrIdentity
	}
	checkpoint, err := s.read(stateName, maxManifest)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read packet spool checkpoint: %w", err)
	}
	if err := decodeJSON(checkpoint, &s.state); err != nil {
		return nil, fmt.Errorf("decode packet spool checkpoint: %w", err)
	}
	if s.state.Identity != id {
		return nil, ErrIdentity
	}
	if err := s.validateState(s.state); err != nil {
		return nil, err
	}
	active := make(map[string]bool, len(s.state.Records))
	for _, record := range s.state.Records {
		if _, err := s.readBatch(record); err != nil {
			return nil, err
		}
		active[recordName(record.Sequence)] = true
	}
	if err := s.dir.WalkEntries(func(name string) error {
		if name == stateName || name == identityName || strings.HasPrefix(name, ".securestore-lock-") {
			return nil
		}
		if s.config.Keys != nil && name == s.config.Keys.UsageFileName() {
			return nil
		}
		if active[name] {
			return nil
		}
		if _, ok := parseRecordName(name); !ok {
			return fmt.Errorf("unexpected packet spool object %q; preserved for inspection", name)
		}
		// A published but uncommitted record is not pending custody. Authenticate
		// framing before treating it as an orphan, rather than hiding corruption.
		payload, err := s.read(name, int64(s.config.MaxRecordBytes))
		if err != nil {
			return fmt.Errorf("read orphan packet spool record: %w", err)
		}
		batch := new(data.PacketBatch)
		if err := proto.Unmarshal(payload, batch); err != nil {
			return fmt.Errorf("decode orphan packet spool record: %w", err)
		}
		sequence, _ := parseRecordName(name)
		if batch.HunterId != id.SourceID || batch.ProducerSessionId != id.SessionID || batch.CaptureEpoch != id.CaptureEpoch || batch.Sequence != sequence {
			return ErrIdentity
		}
		s.orphans[name] = struct{}{}
		return nil
	}); err != nil {
		return nil, err
	}
	// Settle a rename visible after an earlier uncertain sync before collection.
	if err := s.fs.sync(); err != nil {
		return nil, fmt.Errorf("settle packet spool recovery: %w", err)
	}
	if err := s.cleanup(); err != nil {
		return nil, err
	}
	return s, nil
}

func openStore(config Config, initialize bool) (*Spool, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	if initialize {
		if err := securestore.EnsureDir(config.Directory); err != nil {
			return nil, err
		}
	}
	dir, err := securestore.OpenDir(config.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	lock, err := dir.Lock(stateName)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	s := &Spool{config: config, dir: dir, lock: lock, orphans: make(map[string]struct{})}
	s.fs = fileOps{create: dir.Create, replace: dir.Replace, remove: dir.Remove, sync: dir.Sync}
	if config.fs != nil {
		if config.fs.create != nil {
			s.fs.create = config.fs.create
		}
		if config.fs.replace != nil {
			s.fs.replace = config.fs.replace
		}
		if config.fs.remove != nil {
			s.fs.remove = config.fs.remove
		}
		if config.fs.sync != nil {
			s.fs.sync = config.fs.sync
		}
	}
	return s, nil
}

func (s *Spool) openCrypto() error {
	u, err := securestore.OpenUsage(s.dir, s.config.Keys, [16]byte{})
	if err != nil {
		return fmt.Errorf("open required packet spool encryption ledger: %w", err)
	}
	s.usage = u
	s.writer, err = securestore.NewWriter(u)
	return err
}

func (s *Spool) matches(id Identity) bool {
	return validID(id.SessionID) && validID(id.CaptureEpoch) && id.SourceID == s.config.SourceID && id.DestinationID == s.config.DestinationID && id.AckScope == s.config.AckScope && id.Protection == s.config.Protection && (s.config.CaptureEpoch == "" || s.config.CaptureEpoch == id.CaptureEpoch)
}

func recordName(sequence uint64) string { return fmt.Sprintf("%020d.packetbatch", sequence) }
func parseRecordName(name string) (uint64, bool) {
	if len(name) != 32 || !strings.HasSuffix(name, ".packetbatch") {
		return 0, false
	}
	sequence, err := strconv.ParseUint(name[:20], 10, 64)
	return sequence, err == nil && sequence > 0 && recordName(sequence) == name
}

func frame(payload []byte) []byte {
	result := make([]byte, headerBytes+len(payload))
	copy(result, "LCPKSPL1")
	binary.BigEndian.PutUint64(result[8:16], uint64(len(payload)))
	digest := sha256.Sum256(payload)
	copy(result[16:headerBytes], digest[:])
	copy(result[headerBytes:], payload)
	return result
}
func unframe(encoded []byte, limit int64) ([]byte, error) {
	if len(encoded) < headerBytes || string(encoded[:8]) != "LCPKSPL1" {
		return nil, errors.New("packet spool framing is invalid")
	}
	size := binary.BigEndian.Uint64(encoded[8:16])
	if size > uint64(limit) || size != uint64(len(encoded)-headerBytes) {
		return nil, errors.New("packet spool frame size is invalid")
	}
	digest := sha256.Sum256(encoded[headerBytes:])
	if !bytes.Equal(digest[:], encoded[16:headerBytes]) {
		return nil, errors.New("packet spool checksum mismatch")
	}
	return encoded[headerBytes:], nil
}
func (s *Spool) protect(name string, payload []byte, product bool) ([]byte, error) {
	plain := frame(payload)
	if s.config.Protection == Private {
		return plain, nil
	}
	purpose := securestore.PacketSpoolState
	if product {
		purpose = securestore.PacketSpoolBatch
	}
	return s.writer.Seal(purpose, securestore.Binding{Store: s.usage.StoreID(), Object: name}, plain)
}
func (s *Spool) read(name string, limit int64) ([]byte, error) {
	// The filesystem size is checked before allocation; envelope overhead is
	// separately bounded even for adversarial length fields inside the file.
	encoded, err := s.dir.Read(name, limit+headerBytes+securestore.MaxHeaderBytes+securestore.MaxObjectIDBytes+64)
	if err != nil {
		return nil, err
	}
	if s.config.Protection == Encrypted {
		purpose := securestore.PacketSpoolState
		if strings.HasSuffix(name, ".packetbatch") {
			purpose = securestore.PacketSpoolBatch
		}
		encoded, err = s.config.Keys.Open(purpose, securestore.Binding{Store: s.usage.StoreID(), Object: name}, encoded, int(limit)+headerBytes)
		if err != nil {
			return nil, err
		}
	}
	return unframe(encoded, limit)
}
func decodeJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("packet spool JSON contains trailing data")
	}
	return nil
}
func (s *Spool) encodeState(next state) ([]byte, error) {
	if err := s.validateState(next); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxManifest {
		return nil, errors.New("packet spool checkpoint exceeds bounded metadata capacity")
	}
	return s.protect(stateName, payload, false)
}

func (s *Spool) readBatch(r record) (*data.PacketBatch, error) {
	encoded, err := s.dir.Read(recordName(r.Sequence), int64(s.config.MaxRecordBytes)+headerBytes+securestore.MaxHeaderBytes+securestore.MaxObjectIDBytes+64)
	if err != nil {
		return nil, fmt.Errorf("read committed packet batch %d: %w", r.Sequence, err)
	}
	digest := sha256.Sum256(encoded)
	if uint64(len(encoded)) != r.Size || hex.EncodeToString(digest[:]) != r.Digest {
		return nil, errors.New("packet spool record differs from committed checkpoint")
	}
	payload, err := s.read(recordName(r.Sequence), int64(s.config.MaxRecordBytes))
	if err != nil {
		return nil, err
	}
	batch := new(data.PacketBatch)
	if err := proto.Unmarshal(payload, batch); err != nil {
		return nil, fmt.Errorf("decode packet spool record: %w", err)
	}
	id := s.state.Identity
	if batch.Sequence != r.Sequence || batch.HunterId != id.SourceID || batch.ProducerSessionId != id.SessionID || batch.CaptureEpoch != id.CaptureEpoch {
		return nil, ErrIdentity
	}
	return batch, nil
}

func (s *Spool) commit(next state) (bool, error) {
	encoded, err := s.encodeState(next)
	if err != nil {
		return false, err
	}
	out, err := s.fs.replace(stateName, encoded)
	if out == securestore.Uncertain {
		s.uncertain = true
		return false, errors.Join(ErrUncertain, err)
	}
	if out != securestore.Committed {
		if err == nil {
			err = errors.New("packet spool mutation was not committed")
		}
		return false, err
	}
	s.state = next
	return true, err
}
func (s *Spool) cleanup() error {
	var result error
	for name := range s.orphans {
		_, err := s.fs.remove(name)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			delete(s.orphans, name)
			continue
		}
		result = errors.Join(result, fmt.Errorf("remove retired packet batch: %w", err))
	}
	s.cleanupErr = result
	if result != nil {
		return &securestore.CommitError{Outcome: securestore.Committed, Op: "packet spool cleanup", Err: errors.Join(ErrCleanup, result)}
	}
	return nil
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	if s.usage != nil {
		result = errors.Join(result, s.usage.Close())
	}
	if s.lock != nil {
		result = errors.Join(result, s.lock.Close())
	}
	if s.dir != nil {
		result = errors.Join(result, s.dir.Close())
	}
	return result
}
