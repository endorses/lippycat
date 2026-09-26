//go:build li

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// PreparedJournal retains authenticated ownership without starting recovery,
// usage reservation, expiry, callbacks, or a runtime worker. Activate transfers
// that same ownership; Close before activation is pure owner cleanup.
type PreparedJournal struct {
	mu      sync.Mutex
	cfg     JournalConfig
	dir     *securestore.Dir
	lock    *securestore.Lock
	journal *Journal
	closed  bool
}

// PrepareJournals authenticates every configured journal before any journal is
// initialized or promoted. Disabled entries remain nil in the returned slice.
// Existing directories are acquired in descriptor order. Missing directories
// are provisioned only after all existing stores authenticate; they are then
// acquired and inspected before any Activate call may initialize them.
func PrepareJournals(configs []JournalConfig) (prepared []*PreparedJournal, result error) {
	prepared = make([]*PreparedJournal, len(configs))
	defer func() {
		if result != nil {
			for _, p := range prepared {
				if p != nil {
					result = errors.Join(result, p.Close())
				}
			}
			prepared = nil
		}
	}()
	var rings []*securestore.Keyring
	var paths []string
	for i, cfg := range configs {
		if cfg.Dir == "" {
			continue
		}
		if cfg.offline || cfg.rewriteDir != nil || cfg.rewriteLock != nil || cfg.rewriteUsage != nil {
			return prepared, errors.New("journal preparation requires runtime configuration")
		}
		if err := validateJournalPreparation(cfg); err != nil {
			return prepared, err
		}
		path, err := filepath.Abs(cfg.Dir)
		if err != nil {
			return prepared, err
		}
		for _, other := range paths {
			if path == other || strings.HasPrefix(path, other+string(filepath.Separator)) || strings.HasPrefix(other, path+string(filepath.Separator)) {
				return prepared, errors.New("journal preparation directories overlap")
			}
		}
		paths = append(paths, path)
		if cfg.Keys == nil {
			id, legacy := cfg.KeyID, cfg.LegacyKeyID
			if id == "" {
				id = journalDefaultKeyID
				if legacy == "" {
					legacy = id
				}
			}
			cfg.Keys, err = securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: id, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: legacy})
			if err != nil {
				return prepared, err
			}
		}
		if cfg.ValidateKeys != nil {
			if err := cfg.ValidateKeys(cfg.Keys); err != nil {
				return prepared, err
			}
			cfg.ValidateKeys = nil
		}
		rings = append(rings, cfg.Keys)
		p := &PreparedJournal{cfg: cfg}
		prepared[i] = p
		p.dir, err = securestore.OpenDir(cfg.Dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return prepared, err
		}
	}
	if err := securestore.CheckIndependent(rings...); err != nil {
		return prepared, err
	}
	type orderedOwner struct {
		key string
		p   *PreparedJournal
	}
	var ordered []orderedOwner
	for _, p := range prepared {
		if p == nil || p.dir == nil {
			continue
		}
		for _, other := range ordered {
			same, err := p.dir.SameDirectory(other.p.dir)
			if err != nil {
				return prepared, err
			}
			if same {
				return prepared, errors.New("journal preparation directories alias")
			}
		}
		key, err := p.dir.LockOrderKey(".lock")
		if err != nil {
			return prepared, err
		}
		ordered = append(ordered, orderedOwner{key, p})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })
	for _, o := range ordered {
		var err error
		o.p.lock, err = o.p.dir.Lock(".lock")
		if err != nil {
			return prepared, err
		}
	}
	for _, o := range ordered {
		if err := o.p.authenticate(); err != nil {
			return prepared, err
		}
	}
	// No existing store has failed authentication before this first mkdir.
	for _, p := range prepared {
		if p == nil || p.dir != nil {
			continue
		}
		if err := securestore.EnsureDir(p.cfg.Dir); err != nil {
			return prepared, err
		}
		var err error
		p.dir, err = securestore.OpenDir(p.cfg.Dir)
		if err != nil {
			return prepared, err
		}
		for _, other := range prepared {
			if other == nil || other == p || other.dir == nil {
				continue
			}
			same, err := p.dir.SameDirectory(other.dir)
			if err != nil {
				return prepared, err
			}
			if same {
				return prepared, errors.New("journal preparation directories alias")
			}
		}
		p.lock, err = p.dir.Lock(".lock")
		if err != nil {
			return prepared, err
		}
		// Another owner may have populated the formerly absent path. Authenticate
		// its actual state under our retained lock instead of trusting absence.
		if err := p.authenticate(); err != nil {
			return prepared, err
		}
	}
	return prepared, nil
}

func (p *PreparedJournal) authenticate() error {
	if _, err := p.dir.Read(".journal-retired", 4<<20); err == nil {
		return errors.New("journal source has been retired by offline rewrite")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, segmentErr := p.dir.FileIdentity(".segments")
	if segmentErr != nil && !errors.Is(segmentErr, os.ErrNotExist) {
		return segmentErr
	}
	_, stateErr := p.dir.FileIdentity(".state")
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	if errors.Is(segmentErr, os.ErrNotExist) && errors.Is(stateErr, os.ErrNotExist) {
		hash := sha256.Sum256([]byte(".lock"))
		ownName := ".securestore-lock-" + hex.EncodeToString(hash[:])
		return p.dir.WalkEntries(func(name string) error {
			if name != ownName {
				return errors.New("journal state is missing from nonempty storage")
			}
			_, err := p.dir.MetadataAllocatedSize(name)
			return err
		})
	}
	// An existing selected store requires its historical data-inode lock. Never
	// create it during preauthentication of a malformed/missing-prerequisite store.
	if _, err := p.dir.Read(".lock", 0); err != nil {
		if errors.Is(err, os.ErrNotExist) && errors.Is(segmentErr, os.ErrNotExist) && p.cfg.Interface != PDUTypeX3 {
			state, readErr := p.dir.Read(".state", 4096)
			if readErr != nil {
				return errors.Join(err, readErr)
			}
			// This is rejection-only format classification, not authentication or
			// permission to initialize. Historical LCX2 exports may lack .lock;
			// they still require explicit offline migration before live writes.
			if bytes.HasPrefix(state, []byte("LCX2")) {
				return errors.Join(ErrJournalMigrationRequired, err)
			}
		}
		return err
	}
	cfg := p.cfg
	cfg.offline = true
	cfg.preflight = true
	cfg.rewriteDir = p.dir
	cfg.rewriteLock = p.lock
	var j *Journal
	var err error
	if segmentErr == nil {
		if cfg.Interface == 0 {
			cfg.Interface = PDUTypeX2
			p.cfg.Interface = PDUTypeX2
		}
		j, err = openSegmentJournal(cfg, false)
	} else {
		if cfg.Interface == PDUTypeX3 {
			return errors.New("legacy X2 directory cannot be opened as X3")
		}
		j, err = openLegacyJournal(cfg, false)
	}
	if err != nil {
		return err
	}
	p.journal = j
	if j.usage == nil {
		return ErrJournalMigrationRequired
	}
	return authenticatePreparedProducts(j)
}

func (p *PreparedJournal) Activate() (_ *Journal, result error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, os.ErrClosed
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, p.closeLocked())
		}
	}()
	j := p.journal
	if j == nil {
		cfg := p.cfg
		cfg.rewriteDir = p.dir
		cfg.rewriteLock = p.lock
		var err error
		j, err = OpenJournal(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		if err := activatePreparedJournal(j); err != nil {
			return nil, err
		}
	}
	// The authenticated owner is now the runtime owner. No descriptor, lock,
	// immutable keyring or usage object is released/reloaded across this handoff.
	j.cfg.rewriteDir = nil
	j.cfg.rewriteLock = nil
	p.journal = nil
	p.dir = nil
	p.lock = nil
	p.closed = true
	return j, nil
}
func (p *PreparedJournal) Close() error { p.mu.Lock(); defer p.mu.Unlock(); return p.closeLocked() }
func (p *PreparedJournal) closeLocked() (result error) {
	if p.closed {
		return nil
	}
	p.closed = true
	if p.journal != nil {
		result = errors.Join(result, p.journal.Close())
		p.journal = nil
	}
	if p.lock != nil {
		result = errors.Join(result, p.lock.Close())
		p.lock = nil
	}
	if p.dir != nil {
		result = errors.Join(result, p.dir.Close())
		p.dir = nil
	}
	return result
}
func startPreparedLegacy(j *Journal) (result error) {
	if j.usage == nil {
		return ErrJournalMigrationRequired
	}
	// Authentication has completed for every configured store. Permit repair
	// seals now, but keep the pre-start lifecycle until every fallible step has
	// succeeded so cleanup never waits for a worker that has not been launched.
	wasReadOnly := j.readOnly
	j.readOnly = false
	defer func() {
		if result != nil {
			j.readOnly = wasReadOnly
		}
	}()
	if _, err := j.store.RecoverTemporaries(); err != nil {
		return err
	}
	for _, name := range j.preparedTemporaries {
		out, err := j.store.Remove(name)
		if err != nil {
			return journalStorageError(out, err)
		}
	}
	if err := j.repairRecoveredCheckpoints(); err != nil {
		return fmt.Errorf("repair prepared journal checkpoints: %w", err)
	}
	j.cfg.offline = false
	j.cfg.preflight = false
	j.cfg.rewriteDir = nil
	j.cfg.rewriteLock = nil
	j.readOnly = false
	j.preparedTemporaries = nil
	j.telemetry.Ready()
	go j.run()
	return nil
}
