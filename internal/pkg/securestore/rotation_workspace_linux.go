//go:build linux

package securestore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// RotationStage identifies one write, not a reusable role. The caller selects
// the remaining set only after authenticating the request and recovery cut.
type RotationStage uint8

const (
	RotationBootstrapUninitialized RotationStage = iota
	RotationBootstrapRequired
	RotationUsageZero
	RotationUsageReservation0
	RotationUsageReservation1
	RotationUsageReservation2
	RotationUsageReservation3
	RotationPlanned
	RotationPrepared
	RotationComplete
	RotationCandidateStage
	RotationPublication
	RotationPredecessorBootstrapStage
	RotationPredecessorProgressStage
	rotationStageCount
)

var rotationStageNames = [...]string{"bootstrap-u", "bootstrap-r", "usage-zero", "usage-0", "usage-1", "usage-2", "usage-3", "planned", "prepared", "complete", "candidate", "publication", "predecessor-bootstrap", "predecessor-progress"}

const rotationWorkspacePrefix = ".securestore-stage-"

// RotationOutputProof is supplied ONLY after authenticating the current output
// against this operation's prepared record. Historical completed receipts do
// not pin later runtime saves. Durable additionally records an already proven
// directory sync; false means a visible but uncertain prior publication.
type RotationOutputProof struct {
	Identity FileIdentity
	Bytes    int64
	SHA256   [32]byte
	Durable  bool
}

// RotationWorkspaceConfig does not confer authentication. The caller must hold
// source, destination, and old/new usage locks in stable order, authenticate all
// selected records and keys, and enforce the ledger-required bootstrap guard.
// All Owners must come from dir; destination and new usage ownership are required.
// Protected excludes a legitimate in-place source/destination, which is instead
// protected by its retained data-inode lock. Other immutable inputs belong here.
type RotationWorkspaceConfig struct {
	RotationIOConfig
	Stages      []RotationStage
	Owners      []*Lock
	PriorOutput *RotationOutputProof
}

type workspaceSlot struct {
	rotationSlot
	selected, consumed bool
}

// RotationWorkspace reserves a finite attempt, never a renewable reserve file.
// Once Reserve succeeds no method creates or allocates another file. A failed
// attempt must be closed, authenticated again, explicitly cleaned, and rebuilt.
// Close Usage, then workspace, then caller-owned locks. Close leaves attributed
// unselected slots for authenticated recovery; it never deletes a usage ledger.
type RotationWorkspace struct {
	mu                                     sync.Mutex
	dir                                    *Dir
	cfg                                    RotationWorkspaceConfig
	names                                  [rotationStageCount]string
	slots                                  [rotationStageCount]workspaceSlot
	ops                                    rotationIOOps
	unit, pool                             int64
	reserved, closed, usageOpen, usageUsed bool
	fault                                  error
	output                                 *RotationOutputProof
	outcome                                Outcome
	sealLimit, seals                       int
}

func OpenRotationWorkspace(d *Dir, cfg RotationWorkspaceConfig) (*RotationWorkspace, error) {
	if d == nil || !rotationHex(cfg.Token, 64) || cfg.Token == strings.Repeat("0", 64) ||
		(cfg.Purpose != FilterSnapshot && cfg.Purpose != AdministrativeState) || cfg.EnvelopeBytes <= 0 || cfg.EnvelopeBytes > MaxEnvelopeBytes || cfg.MaxWorkingBytes <= 0 ||
		len(cfg.Stages) > int(rotationStageCount) || len(cfg.Owners) < 2 || len(cfg.Owners) > 4 || len(cfg.Keyrings) > 2 || len(cfg.Protected) > 16 {
		return nil, errors.New("securestore: invalid finite rotation workspace")
	}
	if err := checkName(cfg.Destination); err != nil {
		return nil, err
	}
	if strings.HasPrefix(cfg.Destination, ".rotation-") || strings.HasPrefix(cfg.Destination, ".usage-") || !strings.HasPrefix(cfg.UsageName, ".usage-") || !rotationHex(strings.TrimPrefix(cfg.UsageName, ".usage-"), 64) {
		return nil, errors.New("securestore: invalid workspace target")
	}
	unit, err := d.AllocationUnit()
	if err != nil {
		return nil, err
	}
	if unit > math.MaxInt64/64 {
		return nil, errors.New("securestore: workspace allocation overflow")
	}
	cfg.Stages = append([]RotationStage(nil), cfg.Stages...)
	cfg.Owners = append([]*Lock(nil), cfg.Owners...)
	cfg.Keyrings = append([]*Keyring(nil), cfg.Keyrings...)
	cfg.Protected = append([]FileIdentity(nil), cfg.Protected...)
	w := &RotationWorkspace{dir: d, cfg: cfg, unit: unit, ops: defaultRotationIOOps(), outcome: NotCommitted}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", cfg.Purpose, cfg.Destination)))
	base := hex.EncodeToString(digest[:])
	for s := RotationStage(0); s < rotationStageCount; s++ {
		switch s {
		case RotationBootstrapUninitialized, RotationBootstrapRequired:
			w.names[s] = ".rotation-bootstrap-" + base
		case RotationUsageZero, RotationUsageReservation0, RotationUsageReservation1, RotationUsageReservation2, RotationUsageReservation3:
			w.names[s] = cfg.UsageName
		case RotationPlanned, RotationPrepared, RotationComplete:
			w.names[s] = ".rotation-progress-" + base
		case RotationCandidateStage:
			w.names[s] = ".rotation-candidate-" + base
		case RotationPublication:
			w.names[s] = cfg.Destination
		case RotationPredecessorBootstrapStage:
			w.names[s] = ".rotation-prev-bootstrap-" + cfg.Token
		case RotationPredecessorProgressStage:
			w.names[s] = ".rotation-prev-progress-" + cfg.Token
		}
	}
	for _, s := range cfg.Stages {
		if s >= rotationStageCount || w.slots[s].selected {
			return nil, errors.New("securestore: invalid or duplicate workspace stage")
		}
		w.slots[s].selected = true
		w.pool += w.round(s)
		if s >= RotationUsageReservation0 && s <= RotationUsageReservation3 {
			w.sealLimit++
		}
	}
	if w.pool > cfg.MaxWorkingBytes {
		return nil, errors.New("securestore: workspace cap below remaining pool")
	}
	if cfg.DestinationIsOutput && cfg.PriorOutput == nil {
		return nil, errors.New("securestore: output requires authenticated proof")
	}
	if cfg.PriorOutput != nil {
		if w.slots[RotationPublication].selected {
			return nil, errors.New("securestore: already published output cannot be republished")
		}
		p := *cfg.PriorOutput
		if p.Identity == (FileIdentity{}) || p.Bytes <= 0 || p.Bytes > cfg.EnvelopeBytes {
			return nil, errors.New("securestore: invalid authenticated output proof")
		}
		w.output = &p
		w.outcome = Uncertain
		if p.Durable {
			w.outcome = Committed
		}
	}
	d.mu.Lock()
	claimed := make([]*Lock, 0, len(cfg.Owners))
	seen := make(map[string]bool)
	for _, owner := range cfg.Owners {
		if owner == nil || owner.dir != d || d.locks[owner.name] != owner || seen[owner.name] {
			err = errors.New("securestore: invalid workspace owner set")
			break
		}
		seen[owner.name] = true
		owner.mu.Lock()
		if owner.file == nil || owner.rotationIOActive || owner.fixedSegmentActive {
			err = ErrLocked
		} else {
			owner.rotationIOActive = true
			claimed = append(claimed, owner)
		}
		owner.mu.Unlock()
		if err != nil {
			break
		}
	}
	if err == nil && (!seen[cfg.Destination] || !seen[cfg.UsageName]) {
		err = errors.New("securestore: workspace requires destination and usage owners")
	}
	if err == nil {
		err = w.checkOwnersLocked()
	}
	if err != nil {
		for _, owner := range claimed {
			owner.mu.Lock()
			owner.rotationIOActive = false
			owner.mu.Unlock()
		}
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if _, _, err = w.inventory(); err != nil {
		return nil, errors.Join(err, w.Close())
	}
	return w, nil
}
func (w *RotationWorkspace) limit(s RotationStage) int64 {
	if s == RotationCandidateStage || s == RotationPublication {
		return w.cfg.EnvelopeBytes
	}
	return rotationMetadataBytes
}
func (w *RotationWorkspace) round(s RotationStage) int64 {
	return (w.limit(s) + w.unit - 1) / w.unit * w.unit
}
func (w *RotationWorkspace) Name(s RotationStage) (string, error) {
	if s >= rotationStageCount {
		return "", errors.New("securestore: invalid workspace stage")
	}
	return w.names[s], nil
}
func (w *RotationWorkspace) RequiredPoolBytes() int64 { return w.pool }
func (w *RotationWorkspace) SnapshotOutcome() Outcome {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.outcome
}
func (w *RotationWorkspace) Ready() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reserved && !w.closed && w.fault == nil
}
func (w *RotationWorkspace) checkOwnersLocked() error {
	d := w.dir
	if d.file == nil {
		return os.ErrClosed
	}
	if err := validateDirectory(int(d.file.Fd()), "", true); err != nil {
		return err
	}
	for _, name := range w.names {
		if owner := d.locks[name]; owner != nil {
			retained := false
			for _, expected := range w.cfg.Owners {
				retained = retained || owner == expected
			}
			if !retained {
				return ErrLocked
			}
		}
	}
	for _, o := range w.cfg.Owners {
		o.mu.Lock()
		err := func() error {
			if o.file == nil || !o.rotationIOActive || d.locks[o.name] != o {
				return ErrLocked
			}
			if err := rotationNamedIdentity(int(d.file.Fd()), rotationLockName(o.name), o.file); err != nil {
				return err
			}
			if o.data != nil {
				return rotationNamedIdentity(int(d.file.Fd()), o.name, o.data)
			}
			var named unix.Stat_t
			err := unix.Fstatat(int(d.file.Fd()), o.name, &named, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil {
				return errors.New("securestore: unowned data inode appeared")
			}
			if !errors.Is(err, unix.ENOENT) {
				return err
			}
			return nil
		}()
		o.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
func (w *RotationWorkspace) usable() error {
	if w.closed {
		return os.ErrClosed
	}
	if w.fault != nil {
		return errors.Join(ErrRotationIOFault, w.fault)
	}
	w.dir.mu.Lock()
	defer w.dir.mu.Unlock()
	return w.checkOwnersLocked()
}
func (w *RotationWorkspace) guard(st *unix.Stat_t) error { return w.guardInput(st, false) }
func (w *RotationWorkspace) guardInput(st *unix.Stat_t, readOnly bool) error {
	id := FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}
	for _, r := range w.cfg.Keyrings {
		if r != nil && r.UsesFile(id) {
			return errors.New("securestore: workspace aliases key")
		}
	}
	if readOnly {
		return nil
	}
	for _, p := range w.cfg.Protected {
		if p == id {
			return errors.New("securestore: workspace aliases protected input")
		}
	}
	return nil
}
func (w *RotationWorkspace) inspect(name string, s RotationStage, unbounded bool) (st *unix.Stat_t, result error) {
	d := w.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil, os.ErrClosed
	}
	f, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	st, err = w.ops.stat(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(name, rotationWorkspacePrefix) && st.Mode&07777 != 0600 {
		return nil, errors.New("securestore: workspace temporary must have mode 0600")
	}
	if err = w.guardInput(st, unbounded && name != w.cfg.Destination); err != nil {
		return nil, err
	}
	if st.Size < 0 || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || (!unbounded && (st.Size > w.limit(s) || st.Blocks*512 > w.round(s))) {
		return nil, errors.New("securestore: workspace allocation exceeds role")
	}
	return st, nil
}

type workspaceTemp struct {
	name     string
	stage    RotationStage
	identity FileIdentity
}

// inventory validates all recognized objects before cleanup. It neither adopts
// staged bytes nor interprets filenames as committed protocol state.
func (w *RotationWorkspace) inventory() (temps []workspaceTemp, total int64, result error) {
	identities := make(map[FileIdentity]bool)
	names := make(map[string]bool)
	add := func(name string, s RotationStage, count, unbounded bool) (FileIdentity, error) {
		st, err := w.inspect(name, s, unbounded)
		if err != nil {
			return FileIdentity{}, err
		}
		id := FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}
		if identities[id] {
			return id, errors.New("securestore: workspace object alias")
		}
		identities[id] = true
		if count {
			if st.Blocks*512 > w.cfg.MaxWorkingBytes-total {
				return id, errors.New("securestore: workspace allocation exceeds cap")
			}
			total += st.Blocks * 512
		}
		return id, nil
	}
	for s, name := range w.names {
		if names[name] {
			continue
		}
		names[name] = true
		oldOutput := RotationStage(s) == RotationPublication && w.output == nil
		_, err := add(name, RotationStage(s), !oldOutput, oldOutput)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	for _, o := range w.cfg.Owners {
		if _, err := add(rotationLockName(o.name), RotationBootstrapUninitialized, true, false); err != nil {
			return nil, 0, err
		}
		if !names[o.name] {
			_, err := add(o.name, RotationPublication, false, true)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, 0, err
			}
			names[o.name] = true
		}
	}
	prefix := rotationWorkspacePrefix + w.cfg.Token + "-"
	seen := [rotationStageCount]bool{}
	entries := 0
	err := w.dir.WalkEntries(func(name string) error {
		entries++
		if entries > rotationInventoryMax {
			return errors.New("securestore: workspace inventory limit exceeded")
		}
		if !strings.HasPrefix(name, prefix) {
			return nil
		}
		rest := strings.TrimPrefix(name, prefix)
		s := rotationStageCount
		for i, word := range rotationStageNames {
			if strings.HasPrefix(rest, word+"-") && rotationHex(strings.TrimPrefix(rest, word+"-"), 32) {
				s = RotationStage(i)
				break
			}
		}
		if s == rotationStageCount || seen[s] {
			return errors.New("securestore: invalid or repeated workspace stage")
		}
		seen[s] = true
		id, err := add(name, s, true, false)
		if err != nil {
			return err
		}
		temps = append(temps, workspaceTemp{name, s, id})
		return nil
	})
	return temps, total, err
}
func (w *RotationWorkspace) AllocatedBytes() (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.usable(); err != nil {
		return 0, err
	}
	_, n, err := w.inventory()
	return n, err
}

// Reserve creates and physically allocates every remaining stage before setting
// Ready. Failure retains bounded attributed leftovers and latches this attempt.
func (w *RotationWorkspace) Reserve() (result error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if result != nil {
			w.fault = result
		}
	}()
	if err := w.usable(); err != nil {
		return err
	}
	if w.reserved {
		return errors.New("securestore: workspace cannot refill")
	}
	temps, n, err := w.inventory()
	if err != nil {
		return err
	}
	if len(temps) != 0 {
		return errors.New("securestore: recover unselected stages before reserving")
	}
	if w.pool > w.cfg.MaxWorkingBytes-n {
		return errors.New("securestore: workspace cap below retained plus remaining pool")
	}
	d := w.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := w.checkOwnersLocked(); err != nil {
		return err
	}
	for _, s := range w.cfg.Stages {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		name := rotationWorkspacePrefix + w.cfg.Token + "-" + rotationStageNames[s] + "-" + hex.EncodeToString(nonce[:])
		fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return contextual("create workspace stage", err)
		}
		f := os.NewFile(uintptr(fd), name)
		w.slots[s].rotationSlot = rotationSlot{name, f}
		if err := w.ops.allocate(f, w.round(s)); err != nil {
			return contextual("allocate workspace stage", err)
		}
		st, err := w.ops.stat(fd)
		if err != nil {
			return err
		}
		if st.Size != 0 || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || st.Blocks*512 != w.round(s) {
			return errors.New("securestore: exact workspace allocation unsupported")
		}
		if err := w.guard(st); err != nil {
			return err
		}
		if err := d.ops.sync(f); err != nil {
			return contextual("sync workspace stage", err)
		}
	}
	for _, s := range w.cfg.Stages {
		if err := rotationNamedIdentity(int(d.file.Fd()), w.slots[s].name, w.slots[s].file); err != nil {
			return err
		}
		st, err := w.ops.stat(int(w.slots[s].file.Fd()))
		if err != nil {
			return err
		}
		if st.Size != 0 || st.Blocks*512 != w.round(s) {
			return errors.New("securestore: stage allocation changed before readiness")
		}
	}
	if _, err := w.syncLocked(); err != nil {
		return err
	}
	w.reserved = true
	return nil
}

// SettleOutput rechecks caller-authenticated output identity and ciphertext before
// syncing the directory. It can establish prior Committed even when a later
// reservation fails. It never authenticates a receipt or advances a protocol cut.
func (w *RotationWorkspace) SettleOutput() (result error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if result != nil {
			w.fault = result
		}
	}()
	if err := w.usable(); err != nil {
		return err
	}
	w.dir.mu.Lock()
	defer w.dir.mu.Unlock()
	synced, err := w.syncLocked()
	if err != nil {
		out := Uncertain
		if synced {
			out = Committed
		}
		return &CommitError{Outcome: out, Op: "settle rotation output", Err: err}
	}
	return nil
}
func (w *RotationWorkspace) syncLocked() (synced bool, result error) {
	d := w.dir
	if w.output != nil {
		f, err := openPrivate(int(d.file.Fd()), w.cfg.Destination)
		if err != nil {
			return false, err
		}
		defer func() { result = errors.Join(result, d.ops.close(f)) }()
		st, err := validatePrivate(int(f.Fd()))
		if err != nil {
			return false, err
		}
		p := w.output
		if (FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}) != p.Identity || st.Size != p.Bytes {
			return false, errors.New("securestore: authenticated output changed")
		}
		h := sha256.New()
		if n, err := io.CopyBuffer(h, io.LimitReader(f, p.Bytes+1), make([]byte, 64<<10)); err != nil || n != p.Bytes {
			return false, errors.Join(errors.New("securestore: cannot verify authenticated output"), err)
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		if digest != p.SHA256 {
			return false, errors.New("securestore: authenticated output bytes changed")
		}
		if err := rotationNamedIdentity(int(d.file.Fd()), w.cfg.Destination, f); err != nil {
			return false, err
		}
	}
	if err := d.ops.sync(d.file); err != nil {
		return false, contextual("sync workspace directory", err)
	}
	if w.output != nil {
		w.outcome = Committed
	}
	return true, nil
}

func (w *RotationWorkspace) Create(s RotationStage, data []byte) (Outcome, error) {
	return w.write(s, data, true)
}
func (w *RotationWorkspace) Replace(s RotationStage, data []byte) (Outcome, error) {
	return w.write(s, data, false)
}
func (w *RotationWorkspace) write(s RotationStage, data []byte, create bool) (out Outcome, result error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "publish workspace stage", Err: result}
			w.fault = result
		}
	}()
	if err := w.usable(); err != nil {
		return out, err
	}
	if !w.reserved || s >= rotationStageCount || !w.slots[s].selected || w.slots[s].consumed || w.slots[s].file == nil || int64(len(data)) > w.limit(s) || len(data) == 0 {
		return out, errors.New("securestore: invalid or unready workspace stage")
	}
	if (s == RotationCandidateStage || s == RotationUsageZero || s >= RotationPredecessorBootstrapStage) && !create {
		return out, errors.New("securestore: stage requires exclusive creation")
	}
	if _, _, err := w.inventory(); err != nil {
		return out, err
	}
	d := w.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := w.checkOwnersLocked(); err != nil {
		return out, err
	}
	slot := &w.slots[s]
	f := slot.file
	fd := int(d.file.Fd())
	if err := rotationNamedIdentity(fd, slot.name, f); err != nil {
		return out, err
	}
	before, err := w.ops.stat(int(f.Fd()))
	if err != nil {
		return out, err
	}
	if before.Size != 0 || before.Blocks < 0 || before.Blocks > math.MaxInt64/512 || before.Blocks*512 != w.round(s) {
		return out, errors.New("securestore: reserved stage changed before write")
	}
	var pending *os.File
	owner := d.locks[w.names[s]]
	if owner != nil {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		dup, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return out, err
		}
		pending = os.NewFile(uintptr(dup), w.names[s])
		defer func() {
			if pending != nil {
				result = errors.Join(result, pending.Close())
			}
		}()
		if err := unix.Flock(dup, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return out, err
		}
	}
	slot.consumed = true
	for remaining := data; len(remaining) > 0; {
		n, err := d.ops.write(f, remaining)
		if n < 0 || n > len(remaining) {
			return out, errors.New("securestore: invalid workspace write count")
		}
		remaining = remaining[n:]
		if err != nil {
			return out, err
		}
		if n == 0 {
			return out, io.ErrShortWrite
		}
	}
	if err := d.ops.sync(f); err != nil {
		return out, err
	}
	st, err := w.ops.stat(int(f.Fd()))
	if err != nil {
		return out, err
	}
	if st.Size != int64(len(data)) || st.Blocks*512 != w.round(s) {
		return out, errors.New("securestore: workspace allocation changed during write")
	}
	if err := rotationNamedIdentity(fd, slot.name, f); err != nil {
		return out, err
	}
	err = d.ops.close(f)
	slot.file = nil
	if err != nil {
		return out, err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(fd, slot.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return out, err
	}
	if named.Dev != st.Dev || named.Ino != st.Ino {
		return out, errors.New("securestore: workspace stage changed before publication")
	}
	var publicationErr error
	if create {
		published, remaining, err := d.ops.noReplace(fd, slot.name, fd, w.names[s])
		publicationErr = err
		if !published {
			return out, errors.Join(errors.New("securestore: workspace stage not published"), err)
		}
		if remaining {
			publicationErr = errors.Join(publicationErr, errors.New("securestore: atomic no-replace required"))
		} else {
			slot.name = ""
		}
	} else {
		if err := d.ops.rename(fd, slot.name, fd, w.names[s]); err != nil {
			return out, err
		}
		slot.name = ""
	}
	out = Uncertain
	if s == RotationPublication {
		w.output = &RotationOutputProof{Identity: FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}, Bytes: int64(len(data)), SHA256: sha256.Sum256(data)}
		if w.outcome != Committed {
			w.outcome = Uncertain
		}
	}
	if owner != nil {
		old := owner.data
		owner.data, pending = pending, nil
		if old != nil {
			result = errors.Join(result, old.Close())
		}
	}
	if publicationErr != nil {
		return out, errors.Join(result, publicationErr)
	}
	synced, err := w.syncLocked()
	if synced {
		out = Committed
	}
	return out, errors.Join(result, err)
}

// RecoverUnselected requires renewed authentication of this exact operation. It
// removes only valid token-attributed stage files; selected canonical files,
// generic temporaries, other tokens and usage history are untouched. Any failure
// latches the handle. Successful parent sync may settle a prior output.
func (w *RotationWorkspace) RecoverUnselected() (out Outcome, result error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "recover unselected workspace", Err: result}
			w.fault = result
		}
	}()
	if err := w.usable(); err != nil {
		return out, err
	}
	if w.reserved {
		return out, errors.New("securestore: ready workspace cannot recover/refill")
	}
	temps, _, err := w.inventory()
	if err != nil {
		return out, err
	}
	d := w.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := w.checkOwnersLocked(); err != nil {
		return out, err
	}
	for _, temp := range temps {
		var st unix.Stat_t
		if err := unix.Fstatat(int(d.file.Fd()), temp.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return out, err
		}
		if temp.identity != (FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}) {
			return out, errors.New("securestore: unselected stage changed")
		}
		if err := d.ops.unlink(int(d.file.Fd()), temp.name, 0); err != nil {
			return out, err
		}
		out = Uncertain
	}
	synced, err := w.syncLocked()
	if synced {
		out = Committed
	}
	return out, err
}
func (w *RotationWorkspace) Close() (result error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	if w.usageOpen {
		return errors.New("securestore: close workspace usage first")
	}
	w.closed = true
	for s := range w.slots {
		if f := w.slots[s].file; f != nil {
			result = errors.Join(result, f.Close())
			w.slots[s].file = nil
		}
	}
	for _, o := range w.cfg.Owners {
		o.mu.Lock()
		o.rotationIOActive = false
		o.mu.Unlock()
	}
	return result
}
