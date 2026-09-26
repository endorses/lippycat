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

const (
	rotationMetadataBytes = 16 << 10
	rotationInventoryMax  = 4096
	rotationTempPrefix    = ".securestore-rotation-"
)

var ErrRotationIOFault = errors.New("securestore: rotation I/O faulted; reopen and reconcile")

// RotationRole is a bounded workspace slot, not a caller-controlled pathname.
type RotationRole uint8

const (
	RotationBootstrap RotationRole = iota
	RotationProgress
	RotationUsage
	RotationPredecessorBootstrap
	RotationPredecessorProgress
	RotationCandidate
	RotationDestination
	rotationRoleCount
)

var rotationRoleNames = [...]string{"bootstrap", "progress", "usage", "prev-bootstrap", "prev-progress", "candidate", "destination"}

// RotationIOConfig is supplied only after authenticating the complete offline
// request. Token is its opaque, domain-separated keyed commitment (64 lowercase
// hex digits); possession of a string alone is NOT authorization to recover it.
// The caller retains source/destination ownership and all authenticated keyrings.
type RotationIOConfig struct {
	Token               string
	Purpose             Purpose
	Destination         string
	UsageName           string
	EnvelopeBytes       int64
	MaxWorkingBytes     int64
	DestinationIsOutput bool // authenticated resume proved this is already the new output
	Keyrings            []*Keyring
	Protected           []FileIdentity // additional inputs which writes/recovery cannot alias
}

type rotationIOOps struct {
	allocate func(*os.File, int64) error
	stat     func(int) (*unix.Stat_t, error)
}

func defaultRotationIOOps() rotationIOOps {
	return rotationIOOps{
		allocate: func(f *os.File, n int64) error { return unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, 0, n) },
		stat:     validatePrivate,
	}
}

type rotationSlot struct {
	name string
	file *os.File
}

// RotationIO supplies attributed, preallocated durable I/O, not a rotation
// protocol. It does not authenticate snapshots/bootstrap, initialize identity,
// select keys, or infer whether a pending operation may be resumed.
// Close releases descriptors but leaves owned temporary files for explicit
// recovery. Close this object before releasing the destination ownership lock.
type RotationIO struct {
	mu        sync.Mutex
	dir       *Dir
	config    RotationIOConfig
	names     [rotationRoleCount]string
	slots     [rotationRoleCount]rotationSlot
	unit      int64
	required  int64
	owner     *Lock
	ops       rotationIOOps
	published bool
	fault     error
	closed    bool
}

// OpenRotationIO validates the fixed layout without writing files. The caller
// must hold Destination through the same Dir. Recovery is explicit; PrepareAll
// allocates every next-write slot before the coordinator's first GCM seal.
func OpenRotationIO(dir *Dir, cfg RotationIOConfig) (*RotationIO, error) {
	if dir == nil || !rotationHex(cfg.Token, 64) || cfg.Token == strings.Repeat("0", 64) ||
		(cfg.Purpose != FilterSnapshot && cfg.Purpose != AdministrativeState) ||
		cfg.EnvelopeBytes <= 0 || cfg.EnvelopeBytes > MaxEnvelopeBytes || cfg.MaxWorkingBytes <= 0 {
		return nil, errors.New("securestore: invalid rotation workspace configuration")
	}
	if err := checkName(cfg.Destination); err != nil {
		return nil, err
	}
	if strings.HasPrefix(cfg.Destination, ".rotation-") || strings.HasPrefix(cfg.Destination, ".usage-") ||
		!strings.HasPrefix(cfg.UsageName, ".usage-") || !rotationHex(strings.TrimPrefix(cfg.UsageName, ".usage-"), 64) {
		return nil, errors.New("securestore: invalid rotation target role")
	}
	unit, err := dir.AllocationUnit()
	if err != nil {
		return nil, err
	}
	if unit > math.MaxInt64/16 || cfg.EnvelopeBytes > math.MaxInt64-unit || rotationMetadataBytes > math.MaxInt64-unit {
		return nil, errors.New("securestore: rotation allocation overflow")
	}
	round := func(n int64) int64 { return (n + unit - 1) / unit * unit }
	data, metadata := round(cfg.EnvelopeBytes), round(rotationMetadataBytes)
	if data > (math.MaxInt64-12*metadata)/2 {
		return nil, errors.New("securestore: rotation allocation overflow")
	}
	required := 2*data + 12*metadata
	if cfg.MaxWorkingBytes < required {
		return nil, errors.New("securestore: rotation working byte cap is too small")
	}
	if len(cfg.Keyrings) > 2 || len(cfg.Protected) > 16 {
		return nil, errors.New("securestore: too many rotation identity guards")
	}
	cfg.Keyrings = append([]*Keyring(nil), cfg.Keyrings...)
	cfg.Protected = append([]FileIdentity(nil), cfg.Protected...)
	r := &RotationIO{dir: dir, config: cfg, unit: unit, required: required, ops: defaultRotationIOOps(), published: cfg.DestinationIsOutput}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", cfg.Purpose, cfg.Destination)))
	for role := RotationRole(0); role < rotationRoleCount; role++ {
		r.names[role] = ".rotation-" + rotationRoleNames[role] + "-" + hex.EncodeToString(digest[:])
	}
	r.names[RotationUsage], r.names[RotationDestination] = cfg.UsageName, cfg.Destination
	dir.mu.Lock()
	r.owner = dir.locks[cfg.Destination]
	if r.owner == nil {
		dir.mu.Unlock()
		return nil, errors.New("securestore: rotation requires retained destination ownership")
	}
	r.owner.mu.Lock()
	if r.owner.file == nil || r.owner.rotationIOActive || r.owner.fixedSegmentActive {
		r.owner.mu.Unlock()
		dir.mu.Unlock()
		return nil, ErrLocked
	}
	r.owner.rotationIOActive = true
	r.owner.mu.Unlock()
	dir.mu.Unlock()
	if err := r.checkOwner(); err != nil {
		r.releaseOwner()
		return nil, err
	}
	if _, _, err := r.inventory(); err != nil {
		r.releaseOwner()
		return nil, err
	}
	return r, nil
}

func rotationHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r *RotationIO) Name(role RotationRole) (string, error) {
	if role >= rotationRoleCount {
		return "", errors.New("securestore: invalid rotation role")
	}
	return r.names[role], nil
}

// RequiredBytes includes two envelope slots, two slots for each of five metadata
// roles, and two metadata units for stable ownership/inspection overhead.
func (r *RotationIO) RequiredBytes() int64 { return r.required }

func (r *RotationIO) limit(role RotationRole) int64 {
	if role >= RotationCandidate {
		return r.config.EnvelopeBytes
	}
	return rotationMetadataBytes
}

func (r *RotationIO) rounded(role RotationRole) int64 {
	return (r.limit(role) + r.unit - 1) / r.unit * r.unit
}

func (r *RotationIO) checkOwner() error {
	d := r.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	return r.checkOwnerLocked()
}

func (r *RotationIO) checkOwnerLocked() error {
	d := r.dir
	if d.file == nil {
		return os.ErrClosed
	}
	if r.owner == nil || d.locks[r.config.Destination] != r.owner {
		return errors.New("securestore: rotation requires retained destination ownership")
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if r.owner.file == nil || !r.owner.rotationIOActive {
		return errors.New("securestore: rotation requires retained destination ownership")
	}
	if err := rotationNamedIdentity(int(d.file.Fd()), rotationLockName(r.config.Destination), r.owner.file); err != nil {
		return err
	}
	if r.owner.data != nil {
		if err := rotationNamedIdentity(int(d.file.Fd()), r.config.Destination, r.owner.data); err != nil {
			return err
		}
	}
	return validateDirectory(int(d.file.Fd()), "", true)
}

func rotationLockName(name string) string {
	digest := sha256.Sum256([]byte(name))
	return ".securestore-lock-" + hex.EncodeToString(digest[:])
}

func rotationNamedIdentity(dirFD int, name string, file *os.File) error {
	opened, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return contextual("inspect rotation ownership name", err)
	}
	if named.Dev != opened.Dev || named.Ino != opened.Ino {
		return errors.New("securestore: rotation ownership inode changed")
	}
	return nil
}

func (r *RotationIO) releaseOwner() {
	r.owner.mu.Lock()
	r.owner.rotationIOActive = false
	r.owner.mu.Unlock()
}

func (r *RotationIO) ready() error {
	if r.closed {
		return os.ErrClosed
	}
	if r.fault != nil {
		return errors.Join(ErrRotationIOFault, r.fault)
	}
	return r.checkOwner()
}

func (r *RotationIO) guard(st *unix.Stat_t) error {
	id := FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}
	for _, ring := range r.config.Keyrings {
		if ring != nil && ring.UsesFile(id) {
			return errors.New("securestore: rotation object aliases key material")
		}
	}
	for _, protected := range r.config.Protected {
		if protected == id {
			return errors.New("securestore: rotation object aliases protected input")
		}
	}
	return nil
}

func (r *RotationIO) inspect(name string, role RotationRole) (_ *unix.Stat_t, result error) {
	d := r.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil, os.ErrClosed
	}
	f, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, contextual("close rotation inspection", f.Close())) }()
	st, err := r.ops.stat(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	if err := r.guard(st); err != nil {
		return nil, err
	}
	oldDestination := role == RotationDestination && name == r.names[role] && !r.published
	if st.Size < 0 || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 ||
		(!oldDestination && (st.Size > r.limit(role) || st.Blocks*512 > r.rounded(role))) {
		return nil, errors.New("securestore: rotation object exceeds its allocation slot")
	}
	if strings.HasPrefix(name, rotationTempPrefix) && st.Mode&07777 != 0600 {
		return nil, errors.New("securestore: rotation temporary must have mode 0600")
	}
	return st, nil
}

type rotationTemp struct {
	name string
	role RotationRole
}

// inventory checks the complete recognized set before recovery can remove any
// file. Generic temporaries and other operation tokens are never claimed.
func (r *RotationIO) inventory() (temps []rotationTemp, allocated int64, result error) {
	identities := make(map[FileIdentity]struct{}, int(rotationRoleCount)*2)
	var present [rotationRoleCount]bool
	add := func(name string, role RotationRole, count bool) error {
		st, err := r.inspect(name, role)
		if err != nil {
			return err
		}
		id := FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}
		if _, exists := identities[id]; exists {
			return errors.New("securestore: rotation role aliases another object")
		}
		identities[id] = struct{}{}
		if count {
			allocated += st.Blocks * 512
		}
		return nil
	}
	for role := RotationRole(0); role < rotationRoleCount; role++ {
		err := add(r.names[role], role, role != RotationDestination || r.published)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		present[role] = true
	}
	for _, name := range []string{r.names[RotationDestination], r.names[RotationUsage]} {
		lockName := rotationLockName(name)
		if err := add(lockName, RotationBootstrap, true); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	prefix := rotationTempPrefix + r.config.Token + "-"
	seen := [rotationRoleCount]bool{}
	entries := 0
	err := r.dir.WalkEntries(func(name string) error {
		entries++
		if entries > rotationInventoryMax {
			return errors.New("securestore: rotation inventory limit exceeded")
		}
		if !strings.HasPrefix(name, prefix) {
			return nil
		}
		rest := strings.TrimPrefix(name, prefix)
		role := rotationRoleCount
		for i, word := range rotationRoleNames {
			if strings.HasPrefix(rest, word+"-") && rotationHex(strings.TrimPrefix(rest, word+"-"), 32) {
				role = RotationRole(i)
				break
			}
		}
		if role == rotationRoleCount || seen[role] {
			return errors.New("securestore: invalid or repeated rotation temporary role")
		}
		if role >= RotationCandidate && present[role] && (role != RotationDestination || r.published) {
			return errors.New("securestore: rotation envelope role has two allocations")
		}
		seen[role] = true
		if err := add(name, role, true); err != nil {
			return err
		}
		temps = append(temps, rotationTemp{name: name, role: role})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if allocated > r.config.MaxWorkingBytes || allocated > r.required {
		return nil, 0, errors.New("securestore: rotation working allocation exceeds cap")
	}
	return temps, allocated, nil
}

// AllocatedBytes reports actual blocks for recognized live output/metadata and
// attributed temporaries. It excludes the old destination and old usage history.
func (r *RotationIO) AllocatedBytes() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return 0, err
	}
	_, n, err := r.inventory()
	return n, err
}

// PrepareAll preallocates a next-write inode for each absent envelope role and
// each metadata role. A later metadata write consumes its inode; Prepare or the
// usage writer allocates the next one before writing. Future allocation may fail.
func (r *RotationIO) PrepareAll() (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			r.fault = result
		}
	}()
	for role := RotationRole(0); role < rotationRoleCount; role++ {
		if role >= RotationCandidate {
			if _, err := r.inspect(r.names[role], role); err == nil && (role != RotationDestination || r.published) {
				continue
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := r.prepare(role); err != nil {
			return err
		}
	}
	return nil
}

func (r *RotationIO) Prepare(role RotationRole) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			r.fault = result
		}
	}()
	return r.prepare(role)
}

func (r *RotationIO) prepare(role RotationRole) (result error) {
	if role >= rotationRoleCount {
		return errors.New("securestore: invalid rotation role")
	}
	if r.slots[role].file != nil {
		return nil
	}
	temps, _, err := r.inventory()
	if err != nil {
		return err
	}
	for _, temp := range temps {
		if temp.role == role {
			return errors.New("securestore: recover interrupted rotation temporary before preparing")
		}
	}
	if role >= RotationCandidate {
		if _, err := r.inspect(r.names[role], role); err == nil && (role != RotationDestination || r.published) {
			return os.ErrExist
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return contextual("generate rotation temporary name", err)
	}
	name := rotationTempPrefix + r.config.Token + "-" + rotationRoleNames[role] + "-" + hex.EncodeToString(nonce[:])
	d := r.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.checkOwnerLocked(); err != nil {
		return err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return contextual("create rotation reservation", err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() {
		if result != nil {
			result = errors.Join(result, contextual("close rejected rotation reservation", d.ops.close(f)),
				contextual("remove rejected rotation reservation", d.ops.unlink(int(d.file.Fd()), name, 0)),
				contextual("sync rejected rotation reservation", d.ops.sync(d.file)))
		}
	}()
	if _, err := validatePrivate(fd); err != nil {
		return err
	}
	if err := r.ops.allocate(f, r.rounded(role)); err != nil {
		return contextual("preallocate rotation slot", err)
	}
	st, err := r.ops.stat(fd)
	if err != nil {
		return err
	}
	if st.Size != 0 || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || st.Blocks*512 != r.rounded(role) {
		return errors.New("securestore: filesystem did not retain exact rotation allocation")
	}
	if err := errors.Join(contextual("sync rotation reservation", d.ops.sync(f)), contextual("sync rotation reservation directory", d.ops.sync(d.file))); err != nil {
		return err
	}
	r.slots[role] = rotationSlot{name: name, file: f}
	return nil
}

// Create/Replace accept already encrypted or authenticated metadata bytes. The
// caller must have prepared the role before sealing sensitive data. Only the
// usage adapter prepares automatically, before the Writer is allowed to seal.
func (r *RotationIO) Create(role RotationRole, data []byte) (Outcome, error) {
	return r.write(role, data, true)
}

func (r *RotationIO) Replace(role RotationRole, data []byte) (Outcome, error) {
	return r.write(role, data, false)
}

func (r *RotationIO) write(role RotationRole, data []byte, create bool) (out Outcome, result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "publish rotation role", Err: result}
			r.fault = result
		}
	}()
	if err := r.ready(); err != nil {
		return out, err
	}
	if role >= rotationRoleCount || int64(len(data)) > r.limit(role) || r.slots[role].file == nil ||
		(role == RotationCandidate && !create) || (role == RotationDestination && r.published) {
		return out, errors.New("securestore: invalid or unprepared rotation write")
	}
	if _, _, err := r.inventory(); err != nil {
		return out, err
	}
	d := r.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.checkOwnerLocked(); err != nil {
		return out, err
	}
	fd := int(d.file.Fd())
	slot := &r.slots[role]
	f := slot.file
	opened, err := validatePrivate(int(f.Fd()))
	if err != nil {
		return out, err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(fd, slot.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return out, err
	}
	if named.Dev != opened.Dev || named.Ino != opened.Ino {
		return out, errors.New("securestore: rotation temporary identity changed")
	}
	owner := d.locks[r.names[role]]
	var pending *os.File
	if owner != nil {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		if owner.file == nil {
			return out, errors.New("securestore: rotation role ownership was released")
		}
		if err := rotationNamedIdentity(fd, rotationLockName(r.names[role]), owner.file); err != nil {
			return out, err
		}
		if owner.data != nil {
			if err := rotationNamedIdentity(fd, r.names[role], owner.data); err != nil {
				return out, err
			}
		}
		duplicate, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return out, err
		}
		pending = os.NewFile(uintptr(duplicate), r.names[role])
		defer func() {
			if pending != nil {
				result = errors.Join(result, contextual("close unpublished rotation lock", pending.Close()))
			}
		}()
		if err := unix.Flock(duplicate, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return out, err
		}
	}
	for remaining := data; len(remaining) > 0; {
		n, err := d.ops.write(f, remaining)
		if n < 0 || n > len(remaining) {
			return out, errors.New("securestore: invalid rotation write count")
		}
		remaining = remaining[n:]
		if err != nil {
			return out, contextual("write rotation role", err)
		}
		if n == 0 {
			return out, io.ErrShortWrite
		}
	}
	if err := d.ops.sync(f); err != nil {
		return out, contextual("sync rotation role", err)
	}
	st, err := r.ops.stat(int(f.Fd()))
	if err != nil {
		return out, err
	}
	if st.Size != int64(len(data)) || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || st.Blocks*512 != r.rounded(role) {
		return out, errors.New("securestore: rotation allocation changed while writing")
	}
	if err := r.guard(st); err != nil {
		return out, err
	}
	err = d.ops.close(f)
	slot.file = nil
	if err != nil {
		return out, contextual("close rotation role", err)
	}
	if err := unix.Fstatat(fd, slot.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return out, err
	}
	if named.Dev != st.Dev || named.Ino != st.Ino {
		return out, errors.New("securestore: rotation temporary identity changed before publication")
	}
	var publicationErr error
	remaining := false
	if create {
		var published bool
		published, remaining, publicationErr = d.ops.noReplace(fd, slot.name, fd, r.names[role])
		if !published {
			return out, errors.Join(contextual("create rotation role", publicationErr), errors.New("securestore: rotation role was not published"))
		}
		out = Uncertain
		if remaining {
			publicationErr = errors.Join(publicationErr, errors.New("securestore: rotation requires atomic no-replace publication"))
		}
	} else {
		if err := d.ops.rename(fd, slot.name, fd, r.names[role]); err != nil {
			return out, contextual("replace rotation role", err)
		}
		out = Uncertain
	}
	if !remaining {
		slot.name = ""
	}
	if role == RotationDestination {
		r.published = true
	}
	if owner != nil {
		old := owner.data
		owner.data, pending = pending, nil
		if old != nil {
			result = errors.Join(result, contextual("close previous rotation inode lock", old.Close()))
		}
	}
	if publicationErr != nil {
		return out, errors.Join(result, contextual("create rotation role", publicationErr))
	}
	if err := d.ops.sync(d.file); err != nil {
		return out, errors.Join(result, contextual("sync rotation publication directory", err))
	}
	return Committed, result
}

// Recover removes only this authenticated token's attributed temporary roles.
// It validates the entire bounded set and aliases first. It does not remove any
// published role, historical ledger, generic temporary, or other token's file.
func (r *RotationIO) Recover() (out Outcome, result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "recover rotation workspace", Err: result}
			r.fault = result
		}
	}()
	if err := r.ready(); err != nil {
		return out, err
	}
	temps, _, err := r.inventory()
	if err != nil {
		return out, err
	}
	d := r.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.checkOwnerLocked(); err != nil {
		return out, err
	}
	for role := range r.slots {
		if r.slots[role].file != nil {
			err := d.ops.close(r.slots[role].file)
			r.slots[role].file = nil
			if err != nil {
				return out, contextual("close rotation reservation before recovery", err)
			}
		}
	}
	for _, temp := range temps {
		if err := d.ops.unlink(int(d.file.Fd()), temp.name, 0); err != nil {
			return out, contextual("remove attributed rotation temporary", err)
		}
		out = Uncertain
		r.slots[temp.role] = rotationSlot{}
	}
	if len(temps) > 0 {
		if err := d.ops.sync(d.file); err != nil {
			return out, contextual("sync rotation temporary recovery", err)
		}
	}
	return Committed, nil
}

func (r *RotationIO) Close() (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	for i := range r.slots {
		if r.slots[i].file != nil {
			result = errors.Join(result, contextual("close rotation reservation", r.slots[i].file.Close()))
			r.slots[i].file = nil
		}
	}
	r.releaseOwner()
	return result
}
