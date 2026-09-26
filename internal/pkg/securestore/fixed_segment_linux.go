//go:build linux

package securestore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	FixedSegmentBytes        = 32 << 20
	FixedSegmentBlock        = 4096
	FixedSegmentDataStart    = 3 * FixedSegmentBlock
	FixedSegmentMaxAppend    = 2 << 20
	fixedSegmentMaxAllocated = 64 << 20
)

var ErrFixedDirtyTail = errors.New("securestore: fixed segment has unselected tail")

type fixedSegmentOps struct {
	writeAt  func(*os.File, []byte, int64) (int, error)
	allocate func(*os.File, int64) error
	dataSync func(*os.File) error
}

func defaultFixedSegmentOps() fixedSegmentOps {
	return fixedSegmentOps{
		writeAt:  (*os.File).WriteAt,
		allocate: func(f *os.File, n int64) error { return unix.Fallocate(int(f.Fd()), 0, 0, n) },
		dataSync: func(f *os.File) error { return unix.Fdatasync(int(f.Fd())) },
	}
}

// InitializeFixedSegment creates a fully allocated and physically zero-written
// fixed-size inode, then installs the caller's already encrypted bootstrap bytes.
// The caller must prove fresh-store initialization, own name through this Dir,
// and make all nonce reservations durable before supplying bootstrap. Failed
// initialization preserves its distinct, nonreserved staged name for inspection.
func (d *Dir) InitializeFixedSegment(stage, name string, bootstrap []byte) (Outcome, error) {
	return d.initializeFixedSegment(stage, name, bootstrap, defaultFixedSegmentOps())
}
func (d *Dir) initializeFixedSegment(stage, name string, bootstrap []byte, ops fixedSegmentOps) (out Outcome, resultErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &CommitError{Outcome: out, Op: "initialize fixed segment", Err: resultErr}
		}
	}()
	if len(bootstrap) != FixedSegmentDataStart {
		return out, errors.New("securestore: fixed bootstrap size invalid")
	}
	for _, n := range []string{stage, name} {
		if err := checkName(n); err != nil {
			return out, err
		}
	}
	if stage == name {
		return out, errors.New("securestore: fixed initialization names alias")
	}
	if d.file == nil {
		return out, os.ErrClosed
	}
	if err := validateDirectory(int(d.file.Fd()), "", true); err != nil {
		return out, err
	}
	if err := fixedSegmentFilesystem(d.file); err != nil {
		return out, err
	}
	owner := d.locks[name]
	if owner == nil {
		return out, errors.New("securestore: fixed initialization requires ownership")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.file == nil || owner.data != nil || owner.fixedSegmentActive || owner.rotationIOActive {
		return out, errors.New("securestore: fixed initialization ownership invalid")
	}
	stable, err := validatePrivate(int(owner.file.Fd()))
	if err != nil {
		return out, err
	}
	fd := int(d.file.Fd())
	var namedStable unix.Stat_t
	if err := unix.Fstatat(fd, owner.file.Name(), &namedStable, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return out, contextual("inspect fixed bootstrap ownership", err)
	}
	if stable.Dev != namedStable.Dev || stable.Ino != namedStable.Ino {
		return out, errors.New("securestore: fixed bootstrap ownership inode changed")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return out, os.ErrExist
	} else if !errors.Is(err, unix.ENOENT) {
		return out, err
	}
	raw, err := unix.Openat(fd, stage, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return out, contextual("create fixed stage", err)
	}
	writer := os.NewFile(uintptr(raw), stage)
	var pending *os.File
	defer func() {
		if writer != nil {
			resultErr = errors.Join(resultErr, contextual("close fixed initializer", d.ops.close(writer)))
		}
		if pending != nil {
			resultErr = errors.Join(resultErr, contextual("close unpublished fixed lock", pending.Close()))
		}
	}()
	if _, err := validatePrivate(raw); err != nil {
		return out, err
	}
	duplicate, err := unix.FcntlInt(uintptr(raw), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	pending = os.NewFile(uintptr(duplicate), stage)
	if err := unix.Flock(duplicate, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return out, err
	}
	if err := ops.allocate(writer, FixedSegmentBytes); err != nil {
		return out, contextual("allocate fixed segment", err)
	}
	zeros := make([]byte, 64<<10)
	for offset := int64(0); offset < FixedSegmentBytes; offset += int64(len(zeros)) {
		if err := fixedWriteAll(ops, writer, zeros, offset); err != nil {
			return out, err
		}
	}
	if err := fixedWriteAll(ops, writer, bootstrap, 0); err != nil {
		return out, err
	}
	if err := d.ops.sync(writer); err != nil {
		return out, contextual("sync fixed bootstrap", err)
	}
	if _, err := fixedSegmentStat(writer); err != nil {
		return out, err
	}
	err = d.ops.close(writer)
	writer = nil
	if err != nil {
		return out, contextual("close synced fixed bootstrap", err)
	}
	actual, err := openPrivate(fd, stage)
	if err != nil {
		return out, err
	}
	a, aerr := fixedSegmentStat(actual)
	b, berr := fixedSegmentStat(pending)
	cerr := actual.Close()
	if err := errors.Join(aerr, berr, cerr); err != nil {
		return out, err
	}
	if a.Dev != b.Dev || a.Ino != b.Ino {
		return out, errors.New("securestore: fixed staged inode changed")
	}
	published, remaining, err := d.ops.noReplace(fd, stage, fd, name)
	if published {
		out = Uncertain
		owner.data = pending
		pending = nil
	}
	if err != nil {
		return out, contextual("publish fixed segment", err)
	}
	if !published || remaining {
		return out, errors.New("securestore: fixed publication incomplete")
	}
	if err := d.ops.sync(d.file); err != nil {
		return out, contextual("sync fixed directory", err)
	}
	return Committed, nil
}

func fixedWriteAll(ops fixedSegmentOps, f *os.File, data []byte, offset int64) error {
	for len(data) > 0 {
		n, err := ops.writeAt(f, data, offset)
		if n < 0 || n > len(data) {
			return errors.New("securestore: invalid fixed write count")
		}
		data = data[n:]
		offset += int64(n)
		if err != nil {
			return contextual("write fixed segment", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func fixedSegmentStat(f *os.File) (*unix.Stat_t, error) {
	st, err := validatePrivate(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	if st.Mode&07777 != 0600 || st.Size != FixedSegmentBytes || st.Blocks < FixedSegmentBytes/512 || st.Blocks > fixedSegmentMaxAllocated/512 {
		return nil, errors.New("securestore: fixed size, mode or allocation invalid")
	}
	return st, nil
}

func fixedSegmentFilesystem(parent *os.File) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(parent.Fd()), &st); err != nil {
		return contextual("inspect fixed filesystem", err)
	}
	if st.Bsize != FixedSegmentBlock {
		return errors.New("securestore: fixed filesystem block size unsupported")
	}
	return nil
}

// FixedSegment permits only bounded append-plus-alternate-head transactions.
// Open is read-only in effect until Activate is called after owner authentication
// of BOTH head slots and the selected data prefix. Activate also independently
// refuses every dirty tail. Neither Open nor Activate repairs or erases bytes.
// The Dir's stable/data Lock remains caller-owned and must outlive this handle.
type FixedSegment struct {
	mu        sync.Mutex
	dir       *Dir
	owner     *Lock
	file      *os.File
	name      string
	parentDev uint64
	parentIno uint64
	allocated int64
	cursor    int64
	active    uint8
	armed     bool
	fault     error
	ops       fixedSegmentOps
}

func (d *Dir) OpenFixedSegment(name string) (_ *FixedSegment, resultErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkName(name); err != nil {
		return nil, err
	}
	if d.file == nil {
		return nil, os.ErrClosed
	}
	if err := fixedSegmentFilesystem(d.file); err != nil {
		return nil, err
	}
	owner := d.locks[name]
	if owner == nil {
		return nil, errors.New("securestore: fixed open requires ownership")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.file == nil || owner.data == nil || owner.fixedSegmentActive || owner.rotationIOActive {
		return nil, errors.New("securestore: fixed open ownership invalid")
	}
	raw, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, contextual("open fixed inode", err)
	}
	f := os.NewFile(uintptr(raw), name)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, contextual("close rejected fixed inode", f.Close()))
		}
	}()
	st, err := fixedSegmentStat(f)
	if err != nil {
		return nil, err
	}
	var parent unix.Stat_t
	if err := unix.Fstat(int(d.file.Fd()), &parent); err != nil {
		return nil, err
	}
	s := &FixedSegment{dir: d, owner: owner, file: f, name: name, parentDev: uint64(parent.Dev), parentIno: parent.Ino, allocated: st.Blocks * 512, ops: defaultFixedSegmentOps()}
	if err := s.validateLocked(); err != nil {
		return nil, err
	}
	owner.fixedSegmentActive = true
	return s, nil
}

// validateLocked requires dir.mu, segment.mu (unless unpublished), and owner.mu.
func (s *FixedSegment) validateLocked() error {
	if s.file == nil || s.dir.file == nil || s.owner.file == nil || s.owner.data == nil || s.dir.locks[s.name] != s.owner {
		return os.ErrClosed
	}
	if err := validateDirectory(int(s.dir.file.Fd()), "", true); err != nil {
		return err
	}
	var parent unix.Stat_t
	if err := unix.Fstat(int(s.dir.file.Fd()), &parent); err != nil {
		return err
	}
	if uint64(parent.Dev) != s.parentDev || parent.Ino != s.parentIno {
		return errors.New("securestore: fixed parent descriptor changed")
	}
	stable, err := validatePrivate(int(s.owner.file.Fd()))
	if err != nil {
		return err
	}
	var namedStable unix.Stat_t
	if err := unix.Fstatat(int(s.dir.file.Fd()), s.owner.file.Name(), &namedStable, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return contextual("inspect fixed ownership name", err)
	}
	if stable.Dev != namedStable.Dev || stable.Ino != namedStable.Ino {
		return errors.New("securestore: fixed ownership inode changed")
	}
	st, err := fixedSegmentStat(s.file)
	if err != nil {
		return err
	}
	locked, err := fixedSegmentStat(s.owner.data)
	if err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(s.dir.file.Fd()), s.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return contextual("inspect fixed name", err)
	}
	if st.Dev != locked.Dev || st.Ino != locked.Ino || st.Dev != named.Dev || st.Ino != named.Ino || st.Blocks*512 != s.allocated {
		return errors.New("securestore: fixed descriptor identity or allocation changed")
	}
	return nil
}
func (s *FixedSegment) lock()   { s.dir.mu.Lock(); s.mu.Lock(); s.owner.mu.Lock() }
func (s *FixedSegment) unlock() { s.owner.mu.Unlock(); s.mu.Unlock(); s.dir.mu.Unlock() }
func (s *FixedSegment) ReadAt(dst []byte, offset int64) error {
	s.lock()
	defer s.unlock()
	if offset < 0 || offset > FixedSegmentBytes || int64(len(dst)) > FixedSegmentBytes-offset {
		return errors.New("securestore: fixed read bounds")
	}
	if err := s.validateLocked(); err != nil {
		return err
	}
	n, err := s.file.ReadAt(dst, offset)
	if err != nil {
		return contextual("read fixed segment", err)
	}
	if n != len(dst) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (s *FixedSegment) AllocatedBytes() int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.allocated }

// Activate is called exactly once after the owner's authenticated recovery.
// cursor/active are trusted owner results, not values supplied by a file header.
func (s *FixedSegment) Activate(cursor int64, active uint8) (resultErr error) {
	s.lock()
	defer s.unlock()
	defer func() {
		if resultErr != nil {
			s.fault = resultErr
		}
	}()
	if s.fault != nil {
		return s.fault
	}
	if s.armed || cursor < FixedSegmentDataStart || cursor > FixedSegmentBytes || cursor%FixedSegmentBlock != 0 || active > 1 {
		return errors.New("securestore: fixed activation invalid")
	}
	if err := s.validateLocked(); err != nil {
		return err
	}
	buffer := make([]byte, 64<<10)
	zeros := make([]byte, len(buffer))
	for offset := cursor; offset < FixedSegmentBytes; {
		n := min(int64(len(buffer)), FixedSegmentBytes-offset)
		if _, err := s.file.ReadAt(buffer[:n], offset); err != nil {
			return contextual("read fixed activation tail", err)
		}
		if !bytes.Equal(buffer[:n], zeros[:n]) {
			return ErrFixedDirtyTail
		}
		offset += n
	}
	s.cursor, s.active, s.armed = cursor, active, true
	return nil
}

// Commit appends already encrypted, block-padded data and replaces the inactive
// full head slot, then fdatasyncs both together. Any error permanently poisons
// this handle. Failed data-only writes are NotCommitted; once any head write is
// attempted the result is Uncertain until successful fdatasync. No rollback,
// retry, truncation, tail repair or callback is performed by this primitive.
func (s *FixedSegment) Commit(data, head []byte) (out Outcome, resultErr error) {
	s.lock()
	defer s.unlock()
	out = NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &CommitError{Outcome: out, Op: "commit fixed segment", Err: resultErr}
			s.fault = resultErr
		}
	}()
	if s.fault != nil {
		return out, s.fault
	}
	if !s.armed || len(data) == 0 || len(data) > FixedSegmentMaxAppend || len(data)%FixedSegmentBlock != 0 || len(head) != FixedSegmentBlock || int64(len(data)) > FixedSegmentBytes-s.cursor {
		return out, errors.New("securestore: fixed transaction bounds")
	}
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	if err := fixedWriteAll(s.ops, s.file, data, s.cursor); err != nil {
		return out, err
	}
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	next := s.active ^ 1
	out = Uncertain
	if err := fixedWriteAll(s.ops, s.file, head, int64(next+1)*FixedSegmentBlock); err != nil {
		return out, err
	}
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	if err := s.ops.dataSync(s.file); err != nil {
		return out, contextual("sync fixed transaction data", err)
	}
	out = Committed
	s.cursor += int64(len(data))
	s.active = next
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	return out, nil
}
func (s *FixedSegment) Close() error {
	s.lock()
	defer s.unlock()
	if s.file == nil {
		return nil
	}
	err := s.dir.ops.close(s.file)
	s.file = nil
	s.owner.fixedSegmentActive = false
	if err != nil {
		s.fault = err
	}
	return contextual("close fixed segment", err)
}
