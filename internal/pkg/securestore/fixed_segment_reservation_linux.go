//go:build linux

package securestore

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// FixedSegmentReservation owns a physically allocated, zeroed staged inode.
// Offline callers reserve the entire remaining attempt before their first seal.
// Initialize consumes this inode without creating or allocating another one.
// Close preserves an unpublished stage for authenticated owner recovery.
type FixedSegmentReservation struct {
	mu                      sync.Mutex
	segment                 *FixedSegment
	stageOwner, targetOwner *Lock
	stage, name             string
	allocated               int64
	consumed, closed        bool
}

func (d *Dir) ReserveFixedSegment(stage, name string) (_ *FixedSegmentReservation, result error) {
	for _, value := range []string{stage, name, stage + ".reserve"} {
		if err := checkName(value); err != nil {
			return nil, err
		}
	}
	if stage == name || stage+".reserve" == name {
		return nil, errors.New("securestore: fixed reservation names alias")
	}
	d.mu.Lock()
	target := d.locks[name]
	if d.file == nil || target == nil {
		d.mu.Unlock()
		return nil, errors.New("securestore: fixed reservation requires destination ownership")
	}
	target.mu.Lock()
	valid := target.file != nil && target.data == nil && !target.fixedSegmentActive && !target.rotationIOActive
	target.mu.Unlock()
	d.mu.Unlock()
	if !valid {
		return nil, errors.New("securestore: fixed reservation destination is occupied")
	}
	owner, err := d.Lock(stage)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, owner.Close())
		}
	}()
	out, err := d.InitializeFixedSegment(stage+".reserve", stage, make([]byte, FixedSegmentDataStart))
	if err != nil || out != Committed {
		if err == nil {
			err = errors.New("securestore: fixed reservation allocation was not committed")
		}
		return nil, &CommitError{Outcome: out, Op: "reserve fixed segment", Err: err}
	}
	segment, err := d.OpenFixedSegment(stage)
	if err != nil {
		return nil, err
	}
	return &FixedSegmentReservation{segment: segment, stageOwner: owner, targetOwner: target, stage: stage, name: name, allocated: segment.allocated}, nil
}

// AllocatedBytes is the actual segment inode allocation, including its headers.
// The coordinator separately charges locks, directory metadata and other slots.
func (r *FixedSegmentReservation) AllocatedBytes() int64 { return r.allocated }

func (r *FixedSegmentReservation) Initialize(bootstrap []byte) (out Outcome, result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out = NotCommitted
	if r.closed || r.consumed || r.segment == nil {
		return out, os.ErrClosed
	}
	if len(bootstrap) != FixedSegmentDataStart {
		return out, errors.New("securestore: fixed bootstrap size invalid")
	}
	r.consumed = true
	s := r.segment
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	r.stageOwner.mu.Lock()
	defer r.stageOwner.mu.Unlock()
	r.targetOwner.mu.Lock()
	defer r.targetOwner.mu.Unlock()
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "initialize reserved fixed segment", Err: result}
		}
	}()
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	target := r.targetOwner
	if d.locks[r.name] != target || target.file == nil || target.data != nil || target.fixedSegmentActive || target.rotationIOActive {
		return out, errors.New("securestore: fixed reservation destination ownership changed")
	}
	stable, err := validatePrivate(int(target.file.Fd()))
	if err != nil {
		return out, err
	}
	var named unix.Stat_t
	fd := int(d.file.Fd())
	if err = unix.Fstatat(fd, target.file.Name(), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return out, err
	}
	if named.Dev != stable.Dev || named.Ino != stable.Ino {
		return out, errors.New("securestore: fixed reservation destination lock changed")
	}
	if err = unix.Fstatat(fd, r.name, &named, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return out, os.ErrExist
	} else if !errors.Is(err, unix.ENOENT) {
		return out, err
	}
	if err = fixedWriteAll(s.ops, s.file, bootstrap, 0); err != nil {
		return out, err
	}
	if err = d.ops.sync(s.file); err != nil {
		return out, contextual("sync reserved fixed bootstrap", err)
	}
	if _, err = fixedSegmentStat(s.file); err != nil {
		return out, err
	}
	published, remaining, err := d.ops.noReplace(fd, r.stage, fd, r.name)
	if published {
		out = Uncertain
		target.data = r.stageOwner.data
		r.stageOwner.data = nil
		r.stageOwner.fixedSegmentActive = false
		target.fixedSegmentActive = true
		s.owner = target
		s.name = r.name
	}
	if err != nil {
		return out, contextual("publish reserved fixed segment", err)
	}
	if !published || remaining {
		return out, errors.New("securestore: reserved fixed publication incomplete")
	}
	if err = d.ops.sync(d.file); err != nil {
		return out, contextual("sync reserved fixed directory", err)
	}
	return Committed, nil
}

func (r *FixedSegmentReservation) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return errors.Join(r.segment.Close(), r.stageOwner.Close())
}
