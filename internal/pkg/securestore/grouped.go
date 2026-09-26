package securestore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	MaxGroupedNewBytes  = 2 << 20
	MaxGroupedHeadBytes = (64 << 10) + MaxHeaderBytes + tagBytes
)

// CreateAndReplace publishes one immutable prerequisite and replaces one existing
// authoritative head in this same directory. The caller must hold headName's
// Lock through this Dir, authenticate the expected old head, reserve all pending
// allocations, and supply already encrypted bytes whose usage reservations are
// independently durable. This helper performs no encryption or quota allocation.
//
// Both temporary files are fully written, synced concurrently, and closed before
// prerequisite no-replace publication and head replacement. One final directory
// sync commits both names. Outcome describes the head transaction: NotCommitted
// can leave a complete unreferenced prerequisite requiring owned reconciliation.
// After head replacement, any failure is Uncertain until directory sync succeeds.
// Never acknowledge an object until Committed; the owner must stop on uncertainty.
func (d *Dir) CreateAndReplace(newName string, newData []byte, headName string, headData []byte) (out Outcome, resultErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &CommitError{Outcome: out, Op: "create prerequisite and replace head", Err: resultErr}
		}
	}()
	if err := checkName(newName); err != nil {
		return out, err
	}
	if err := checkName(headName); err != nil {
		return out, err
	}
	if newName == headName || len(newData) == 0 || len(newData) > MaxGroupedNewBytes || len(headData) == 0 || len(headData) > MaxGroupedHeadBytes {
		return out, errors.New("securestore: grouped object names or sizes invalid")
	}
	if d.file == nil {
		return out, os.ErrClosed
	}
	headOwner := d.locks[headName]
	if headOwner == nil {
		return out, errors.New("securestore: grouped head requires active ownership through this directory")
	}
	headOwner.mu.Lock()
	defer headOwner.mu.Unlock()
	if headOwner.file == nil || headOwner.data == nil {
		return out, errors.New("securestore: grouped head must already exist and be owned")
	}
	if _, err := validatePrivate(int(headOwner.file.Fd())); err != nil {
		return out, err
	}
	newOwner := d.locks[newName]
	if newOwner != nil {
		newOwner.mu.Lock()
		defer newOwner.mu.Unlock()
		if newOwner.file == nil || newOwner.data != nil {
			return out, errors.New("securestore: grouped prerequisite ownership invalid")
		}
		if _, err := validatePrivate(int(newOwner.file.Fd())); err != nil {
			return out, err
		}
	}
	fd := int(d.file.Fd())
	var st unix.Stat_t
	if err := unix.Fstatat(fd, newName, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return out, os.ErrExist
	} else if !errors.Is(err, unix.ENOENT) {
		return out, contextual("inspect grouped prerequisite", err)
	}
	old, err := openPrivate(fd, headName)
	if err != nil {
		return out, err
	}
	actual, actualErr := validatePrivate(int(old.Fd()))
	locked, lockedErr := validatePrivate(int(headOwner.data.Fd()))
	closeErr := old.Close()
	if err := errors.Join(actualErr, lockedErr, contextual("close grouped head validation", closeErr)); err != nil {
		return out, err
	}
	if actual.Dev != locked.Dev || actual.Ino != locked.Ino {
		return out, errors.New("securestore: grouped head no longer matches its owned inode")
	}
	if actual.Size <= 0 || actual.Size > MaxGroupedHeadBytes {
		return out, errors.New("securestore: existing grouped head size invalid")
	}
	var files [2]groupedTemporary
	var retiredHead *os.File
	defer func() {
		if retiredHead != nil {
			resultErr = errors.Join(resultErr, contextual("close replaced grouped head inode", d.ops.close(retiredHead)))
		}
		for i := range files {
			file := &files[i]
			if file.pendingLock != nil {
				resultErr = errors.Join(resultErr, contextual("close unpublished grouped inode lock", file.pendingLock.Close()))
			}
			if file.file != nil {
				resultErr = errors.Join(resultErr, contextual("close grouped temporary", d.ops.close(file.file)))
			}
			if file.present {
				resultErr = errors.Join(resultErr, contextual("remove grouped temporary", d.ops.unlink(fd, file.name, 0)))
			}
		}
	}()
	for i, owner := range []*Lock{newOwner, headOwner} {
		if err := files[i].create(fd, owner != nil); err != nil {
			return out, err
		}
	}
	for i, data := range [][]byte{newData, headData} {
		for len(data) > 0 {
			n, err := d.ops.write(files[i].file, data)
			if n < 0 || n > len(data) {
				return out, errors.New("securestore: invalid grouped write count")
			}
			data = data[n:]
			if err != nil {
				return out, contextual("write grouped temporary", err)
			}
			if n == 0 {
				return out, io.ErrShortWrite
			}
		}
	}
	// The two independent file syncs must both finish before any name publication.
	// Neither a failed peer nor caller cancellation permits abandoning a live fd.
	var syncErrors [2]error
	var syncing sync.WaitGroup
	syncing.Add(2)
	for i := range files {
		go func(i int) {
			defer syncing.Done()
			syncErrors[i] = d.ops.sync(files[i].file)
		}(i)
	}
	syncing.Wait()
	if err := errors.Join(contextual("sync grouped prerequisite", syncErrors[0]), contextual("sync grouped head", syncErrors[1])); err != nil {
		return out, err
	}
	for i := range files {
		err := d.ops.close(files[i].file)
		files[i].file = nil
		if err != nil {
			return out, contextual("close synced grouped temporary", err)
		}
	}
	published, remaining, err := d.ops.noReplace(fd, files[0].name, fd, newName)
	files[0].present = remaining
	if published && newOwner != nil {
		newOwner.data = files[0].pendingLock
		files[0].pendingLock = nil
	}
	if err != nil || !published {
		if err == nil {
			err = errors.New("securestore: grouped prerequisite not published")
		}
		prerequisiteOutcome := NotCommitted
		if published {
			prerequisiteOutcome = Uncertain
		}
		return out, &CommitError{Outcome: prerequisiteOutcome, Op: "publish grouped prerequisite", Err: err}
	}
	if err := d.ops.rename(fd, files[1].name, fd, headName); err != nil {
		return out, contextual("replace grouped head; unreferenced prerequisite requires reconciliation", err)
	}
	files[1].present = false
	out = Uncertain
	retiredHead, headOwner.data = headOwner.data, files[1].pendingLock
	files[1].pendingLock = nil
	if err := d.ops.sync(d.file); err != nil {
		return out, contextual("sync grouped publication directory", err)
	}
	return Committed, nil
}

type groupedTemporary struct {
	name        string
	file        *os.File
	pendingLock *os.File
	present     bool
}

func (f *groupedTemporary) create(parentFD int, retainLock bool) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return contextual("generate grouped temporary name", err)
	}
	f.name = ".securestore-tmp-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(parentFD, f.name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return contextual("create grouped temporary", err)
	}
	f.file, f.present = os.NewFile(uintptr(fd), f.name), true
	if _, err := validatePrivate(fd); err != nil {
		return err
	}
	if retainLock {
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return contextual("retain grouped replacement inode", err)
		}
		f.pendingLock = os.NewFile(uintptr(duplicate), f.name)
		if err := unix.Flock(duplicate, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("securestore: lock grouped replacement inode: %w", err)
		}
	}
	return nil
}
