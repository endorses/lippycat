//go:build linux

package securestore

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// MaxExchangeBytes bounds the narrow head-container publication primitive.
const MaxExchangeBytes = 2097591

func exchangeNames(a int, from string, b int, to string) error {
	return unix.Renameat2(a, from, b, to, unix.RENAME_EXCHANGE)
}

// ExchangeAndArchive publishes encrypted data under an existing owned head,
// moving its previous inode to archive without replacement. All names refer to
// this Dir. A successful exchange makes every subsequent failure Uncertain until
// the final parent sync succeeds. It never rolls back or deletes staged evidence.
// The caller authenticates predecessor identities and reserves capacity/usage.
//
// An empty archive explicitly requests initial no-replace publication and
// REQUIRES an absent head; it never converts a missing used head into a new store.
// stage must be a distinct nonreserved basename outside RecoverTemporaries's
// namespace. The caller owns classification/reconciliation after any failure.
func (d *Dir) ExchangeAndArchive(stage, head, archive string, data []byte) (out Outcome, resultErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &CommitError{Outcome: out, Op: "exchange and archive", Err: resultErr}
		}
	}()
	if len(data) == 0 || len(data) > MaxExchangeBytes {
		return out, errors.New("securestore: exchange size invalid")
	}
	for _, name := range []string{stage, head} {
		if err := checkName(name); err != nil {
			return out, err
		}
	}
	if archive != "" {
		if err := checkName(archive); err != nil {
			return out, err
		}
	}
	if stage == head || stage == archive || head == archive {
		return out, errors.New("securestore: exchange names alias")
	}
	if d.file == nil {
		return out, os.ErrClosed
	}
	owner := d.locks[head]
	if owner == nil {
		return out, errors.New("securestore: exchange requires active head ownership")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.file == nil {
		return out, errors.New("securestore: exchange ownership closed")
	}
	if _, err := validatePrivate(int(owner.file.Fd())); err != nil {
		return out, err
	}
	fd := int(d.file.Fd())
	absent := func(name string) error {
		var st unix.Stat_t
		err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return os.ErrExist
		}
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return contextual("inspect exchange target", err)
	}
	if err := absent(stage); err != nil {
		return out, err
	}
	if archive == "" {
		if owner.data != nil {
			return out, errors.New("securestore: initial head already owned")
		}
		if err := absent(head); err != nil {
			return out, err
		}
	} else {
		if owner.data == nil {
			return out, errors.New("securestore: exchange requires existing head")
		}
		if err := absent(archive); err != nil {
			return out, err
		}
	}
	validateOwnedName := func(name string, owned *os.File, exactSize int64) error {
		old, err := openPrivate(fd, name)
		if err != nil {
			return err
		}
		actual, aerr := validatePrivate(int(old.Fd()))
		locked, lerr := validatePrivate(int(owned.Fd()))
		if err := errors.Join(aerr, lerr, contextual("close exchange validation", old.Close())); err != nil {
			return err
		}
		if actual.Dev != locked.Dev || actual.Ino != locked.Ino || actual.Size <= 0 || actual.Size > MaxExchangeBytes {
			return errors.New("securestore: exchange head identity or size invalid")
		}
		if exactSize > 0 && actual.Size != exactSize {
			return errors.New("securestore: exchange staged size changed")
		}
		return nil
	}
	if archive != "" {
		if err := validateOwnedName(head, owner.data, 0); err != nil {
			return out, err
		}
	}
	var writer, pending, retired *os.File
	defer func() {
		if writer != nil {
			resultErr = errors.Join(resultErr, contextual("close exchange writer", d.ops.close(writer)))
		}
		if pending != nil {
			resultErr = errors.Join(resultErr, contextual("close pending exchange lock", pending.Close()))
		}
		if retired != nil {
			resultErr = errors.Join(resultErr, contextual("close archived inode lock", d.ops.close(retired)))
		}
	}()
	tempFD, err := unix.Openat(fd, stage, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return out, contextual("create exchange stage", err)
	}
	writer = os.NewFile(uintptr(tempFD), stage)
	if _, err := validatePrivate(tempFD); err != nil {
		return out, err
	}
	dup, err := unix.FcntlInt(uintptr(tempFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return out, contextual("retain exchange inode", err)
	}
	pending = os.NewFile(uintptr(dup), stage)
	if err := unix.Flock(dup, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return out, contextual("lock exchange inode", err)
	}
	exactSize := int64(len(data))
	for len(data) > 0 {
		n, err := d.ops.write(writer, data)
		if n < 0 || n > len(data) {
			return out, errors.New("securestore: invalid exchange write count")
		}
		data = data[n:]
		if err != nil {
			return out, contextual("write exchange stage", err)
		}
		if n == 0 {
			return out, io.ErrShortWrite
		}
	}
	if err := d.ops.sync(writer); err != nil {
		return out, contextual("sync exchange stage", err)
	}
	err = d.ops.close(writer)
	writer = nil
	if err != nil {
		return out, contextual("close synced exchange stage", err)
	}
	if err := validateOwnedName(stage, pending, exactSize); err != nil {
		return out, err
	}
	if archive == "" {
		published, remaining, err := d.ops.noReplace(fd, stage, fd, head)
		if published {
			out = Uncertain
			owner.data = pending
			pending = nil
		}
		if err != nil {
			return out, contextual("publish initial exchange head", err)
		}
		if !published || remaining {
			return out, errors.New("securestore: initial exchange publication incomplete")
		}
	} else {
		if err := validateOwnedName(head, owner.data, 0); err != nil {
			return out, err
		}
		if err := d.ops.exchange(fd, stage, fd, head); err != nil {
			return out, contextual("exchange head", err)
		}
		out = Uncertain
		retired, owner.data = owner.data, pending
		pending = nil
		if err := validateOwnedName(stage, retired, 0); err != nil {
			return out, err
		}
		published, remaining, err := d.ops.noReplace(fd, stage, fd, archive)
		if err != nil {
			return out, contextual("archive exchanged head", err)
		}
		if !published || remaining {
			return out, errors.New("securestore: exchanged archive publication incomplete")
		}
	}
	if err := d.ops.sync(d.file); err != nil {
		return out, contextual("sync exchange directory", err)
	}
	return Committed, nil
}
