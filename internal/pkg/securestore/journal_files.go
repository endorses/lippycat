package securestore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// WalkEntries visits a directory in bounded batches through a separately opened
// descriptor. Callbacks may use Dir.Read; no directory mutex covers callbacks.
// The owner must hold its whole-store lock until the walk and callbacks finish.
func (d *Dir) WalkEntries(visit func(string) error) (result error) {
	if visit == nil {
		return errors.New("securestore: directory visitor is required")
	}
	d.mu.Lock()
	if d.file == nil {
		d.mu.Unlock()
		return os.ErrClosed
	}
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	d.mu.Unlock()
	if err != nil {
		return fmt.Errorf("securestore: open directory iteration: %w", err)
	}
	file := os.NewFile(uintptr(fd), "store directory")
	defer func() { result = errors.Join(result, contextual("close directory iteration", file.Close())) }()
	for {
		names, err := file.Readdirnames(128)
		for _, name := range names {
			if err := visit(name); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("securestore: iterate directory: %w", err)
		}
	}
}

// AllocationUnit reports the filesystem's allocation unit for conservative
// pending reservations. Actual completed file allocation uses AllocatedSize.
func (d *Dir) AllocationUnit() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return 0, os.ErrClosed
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(d.file.Fd()), &stat); err != nil {
		return 0, contextual("inspect storage allocation unit", err)
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("securestore: invalid filesystem allocation unit")
	}
	return max(4096, int64(stat.Bsize)), nil
}

func (d *Dir) AllocatedSize(name string) (_ int64, result error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkName(name); err != nil {
		return 0, err
	}
	if d.file == nil {
		return 0, os.ErrClosed
	}
	file, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return 0, err
	}
	defer func() { result = errors.Join(result, contextual("close allocation inspection", file.Close())) }()
	stat, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return 0, err
	}
	if stat.Blocks < 0 || uint64(stat.Blocks) > math.MaxInt64/512 {
		return 0, errors.New("securestore: invalid file allocation size")
	}
	return stat.Blocks * 512, nil
}

// Sync makes preceding owner-controlled directory operations durable.
func (d *Dir) Sync() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return os.ErrClosed
	}
	return contextual("sync private directory", d.ops.sync(d.file))
}

// Remove durably deletes a validated private object. An absent object is a
// definitely-not-committed error, so owners explicitly decide idempotence.
func (d *Dir) Remove(name string) (out Outcome, result error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "remove", Err: result}
		}
	}()
	if err := checkName(name); err != nil {
		return out, err
	}
	if d.file == nil {
		return out, os.ErrClosed
	}
	fd := int(d.file.Fd())
	file, err := openPrivate(fd, name)
	if err != nil {
		return out, err
	}
	if err := file.Close(); err != nil {
		return out, contextual("close removal validation", err)
	}
	if err := d.ops.unlink(fd, name, 0); err != nil {
		return out, contextual("remove private object", err)
	}
	out = Uncertain
	if err := d.ops.sync(d.file); err != nil {
		return out, contextual("sync private deletion", err)
	}
	return Committed, nil
}

func temporaryName(name string) bool {
	const prefix = ".securestore-tmp-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return err == nil
}

// RecoverTemporaries is exclusively for an owner of an ENTIRE private directory
// (such as a journal), before admitting any operations. Snapshot owners sharing
// a directory must not call it. At most 128 interrupted writes are recovered per
// invocation; larger sets are rejected for explicit offline investigation.
// A published Create with two names is reconciled only when the other private
// link is in this same directory; unexplained external hardlinks fail closed.
func (d *Dir) RecoverTemporaries() (out Outcome, result error) {
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "recover temporary objects", Err: result}
		}
	}()
	var names []string
	if err := d.WalkEntries(func(name string) error {
		if strings.HasPrefix(name, ".securestore-tmp-") {
			if !temporaryName(name) {
				return errors.New("securestore: invalid temporary object name")
			}
			if len(names) >= 128 {
				return errors.New("securestore: too many interrupted writes")
			}
			names = append(names, name)
		}
		return nil
	}); err != nil {
		return out, err
	}
	for _, name := range names {
		stat, err := d.inspectTemporary(name)
		if err != nil {
			return out, err
		}
		if stat.Nlink == 2 {
			matches := 0
			err := d.WalkEntries(func(other string) error {
				if other == name || strings.HasPrefix(other, ".securestore-") {
					return nil
				}
				d.mu.Lock()
				defer d.mu.Unlock()
				if d.file == nil {
					return os.ErrClosed
				}
				var candidate unix.Stat_t
				if err := unix.Fstatat(int(d.file.Fd()), other, &candidate, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				if candidate.Dev == stat.Dev && candidate.Ino == stat.Ino {
					matches++
				}
				return nil
			})
			if err != nil {
				return out, err
			}
			if matches != 1 {
				return out, errors.New("securestore: interrupted create has unexplained hardlinks")
			}
		}
		d.mu.Lock()
		if d.file == nil {
			d.mu.Unlock()
			return out, os.ErrClosed
		}
		err = d.ops.unlink(int(d.file.Fd()), name, 0)
		d.mu.Unlock()
		if err != nil {
			return out, contextual("remove interrupted temporary object", err)
		}
		out = Uncertain
	}
	if len(names) > 0 {
		if err := d.Sync(); err != nil {
			return out, err
		}
	}
	return Committed, nil
}

func (d *Dir) inspectTemporary(name string) (_ *unix.Stat_t, result error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil, os.ErrClosed
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, contextual("open interrupted temporary object", err)
	}
	file := os.NewFile(uintptr(fd), "temporary object")
	defer func() { result = errors.Join(result, contextual("close temporary inspection", file.Close())) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0600 || stat.Nlink < 1 || stat.Nlink > 2 {
		return nil, errors.New("securestore: invalid interrupted temporary object")
	}
	return &stat, nil
}

// MetadataAllocatedSize inspects only the shared package's recognized ownership
// and usage metadata. The fixed sizes prevent arbitrary files hidden behind a
// metadata prefix from escaping an owning journal's capacity accounting.
func (d *Dir) MetadataAllocatedSize(name string) (_ int64, result error) {
	var suffix string
	var expected int64
	switch {
	case strings.HasPrefix(name, ".securestore-lock-"):
		suffix = strings.TrimPrefix(name, ".securestore-lock-")
	case strings.HasPrefix(name, ".usage-"):
		suffix = strings.TrimPrefix(name, ".usage-")
		expected = usageBytes
	default:
		return 0, errors.New("securestore: unrecognized metadata name")
	}
	if raw, err := hex.DecodeString(suffix); err != nil || len(raw) != 32 {
		return 0, errors.New("securestore: invalid metadata name")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return 0, os.ErrClosed
	}
	file, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return 0, err
	}
	defer func() { result = errors.Join(result, contextual("close metadata inspection", file.Close())) }()
	stat, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return 0, err
	}
	if stat.Size != expected {
		return 0, errors.New("securestore: unexpected metadata size")
	}
	if stat.Blocks < 0 || uint64(stat.Blocks) > math.MaxInt64/512 {
		return 0, errors.New("securestore: invalid metadata allocation size")
	}
	return stat.Blocks * 512, nil
}
