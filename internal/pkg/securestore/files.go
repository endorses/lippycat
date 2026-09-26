package securestore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Outcome identifies the durable result of a mutation. An uncertain result must
// block further store mutations until its owner reconciles or restarts.
type Outcome uint8

const (
	NotCommitted Outcome = iota
	Committed
	Uncertain
)

// CommitError preserves the operation's durable outcome, including when cleanup
// also fails. Unwrap exposes the original error and any cleanup errors.
type CommitError struct {
	Outcome Outcome
	Op      string
	Err     error
}

func (e *CommitError) Error() string { return fmt.Sprintf("securestore %s: %v", e.Op, e.Err) }
func (e *CommitError) Unwrap() error { return e.Err }

// OutcomeOf treats ordinary errors as definite failures and nil as success.
func OutcomeOf(err error) Outcome {
	if err == nil {
		return Committed
	}
	var commit *CommitError
	if errors.As(err, &commit) {
		return commit.Outcome
	}
	return NotCommitted
}

var ErrLocked = errors.New("securestore is already owned by another operation")

// Dir holds a validated private directory descriptor. All child access stays
// relative to this descriptor, even if a pathname is renamed concurrently.
// Callers must hold a Lock for their store while reading or mutating its objects.
// One store lock may cover multiple child files (for example, a journal).
// Use the same Dir for acquiring a snapshot lock and replacing that snapshot so
// its supplementary data-inode lock follows the current inode across renames.
type Dir struct {
	mu    sync.Mutex
	file  *os.File
	ops   fileOps
	locks map[string]*Lock
}

// fileOps keeps fault injection local to a directory and out of production APIs.
type fileOps struct {
	write     func(*os.File, []byte) (int, error)
	sync      func(*os.File) error
	close     func(*os.File) error
	rename    func(int, string, int, string) error
	exchange  func(int, string, int, string) error
	noReplace func(int, string, int, string) (bool, bool, error)
	unlink    func(int, string, int) error
}

func defaultFileOps() fileOps {
	return fileOps{
		write: (*os.File).Write, sync: (*os.File).Sync, close: (*os.File).Close,
		rename: unix.Renameat, exchange: exchangeNames, noReplace: publishNoReplace, unlink: unix.Unlinkat,
	}
}

// OpenDir opens an existing private directory without following any symlinks.
// The store directory must be owned by the effective user, have owner rwx, no
// other access, and at most group read/execute (0700 or 0750 are typical).
// Ancestors may be root- or effective-user-owned and readable/traversable by
// others, but must not be group/world writable. Root-owned sticky /tmp is the
// sole writable-ancestor exception; the store directory itself is always private.
func OpenDir(path string) (*Dir, error) {
	file, err := openDirectory(path, true)
	if err != nil {
		return nil, err
	}
	return &Dir{file: file, ops: defaultFileOps(), locks: make(map[string]*Lock)}, nil
}

func openDirectory(path string, private bool) (_ *os.File, retErr error) {
	if path == "" {
		return nil, errors.New("securestore: empty directory path")
	}
	abs := path
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("securestore: resolve directory: %w", err)
		}
		// Do not Clean before walking: a symlink before '..' must be rejected,
		// rather than silently removed from the descriptor validation path.
		abs = cwd + "/" + path
	}
	var components []string
	for _, component := range strings.Split(abs, "/") {
		if component != "" && component != "." {
			components = append(components, component)
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("securestore: open root directory: %w", err)
	}
	current := os.NewFile(uintptr(fd), "/")
	defer func() {
		if current != nil {
			retErr = errors.Join(retErr, contextual("close directory", current.Close()))
		}
	}()
	if err := validateDirectory(fd, "/", len(components) == 0 && private); err != nil {
		return nil, err
	}
	walked := ""
	for i, component := range components {
		walked = filepath.Clean(walked + "/" + component)
		nextFD, err := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("securestore: open directory component %q: %w", component, err)
		}
		next := os.NewFile(uintptr(nextFD), walked)
		validationErr := validateDirectory(nextFD, walked, private && i == len(components)-1)
		closeErr := current.Close()
		current = next
		if err := errors.Join(validationErr, contextual("close ancestor directory", closeErr)); err != nil {
			return nil, err
		}
	}
	result := current
	current = nil
	return result, nil
}

func validateDirectory(fd int, path string, private bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("securestore: inspect directory: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("securestore: expected a directory")
	}
	if private {
		if st.Uid != uint32(os.Geteuid()) || st.Mode&0700 != 0700 || st.Mode&0027 != 0 || st.Mode&07000 != 0 {
			return errors.New("securestore: store directory must be user-owned and private (0700 or 0750)")
		}
		return nil
	}
	if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return errors.New("securestore: ancestor directory has unexpected owner")
	}
	if st.Mode&0022 != 0 && !(path == "/tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
		return errors.New("securestore: ancestor directory is group/world writable")
	}
	return nil
}

func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > 255 {
		return errors.New("securestore: object name must be a single valid basename")
	}
	if strings.HasPrefix(name, ".securestore-") {
		return errors.New("securestore: object name uses the reserved internal prefix")
	}
	return nil
}

func openPrivate(fd int, name string) (*os.File, error) {
	// NONBLOCK ensures a substituted FIFO cannot block before its type is checked.
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("securestore: open private file: %w", err)
	}
	file := os.NewFile(uintptr(child), name)
	if _, err := validatePrivate(child); err != nil {
		return nil, errors.Join(err, contextual("close invalid private file", file.Close()))
	}
	return file, nil
}

func validatePrivate(fd int) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("securestore: inspect private file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("securestore: expected regular private file")
	}
	if st.Uid != uint32(os.Geteuid()) || (st.Mode&07777 != 0600 && st.Mode&07777 != 0400) {
		return nil, errors.New("securestore: private file must be user-owned with mode 0600 or 0400")
	}
	if st.Nlink != 1 {
		return nil, errors.New("securestore: hardlinked private files are not permitted")
	}
	return &st, nil
}

// ReadFile reads a bounded private file from a trusted, not necessarily private,
// directory. This permits provisioned keys in locations such as /etc/lippycat.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	data, _, err := ReadFileWithIdentity(path, maxBytes)
	return data, err
}

// Read checks the file's size before allocating and rejects changes in length.
func (d *Dir) Read(name string, maxBytes int64) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil, os.ErrClosed
	}
	return readPrivate(int(d.file.Fd()), name, maxBytes)
}

func readPrivate(fd int, name string, maxBytes int64) (_ []byte, retErr error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if maxBytes < 0 {
		return nil, errors.New("securestore: negative read limit")
	}
	file, err := openPrivate(fd, name)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, contextual("close private file", file.Close())) }()
	return readOpenedPrivate(file, maxBytes)
}

// Replace writes already encoded bytes to an exclusive 0600 temporary file,
// fsyncs it, atomically replaces the destination, then fsyncs the directory.
// The caller must encrypt sensitive data before calling Replace or Create.
func (d *Dir) Replace(name string, data []byte) (Outcome, error) {
	return d.write(name, data, false)
}

// Create publishes a new file without clobbering an existing destination. It
// atomically renames on Linux with RENAME_NOREPLACE; unsupported filesystems fail
// before publication. Other Unix systems link the synced inode then remove its
// temporary name, requiring explicit recovery if interrupted between those steps.
// A failure after publication is uncertain, including temporary cleanup.
func (d *Dir) Create(name string, data []byte) (Outcome, error) {
	return d.write(name, data, true)
}

func (d *Dir) write(name string, data []byte, create bool) (out Outcome, retErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out = NotCommitted
	op := "replace"
	if create {
		op = "create"
	}
	defer func() {
		if retErr != nil {
			retErr = &CommitError{Outcome: out, Op: op, Err: retErr}
		}
	}()
	if err := checkName(name); err != nil {
		return out, err
	}
	if d.file == nil {
		return out, os.ErrClosed
	}
	fd := int(d.file.Fd())
	owner := d.locks[name]
	if owner != nil {
		owner.mu.Lock()
		defer owner.mu.Unlock()
		if owner.file == nil {
			owner = nil
		}
	}
	if !create {
		old, err := openPrivate(fd, name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
		if old != nil {
			if err := old.Close(); err != nil {
				return out, fmt.Errorf("close previous private file: %w", err)
			}
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return out, fmt.Errorf("generate temporary name: %w", err)
	}
	tempName := ".securestore-tmp-" + hex.EncodeToString(random[:])
	tempFD, err := unix.Openat(fd, tempName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return out, fmt.Errorf("create private temporary file: %w", err)
	}
	temp := os.NewFile(uintptr(tempFD), tempName)
	tempExists := true
	var pendingData *os.File
	var cleanupErr error
	defer func() {
		retErr = errors.Join(retErr, cleanupErr)
		if pendingData != nil {
			retErr = errors.Join(retErr, contextual("close unpublished inode lock", pendingData.Close()))
		}
		if temp != nil {
			retErr = errors.Join(retErr, contextual("close temporary file", d.ops.close(temp)))
		}
		if tempExists {
			retErr = errors.Join(retErr, contextual("remove temporary file", d.ops.unlink(fd, tempName, 0)))
		}
	}()
	if _, err := validatePrivate(tempFD); err != nil {
		return out, err
	}
	if owner != nil {
		// Dup shares the temporary file's open-file description; closing the
		// writer before publication therefore retains the new inode's flock.
		duplicate, err := unix.FcntlInt(uintptr(tempFD), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return out, fmt.Errorf("retain replacement inode lock: %w", err)
		}
		pendingData = os.NewFile(uintptr(duplicate), name)
		if err := unix.Flock(duplicate, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return out, fmt.Errorf("lock replacement inode: %w", err)
		}
	}
	transferLock := func() {
		if owner == nil {
			return
		}
		oldData := owner.data
		owner.data = pendingData
		pendingData = nil
		if oldData != nil {
			cleanupErr = contextual("close replaced inode lock", oldData.Close())
		}
	}
	for len(data) > 0 {
		n, err := d.ops.write(temp, data)
		if n < 0 || n > len(data) {
			return out, errors.New("invalid private write count")
		}
		data = data[n:]
		if err != nil {
			return out, fmt.Errorf("write private temporary file: %w", err)
		}
		if n == 0 {
			return out, io.ErrShortWrite
		}
	}
	if err := d.ops.sync(temp); err != nil {
		return out, fmt.Errorf("sync private temporary file: %w", err)
	}
	err = d.ops.close(temp)
	temp = nil
	if err != nil {
		return out, fmt.Errorf("close private temporary file: %w", err)
	}
	if create {
		published, remaining, err := d.ops.noReplace(fd, tempName, fd, name)
		tempExists = remaining
		if published {
			out = Uncertain
			transferLock()
		}
		if err != nil {
			return out, fmt.Errorf("publish private file: %w", err)
		}
	} else {
		if err := d.ops.rename(fd, tempName, fd, name); err != nil {
			return out, fmt.Errorf("replace private file: %w", err)
		}
		tempExists = false
		out = Uncertain
		transferLock()
	}
	if err := d.ops.sync(d.file); err != nil {
		return out, fmt.Errorf("sync private directory: %w", err)
	}
	return Committed, nil
}

// Lock owns a stable sidecar inode and, when present, the current data inode.
// The sidecar is retained after Close to prevent split ownership over replacement.
// The supplementary data-inode lock prevents moving a live file to a different
// basename to bypass ownership. Hardlinks and symlink traversal are rejected.
type Lock struct {
	mu   sync.Mutex
	file *os.File
	data *os.File
	dir  *Dir
	name string
}

// Lock exclusively and non-blockingly acquires ownership for name. It validates
// an existing data file too; absence is permitted for explicit initialization.
func (d *Dir) Lock(name string) (_ *Lock, retErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkName(name); err != nil {
		return nil, err
	}
	if d.file == nil {
		return nil, os.ErrClosed
	}
	fd := int(d.file.Fd())
	digest := sha256.Sum256([]byte(name))
	lockName := ".securestore-lock-" + hex.EncodeToString(digest[:])
	created := true
	lockFD, err := unix.Openat(fd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if errors.Is(err, unix.EEXIST) {
		created = false
		lockFD, err = unix.Openat(fd, lockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("securestore: open ownership lock: %w", err)
	}
	file := os.NewFile(uintptr(lockFD), lockName)
	defer func() {
		if file != nil {
			retErr = errors.Join(retErr, contextual("close rejected ownership lock", file.Close()))
		}
	}()
	if _, err := validatePrivate(lockFD); err != nil {
		return nil, err
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %w", ErrLocked, err)
		}
		return nil, fmt.Errorf("securestore: acquire ownership lock: %w", err)
	}
	if created {
		if err := errors.Join(contextual("sync ownership lock", file.Sync()), contextual("sync ownership directory", d.file.Sync())); err != nil {
			return nil, err
		}
	}
	data, err := openPrivate(fd, name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if data != nil {
		if err := unix.Flock(int(data.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, errors.Join(fmt.Errorf("%w: target inode: %w", ErrLocked, err), contextual("close ownership target", data.Close()))
		}
	}
	lock := &Lock{file: file, data: data, dir: d, name: name}
	d.locks[name] = lock
	file = nil
	return lock, nil
}

// Close releases ownership; the stable lock pathname must never be removed.
func (l *Lock) Close() error {
	l.dir.mu.Lock()
	defer l.dir.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	var err error
	if l.data != nil {
		err = contextual("close data inode lock", l.data.Close())
		l.data = nil
	}
	err = errors.Join(err, contextual("close ownership lock", l.file.Close()))
	l.file = nil
	if l.dir.locks[l.name] == l {
		delete(l.dir.locks, l.name)
	}
	return err
}

// Close releases the directory descriptor. Locks have independent lifetimes and
// must also be closed by their owner after all associated operations finish.
func (d *Dir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return contextual("close store directory", err)
}

func contextual(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("securestore: %s: %w", op, err)
}
