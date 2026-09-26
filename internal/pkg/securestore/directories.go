package securestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// EnsureDir explicitly provisions missing private directories. Existing ancestors
// are validated before mkdirat, symlinks are never followed, and each new entry
// is synced in its parent. OpenDir itself never creates directories.
func EnsureDir(path string) (retErr error) {
	if path == "" {
		return errors.New("securestore: empty directory path")
	}
	abs := path
	if !filepath.IsAbs(abs) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("securestore: resolve directory: %w", err)
		}
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
		return fmt.Errorf("securestore: open provisioning root: %w", err)
	}
	current := os.NewFile(uintptr(fd), "/")
	defer func() { retErr = errors.Join(retErr, contextual("close provisioning directory", current.Close())) }()
	if err := validateDirectory(fd, "/", len(components) == 0); err != nil {
		return err
	}
	walked := ""
	for i, component := range components {
		walked = filepath.Clean(walked + "/" + component)
		child, err := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			if err := unix.Mkdirat(int(current.Fd()), component, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("securestore: provision private directory: %w", err)
			}
			if err := current.Sync(); err != nil {
				return &CommitError{Outcome: Uncertain, Op: "sync provisioned directory entry", Err: err}
			}
			child, err = unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			return fmt.Errorf("securestore: open provisioning component: %w", err)
		}
		next := os.NewFile(uintptr(child), walked)
		validationErr := validateDirectory(child, walked, i == len(components)-1)
		closeErr := current.Close()
		current = next
		if err := errors.Join(validationErr, contextual("close provisioning ancestor", closeErr)); err != nil {
			return err
		}
	}
	return nil
}

// PrivateSource is an exclusively locked offline source. Its parent need only
// satisfy the trusted ancestor policy, allowing migration from e.g. a 0755
// configuration directory. It deliberately exposes no mutation operations.
type PrivateSource struct {
	mu     sync.Mutex
	dir    *Dir
	lock   *Lock
	name   string
	closed bool
}

// OpenPrivateSource locks a required private source file for offline migration.
// A source remains locked until Close; regularity, ownership and hardlinks are
// checked just as for runtime snapshots.
func OpenPrivateSource(path string) (_ *PrivateSource, retErr error) {
	source, err := PreparePrivateSource(path)
	if err != nil {
		return nil, err
	}
	if err := source.Acquire(); err != nil {
		return nil, errors.Join(err, source.Close())
	}
	return source, nil
}

// PreparePrivateSource opens the trusted source directory without locking yet,
// permitting multiple offline stores to acquire ownership in descriptor order.
func PreparePrivateSource(path string) (*PrivateSource, error) {
	parent, name := ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	file, err := openDirectory(parent, false)
	if err != nil {
		return nil, err
	}
	dir := &Dir{file: file, ops: defaultFileOps(), locks: make(map[string]*Lock)}
	return &PrivateSource{dir: dir, name: name}, nil
}

func (s *PrivateSource) OrderKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", os.ErrClosed
	}
	return s.dir.LockOrderKey(s.name)
}

func (s *PrivateSource) Identity() (FileIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return FileIdentity{}, os.ErrClosed
	}
	return s.dir.FileIdentity(s.name)
}

func (s *PrivateSource) Acquire() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if s.lock != nil {
		return nil
	}
	lock, err := s.dir.Lock(s.name)
	if err != nil {
		return err
	}
	if lock.data == nil {
		return errors.Join(os.ErrNotExist, lock.Close())
	}
	s.lock = lock
	return nil
}

func (s *PrivateSource) Read(maxBytes int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if s.lock == nil {
		return nil, errors.New("securestore: offline source must be exclusively acquired before reading")
	}
	return s.dir.Read(s.name, maxBytes)
}

func (s *PrivateSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	return errors.Join(err, s.dir.Close())
}
