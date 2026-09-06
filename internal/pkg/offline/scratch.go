package offline

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// ScratchFile is an append-only temporary stream charged to the same disk
// budget as active and replacement datasets. Close retries failed removal;
// Storage retains ownership until the file has actually been removed.
type ScratchFile struct {
	mu              sync.Mutex
	storage         *Storage
	file            *os.File
	path            string
	size            uint64
	closed, removed bool
	sealed          bool
}

func (s *Storage) NewScratchFile() (*ScratchFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("offline storage closed")
	}
	f, err := os.CreateTemp(s.limits.Directory, "lippycat-order-*")
	if err != nil {
		return nil, fmt.Errorf("create offline ordering scratch: %w", err)
	}
	v := &ScratchFile{storage: s, file: f, path: f.Name()}
	if s.scratch == nil {
		s.scratch = make(map[*ScratchFile]struct{})
	}
	s.scratch[v] = struct{}{}
	return v, nil
}

func (f *ScratchFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.sealed {
		return 0, errors.New("offline ordering scratch closed")
	}
	if err := f.storage.reserveDisk(uint64(len(p))); err != nil {
		return 0, err
	}
	n, err := f.file.Write(p)
	f.size += uint64(n)
	f.storage.releaseDisk(uint64(len(p) - n))
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (f *ScratchFile) ReadAt(p []byte, offset int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("offline ordering scratch closed")
	}
	return f.file.ReadAt(p, offset)
}

// Reset discards a completed merge pass before reusing its output stream.
func (f *ScratchFile) Reset() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.sealed {
		return errors.New("offline ordering scratch closed")
	}
	if err := f.file.Truncate(0); err != nil {
		return fmt.Errorf("truncate offline ordering scratch: %w", err)
	}
	f.storage.releaseDisk(f.size)
	f.size = 0
	_, err := f.file.Seek(0, io.SeekStart)
	return err
}

func (f *ScratchFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removed {
		return nil
	}
	var err error
	if !f.closed {
		f.closed = true
		err = f.file.Close()
	}
	if removeErr := os.Remove(f.path); removeErr != nil && !os.IsNotExist(removeErr) {
		return errors.Join(err, fmt.Errorf("remove offline ordering scratch: %w", removeErr))
	}
	f.storage.releaseDisk(f.size)
	f.size = 0
	f.removed = true
	f.storage.mu.Lock()
	delete(f.storage.scratch, f)
	f.storage.mu.Unlock()
	return err
}
