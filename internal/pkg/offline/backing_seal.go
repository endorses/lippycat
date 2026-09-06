package offline

import (
	"errors"
	"fmt"
	"os"
)

// Seal closes owned backing writers and reopens their immutable bytes read-only.
// No reader/scan lease may remain when a completed builder is published. Failure
// poisons the registry; Close retains the scratch paths for retryable cleanup.
func (r *BackingRegistry) Seal() (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return errors.New("offline backings closed")
	}
	if r.failure != nil {
		return r.failure
	}
	if r.sealed {
		return nil
	}
	if r.leases != 0 {
		return errors.New("offline backing leases active during finalization")
	}
	defer func() {
		if err != nil {
			r.failure = err
		}
	}()
	for i, b := range r.entries {
		if err = r.check(b, uint32(i+1), "finalize"); err != nil {
			return err
		}
		if b.scratch == nil {
			continue
		}
		f := b.scratch
		f.mu.Lock()
		if f.closed || f.sealed {
			f.mu.Unlock()
			return errors.New("offline backing writer unavailable during finalization")
		}
		if err = f.flush(); err != nil {
			f.mu.Unlock()
			return fmt.Errorf("flush offline backing: %w", err)
		}
		originalInfo, statErr := f.file.Stat()
		if statErr != nil {
			f.mu.Unlock()
			return fmt.Errorf("stat offline backing before finalization: %w", statErr)
		}
		err = f.file.Sync()
		if err != nil {
			f.mu.Unlock()
			return fmt.Errorf("sync offline backing: %w", err)
		}
		err = f.file.Close()
		f.closed = true
		f.buffer = nil
		f.storage.releaseMemory(f.bufferBytes)
		f.bufferBytes = 0
		if err != nil {
			f.mu.Unlock()
			return fmt.Errorf("close offline backing writer: %w", err)
		}
		var reader *os.File
		reader, err = os.Open(f.path)
		if err != nil {
			f.mu.Unlock()
			return fmt.Errorf("reopen offline backing read-only: %w", err)
		}
		reopenedInfo, statErr := reader.Stat()
		if statErr != nil || !os.SameFile(originalInfo, reopenedInfo) || reopenedInfo.Size() != b.size || !reopenedInfo.ModTime().Equal(originalInfo.ModTime()) {
			closeErr := reader.Close()
			f.mu.Unlock()
			return errors.Join(statErr, closeErr, errors.New("offline backing changed during read-only reopen"))
		}
		f.file = reader
		f.closed = false
		f.sealed = true
		b.file = reader
		f.mu.Unlock()
	}
	r.sealed = true
	return nil
}
