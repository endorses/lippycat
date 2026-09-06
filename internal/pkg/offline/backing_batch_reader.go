package offline

import (
	"context"
	"errors"
	"io"
	"sync"
)

// BackingBatchReader reuses bounded raw scratch for serial borrowed reads.
// Exactly one lease may be active; its packet slices expire when it closes.
// Larger batches retain ReadBatch's independent allocation and integrity checks.
type BackingBatchReader struct {
	mu       sync.Mutex
	registry *BackingRegistry
	buffer   []byte
	held     uint64
	active   bool
	closed   bool
}

func (r *BackingRegistry) NewBatchReader(ctx context.Context, capacity uint64) (*BackingBatchReader, error) {
	capacity = min(capacity, r.storage.limits.MaxRecordBytes)
	if capacity == 0 || capacity > uint64(int(^uint(0)>>1))-256 {
		return nil, errors.New("offline batch reader capacity is out of range")
	}
	held := capacity + 256
	if err := r.storage.reserveMemory(ctx, held); err != nil {
		return nil, err
	}
	return &BackingBatchReader{registry: r, buffer: make([]byte, int(capacity)), held: held}, nil
}
func (r *BackingBatchReader) ReadBatch(ctx context.Context, locs []Locator, maxBytes uint64) (io.Closer, [][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, errors.New("offline batch reader closed")
	}
	if r.active {
		return nil, nil, errors.New("offline batch reader lease still active")
	}
	lease, data, err := r.registry.readBatch(ctx, locs, maxBytes, r.buffer)
	if err != nil {
		return nil, nil, err
	}
	r.active = true
	return &backingBatchReadLease{reader: r, lease: lease}, data, nil
}
func (r *BackingBatchReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.active {
		return errors.New("offline batch reader lease still active")
	}
	r.closed = true
	r.buffer = nil
	r.registry.storage.releaseMemory(r.held)
	r.held = 0
	return nil
}

type backingBatchReadLease struct {
	once   sync.Once
	reader *BackingBatchReader
	lease  *BackingLease
	err    error
}

func (l *backingBatchReadLease) Close() error {
	l.once.Do(func() {
		l.reader.mu.Lock()
		defer l.reader.mu.Unlock()
		l.err = l.lease.Close()
		l.reader.active = false
	})
	return l.err
}
