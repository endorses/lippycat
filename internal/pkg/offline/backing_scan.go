package offline

import (
	"context"
	"errors"
	"hash"
	"io"
	"sync"
)

type backingScanReader struct {
	reader io.Reader
	hash   hash.Hash
	bytes  int64
}

func (r *backingScanReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
		r.bytes += int64(n)
	}
	return n, err
}

// FinishScan completes the original-byte identity after the parser reaches EOF.
// It drains only unread trailing bytes, including formats whose parser stops
// before the underlying reader, without rereading any bytes already scanned.
func (b *BackingInput) FinishScan(ctx context.Context) error {
	r := b.lease.registry
	if b.scan != nil && b.scan.bytes < b.Size {
		reservation, err := r.storage.ReserveTransient(ctx, 64<<10)
		if err != nil {
			return err
		}
		_, err = copyBacking(ctx, io.Discard, b.scan, make([]byte, 64<<10))
		err = errors.Join(err, reservation.Close())
		if err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return errors.New("offline backings closed")
	}
	if r.failure != nil {
		return r.failure
	}
	entry := r.entries[b.ID-1]
	if err := r.check(entry, b.ID, "scan"); err != nil {
		return err
	}
	if b.scan != nil {
		if b.scan.bytes != entry.identity.Size {
			return r.changed(entry, b.ID, "scan", "short_read", io.ErrUnexpectedEOF)
		}
		copy(entry.identity.Digest[:], b.scan.hash.Sum(nil))
		entry.identityReady = true
		b.Digest = entry.identity.Digest
		b.scan = nil
	}
	for _, derived := range r.entries {
		if derived.derived && derived.sourceIndex == entry.sourceIndex {
			derived.identity = entry.identity
			derived.identityReady = true
		}
	}
	return ctx.Err()
}

type transientReservation struct {
	once    sync.Once
	storage *Storage
	bytes   uint64
}

func (r *transientReservation) Close() error {
	r.once.Do(func() { r.storage.releaseMemory(r.bytes) })
	return nil
}

// ReserveTransient charges caller-owned bounded buffers until the returned lease closes.
func (s *Storage) ReserveTransient(ctx context.Context, n uint64) (io.Closer, error) {
	if err := s.reserveMemory(ctx, n); err != nil {
		return nil, err
	}
	return &transientReservation{storage: s, bytes: n}, nil
}
