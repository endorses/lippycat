package offline

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Cache encoded frames, not mutable PacketDisplay pointers. Every read decodes
// an owned result, including cache hits. Both frames and their bookkeeping count
// against the shared budget; transient decoding and selected pins count too.
type cacheKey struct {
	dataset *diskDataset
	id      PacketID
	kind    uint16
}
type cachedFrame struct {
	key  cacheKey
	data []byte
	cost uint64
}

func (s *Storage) evictMemoryLocked(needed uint64) {
	for s.cacheLRU.Len() > 0 {
		used := s.usage.CachedBytes + s.usage.PinnedBytes + s.usage.PrefetchBytes + s.usage.InFlightBytes
		if needed <= s.limits.CacheBytes-used {
			return
		}
		s.removeCacheLocked(s.cacheLRU.Back())
	}
}
func (s *Storage) removeCacheLocked(e *list.Element) {
	c := e.Value.(*cachedFrame)
	delete(s.cache, c.key)
	s.cacheLRU.Remove(e)
	s.usage.CachedBytes -= c.cost
}
func (s *Storage) cached(key cacheKey) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.cache[key]; e != nil {
		s.cacheLRU.MoveToFront(e)
		return e.Value.(*cachedFrame).data
	}
	return nil
}
func (s *Storage) cacheFrame(key cacheKey, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.cache[key] != nil {
		return
	}
	cost := uint64(len(data)) + 192 // map slot, key, entry, list node and allocator rounding
	s.evictMemoryLocked(cost)
	used := s.usage.CachedBytes + s.usage.PinnedBytes + s.usage.PrefetchBytes + s.usage.InFlightBytes
	if cost > s.limits.CacheBytes-used {
		return
	}
	if s.cache == nil {
		s.cache = make(map[cacheKey]*list.Element)
	}
	s.cache[key] = s.cacheLRU.PushFront(&cachedFrame{key: key, data: data, cost: cost})
	s.usage.CachedBytes += cost
	s.peaks.MemoryBytes = max(s.peaks.MemoryBytes, used+cost)
}
func (s *Storage) discardDatasetCache(d *diskDataset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, e := range s.cache {
		if key.dataset == d {
			s.removeCacheLocked(e)
		}
	}
	// Release map buckets after the final dataset leaves the shared owner.
	if len(s.cache) == 0 {
		s.cache = nil
	}
}
func (d *diskDataset) readCachedRecord(ctx context.Context, f *os.File, off, size uint64, kind uint16, id PacketID, value any) (uint64, error) {
	maxBytes := d.storage.limits.MaxRecordBytes
	if size < frameHeaderBytes || size-frameHeaderBytes > maxBytes {
		return 0, fmt.Errorf("offline invalid framed record size %d", size)
	}
	// Keep one encoded frame plus at most MaxRecordBytes of decoded allocations.
	// The decoder borrows the frame payload instead of allocating a second copy.
	reservation := size + maxBytes
	if err := d.storage.reserveMemory(ctx, reservation); err != nil {
		return 0, err
	}
	fail := func(err error) (uint64, error) { d.storage.releaseMemory(reservation); return 0, err }
	key := cacheKey{d, id, kind}
	data := d.storage.cached(key)
	if data == nil {
		data = make([]byte, int(size))
		if _, err := f.ReadAt(data, int64(off)); err != nil {
			return fail(fmt.Errorf("read offline frame: %w", err))
		}
	}
	n, err := readRecordAt(frameReader{Reader: bytes.NewReader(data), data: data}, 0, kind, id, maxBytes, value)
	if err != nil {
		return fail(err)
	}
	if n != size {
		return fail(errors.New("offline framed length differs from offset entry"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	actual, err := recordMemory(value, maxBytes)
	if err != nil {
		return fail(err)
	}
	d.storage.cacheFrame(key, data)
	d.storage.releaseMemory(reservation - actual)
	return actual, nil
}

// DetailPin retains a selected detail within the shared memory budget and keeps
// its dataset alive. Value must be treated as immutable. Release with Close
// before closing its dataset; Close is safe to call repeatedly.
type DetailPin struct {
	Value   Detail
	once    sync.Once
	dataset *diskDataset
	bytes   uint64
}

func (p *DetailPin) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.dataset.storage.mu.Lock()
		p.dataset.storage.usage.PinnedBytes -= p.bytes
		p.dataset.storage.mu.Unlock()
		p.Value = Detail{}
		p.dataset.mu.RUnlock()
	})
	return nil
}
func (d *diskDataset) PinDetail(ctx context.Context, token Token, id PacketID) (*DetailPin, error) {
	d.mu.RLock()
	if d.closed || token.Dataset != d.generation {
		d.mu.RUnlock()
		return nil, errors.New("offline dataset closed or generation mismatch")
	}
	detail, n, err := d.readDetail(ctx, id)
	if err != nil {
		d.mu.RUnlock()
		return nil, err
	}
	detail.Token = token
	const pinOverhead = 64
	if err := d.storage.reserveMemory(ctx, pinOverhead); err != nil {
		d.storage.releaseMemory(n)
		d.mu.RUnlock()
		return nil, err
	}
	n += pinOverhead
	d.storage.mu.Lock()
	d.storage.usage.InFlightBytes -= n
	d.storage.usage.PinnedBytes += n
	d.storage.mu.Unlock()
	return &DetailPin{Value: detail, dataset: d, bytes: n}, nil
}
