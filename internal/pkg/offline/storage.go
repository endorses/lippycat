package offline

import (
	"container/list"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

// Storage owns budgets shared by the current and replacement datasets.
// Callers close datasets/builders before closing their Storage.
type Storage struct {
	mu       sync.Mutex
	limits   ResourceLimits
	usage    ResourceUsage
	peaks    ResourcePeaks
	closed   bool
	cache    map[cacheKey]*list.Element
	cacheLRU list.List
	scratch  map[*ScratchFile]struct{}
	backings map[*BackingRegistry]struct{}
}

func NewStorage(limits ResourceLimits) (*Storage, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if limits.MaxRecordBytes > uint64(int(^uint(0)>>1)-frameHeaderBytes)/4 {
		return nil, errors.New("offline record limit exceeds addressable allocation size")
	}
	if err := os.MkdirAll(limits.Directory, 0700); err != nil {
		return nil, fmt.Errorf("create offline storage parent: %w", err)
	}
	return &Storage{limits: limits}, nil
}
func (s *Storage) reserveDisk(n uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("offline storage closed")
	}
	if n > s.limits.DiskBytes-s.usage.DiskBytes {
		return errors.New("offline session disk budget exhausted")
	}
	s.usage.DiskBytes += n
	s.peaks.DiskBytes = max(s.peaks.DiskBytes, s.usage.DiskBytes)
	return nil
}
func (s *Storage) releaseDisk(n uint64) { s.mu.Lock(); defer s.mu.Unlock(); s.usage.DiskBytes -= n }
func (s *Storage) reserveMemory(ctx context.Context, n uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("offline storage closed")
	}
	s.evictMemoryLocked(n)
	used := s.usage.CachedBytes + s.usage.PinnedBytes + s.usage.PrefetchBytes + s.usage.InFlightBytes
	if n > s.limits.CacheBytes-used {
		return errors.New("offline cache/allocation budget exhausted")
	}
	s.usage.InFlightBytes += n
	s.peaks.MemoryBytes = max(s.peaks.MemoryBytes, used+n)
	return nil
}
func (s *Storage) releaseMemory(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usage.InFlightBytes -= n
}
func (s *Storage) Resources() ResourceUsage { s.mu.Lock(); defer s.mu.Unlock(); return s.usage }
func (s *Storage) Close() error {
	// Failed scratch cleanup remains owned here, even after its caller returns.
	s.mu.Lock()
	registries := make([]*BackingRegistry, 0, len(s.backings))
	for r := range s.backings {
		registries = append(registries, r)
	}
	files := make([]*ScratchFile, 0, len(s.scratch))
	for f := range s.scratch {
		files = append(files, f)
	}
	s.mu.Unlock()
	var cleanupErr error
	for _, r := range registries {
		cleanupErr = errors.Join(cleanupErr, r.Close())
	}
	for _, f := range files {
		cleanupErr = errors.Join(cleanupErr, f.Close())
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usage.DiskBytes != 0 || s.usage.InFlightBytes != 0 || s.usage.PinnedBytes != 0 || len(s.scratch) != 0 {
		return errors.New("offline storage still owns active datasets or readers")
	}
	s.closed = true
	return nil
}

type diskDataset struct {
	compact                     *compactState
	mu                          sync.RWMutex
	queryMu                     sync.Mutex
	closed                      bool
	cleaned                     bool
	storage                     *Storage
	dir                         string
	count                       uint64
	generation                  DatasetGeneration
	stats                       Statistics
	summaries, details, offsets *os.File
	ownedBytes                  uint64
	queries                     map[*diskQuery]struct{}
}

// Manifest timestamps use the same seconds/nanoseconds domain as records.
type manifestTimestamp struct {
	Seconds     int64
	Nanoseconds uint32
}
type manifestStatistics struct {
	Statistics
	First, Last manifestTimestamp
}

func statisticsForManifest(s Statistics) manifestStatistics {
	timestamp := func(t time.Time) manifestTimestamp { return manifestTimestamp{t.Unix(), uint32(t.Nanosecond())} }
	return manifestStatistics{s, timestamp(s.First), timestamp(s.Last)}
}

type Builder struct {
	// Stream ends are maintained under mu by Append and UpdateDetail. Reads and
	// offset-table amendments use ReadAt/WriteAt and never move these cursors.
	summaryEnd, detailEnd uint64
	mu                    sync.Mutex
	d                     *diskDataset
	sources               []SourcePosition
	accumulator           *statisticsAccumulator
	done                  bool
	published             bool
	failure               error
	amended               bool
}

func (s *Storage) NewBuilder(generation DatasetGeneration, sources []SourcePosition) (*Builder, error) {
	if len(sources) > int(s.limits.MaxSources) {
		return nil, fmt.Errorf("offline source count exceeds %d", s.limits.MaxSources)
	}
	var sourceBytes uint64
	if err := measureMemory(reflect.ValueOf(sources), &sourceBytes, s.limits.MaxRecordBytes); err != nil {
		return nil, fmt.Errorf("offline source identities: %w", err)
	}
	dir, err := os.MkdirTemp(s.limits.Directory, "lippycat-offline-")
	if err != nil {
		return nil, fmt.Errorf("create private offline session: %w", err)
	}
	d := &diskDataset{storage: s, dir: dir, generation: generation, queries: make(map[*diskQuery]struct{})}
	b := &Builder{d: d, summaryEnd: streamHeaderBytes, detailEnd: streamHeaderBytes, sources: append([]SourcePosition(nil), sources...), accumulator: newStatisticsAccumulator()}
	for _, entry := range []struct {
		name   string
		kind   uint16
		target **os.File
	}{{"summaries", 1, &d.summaries}, {"details", 2, &d.details}, {"offsets", 3, &d.offsets}} {
		f, e := os.OpenFile(filepath.Join(dir, entry.name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return nil, errors.Join(e, b.Close())
		}
		*entry.target = f
		var header [16]byte
		copy(header[:], "LCODATA\x00")
		binary.LittleEndian.PutUint16(header[8:], RecordSchemaVersion)
		binary.LittleEndian.PutUint16(header[10:], entry.kind)
		if e = b.write(f, header[:]); e != nil {
			return nil, errors.Join(e, b.Close())
		}
	}
	return b, nil
}
func (b *Builder) write(f *os.File, p []byte) error {
	if err := b.d.storage.reserveDisk(uint64(len(p))); err != nil {
		return err
	}
	b.d.ownedBytes += uint64(len(p))
	n, err := f.Write(p)
	if err != nil {
		return fmt.Errorf("write offline %s: %w", f.Name(), err)
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

// Append snapshots a finalized packet and assigns its zero-based dataset ID.
// The supplied ID and Token are ignored; source positions and packet metadata
// are persisted unchanged. After any failure only Close is permitted.
func (b *Builder) Append(ctx context.Context, detail Detail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return errors.New("offline builder closed")
	}
	if b.failure != nil {
		return b.failure
	}
	var err error
	if b.d.compact != nil {
		err = errors.New("compact builder requires AppendCompact locator")
	} else {
		err = b.append(ctx, detail)
	}
	if err != nil {
		b.failure = err
	}
	return err
}
func (b *Builder) append(ctx context.Context, detail Detail) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d := b.d
	if detail.Packet.Length < 0 {
		return errors.New("offline packet length must be nonnegative")
	}
	if uint64(detail.Packet.Length) > ^uint64(0)-b.accumulator.stats.Bytes {
		return errors.New("offline packet byte total exceeds uint64 range")
	}
	if d.count >= (uint64(^uint64(0)>>1)-16)/32 {
		return errors.New("offline packet offset limit exceeded")
	}
	detail.ID = PacketID(d.count)
	detail.Token = Token{}
	summary := NewSummary(detail.ID, detail.Packet)
	sm, err := recordMemory(summary, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	dm, err := recordMemory(detail, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	reservation := sm + dm + 2*(d.storage.limits.MaxRecordBytes+frameHeaderBytes)
	if err = d.storage.reserveMemory(ctx, reservation); err != nil {
		return err
	}
	defer d.storage.releaseMemory(reservation)
	so, do := b.summaryEnd, b.detailEnd
	sw := &builderWriter{b: b, f: d.summaries}
	sn, err := writeRecord(sw, 1, detail.ID, summary, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	dw := &builderWriter{b: b, f: d.details}
	dn, err := writeRecord(dw, 2, detail.ID, detail, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	var offset [32]byte
	for i, v := range []uint64{uint64(so), sn, uint64(do), dn} {
		binary.LittleEndian.PutUint64(offset[i*8:], v)
	}
	if err = b.write(d.offsets, offset[:]); err != nil {
		return err
	}
	b.summaryEnd += sn
	b.detailEnd += dn
	b.accumulator.Add(summary)
	d.count++
	return nil
}

type builderWriter struct {
	b *Builder
	f *os.File
}

func (w *builderWriter) Write(p []byte) (int, error) {
	if err := w.b.write(w.f, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Finish publishes only after all writes, flushes and writer closes succeed.
// The caller must first drain analyzers and finalize deferred metadata. On
// success ownership transfers to Dataset; on failure the caller must Close.
func (b *Builder) Finish(ctx context.Context) (dataset Dataset, finishErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() {
		if finishErr != nil {
			b.failure = finishErr
		}
	}()
	if b.done {
		return nil, errors.New("offline builder closed")
	}
	if b.failure != nil {
		return nil, b.failure
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.d.compact != nil {
		if err := b.flushCompact(); err != nil {
			return nil, err
		}
		if err := b.d.compact.registry.Validate(); err != nil {
			return nil, err
		}
		if err := b.d.compact.registry.Seal(); err != nil {
			return nil, err
		}
	}
	if b.amended {
		if err := b.rebuildStatistics(ctx); err != nil {
			return nil, err
		}
	}
	for _, f := range []*os.File{b.d.summaries, b.d.details, b.d.offsets} {
		if err := f.Sync(); err != nil {
			b.failure = fmt.Errorf("flush offline stream: %w", err)
			return nil, b.failure
		}
	}
	// Close the writing handles before publication so delayed close failures
	// cannot yield a completed dataset. Readers receive fresh read-only handles.
	for _, target := range []**os.File{&b.d.summaries, &b.d.details, &b.d.offsets} {
		name := (*target).Name()
		if err := (*target).Close(); err != nil {
			b.failure = fmt.Errorf("close offline writer: %w", err)
			return nil, b.failure
		}
		*target = nil
		f, err := os.Open(name)
		if err != nil {
			b.failure = fmt.Errorf("open completed offline stream: %w", err)
			return nil, b.failure
		}
		*target = f
	}
	b.d.stats = b.accumulator.Snapshot()
	lengths := map[string]int64{}
	for _, f := range []*os.File{b.d.summaries, b.d.details, b.d.offsets} {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		lengths[filepath.Base(f.Name())] = st.Size()
	}
	var registries *compactRegistries
	if b.d.compact != nil {
		registries = &b.d.compact.registries
	}
	completion, completionMemory, err := b.compactCompletion(ctx)
	if err != nil {
		return nil, err
	}
	defer b.d.storage.releaseMemory(completionMemory)
	manifest := struct {
		Version           uint16
		Generation        DatasetGeneration
		Sources           []SourcePosition
		Count             uint64
		Statistics        manifestStatistics
		StreamLengths     map[string]int64
		AnalysisVersion   string
		Complete          bool
		CompactRegistries *compactRegistries `json:",omitempty"`
		Compact           *compactCompletion `json:",omitempty"`
	}{b.d.schemaVersion(), b.d.generation, b.sources, b.d.count, statisticsForManifest(b.d.stats), lengths, "1", true, registries, completion}
	// Preflight source/statistics strings and maps before JSON allocates escaped
	// text. This independently bounds the manifest serializer, not just records.
	var manifestMemory uint64
	if err := measureMemory(reflect.ValueOf(manifest), &manifestMemory, b.d.storage.limits.CacheBytes/16); err != nil {
		return nil, fmt.Errorf("offline manifest allocation: %w", err)
	}
	reservation := manifestMemory*16 + 4096
	if err := b.d.storage.reserveMemory(ctx, reservation); err != nil {
		return nil, err
	}
	defer b.d.storage.releaseMemory(reservation)
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(b.d.dir, "manifest.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = b.write(f, payload)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		b.failure = err
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err = os.Rename(filepath.Join(b.d.dir, "manifest.tmp"), filepath.Join(b.d.dir, "manifest")); err != nil {
		b.failure = err
		return nil, err
	}
	b.done = true
	b.published = true
	return b.d, nil
}
func (b *Builder) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.published {
		return nil
	}
	b.done = true
	return b.d.Close()
}
func (d *diskDataset) Generation() DatasetGeneration { return d.generation }
func (d *diskDataset) Count() uint64                 { return d.count }
func (d *diskDataset) Statistics() Statistics        { return cloneStatistics(d.stats) }
func (d *diskDataset) Resources() ResourceUsage      { return d.storage.Resources() }
func (d *diskDataset) read(ctx context.Context, id PacketID, kind uint16, value any) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := d.validateStreams(); err != nil {
		return 0, err
	}
	f := d.summaries
	if kind == 2 {
		f = d.details
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return d.readValidated(ctx, id, kind, uint64(st.Size()), value)
}

func (d *diskDataset) validateStreams() error {
	if d.compact != nil {
		return d.validateCompactStreams()
	}
	if err := readStreamHeader(d.offsets, 3); err != nil {
		return err
	}
	if err := readStreamHeader(d.summaries, 1); err != nil {
		return err
	}
	if err := readStreamHeader(d.details, 2); err != nil {
		return err
	}
	return nil
}

// readValidated checks each offset and frame against an already validated
// stream. Completed datasets are immutable while their read lock is held, so
// a query can validate headers and snapshot stream length once for its scan.
func (d *diskDataset) readValidated(ctx context.Context, id PacketID, kind uint16, streamSize uint64, value any) (uint64, error) {
	if d.compact != nil {
		return d.readCompact(ctx, id, kind, value)
	}
	if uint64(id) >= d.count {
		return 0, fmt.Errorf("offline packet ID %d out of range", id)
	}
	if uint64(id) > (uint64(^uint64(0)>>1)-16)/32 {
		return 0, errors.New("offline offset overflow")
	}
	var offset [32]byte
	if _, err := d.offsets.ReadAt(offset[:], 16+int64(id)*32); err != nil {
		return 0, fmt.Errorf("read packet offsets: %w", err)
	}
	pos := 0
	f := d.summaries
	if kind == 2 {
		pos = 16
		f = d.details
	}
	off := binary.LittleEndian.Uint64(offset[pos:])
	size := binary.LittleEndian.Uint64(offset[pos+8:])
	if off < 16 || off > streamSize || size > streamSize-off {
		return 0, errors.New("offline corrupt record offset/length")
	}
	return d.readCachedRecord(ctx, f, off, size, kind, id, value)
}
func (d *diskDataset) readSummary(ctx context.Context, id PacketID) (Summary, uint64, error) {
	var v Summary
	n, e := d.read(ctx, id, 1, &v)
	return v, n, e
}
func (d *diskDataset) readDetail(ctx context.Context, id PacketID) (Detail, uint64, error) {
	var v Detail
	n, e := d.read(ctx, id, 2, &v)
	return v, n, e
}
func (d *diskDataset) Detail(ctx context.Context, token Token, id PacketID) (Detail, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return Detail{}, errors.New("offline dataset closed")
	}
	if token.Dataset != d.generation {
		return Detail{}, errors.New("offline dataset generation mismatch")
	}
	v, n, err := d.readDetail(ctx, id)
	if err != nil {
		return Detail{}, err
	}
	d.storage.releaseMemory(n)
	v.Token = token
	return v, nil
}
func (d *diskDataset) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cleaned {
		if d.compact != nil {
			return d.closeCompact()
		}
		return nil
	}
	var err error
	if d.compact != nil {
		err = errors.Join(err, d.closeCompact())
	}
	if !d.closed {
		d.closed = true
		d.storage.discardDatasetCache(d)
		for q := range d.queries {
			err = errors.Join(err, q.closeLocked())
		}
		for _, target := range []**os.File{&d.summaries, &d.details, &d.offsets} {
			if *target != nil {
				err = errors.Join(err, (*target).Close())
				*target = nil
			}
		}
	}
	if e := os.RemoveAll(d.dir); e != nil {
		err = errors.Join(err, fmt.Errorf("remove private offline session: %w", e))
	} else {
		d.storage.releaseDisk(d.ownedBytes)
		d.ownedBytes = 0
		d.cleaned = true
	}
	return err
}
