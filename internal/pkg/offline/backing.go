package offline

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
)

// BackingPolicy fixes source ownership for a complete offline session.
type BackingPolicy string

const (
	BackingSource   BackingPolicy = "source"
	BackingSnapshot BackingPolicy = "snapshot"
)

func ParseBackingPolicy(s string) (BackingPolicy, error) {
	if s == "" {
		s = "source"
	}
	p := BackingPolicy(s)
	if p != BackingSource && p != BackingSnapshot {
		return "", fmt.Errorf("invalid offline backing policy %q (want source or snapshot)", s)
	}
	return p, nil
}

var ErrSourceChanged = errors.New("offline source changed")
var ErrInvalidLocator = errors.New("invalid offline backing locator")

// SourceChangeError deliberately contains no packet content.
type SourceChangeError struct {
	SourceIndex             int
	SourceID                uint32
	BackingID               uint32
	Path, Operation, Reason string
	Err                     error
}

func (e *SourceChangeError) Error() string {
	return fmt.Sprintf("offline source %d backing %d %q: %s: %s: %v", e.SourceIndex, e.BackingID, e.Path, e.Operation, e.Reason, e.Err)
}
func (e *SourceChangeError) Unwrap() error        { return e.Err }
func (e *SourceChangeError) Is(target error) bool { return target == ErrSourceChanged }

// Locator references exact effective bytes, independent of a source pathname.
type Locator struct {
	BackingID uint32
	Offset    int64
	Length    uint32
	Digest    [32]byte
}

// SourceIdentity describes the original argument, even when bytes are now
// served by a decompressed or derived backing. Info is the original fstat
// snapshot, retaining platform identity and modification/change metadata.
type SourceIdentity struct {
	SourceID    uint32
	Info        os.FileInfo
	SourceIndex int
	Path        string
	Size        int64
	Digest      [32]byte
	Policy      BackingPolicy
	Compressed  bool
}

type BackingKind uint8

const (
	BackingKindSource BackingKind = iota + 1
	BackingKindSnapshot
	BackingKindDecompressed
	BackingKindDerived
)

type BackingDescription struct {
	Kind   BackingKind
	Size   int64
	Source SourceIdentity
}

type BackingInput struct {
	Compressed bool
	lease      *BackingLease
	ID         uint32
	Reader     io.Reader
	scan       *backingScanReader
	Size       int64
	Digest     [32]byte
}

func (b *BackingInput) Close() error { return b.lease.Close() }

type ownedBacking struct {
	identity      SourceIdentity
	kind          BackingKind
	file          *os.File
	scratch       *ScratchFile
	sourceIndex   int
	path          string
	info          os.FileInfo
	size          int64
	derived       bool
	charge        uint64
	identityReady bool
}

// BackingRegistry owns every handle until its last read lease is released.
// Close is retryable; callers close registries before their shared Storage.
type BackingRegistry struct {
	mu      sync.Mutex
	cond    *sync.Cond
	storage *Storage
	entries []*ownedBacking
	leases  int
	closing bool
	sealed  bool
	failure error
}

func (s *Storage) NewBackingRegistry() *BackingRegistry {
	r := &BackingRegistry{storage: s}
	r.cond = sync.NewCond(&r.mu)
	s.mu.Lock()
	if s.backings == nil {
		s.backings = make(map[*BackingRegistry]struct{})
	}
	s.backings[r] = struct{}{}
	s.mu.Unlock()
	return r
}
func (r *BackingRegistry) changed(b *ownedBacking, id uint32, op, reason string, err error) error {
	e := &SourceChangeError{SourceIndex: b.sourceIndex, SourceID: uint32(b.sourceIndex) + 1, BackingID: id, Path: b.path, Operation: op, Reason: reason, Err: err}
	r.failure = e
	return e
}
func (r *BackingRegistry) check(b *ownedBacking, id uint32, op string) error {
	if b.scratch != nil {
		return nil
	}
	info, err := b.file.Stat()
	if err != nil {
		return r.changed(b, id, op, "identity", err)
	}
	if !os.SameFile(info, b.info) {
		return r.changed(b, id, op, "identity", nil)
	}
	if info.Size() != b.info.Size() {
		return r.changed(b, id, op, "size", nil)
	}
	if !info.ModTime().Equal(b.info.ModTime()) {
		return r.changed(b, id, op, "metadata", nil)
	}
	return nil
}

// Open validates the complete original source before returning a seekable parser
// reader. gzip identity always hashes compressed bytes, even with snapshot policy.
func (r *BackingRegistry) Open(ctx context.Context, path string, sourceIndex int, policy BackingPolicy, compressed bool) (*BackingInput, error) {
	return r.open(ctx, path, sourceIndex, policy, compressed, false)
}

// OpenScan fuses identity with mandatory parsing, snapshot copying or decompression.
// Plain source identity becomes available after FinishScan; snapshot and gzip
// identity is ready when their mandatory preparation finishes.
func (r *BackingRegistry) OpenScan(ctx context.Context, path string, sourceIndex int, policy BackingPolicy, compressed bool) (*BackingInput, error) {
	return r.open(ctx, path, sourceIndex, policy, compressed, true)
}

func (r *BackingRegistry) open(ctx context.Context, path string, sourceIndex int, policy BackingPolicy, compressed, scan bool) (*BackingInput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.sealed {
		return nil, errors.New("offline backings closed")
	}
	if r.failure != nil {
		return nil, r.failure
	}
	if sourceIndex < 0 || uint64(sourceIndex) >= uint64(r.storage.limits.MaxSources) {
		return nil, errors.New("offline source argument index out of bounds")
	}
	var policyErr error
	policy, policyErr = ParseBackingPolicy(string(policy))
	if policyErr != nil {
		return nil, policyErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sources := 0
	for _, b := range r.entries {
		if !b.derived {
			sources++
		}
	}
	if sources >= int(r.storage.limits.MaxSources) {
		return nil, errors.New("offline source count limit exceeded")
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("offline source must be a regular seekable file")
	}
	charge := uint64(512 + len(path))
	if err := r.storage.reserveMemory(ctx, charge); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		r.storage.releaseMemory(charge)
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		r.storage.releaseMemory(charge)
		return nil, errors.Join(err, f.Close())
	}
	b := &ownedBacking{file: f, sourceIndex: sourceIndex, path: path, info: info, size: info.Size(), charge: charge}
	r.entries = append(r.entries, b)
	id := uint32(len(r.entries))
	fail := func(err error) (*BackingInput, error) { r.failure = err; return nil, err }
	if info.Size() < 0 || !info.Mode().IsRegular() {
		return fail(errors.New("offline source must be a regular seekable file"))
	}
	var magic [2]byte
	if n, e := f.ReadAt(magic[:], 0); e != nil && e != io.EOF {
		return fail(e)
	} else if n == 2 && magic == [2]byte{0x1f, 0x8b} {
		compressed = true
	}
	const bufferSize = 64 * 1024
	if err := r.storage.reserveMemory(ctx, bufferSize); err != nil {
		return fail(err)
	}
	defer r.storage.releaseMemory(bufferSize)
	buf := make([]byte, bufferSize)
	h := sha256.New()
	var writer io.Writer = h
	var snapshot *ScratchFile
	if policy == BackingSnapshot {
		snapshot, err = r.storage.NewScratchFile()
		if err != nil {
			return fail(err)
		}
		writer = io.MultiWriter(h, snapshot)
	}
	var n int64
	var digest [32]byte
	if !scan || policy == BackingSnapshot {
		n, err = copyBacking(ctx, writer, io.NewSectionReader(f, 0, info.Size()), buf)
		if err != nil {
			if snapshot != nil {
				err = errors.Join(err, snapshot.Close())
			}
			return fail(err)
		}
		if n != info.Size() {
			if snapshot != nil {
				err = snapshot.Close()
			}
			return fail(errors.Join(r.changed(b, id, "scan", "short_read", io.ErrUnexpectedEOF), err))
		}
		if err = r.check(b, id, "scan"); err != nil {
			if snapshot != nil {
				err = errors.Join(err, snapshot.Close())
			}
			return fail(err)
		}
		copy(digest[:], h.Sum(nil))

		b.identityReady = true
	}
	if snapshot != nil {
		if err = snapshot.file.Sync(); err == nil {
			h.Reset()
			var validated int64
			validated, err = copyBacking(ctx, h, io.NewSectionReader(snapshot.file, 0, n), buf)
			if err == nil && validated != n {
				err = io.ErrUnexpectedEOF
			}
			if err == nil && !equalDigest(h.Sum(nil), digest) {
				err = errors.New("offline snapshot digest mismatch")
			}
		}
		if err != nil {
			return fail(errors.Join(err, snapshot.Close()))
		}
		if err = f.Close(); err != nil {
			return fail(errors.Join(err, snapshot.Close()))
		}
		b.file = snapshot.file
		b.scratch = snapshot
		b.info = nil
	}
	// Account conservatively for the inflater window, buffered input and gzip
	// reader state separately from the copy buffer.
	if compressed {
		if e := r.storage.reserveMemory(ctx, 256*1024); e != nil {
			return fail(e)
		}
		defer r.storage.releaseMemory(256 * 1024)
		spool, e := r.storage.NewScratchFile()
		if e != nil {
			return fail(e)
		}
		var compressedReader io.Reader = io.NewSectionReader(b.file, 0, b.size)
		var compressedScan *backingScanReader
		if scan && policy != BackingSnapshot {
			compressedScan = &backingScanReader{reader: compressedReader, hash: sha256.New()}
			compressedReader = compressedScan
		}
		gz, e := gzip.NewReader(compressedReader)
		if e != nil {
			return fail(errors.Join(e, spool.Close()))
		}
		size, e := copyBacking(ctx, spool, gz, buf)
		e = errors.Join(e, gz.Close())
		if e == nil && compressedScan != nil {
			_, e = copyBacking(ctx, io.Discard, compressedScan, buf)
			if e == nil && compressedScan.bytes != info.Size() {
				e = io.ErrUnexpectedEOF
			}
			if e == nil {
				copy(digest[:], compressedScan.hash.Sum(nil))
				b.identityReady = true
			}
		}
		if e == nil {
			e = r.check(b, id, "decompress")
		}
		if e == nil {
			e = spool.file.Sync()
		}
		if e != nil {
			return fail(errors.Join(e, spool.Close()))
		}
		// Keep the compressed snapshot charged until successful cleanup. Original
		// source handles are closed only after checksum completion and metadata checks.
		if b.scratch != nil {
			e = b.scratch.Close()
		} else {
			e = b.file.Close()
		}
		if e != nil {
			return fail(errors.Join(e, spool.Close()))
		}
		b.file = spool.file
		b.scratch = spool
		b.info = nil
		b.size = size
	}
	if err := r.storage.reserveMemory(ctx, 128); err != nil {
		return fail(err)
	}
	b.kind = BackingKindSource
	if policy == BackingSnapshot {
		b.kind = BackingKindSnapshot
	}
	if compressed {
		b.kind = BackingKindDecompressed
	}
	b.identity = SourceIdentity{SourceID: uint32(sourceIndex) + 1, Info: info, SourceIndex: sourceIndex, Path: path, Size: info.Size(), Digest: digest, Policy: policy, Compressed: compressed}
	r.leases++
	input := &BackingInput{ID: id, Reader: io.NewSectionReader(b.file, 0, b.size), Size: b.size, Digest: digest, Compressed: compressed, lease: &BackingLease{registry: r, size: 128}}
	if !b.identityReady {
		input.scan = &backingScanReader{reader: input.Reader, hash: sha256.New()}
		input.Reader = input.scan
	}
	return input, nil
}
func equalDigest(v []byte, d [32]byte) bool {
	if len(v) != len(d) {
		return false
	}
	for i := range d {
		if v[i] != d[i] {
			return false
		}
	}
	return true
}
func copyBacking(ctx context.Context, w io.Writer, rd io.Reader, buf []byte) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, e := rd.Read(buf)
		if n > 0 {
			if int64(n) > math.MaxInt64-total {
				return total, errors.New("offline backing size overflow")
			}
			m, err := w.Write(buf[:n])
			total += int64(m)
			if err != nil {
				return total, err
			}
			if m != n {
				return total, io.ErrShortWrite
			}
		}
		if e == io.EOF {
			return total, nil
		}
		if e != nil {
			return total, e
		}
	}
}
func (r *BackingRegistry) Locator(id uint32, offset int64, data []byte) (Locator, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return Locator{}, errors.New("offline backings closed")
	}
	if r.failure != nil {
		return Locator{}, r.failure
	}
	if id == 0 || uint64(id) > uint64(len(r.entries)) || offset < 0 || uint64(len(data)) > r.storage.limits.MaxRecordBytes || uint64(len(data)) > math.MaxUint32 {
		return Locator{}, ErrInvalidLocator
	}
	b := r.entries[id-1]
	if offset > b.size || int64(len(data)) > b.size-offset {
		return Locator{}, ErrInvalidLocator
	}
	return Locator{id, offset, uint32(len(data)), sha256.Sum256(data)}, nil
}
func (r *BackingRegistry) AppendDerived(ctx context.Context, sourceIndex int, data []byte) (Locator, error) {
	if sourceIndex < 0 || uint64(sourceIndex) >= uint64(r.storage.limits.MaxSources) {
		return Locator{}, ErrInvalidLocator
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.sealed {
		return Locator{}, errors.New("offline backings closed")
	}
	if r.failure != nil {
		return Locator{}, r.failure
	}
	if err := ctx.Err(); err != nil {
		return Locator{}, err
	}
	if uint64(len(data)) > r.storage.limits.MaxRecordBytes || uint64(len(data)) > math.MaxUint32 {
		return Locator{}, ErrInvalidLocator
	}
	var b *ownedBacking
	var id uint32
	for i, v := range r.entries {
		if v.derived && v.sourceIndex == sourceIndex {
			b = v
			id = uint32(i + 1)
			break
		}
	}
	if b == nil {
		if err := r.storage.reserveMemory(ctx, 512); err != nil {
			return Locator{}, err
		}
		s, err := r.storage.NewScratchFile()
		if err != nil {
			r.storage.releaseMemory(512)
			return Locator{}, err
		}
		identityReady := false
		identity := SourceIdentity{SourceID: uint32(sourceIndex) + 1, SourceIndex: sourceIndex}
		for _, v := range r.entries {
			if !v.derived && v.sourceIndex == sourceIndex {
				identity = v.identity
				identityReady = v.identityReady
				break
			}
		}
		b = &ownedBacking{file: s.file, scratch: s, derived: true, sourceIndex: sourceIndex, charge: 512, identity: identity, identityReady: identityReady, kind: BackingKindDerived}
		r.entries = append(r.entries, b)
		id = uint32(len(r.entries))
	}
	offset := b.size
	if int64(len(data)) > math.MaxInt64-offset {
		return Locator{}, ErrInvalidLocator
	}
	n, err := b.scratch.Write(data)
	b.size += int64(n)
	if err != nil {
		r.failure = err
		return Locator{}, err
	}
	return Locator{id, offset, uint32(n), sha256.Sum256(data)}, nil
}

// BackingLease bytes are owned until Close; keeping a lease pins registry Close.
type BackingLease struct {
	Bytes    []byte
	once     sync.Once
	registry *BackingRegistry
	size     uint64
}

func (l *BackingLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		r := l.registry
		r.mu.Lock()
		defer r.mu.Unlock()
		l.Bytes = nil
		r.storage.releaseMemory(l.size)
		r.leases--
		r.cond.Broadcast()
	})
	return nil
}
func (r *BackingRegistry) Read(ctx context.Context, loc Locator) (*BackingLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, errors.New("offline backings closed")
	}
	if r.failure != nil {
		return nil, r.failure
	}
	if loc.BackingID == 0 || uint64(loc.BackingID) > uint64(len(r.entries)) || loc.Offset < 0 || uint64(loc.Length) > r.storage.limits.MaxRecordBytes || uint64(loc.Length) > uint64(int(^uint(0)>>1)) {
		return nil, ErrInvalidLocator
	}
	b := r.entries[loc.BackingID-1]
	if loc.Offset > b.size || int64(loc.Length) > b.size-loc.Offset {
		return nil, ErrInvalidLocator
	}
	if err := r.check(b, loc.BackingID, "read"); err != nil {
		return nil, err
	}
	if err := r.storage.reserveMemory(ctx, uint64(loc.Length)+128); err != nil {
		return nil, err
	}
	data := make([]byte, int(loc.Length))
	_, err := b.file.ReadAt(data, loc.Offset)
	if err != nil {
		if b.scratch == nil {
			err = r.changed(b, loc.BackingID, "read", "short_read", err)
		} else {
			err = fmt.Errorf("%w: %v", ErrInvalidLocator, err)
		}
	}
	if err == nil && sha256.Sum256(data) != loc.Digest {
		if b.scratch == nil {
			err = r.changed(b, loc.BackingID, "read", "digest", nil)
		} else {
			err = fmt.Errorf("%w: digest mismatch", ErrInvalidLocator)
		}
	}
	if err == nil {
		err = r.check(b, loc.BackingID, "read")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		r.storage.releaseMemory(uint64(loc.Length) + 128)
		return nil, err
	}
	r.leases++
	return &BackingLease{Bytes: data, registry: r, size: uint64(loc.Length) + 128}, nil
}
func (r *BackingRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closing = true
	for r.leases > 0 {
		r.cond.Wait()
	}
	var result error
	for _, b := range r.entries {
		if b.file == nil {
			continue
		}
		var err error
		if b.scratch != nil {
			err = b.scratch.Close()
		} else {
			err = b.file.Close()
			if errors.Is(err, os.ErrClosed) {
				err = nil
			}
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		b.file = nil
	}
	if result == nil {
		for _, b := range r.entries {
			r.storage.releaseMemory(b.charge)
			b.charge = 0
		}
		r.entries = nil
		r.storage.mu.Lock()
		delete(r.storage.backings, r)
		r.storage.mu.Unlock()
	}
	return result
}

// Validate checks source stability after the parser has completed its scan.
func (r *BackingRegistry) Validate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return errors.New("offline backings closed")
	}
	if r.failure != nil {
		return r.failure
	}
	for i, b := range r.entries {
		if err := r.check(b, uint32(i+1), "scan"); err != nil {
			return err
		}
	}
	return nil
}

// Identity returns the immutable original-input identity, including compressed
// byte size/hash after its decompressed backing replaces the original handle.
func (r *BackingRegistry) Identity(id uint32) (SourceIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == 0 || uint64(id) > uint64(len(r.entries)) {
		return SourceIdentity{}, ErrInvalidLocator
	}
	if !r.entries[id-1].identityReady {
		return SourceIdentity{}, errors.New("offline source identity scan is incomplete")
	}
	return r.entries[id-1].identity, nil
}

// Describe exposes the backing kind separately from original source context.
func (r *BackingRegistry) Describe(id uint32) (BackingDescription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == 0 || uint64(id) > uint64(len(r.entries)) {
		return BackingDescription{}, ErrInvalidLocator
	}
	b := r.entries[id-1]
	return BackingDescription{Kind: b.kind, Size: b.size, Source: b.identity}, nil
}
