package offline

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
)

// Match vectors use a dedicated fixed-width schema: LCQUERY/version byte,
// dataset and query uint64 generations, followed by ordered uint64 IDs.
const queryHeaderBytes = 24
const queryEntryBytes = 8

var queryMagic = [8]byte{'L', 'C', 'Q', 'U', 'E', 'R', 'Y', 1}

type diskQuery struct {
	mu             sync.RWMutex
	dataset        *diskDataset
	token          Token
	count          uint64
	stats          Statistics
	file           *os.File
	path, manifest string
	bytes          uint64
	manifestBytes  uint64
	closed         bool
	identity       bool
}

// AllPackets returns an unfiltered identity projection without scanning summaries
// or creating a dataset-sized match vector. Wrapped/custom datasets can supply
// their ordinary Query implementation; production storage uses implicit IDs.
func AllPackets(ctx context.Context, dataset Dataset, token Token) (Query, error) {
	d, ok := dataset.(*diskDataset)
	if !ok {
		return dataset.Query(ctx, QuerySpec{Token: token})
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.closed {
		return nil, fmt.Errorf("offline dataset closed")
	}
	if token.Dataset != d.generation {
		return nil, fmt.Errorf("offline query dataset generation mismatch")
	}
	q := &diskQuery{dataset: d, token: token, count: d.count, stats: d.stats, identity: true}
	d.queryMu.Lock()
	d.queries[q] = struct{}{}
	d.queryMu.Unlock()
	return q, nil
}

func (d *diskDataset) Query(ctx context.Context, spec QuerySpec) (result Query, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return nil, fmt.Errorf("offline dataset closed")
	}
	if spec.Token.Dataset != d.generation {
		return nil, fmt.Errorf("offline query dataset generation mismatch")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if spec.Expression != nil {
		if err = spec.Expression.Validate(); err != nil {
			return nil, err
		}
		if err = d.storage.reserveMemory(ctx, spec.Expression.AccountedBytes()); err != nil {
			return nil, err
		}
		defer d.storage.releaseMemory(spec.Expression.AccountedBytes())
	}
	if d.compact != nil && spec.Match == nil && spec.Expression == nil && spec.related == nil {
		if err = d.validateStreams(); err != nil {
			return nil, err
		}
		q := &diskQuery{dataset: d, token: spec.Token, count: d.count, stats: d.stats, identity: true}
		if spec.Progress != nil {
			spec.Progress(QueryProgress{Token: spec.Token, Total: d.count})
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			if d.count != 0 {
				spec.Progress(QueryProgress{Token: spec.Token, Scanned: d.count, Matched: d.count, Total: d.count})
			}
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		d.queryMu.Lock()
		d.queries[q] = struct{}{}
		d.queryMu.Unlock()
		return q, nil
	}
	if err = d.validateStreams(); err != nil {
		return nil, err
	}
	summaryStat, err := d.summaries.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat offline summaries: %w", err)
	}
	// Snapshot the mutable descriptor immediately; predicates are immutable by contract.
	var descriptionBytes uint64
	for _, description := range spec.Description {
		if err := addBudget(&descriptionBytes, uint64(len(description))+16, d.storage.limits.MaxRecordBytes); err != nil {
			return nil, fmt.Errorf("query description: %w", err)
		}
	}
	if err = d.storage.reserveMemory(ctx, descriptionBytes); err != nil {
		return nil, err
	}
	defer d.storage.releaseMemory(descriptionBytes)
	spec.Description = append([]string(nil), spec.Description...)
	var f *os.File
	q := &diskQuery{dataset: d, token: spec.Token}
	defer func() {
		if result == nil {
			err = errors.Join(err, q.closeLocked())
		}
	}()
	createVector := func() error {
		var err error
		f, err = os.CreateTemp(d.dir, "query-*.ids")
		if err != nil {
			return fmt.Errorf("create offline query: %w", err)
		}
		q.file, q.path, q.manifest = f, f.Name(), f.Name()+".complete"
		var header [queryHeaderBytes]byte
		copy(header[:], queryMagic[:])
		binary.LittleEndian.PutUint64(header[8:16], uint64(d.generation))
		binary.LittleEndian.PutUint64(header[16:24], uint64(spec.Token.Query))
		return q.write(header[:])
	}
	if d.compact == nil {
		if err = createVector(); err != nil {
			return nil, err
		}
	}
	stats := newStatisticsAccumulator()
	reportProgress := func(scanned uint64) {
		if spec.Progress != nil {
			spec.Progress(QueryProgress{Token: spec.Token, Scanned: scanned, Matched: q.count, Total: d.count})
		}
	}
	reportProgress(0)
	bufferBytes := min(uint64(32<<10), d.storage.limits.MaxRecordBytes)
	bufferBytes -= bufferBytes % queryEntryBytes
	if d.compact == nil {
		bufferBytes = 0
	}
	if d.compact != nil && bufferBytes < queryEntryBytes {
		return nil, fmt.Errorf("query buffer exceeds memory budget")
	}
	if err = d.storage.reserveMemory(ctx, bufferBytes); err != nil {
		return nil, err
	}
	defer d.storage.releaseMemory(bufferBytes)
	buffer := make([]byte, 0, int(bufferBytes))
	flush := func() error {
		if len(buffer) == 0 {
			return nil
		}
		n, err := f.Write(buffer)
		if err == nil && n != len(buffer) {
			err = io.ErrShortWrite
		}
		buffer = buffer[:0]
		return err
	}
	appendID := func(id PacketID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Charge the vector on admission, before buffered writes reach disk.
		if err := d.storage.reserveDisk(queryEntryBytes); err != nil {
			return err
		}
		q.bytes += queryEntryBytes
		buffer = binary.LittleEndian.AppendUint64(buffer, uint64(id))
		if len(buffer) == cap(buffer) {
			return flush()
		}
		return nil
	}
	// The built-in expression is immutable and does not retain its Record. Reuse
	// this interface target to avoid boxing a complete Summary for each packet.
	var expressionRecord Summary
	visit := func(summary Summary) error {
		matched := true
		if spec.Expression != nil {
			expressionRecord = summary
			matched = spec.Expression.Match(&expressionRecord)
			expressionRecord = Summary{}
		} else if spec.Match != nil {
			matched = spec.Match(summary)
		}
		if spec.related != nil {
			matched = matchesNormalizedFlow(summary, *spec.related)
		}
		if matched {
			stats.Add(summary)
			if d.compact == nil {
				var data [8]byte
				binary.LittleEndian.PutUint64(data[:], uint64(summary.ID))
				if err := q.write(data[:]); err != nil {
					return err
				}
				q.count++
				return ctx.Err()
			}
			if f != nil {
				if err := appendID(summary.ID); err != nil {
					return err
				}
			}
			q.count++
		} else if d.compact != nil && f == nil {
			// A matching prefix is implicit until the first miss. All-match scans
			// never create a vector or consume query disk, regardless of predicate.
			if err := createVector(); err != nil {
				return err
			}
			for id := PacketID(0); uint64(id) < q.count; id++ {
				if err := appendID(id); err != nil {
					return err
				}
			}
		}
		scanned := uint64(summary.ID) + 1
		if d.compact != nil && (scanned%1024 == 0 || scanned == d.count) {
			reportProgress(scanned)
		}
		return ctx.Err()
	}
	if d.compact != nil {
		projection := spec.Expression
		err = d.scanCompactSummaries(ctx, projection, spec.related != nil, visit)
	} else {
		for id := PacketID(0); uint64(id) < d.count; id++ {
			if err = ctx.Err(); err != nil {
				break
			}
			var summary Summary
			var held uint64
			held, err = d.readValidated(ctx, id, 1, uint64(summaryStat.Size()), &summary)
			if err != nil {
				break
			}
			err = visit(summary)
			d.storage.releaseMemory(held)
			scanned := uint64(id) + 1
			if err == nil && (scanned%1024 == 0 || scanned == d.count) {
				reportProgress(scanned)
			}
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if err = flush(); err != nil {
		return nil, fmt.Errorf("flush offline query: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if d.compact != nil && q.count == d.count {
		if err = q.closeLocked(); err != nil {
			return nil, err
		}
		q = &diskQuery{dataset: d, token: spec.Token, count: d.count, stats: d.stats, identity: true}
		d.queryMu.Lock()
		d.queries[q] = struct{}{}
		d.queryMu.Unlock()
		return q, nil
	}
	if err = f.Sync(); err != nil {
		return nil, fmt.Errorf("flush offline query: %w", err)
	}
	// Closing the writer is part of completion. Reopen a read-only handle only
	// after flush and close both succeed, so delayed write errors reject queries.
	closeVectorErr := q.file.Close()
	q.file = nil
	if closeVectorErr != nil {
		return nil, fmt.Errorf("close offline query writer: %w", closeVectorErr)
	}
	q.file, err = os.Open(q.path)
	if err != nil {
		return nil, fmt.Errorf("open completed query vector: %w", err)
	}
	// Publish the complete vector, statistics, and immutable filter description
	// together. Encoding emits each scalar/key directly, never a full manifest
	// buffer whose size grows with matches or retained cardinality.
	q.stats = stats.Snapshot()
	temp := q.manifest + ".tmp"
	mf, createErr := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if createErr != nil {
		return nil, fmt.Errorf("create query manifest: %w", createErr)
	}
	beforeManifest := q.bytes
	writeErr := q.writeManifest(ctx, mf, spec.Description)
	q.manifestBytes = q.bytes - beforeManifest
	syncErr := mf.Sync()
	closeErr := mf.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return nil, fmt.Errorf("write query manifest: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = os.Rename(temp, q.manifest); err != nil {
		return nil, fmt.Errorf("publish query manifest: %w", err)
	}
	d.queryMu.Lock()
	d.queries[q] = struct{}{}
	d.queryMu.Unlock()
	return q, nil
}

func (q *diskQuery) write(p []byte) error { return q.writeTo(q.file, p) }

func (q *diskQuery) writeTo(f *os.File, p []byte) error {
	if err := q.dataset.storage.reserveDisk(uint64(len(p))); err != nil {
		return err
	}
	q.bytes += uint64(len(p))
	n, err := f.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write offline query: %w", err)
	}
	return nil
}

func (q *diskQuery) Token() Token           { return q.token }
func (q *diskQuery) Count() uint64          { return q.count }
func (q *diskQuery) Statistics() Statistics { return cloneStatistics(q.stats) }

func (q *diskQuery) validate() error {
	if q.closed || q.dataset.closed {
		return fmt.Errorf("offline query closed")
	}
	if q.identity {
		return nil
	}
	st, err := q.file.Stat()
	if err != nil {
		return fmt.Errorf("stat offline query: %w", err)
	}
	if q.count > (math.MaxInt64-queryHeaderBytes)/queryEntryBytes || st.Size() != int64(queryHeaderBytes+q.count*queryEntryBytes) {
		return fmt.Errorf("corrupt offline query length")
	}
	var h [queryHeaderBytes]byte
	if _, err := q.file.ReadAt(h[:], 0); err != nil {
		return fmt.Errorf("read query header: %w", err)
	}
	if string(h[:8]) != string(queryMagic[:]) || binary.LittleEndian.Uint64(h[8:16]) != uint64(q.token.Dataset) || binary.LittleEndian.Uint64(h[16:24]) != uint64(q.token.Query) {
		return fmt.Errorf("incompatible or corrupt offline query header")
	}
	mf, err := os.Open(q.manifest)
	if err != nil {
		return fmt.Errorf("open completed query manifest: %w", err)
	}
	var mh [40]byte
	_, readErr := mf.ReadAt(mh[:], 0)
	mst, statErr := mf.Stat()
	closeErr := mf.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return fmt.Errorf("read completed query manifest: %w", err)
	}
	if uint64(mst.Size()) != q.manifestBytes || string(mh[:8]) != "LCQMAN\x00\x01" || binary.LittleEndian.Uint64(mh[8:16]) != uint64(q.token.Dataset) || binary.LittleEndian.Uint64(mh[16:24]) != uint64(q.token.Query) || binary.LittleEndian.Uint64(mh[24:32]) != uint64(q.token.Request) || binary.LittleEndian.Uint64(mh[32:40]) != q.count {
		return fmt.Errorf("corrupt completed query manifest")
	}
	return nil
}

func (q *diskQuery) readID(row uint64) (PacketID, error) {
	var b [queryEntryBytes]byte
	if row >= q.count {
		return 0, fmt.Errorf("query row out of bounds")
	}
	if q.identity {
		return PacketID(row), nil
	}
	if _, err := q.file.ReadAt(b[:], int64(queryHeaderBytes+row*queryEntryBytes)); err != nil {
		return 0, fmt.Errorf("read query ID: %w", err)
	}

	id := PacketID(binary.LittleEndian.Uint64(b[:8]))
	if uint64(id) >= q.dataset.count {
		return 0, fmt.Errorf("corrupt query packet ID %d", id)
	}
	return id, nil
}

func (q *diskQuery) idAt(row uint64) (PacketID, error) {
	id, err := q.readID(row)
	if err != nil {
		return 0, err
	}
	if row > 0 {
		previous, err := q.readID(row - 1)
		if err != nil {
			return 0, err
		}
		if previous >= id {
			return 0, fmt.Errorf("corrupt unordered query IDs")
		}
	}
	return id, nil
}

func (q *diskQuery) Page(ctx context.Context, req PageRequest) (page Page, err error) {
	page = Page{Token: req.Token, Row: req.Row}
	d := q.dataset
	d.mu.RLock()
	defer d.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	if err := q.validate(); err != nil {
		return page, err
	}
	if req.Token.Dataset != q.token.Dataset || req.Token.Query != q.token.Query {
		return page, fmt.Errorf("offline page generation mismatch")
	}
	if req.Limit == 0 || req.MaxBytes == 0 {
		return page, fmt.Errorf("offline page requires positive row and byte limits")
	}
	var held, sliceBytes uint64
	const initialPageCapacity = 16
	rowBytes := uint64(reflect.TypeOf(Summary{}).Size())
	defer func() {
		if err != nil {
			d.storage.releaseMemory(held)
			page = Page{Token: req.Token, Row: req.Row}
			return
		}
		if held != 0 {
			d.storage.mu.Lock()
			d.storage.usage.InFlightBytes -= held
			d.storage.usage.PinnedBytes += held
			d.storage.mu.Unlock()
			page.lease = &pageLease{storage: d.storage, bytes: held}
		}
	}()
	if req.Row < q.count {
		const leaseBytes = 64
		if req.MaxBytes < leaseBytes {
			return page, fmt.Errorf("offline page lease exceeds page byte limit")
		}
		if err := d.storage.reserveMemory(ctx, leaseBytes); err != nil {
			return page, err
		}
		held = leaseBytes
	}
	for row := req.Row; row < q.count && uint64(len(page.Rows)) < uint64(req.Limit); row++ {
		if err := ctx.Err(); err != nil {
			return Page{Token: req.Token, Row: req.Row}, err
		}
		id, err := q.idAt(row)
		if err != nil {
			return page, err
		}
		s, size, err := d.readSummary(ctx, id)
		if err != nil {
			return page, err
		}
		if size > req.MaxBytes-held {
			d.storage.releaseMemory(size)
			if len(page.Rows) == 0 {
				return page, fmt.Errorf("offline summary exceeds page byte limit")
			}
			break
		}
		held += size
		if len(page.Rows) == cap(page.Rows) {
			capacity := min(uint64(req.Limit), q.count-req.Row, max(uint64(initialPageCapacity), uint64(cap(page.Rows))*2))
			// Include spare slice capacity, and reserve the old plus new arrays while
			// copying. Summary reservations deliberately also count each row's struct,
			// making this conservative without hidden append growth.
			newBytes := capacity * rowBytes
			if newBytes > req.MaxBytes-held+sliceBytes {
				capacity = min(capacity, (req.MaxBytes-held+sliceBytes)/rowBytes)
				newBytes = capacity * rowBytes
			}
			if capacity <= uint64(len(page.Rows)) {
				d.storage.releaseMemory(size)
				held -= size
				if len(page.Rows) == 0 {
					return page, fmt.Errorf("offline summary and page allocation exceed page byte limit")
				}
				break
			}
			if err := d.storage.reserveMemory(ctx, newBytes); err != nil {
				d.storage.releaseMemory(size)
				held -= size
				return page, err
			}
			rows := make([]Summary, len(page.Rows), int(capacity))
			copy(rows, page.Rows)
			d.storage.releaseMemory(sliceBytes)
			held += newBytes - sliceBytes
			sliceBytes = newBytes
			page.Rows = rows
		}
		page.Rows = append(page.Rows, s)
	}
	return page, ctx.Err()
}

func (q *diskQuery) Iterate(ctx context.Context, visit func(Detail) error) error {
	if visit == nil {
		return fmt.Errorf("offline iteration requires callback")
	}
	d := q.dataset
	d.mu.RLock()
	defer d.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.iterateLocked(ctx, visit)
}

// iterateLocked requires the dataset and query read locks for the entire visit.
func (q *diskQuery) iterateLocked(ctx context.Context, visit func(Detail) error) error {
	d := q.dataset
	if err := q.validate(); err != nil {
		return err
	}
	for row := uint64(0); row < q.count; row++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, err := q.idAt(row)
		if err != nil {
			return err
		}
		detail, size, err := d.readDetail(ctx, id)
		if err != nil {
			return err
		}
		detail.Token = q.token
		err = func() error { defer d.storage.releaseMemory(size); return visit(detail) }()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (q *diskQuery) Close() error {
	d := q.dataset
	d.mu.RLock()
	defer d.mu.RUnlock()
	return q.closeLocked()
}

// closeLocked holds a dataset lock to exclude dataset cleanup. The query lock
// joins this query's readers without waiting for unrelated dataset detail pins.
func (q *diskQuery) closeLocked() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	var errs []error
	if q.file != nil {
		errs = append(errs, q.file.Close())
	}
	clean := true
	paths := []string{q.path, q.manifest}
	if q.manifest != "" {
		paths = append(paths, q.manifest+".tmp")
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := os.Remove(filepath.Clean(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove query file: %w", err))
			clean = false
		}
	}
	if clean {
		q.dataset.storage.releaseDisk(q.bytes)
		q.bytes = 0
	}
	q.dataset.queryMu.Lock()
	if !clean {
		// The dataset still owns failed-cleanup files; its eventual RemoveAll must
		// release this charge instead of stranding bytes on an inaccessible query.
		q.dataset.ownedBytes += q.bytes
		q.bytes = 0
	}
	delete(q.dataset.queries, q)
	q.dataset.queryMu.Unlock()
	return errors.Join(errs...)
}

func (d *diskDataset) Related(ctx context.Context, token Token, flow Flow) (Query, error) {
	if flow.Source.IsValid() {
		flow.Source = netip.AddrPortFrom(flow.Source.Addr().Unmap(), flow.Source.Port())
	}
	if flow.Destination.IsValid() {
		flow.Destination = netip.AddrPortFrom(flow.Destination.Addr().Unmap(), flow.Destination.Port())
	}
	return d.Query(ctx, QuerySpec{Token: token, related: &flow})
}

func matchesFlow(s Summary, f Flow) bool {
	if f.Source.IsValid() {
		f.Source = netip.AddrPortFrom(f.Source.Addr().Unmap(), f.Source.Port())
	}
	if f.Destination.IsValid() {
		f.Destination = netip.AddrPortFrom(f.Destination.Addr().Unmap(), f.Destination.Port())
	}
	return matchesNormalizedFlow(s, f)
}

func matchesNormalizedFlow(s Summary, f Flow) bool {
	if !f.Source.IsValid() || !f.Destination.IsValid() || f.Source.Port() == 0 || f.Destination.Port() == 0 || (f.Transport != 0 && f.Transport != 6 && f.Transport != 17) {
		return false
	}
	p := s.packet
	transport := p.Transport
	if transport == 0 {
		switch p.Protocol {
		case "TCP", "tcp":
			transport = 6
		case "UDP", "udp":
			transport = 17
		}
	}
	if transport != 0 && transport != 6 && transport != 17 {
		return false
	}
	if f.Transport != 0 && transport != 0 && transport != f.Transport {
		return false
	}
	if f.Node != "" && p.NodeID != "" && f.Node != p.NodeID {
		return false
	}
	src, e1 := netip.ParseAddr(p.SrcIP)
	dst, e2 := netip.ParseAddr(p.DstIP)
	sp, e3 := strconv.ParseUint(p.SrcPort, 10, 16)
	dp, e4 := strconv.ParseUint(p.DstPort, 10, 16)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || sp == 0 || dp == 0 {
		return false
	}
	a, b := netip.AddrPortFrom(src.Unmap(), uint16(sp)), netip.AddrPortFrom(dst.Unmap(), uint16(dp))
	x, y := f.Source, f.Destination
	return (a == x && b == y) || (a == y && b == x)
}

// Query completion manifests use LCQMAN/version byte, token/count, scalar
// statistics, then length-prefixed frequency maps, approximation labels and
// descriptions. Every integer is little endian uint64. Strings stream in
// bounded chunks, so arbitrary supported metadata cannot inflate scratch RAM.
func (q *diskQuery) writeManifest(ctx context.Context, f *os.File, descriptions []string) error {
	if err := q.writeTo(f, []byte{'L', 'C', 'Q', 'M', 'A', 'N', 0, 1}); err != nil {
		return err
	}
	number := func(n uint64) error { var b [8]byte; binary.LittleEndian.PutUint64(b[:], n); return q.writeTo(f, b[:]) }
	str := func(s string) error {
		if err := number(uint64(len(s))); err != nil {
			return err
		}
		var chunk [4096]byte
		for len(s) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := copy(chunk[:], s)
			if err := q.writeTo(f, chunk[:n]); err != nil {
				return err
			}
			s = s[n:]
		}
		return nil
	}
	s := q.stats
	for _, n := range []uint64{uint64(q.token.Dataset), uint64(q.token.Query), uint64(q.token.Request), q.count, s.Packets, s.Bytes, s.MinPacketSize, s.MaxPacketSize, s.Sources, s.Destinations} {
		if err := number(n); err != nil {
			return err
		}
	}
	for _, stamp := range []string{s.First.Format("2006-01-02T15:04:05.999999999Z07:00"), s.Last.Format("2006-01-02T15:04:05.999999999Z07:00")} {
		if err := str(stamp); err != nil {
			return err
		}
	}
	for _, counter := range []map[string]uint64{s.Protocols, s.SourceCounts, s.DestinationCounts} {
		if err := number(uint64(len(counter))); err != nil {
			return err
		}
		for key, value := range counter {
			if err := str(key); err != nil {
				return err
			}
			if err := number(value); err != nil {
				return err
			}
		}
	}
	for _, values := range [][]string{s.TruncatedCardinality, descriptions} {
		if err := number(uint64(len(values))); err != nil {
			return err
		}
		for _, v := range values {
			if err := str(v); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// pageLease retains decoded rows under the budget after disk reads finish.
// It owns no file handles, so dataset cleanup need not wait for page release.
type pageLease struct {
	once    sync.Once
	storage *Storage
	bytes   uint64
}

func (p *pageLease) close() {
	p.once.Do(func() {
		p.storage.mu.Lock()
		p.storage.usage.PinnedBytes -= p.bytes
		p.storage.mu.Unlock()
	})
}
