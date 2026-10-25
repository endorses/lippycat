package offline

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/events"
)

const (
	eventQueryHeaderBytes = 48
	eventQueryEntryBytes  = 16
	eventQueryMemory      = 512
	eventLeaseMemory      = 96
)

var eventQueryMagic = [8]byte{'L', 'C', 'E', 'V', 'Q', 'R', 'Y', 2}

type diskEventQuery struct {
	mu                 sync.RWMutex
	dataset            *diskEventDataset
	token              Token
	count              uint64
	identity           bool
	description        []string
	file               *os.File
	path               string
	bytes, memoryBytes uint64
	closed, cleaned    bool
	previous, next     *diskEventQuery
	registered         bool
}

// AllEvents creates an implicit arrival-ordered projection, without a scan or
// a dataset-sized allocation. Every EventID occurrence remains a distinct row.
func AllEvents(ctx context.Context, dataset EventDataset, token Token) (EventQuery, error) {
	if dataset == nil {
		return nil, errors.New("offline event dataset is nil")
	}
	return dataset.Query(ctx, EventQuerySpec{Token: token})
}

func (d *diskEventDataset) Query(ctx context.Context, spec EventQuerySpec) (result EventQuery, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if spec.Token.Dataset != d.generation || spec.Token.Revision != d.Revision() {
		return nil, errors.New("offline event query dataset generation/revision mismatch")
	}
	if err = d.validate(); err != nil {
		return nil, err
	}
	held := uint64(eventQueryMemory)
	if err = addProduct(&held, uint64(len(spec.Description)), 16, d.storage.limits.CacheBytes); err != nil {
		return nil, err
	}
	for _, description := range spec.Description {
		if err = addBudget(&held, uint64(len(description)), d.storage.limits.CacheBytes); err != nil {
			return nil, err
		}
	}
	if err = d.storage.reserveMemory(ctx, held); err != nil {
		return nil, err
	}
	q := &diskEventQuery{dataset: d, token: spec.Token, memoryBytes: held, description: append([]string(nil), spec.Description...)}
	d.queryMu.Lock()
	q.next, q.registered = d.queryHead, true
	if d.queryHead != nil {
		d.queryHead.previous = q
	}
	d.queryHead = q
	d.queryCount++
	d.queryMu.Unlock()
	defer func() {
		if err != nil {
			err = errors.Join(err, q.closeLocked())
		}
	}()
	progress := QueryProgress{Token: spec.Token, Total: d.count}
	report := func() {
		if spec.Progress != nil {
			spec.Progress(progress)
		}
	}
	report()
	if spec.Match == nil {
		q.identity, q.count = true, d.count
		progress.Scanned, progress.Matched = d.count, d.count
		report()
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		return q, nil
	}
	if q.file, err = os.CreateTemp(d.dir, "events-query-*"); err != nil {
		return nil, fmt.Errorf("create offline event query: %w", err)
	}
	q.path = q.file.Name()
	header := q.header()
	if err = q.write(header[:]); err != nil {
		return nil, err
	}
	for id := EventRowID(1); uint64(id) <= d.count; id++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var record EventRecord
		var retained uint64
		if record, retained, err = d.readRecord(ctx, id); err != nil {
			return nil, err
		}
		var matches bool
		// eventquery projects typed fields into temporary maps/slices. Account
		// their workspace independently of the decoded record retained above.
		workspace := uint64(4096)
		if err = addProduct(&workspace, retained, 4, d.storage.limits.CacheBytes); err == nil {
			err = d.storage.reserveMemory(ctx, workspace)
			if err == nil {
				matches = spec.Match(record.Event)
				d.storage.releaseMemory(workspace)
			}
		}
		d.storage.releaseMemory(retained)
		if err != nil {
			return nil, err
		}
		if matches {
			entry := eventQueryEntry(id, q.count)
			if err = q.write(entry[:]); err != nil {
				return nil, err
			}
			q.count++
		}
		progress.Scanned, progress.Matched = uint64(id), q.count
		if uint64(id)%256 == 0 {
			report()
		}
	}
	header = q.header()
	if _, err = q.file.WriteAt(header[:], 0); err != nil {
		return nil, fmt.Errorf("finalize offline event query: %w", err)
	}
	if err = q.file.Sync(); err != nil {
		return nil, fmt.Errorf("flush offline event query: %w", err)
	}
	err = q.file.Close()
	q.file = nil
	if err != nil {
		return nil, fmt.Errorf("close offline event query writer: %w", err)
	}
	if q.file, err = os.Open(q.path); err != nil {
		return nil, fmt.Errorf("open completed offline event query: %w", err)
	}
	report()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *diskEventQuery) header() [eventQueryHeaderBytes]byte {
	var h [eventQueryHeaderBytes]byte
	copy(h[:8], eventQueryMagic[:])
	binary.LittleEndian.PutUint64(h[8:16], uint64(q.token.Dataset))
	binary.LittleEndian.PutUint64(h[16:24], uint64(q.token.Query))
	binary.LittleEndian.PutUint64(h[24:32], q.count)
	binary.LittleEndian.PutUint64(h[40:48], uint64(q.token.Revision))
	binary.LittleEndian.PutUint32(h[32:36], eventChecksum(h[:32], h[40:48]))
	return h
}

func eventQueryEntry(id EventRowID, row uint64) [eventQueryEntryBytes]byte {
	var entry [eventQueryEntryBytes]byte
	var position [8]byte
	binary.LittleEndian.PutUint64(entry[:8], uint64(id))
	binary.LittleEndian.PutUint64(position[:], row)
	binary.LittleEndian.PutUint32(entry[8:12], eventChecksum(entry[:8], position[:]))
	return entry
}

func (q *diskEventQuery) write(payload []byte) error {
	if err := q.dataset.storage.reserveDisk(uint64(len(payload))); err != nil {
		return err
	}
	n, err := q.file.Write(payload)
	q.bytes += uint64(n)
	q.dataset.storage.releaseDisk(uint64(len(payload) - n))
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write offline event query: %w", err)
	}
	return nil
}

func (q *diskEventQuery) Token() Token  { return q.token }
func (q *diskEventQuery) Count() uint64 { return q.count }

func (q *diskEventQuery) validate() error {
	if q.closed || q.token.Dataset != q.dataset.generation || q.token.Revision != q.dataset.Revision() {
		return errors.New("offline event query closed")
	}
	if err := q.dataset.validate(); err != nil {
		return err
	}
	if q.identity {
		return nil
	}
	if q.file == nil {
		return errors.New("offline event query is incomplete")
	}
	info, err := q.file.Stat()
	if err != nil {
		return err
	}
	if uint64(info.Size()) != eventQueryHeaderBytes+q.count*eventQueryEntryBytes {
		return errors.New("corrupt offline event query length")
	}
	var header [eventQueryHeaderBytes]byte
	if _, err := q.file.ReadAt(header[:], 0); err != nil {
		return err
	}
	if header != q.header() {
		return errors.New("corrupt offline event query header")
	}
	return nil
}

func (q *diskEventQuery) readID(row uint64) (EventRowID, error) {
	if row >= q.count {
		return 0, errors.New("offline event query row outside projection")
	}
	if q.identity {
		return EventRowID(row + 1), nil
	}
	var entry [eventQueryEntryBytes]byte
	if _, err := q.file.ReadAt(entry[:], int64(eventQueryHeaderBytes+row*eventQueryEntryBytes)); err != nil {
		return 0, fmt.Errorf("read offline event query row: %w", err)
	}
	id := EventRowID(binary.LittleEndian.Uint64(entry[:8]))
	if id == 0 || uint64(id) > q.dataset.count || entry != eventQueryEntry(id, row) {
		return 0, errors.New("corrupt offline event query row")
	}
	return id, nil
}

func (q *diskEventQuery) idAt(row uint64) (EventRowID, error) {
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
			return 0, errors.New("corrupt unordered offline event query")
		}
	}
	return id, nil
}

func (q *diskEventQuery) Page(ctx context.Context, req PageRequest) (EventPage, error) {
	q.dataset.mu.RLock()
	defer q.dataset.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.pageLocked(ctx, req)
}

func (q *diskEventQuery) pageLocked(ctx context.Context, req PageRequest) (page EventPage, err error) {
	page = EventPage{Token: req.Token, Row: req.Row}
	if err = ctx.Err(); err != nil {
		return page, err
	}
	if req.Token.Dataset != q.token.Dataset || req.Token.Revision != q.token.Revision || req.Token.Query != q.token.Query {
		return page, errors.New("offline event page generation mismatch")
	}
	if err = q.validate(); err != nil {
		return page, err
	}
	if req.Row > q.count {
		return page, errors.New("offline event page row outside projection")
	}
	if req.Limit == 0 || req.Row == q.count {
		return page, nil
	}
	rowBytes := uint64(reflect.TypeOf(EventRecord{}).Size()) + EventPresentationBytesPerRow
	if req.MaxBytes <= eventLeaseMemory+rowBytes {
		return page, errors.New("offline event page byte limit is too small")
	}
	// Leave room for at least the envelope carried by each decoded row instead
	// of spending a small page budget entirely on an oversized backing slice.
	minimumRow := rowBytes*2 + uint64(reflect.TypeOf(events.Envelope{}).Size())
	limit := min(uint64(req.Limit), q.count-req.Row, max(uint64(1), (req.MaxBytes-eventLeaseMemory)/minimumRow))
	held := eventLeaseMemory + limit*rowBytes
	if err = q.dataset.storage.reserveMemory(ctx, held); err != nil {
		return page, err
	}
	page.Rows = make([]EventRecord, 0, int(limit))
	defer func() {
		if err != nil {
			q.dataset.storage.releaseMemory(held)
			page.Rows = nil
		} else {
			page.lease = &eventLease{storage: q.dataset.storage, bytes: held}
		}
	}()
	for row := req.Row; row < req.Row+limit; row++ {
		var id EventRowID
		if id, err = q.idAt(row); err != nil {
			return page, err
		}
		var record EventRecord
		var memory uint64
		if record, memory, err = q.dataset.readRecord(ctx, id); err != nil {
			return page, err
		}
		if memory > req.MaxBytes-held {
			q.dataset.storage.releaseMemory(memory)
			if len(page.Rows) == 0 {
				return page, errors.New("offline event record exceeds page byte limit")
			}
			break
		}
		held += memory
		page.Rows = append(page.Rows, record)
	}
	if err = ctx.Err(); err != nil {
		return page, err
	}
	return page, nil
}

func (q *diskEventQuery) Iterate(ctx context.Context, visit func(EventRecord) error) error {
	q.dataset.mu.RLock()
	defer q.dataset.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.iterateLocked(ctx, visit)
}

func (q *diskEventQuery) iterateLocked(ctx context.Context, visit func(EventRecord) error) error {
	if visit == nil {
		return errors.New("offline event iteration requires a callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := q.validate(); err != nil {
		return err
	}
	for row := uint64(0); row < q.count; row++ {
		id, err := q.idAt(row)
		if err != nil {
			return err
		}
		record, held, err := q.dataset.readRecord(ctx, id)
		if err != nil {
			return err
		}
		err = visit(record)
		q.dataset.storage.releaseMemory(held)
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (q *diskEventQuery) Close() error {
	q.dataset.mu.RLock()
	defer q.dataset.mu.RUnlock()
	return q.closeLocked()
}

func (q *diskEventQuery) closeLocked() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.cleaned {
		return nil
	}
	q.closed = true
	var result error
	if q.file != nil {
		result = q.file.Close()
		q.file = nil
	}
	if q.path != "" {
		if err := os.Remove(q.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(result, fmt.Errorf("remove offline event query: %w", err))
		}
	}
	q.finishCleanup()
	q.dataset.queryMu.Lock()
	if q.registered {
		if q.previous == nil {
			q.dataset.queryHead = q.next
		} else {
			q.previous.next = q.next
		}
		if q.next != nil {
			q.next.previous = q.previous
		}
		q.dataset.queryCount--
		q.previous, q.next, q.registered = nil, nil, false
	}
	q.dataset.queryMu.Unlock()
	return result
}

func (q *diskEventQuery) finishCleanup() {
	q.dataset.storage.releaseDisk(q.bytes)
	q.dataset.storage.releaseMemory(q.memoryBytes)
	q.bytes, q.memoryBytes = 0, 0
	q.description = nil
	q.cleaned = true
}

// EventQueryPin retains query/source lifetime before asynchronous scheduling.
// Close joins its active reads; call it outside the Bubble Tea update loop.
type EventQueryPin struct {
	mu     sync.RWMutex
	query  *diskEventQuery
	closed bool
}

func PinEventQuery(query EventQuery) (*EventQueryPin, error) {
	q, ok := query.(*diskEventQuery)
	if !ok || q == nil {
		return nil, errors.New("offline event query does not support snapshot pinning")
	}
	q.dataset.mu.RLock()
	q.mu.RLock()
	if err := q.validate(); err != nil {
		q.mu.RUnlock()
		q.dataset.mu.RUnlock()
		return nil, err
	}
	if err := q.dataset.storage.reserveMemory(context.Background(), eventLeaseMemory); err != nil {
		q.mu.RUnlock()
		q.dataset.mu.RUnlock()
		return nil, err
	}
	return &EventQueryPin{query: q}, nil
}

func (p *EventQueryPin) Token() Token  { return p.query.token }
func (p *EventQueryPin) Count() uint64 { return p.query.count }

func (p *EventQueryPin) Page(ctx context.Context, req PageRequest) (EventPage, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return EventPage{Token: req.Token, Row: req.Row}, errors.New("offline event query pin closed")
	}
	return p.query.pageLocked(ctx, req)
}

func (p *EventQueryPin) Iterate(ctx context.Context, visit func(EventRecord) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return errors.New("offline event query pin closed")
	}
	return p.query.iterateLocked(ctx, visit)
}

func (p *EventQueryPin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.query.mu.RUnlock()
		p.query.dataset.mu.RUnlock()
		p.query.dataset.storage.releaseMemory(eventLeaseMemory)
	}
	return nil
}
