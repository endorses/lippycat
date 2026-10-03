package offline

import (
	"context"
	"errors"
	"fmt"
)

// RangeIDs resolves an anchor in this query and returns the inclusive range to
// cursor. Only scalar identities are materialized, up to the caller's limit.
// Query IDs are ordered, so locating a filtered anchor needs no dataset scan.
func (p *QueryPin) RangeIDs(ctx context.Context, anchor PacketID, cursor, limit uint64) ([]PacketID, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, fmt.Errorf("offline query pin closed")
	}
	q := p.query
	if err := q.validate(); err != nil {
		return nil, err
	}
	if cursor >= q.count {
		return nil, fmt.Errorf("selected offline row is unavailable")
	}
	low, high := uint64(0), q.count
	for low < high {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mid := low + (high-low)/2
		id, err := q.idAt(mid)
		if err != nil {
			return nil, err
		}
		if id < anchor {
			low = mid + 1
		} else {
			high = mid
		}
	}
	if low == q.count {
		return nil, fmt.Errorf("mark anchor is hidden by the filter; click or mark a packet to choose a new anchor")
	}
	id, err := q.idAt(low)
	if err != nil {
		return nil, err
	}
	if id != anchor {
		return nil, fmt.Errorf("mark anchor is hidden by the filter; click or mark a packet to choose a new anchor")
	}
	first, last := min(low, cursor), max(low, cursor)
	count := last - first + 1
	if count > limit || count > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("packet marking limit reached; clear marks or select a smaller range")
	}
	ids := make([]PacketID, 0, int(count))
	for row := first; row <= last; row++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, err := q.idAt(row)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, ctx.Err()
}

// IterateSelectedRaw exports ordered dataset identities, independently of the
// pinned query's filter. Every decoded record stays charged to the dataset's
// shared budget and is released before the next record. The callback borrows it.
func (p *QueryPin) IterateSelectedRaw(ctx context.Context, ids []PacketID, visit func(RawRecord) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return fmt.Errorf("offline query pin closed")
	}
	if visit == nil {
		return fmt.Errorf("offline raw iteration requires callback")
	}
	if err := p.query.validate(); err != nil {
		return err
	}
	d := p.query.dataset
	if d.compact != nil {
		if err := d.validateCompactStreams(); err != nil {
			return err
		}
	}
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if uint64(id) >= d.count || (i > 0 && id <= ids[i-1]) {
			return fmt.Errorf("selected offline packet IDs must be ordered, unique, and in range")
		}
		if err := d.visitSelectedRaw(ctx, id, visit); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (d *diskDataset) visitSelectedRaw(ctx context.Context, id PacketID, visit func(RawRecord) error) error {
	if d.compact != nil {
		row, _, held, err := d.readCompactRow(ctx, id, false)
		if err != nil {
			return err
		}
		defer d.storage.releaseMemory(held)
		lease, err := d.compact.registry.Read(ctx, row.Locator)
		if err != nil {
			return err
		}
		err = visit(RawRecord{ID: id, Timestamp: row.Timestamp, CapturedLength: row.Captured, OriginalLength: row.Original, LinkType: row.LinkType, RawData: lease.Bytes})
		return errors.Join(err, lease.Close())
	}
	detail, held, err := d.readDetail(ctx, id)
	if err != nil {
		return err
	}
	defer d.storage.releaseMemory(held)
	return visit(rawRecord(detail))
}
