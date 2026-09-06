package offline

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket/layers"
)

// RawRecord is an effective normalized capture record, independent of detail
// decoding. RawData is owned for the duration of the iterator callback; callers
// retaining it beyond that callback must copy it into their own budget.
type RawRecord struct {
	ID                             PacketID
	Timestamp                      time.Time
	CapturedLength, OriginalLength uint32
	LinkType                       layers.LinkType
	RawData                        []byte
}

func rawRecord(d Detail) RawRecord {
	return RawRecord{ID: d.ID, Timestamp: d.Packet.Timestamp, CapturedLength: d.CapturedLength, OriginalLength: d.OriginalLength, LinkType: d.Packet.LinkType, RawData: d.Packet.RawData}
}

// IterateRaw streams query-ordered effective bytes without invoking compact
// detail decoders. Custom query implementations retain the compatible detail
// fallback. Acquire PinQuery before scheduling an asynchronous operation.
func IterateRaw(ctx context.Context, query Query, visit func(RawRecord) error) error {
	if visit == nil {
		return fmt.Errorf("offline raw iteration requires callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if q, ok := query.(interface {
		IterateRaw(context.Context, func(RawRecord) error) error
	}); ok {
		return q.IterateRaw(ctx, visit)
	}
	return query.Iterate(ctx, func(d Detail) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return visit(rawRecord(d))
	})
}

func (q *diskQuery) IterateRaw(ctx context.Context, visit func(RawRecord) error) error {
	if visit == nil {
		return fmt.Errorf("offline raw iteration requires callback")
	}
	q.dataset.mu.RLock()
	defer q.dataset.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.iterateRawLocked(ctx, visit)
}

// iterateRawLocked uses the existing query pin locks to avoid reacquiring a
// dataset lock behind a pending Close.
func (q *diskQuery) iterateRawLocked(ctx context.Context, visit func(RawRecord) error) error {
	if err := q.validate(); err != nil {
		return err
	}
	d := q.dataset
	if d.compact != nil {
		return q.iterateCompactRaw(ctx, visit)
	}
	for row := uint64(0); row < q.count; row++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, err := q.idAt(row)
		if err != nil {
			return err
		}
		var detail Detail
		var held uint64
		detail, held, err = d.readDetail(ctx, id)
		if err != nil {
			return err
		}
		err = func() error { defer d.storage.releaseMemory(held); return visit(rawRecord(detail)) }()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}
