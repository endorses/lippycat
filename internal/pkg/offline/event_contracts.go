package offline

import (
	"context"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
)

// EventRowID is a one-based admission ordinal, independent of delivery identity.
// Repeated EventIDs, including amended snapshots, occupy distinct immutable rows.
type EventRowID uint64

type EventRecord struct {
	ID    EventRowID
	Event events.Event
}

// EventSchemaVersion identifies the event framing and payload contract. Event
// storage is private to a completed analysis; persistent reuse is not supported.
const EventSchemaVersion uint16 = 1

// EventPresentationBytesPerRow reserves one borrowed presentation record in
// addition to the decoded event and EventRecord backing. A frontend must fit its
// retained presentation struct in this allowance and borrow the event graph;
// retaining deep event clones requires a separate reservation.
const EventPresentationBytesPerRow uint64 = 64

type EventQuerySpec struct {
	Token       Token
	Description []string
	Match       eventquery.Predicate
	Progress    func(QueryProgress)
}

type EventQuery interface {
	Token() Token
	Count() uint64
	Page(context.Context, PageRequest) (EventPage, error)
	Iterate(context.Context, func(EventRecord) error) error
	Close() error
}

type EventDataset interface {
	Generation() DatasetGeneration
	Count() uint64
	Query(context.Context, EventQuerySpec) (EventQuery, error)
	Detail(context.Context, Token, EventRowID) (*EventDetail, error)
	Resources() ResourceUsage
	Close() error
}

// EventPage contains bounded decoded snapshots. Close invalidates every copy of
// the page and releases its shared reservation exactly once. Retaining rows
// beyond Close requires the caller to copy them into separately budgeted memory.
type EventPage struct {
	Token Token
	Row   uint64
	Rows  []EventRecord
	lease *eventLease
}

func (p EventPage) Close() error { p.lease.close(); return nil }

type EventDetail struct {
	Record EventRecord
	lease  *eventLease
}

func (d *EventDetail) Close() error {
	if d != nil {
		d.lease.close()
	}
	return nil
}

type eventLease struct {
	once    sync.Once
	storage *Storage
	bytes   uint64
}

func (l *eventLease) close() {
	if l != nil {
		l.once.Do(func() { l.storage.releaseMemory(l.bytes) })
	}
}
