package offline

import (
	"context"
	"fmt"
	"sync"
)

// QueryPin keeps a completed query and its dataset alive from export scheduling
// through completion, even if the UI replaces its active query or dataset.
// Close joins active iterations and must run outside the UI update loop.
type QueryPin struct {
	mu     sync.RWMutex
	query  *diskQuery
	closed bool
}

// PinQuery acquires ownership before an asynchronous export is scheduled.
// The caller must close the returned pin, including on cancellation or failure.
func PinQuery(query Query) (*QueryPin, error) {
	q, ok := query.(*diskQuery)
	if !ok || q == nil {
		return nil, fmt.Errorf("offline query does not support snapshot pinning")
	}
	q.dataset.mu.RLock()
	q.mu.RLock()
	if q.closed || q.dataset.closed {
		q.mu.RUnlock()
		q.dataset.mu.RUnlock()
		return nil, fmt.Errorf("offline query closed")
	}
	return &QueryPin{query: q}, nil
}

func (p *QueryPin) Count() uint64 { return p.query.count }

// Iterate streams one owned detail at a time under the snapshot's existing
// locks. Reacquiring those locks would deadlock behind a pending dataset close.
func (p *QueryPin) Iterate(ctx context.Context, visit func(Detail) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return fmt.Errorf("offline query pin closed")
	}
	if visit == nil {
		return fmt.Errorf("offline iteration requires callback")
	}
	return p.query.iterateLocked(ctx, visit)
}

// IterateRaw streams effective capture records while retaining the query and
// dataset ownership acquired before asynchronous export scheduling.
func (p *QueryPin) IterateRaw(ctx context.Context, visit func(RawRecord) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return fmt.Errorf("offline query pin closed")
	}
	if visit == nil {
		return fmt.Errorf("offline raw iteration requires callback")
	}
	return p.query.iterateRawLocked(ctx, visit)
}

func (p *QueryPin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.query.mu.RUnlock()
		p.query.dataset.mu.RUnlock()
	}
	return nil
}
