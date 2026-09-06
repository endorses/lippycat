package events

import (
	"context"
	"time"
)

// EnqueueLossless waits for bounded queue space and routes an accepted event to
// every subscribed sink without pressure drops. It is intended for offline
// analysis with a dedicated dispatcher; sharing it with live producers can slow
// their delivery. Flush or Stop is still required to wait for sink completion.
// Cancellation or Stop interrupts admission, but does not discard accepted work.
func (d *Dispatcher) EnqueueLossless(ctx context.Context, ev Event) bool {
	if isNilEvent(ev) {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.started || d.stopped {
		d.dropped.Add(1)
		return false
	}
	// Only lossless admissions hold admissionMu while waiting for capacity.
	// Serialize those callers with a cancellable gate so another blocked
	// producer cannot prevent this caller from observing cancellation.
	select {
	case d.losslessAdmission <- struct{}{}:
		defer func() { <-d.losslessAdmission }()
	case <-ctx.Done():
		d.dropped.Add(1)
		return false
	case <-d.ctx.Done():
		d.dropped.Add(1)
		return false
	case <-d.stopping:
		d.dropped.Add(1)
		return false
	}
	d.admissionMu.Lock()
	defer d.admissionMu.Unlock()
	select {
	case <-ctx.Done():
		d.dropped.Add(1)
		return false
	case <-d.ctx.Done():
		d.dropped.Add(1)
		return false
	case <-d.stopping:
		d.dropped.Add(1)
		return false
	default:
	}
	if d.cfg.Producer != nil {
		ev = d.cfg.Producer.Assign(ev)
		if isNilEvent(ev) || !hasDeliveryIdentity(ev.Envelope()) {
			d.dropped.Add(1)
			return false
		}
	}
	select {
	case d.queue <- dispatchItem{event: ev, admittedAt: time.Now(), lossless: true}:
		d.enqueued.Add(1)
		return true
	case <-ctx.Done():
	case <-d.ctx.Done():
	case <-d.stopping:
	}
	d.dropped.Add(1)
	return false
}
