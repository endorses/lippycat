//go:build li

package delivery

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
)

const maxReorderCallIdentities = 4096

// Includes retained map/key/ticket/channel and the one drain goroutine stack.
const reorderCallCharge int64 = 4096

var ErrReorderDrain = errors.New("reorder exact call closure unavailable")

type reorderCallKey struct {
	callID      string
	generation  uint64
	incarnation uuid.UUID
}

func (key reorderCallKey) valid() bool {
	return key.callID != "" && len(key.callID) <= 128 && key.generation != 0 && key.incarnation != uuid.Nil
}

// DrainTicket is a callback frontier, not evidence of journal durability. Wait
// must not run recursively from this buffer's callbacks. Cancellation abandons
// only the wait, never the owned work or its budget.
type DrainTicket struct {
	done                        chan struct{}
	draining, complete, retired bool // rb.mu
}

// HasAcceptedCall restricts processor closure fan-out to identities actually
// reserved in this buffer, including entries already owned by callbacks.
func (rb *ReorderBuffer) HasAcceptedCall(callID string, generation uint64, incarnation uuid.UUID) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.calls[reorderCallKey{callID: callID, generation: generation, incarnation: incarnation}] != nil
}

func (ticket *DrainTicket) Wait(ctx context.Context) error {
	if ticket == nil {
		return ErrReorderDrain
	}
	select {
	case <-ticket.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rb *ReorderBuffer) reserveCallLocked(key reorderCallKey) *DrainTicket {
	if old := rb.calls[key]; old != nil {
		return old
	}
	if len(rb.calls) >= maxReorderCallIdentities || !rb.budget.reserve(reorderCallCharge) {
		return nil
	}
	if rb.calls == nil {
		rb.calls = make(map[reorderCallKey]*DrainTicket)
	}
	key.callID = strings.Clone(key.callID)
	ticket := &DrainTicket{done: make(chan struct{})}
	rb.calls[key] = ticket
	return ticket
}

// DrainCall seals exactly Call-ID/local-generation/random-incarnation against
// new insertion. It fences already detached callbacks even with no buffered
// output and coalesces concurrent/repeated requests for this buffer's lifetime.
// The shared budget bounds retained closed keys until Stop/Discard. A persistent
// client additionally retains the durable closure gate beyond buffer retirement.
func (rb *ReorderBuffer) DrainCall(callID string, generation uint64, incarnation uuid.UUID) (*DrainTicket, error) {
	key := reorderCallKey{callID: callID, generation: generation, incarnation: incarnation}
	if !key.valid() {
		return nil, ErrReorderDrain
	}
	rb.mu.Lock()
	if ticket := rb.calls[key]; ticket != nil && ticket.draining {
		rb.mu.Unlock()
		return ticket, nil
	}
	if rb.stopped {
		rb.mu.Unlock()
		return nil, ErrReorderDrain
	}
	ticket := rb.reserveCallLocked(key)
	if ticket == nil {
		rb.mu.Unlock()
		return nil, ErrReorderDrain
	}
	ticket.draining = true
	var out []ReorderEntry
	for streamKey, stream := range rb.streams {
		if streamKey.callID != callID || streamKey.generation != generation || streamKey.incarnation != incarnation {
			continue
		}
		rb.disarmLocked(stream)
		out = append(out, drainAll(stream)...)
		rb.budget.release(reorderStreamCharge)
		delete(rb.streams, streamKey)
	}
	previous, done := rb.reserveCallbackLocked()
	// Include ticket completion/retirement, not just its delivery callbacks, in
	// shutdown joining so no charged closure worker outlives Wait.
	rb.callbackWG.Add(1)
	if rb.sharedWorkers != nil {
		rb.sharedWorkers.Add(1)
	}
	rb.mu.Unlock()
	go func() {
		defer rb.callbackWG.Done()
		if rb.sharedWorkers != nil {
			defer rb.sharedWorkers.Done()
		}
		rb.deliver(out, previous, done)
		rb.mu.Lock()
		ticket.complete = true
		close(ticket.done)
		if ticket.retired {
			rb.budget.release(reorderCallCharge)
		}
		rb.mu.Unlock()
	}()
	return ticket, nil
}

func (rb *ReorderBuffer) retireCallsLocked() {
	for _, ticket := range rb.calls {
		ticket.retired = true
		if ticket.complete || !ticket.draining {
			rb.budget.release(reorderCallCharge)
		}
	}
	clear(rb.calls)
}

func (entry ReorderEntry) releaseAccepted() {
	if entry.Accepted != nil {
		entry.Accepted.Release()
	}
}
