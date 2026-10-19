//go:build li

package li

import (
	"context"
	"errors"
	"maps"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// A response wait owns snapshots but has no reserved ID. One worker per bounded
// dialog owns its FIFO through request selection, persistence and final handoff.
// All state and accounting below are protected by the correlator's mutex.
type correlationPending struct {
	callID, transaction string
	deadline            time.Time
	wake                chan struct{}
	reason              string
	seed                *correlationPendingPacket
	packets             []*correlationPendingPacket
	bytes               int
	finalized           bool
}

type correlationPendingPacket struct {
	ctx    context.Context
	packet *types.PacketDisplay
	tasks  []CallCorrelationTask
	fn     func(CallCorrelationDecision)
	bytes  int
	queued bool
	stop   func() bool
}

var errCorrelationResponsePressure = errors.New("LI correlation response-wait capacity exhausted")

// queueResponseLocked participates in the same lock acquisition as first-ID
// reservation. Releasing mu before deciding whether to wait would let a racing
// INVITE or response bypass the pending FIFO and select an independent ID.
func (c *CallCorrelator) queueResponseLocked(ctx context.Context, pkt *types.PacketDisplay, tasks []CallCorrelationTask, bytes int, fn func(CallCorrelationDecision)) (bool, error) {
	if !c.config.ResponseWait || !c.config.Enabled() || pkt == nil || pkt.VoIPData == nil {
		return false, nil
	}
	callID := pkt.VoIPData.CallID
	c.expireRecord(callID, c.now())
	e := c.responsePending[callID]
	if e != nil && e.reason == "" && !c.waitNow().Before(e.deadline) {
		c.triggerResponseLocked(e, "timeout", nil)
	}
	if e == nil {
		if c.records[callID] != nil || callID == "" || len(callID) > correlationMaxValue || !validCorrelationParentID(callID) || pkt.VoIPData.Status <= 0 || len(taskSet(tasks)) == 0 {
			return false, nil
		}
		tx, eligible := correlationTx(pkt)
		if !eligible {
			return false, nil
		}
		entryBytes := 512 + len(callID) + len(tx)
		if len(c.responsePending) >= c.config.MaxPendingDialogs || len(c.responsePending)+len(c.records) >= c.config.MaxRecords || len(c.responsePending)+len(c.transactions) >= c.config.MaxCandidates || !c.responseCapacityLocked(bytes, len(tasks), entryBytes) {
			// No snapshot was admitted: reserve the ordinary conservative result
			// under this same lock, rather than allocating an unbounded worker.
			c.stats.ResponseWait["pressure"]++
			return false, nil
		}
		e = &correlationPending{callID: callID, transaction: tx, deadline: c.waitNow().Add(c.config.ResponseWaitWindow), wake: make(chan struct{}), bytes: entryBytes}
		c.responsePending[callID] = e
		c.pendingBytes += entryBytes
		c.stats.ResponseWait["waiting"]++
		c.asyncWG.Add(1)
		go c.awaitResponse(e)
	} else if !c.responseCapacityLocked(bytes, len(tasks), 0) {
		// The current snapshot is not retained. Already admitted packets release
		// standalone in order; do not hold an unaccounted snapshot or spawn a
		// worker for every rejected packet while a dialog is under pressure.
		c.triggerResponseLocked(e, "pressure", nil)
		c.stats.ResponseWait["rejected"]++
		c.stats.DeferredRejected++
		return true, errCorrelationResponsePressure
	}
	p := &correlationPendingPacket{ctx: ctx, packet: pkt, tasks: append([]CallCorrelationTask(nil), tasks...), fn: fn, bytes: bytes + 256 + len(tasks)*64, queued: true}
	e.packets = append(e.packets, p)
	c.pendingPackets++
	c.pendingBytes += p.bytes
	p.stop = context.AfterFunc(ctx, func() { c.cancelResponsePacket(e, p) })
	if e.reason == "" && pkt.VoIPData.Status == 0 {
		if tx, eligible := correlationTx(pkt); eligible && tx == e.transaction {
			c.triggerResponseLocked(e, "request", p)
		}
	}
	return true, nil
}

func (c *CallCorrelator) responseCapacityLocked(bytes, tasks, entryBytes int) bool {
	if bytes < 0 || tasks > maxCallCorrelationStoredTasks || bytes > maxCallCorrelationStoreBytes-256-tasks*64-entryBytes {
		return false
	}
	cost := bytes + 256 + tasks*64 + entryBytes
	return c.pendingPackets < c.config.MaxPendingPackets && c.pendingPackets+c.deferredPackets < c.config.MaxCandidates && cost <= c.config.MaxPendingBytes && c.pendingBytes <= c.config.MaxPendingBytes-cost && c.pendingBytes+c.deferredBytes <= maxCallCorrelationStoreBytes-cost
}

func (c *CallCorrelator) triggerResponseLocked(e *correlationPending, reason string, seed *correlationPendingPacket) {
	if e.reason == "" {
		e.reason, e.seed = reason, seed
		c.stats.ResponseWait[reason]++
		close(e.wake)
	}
}

func (c *CallCorrelator) releaseExpiredResponsesLocked() {
	if !c.config.ResponseWait {
		return
	}
	now := c.waitNow()
	for _, e := range c.responsePending {
		if e.reason == "" && !now.Before(e.deadline) {
			c.triggerResponseLocked(e, "timeout", nil)
		}
	}
}

func (c *CallCorrelator) cancelResponsePacket(e *correlationPending, p *correlationPendingPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.responsePending[e.callID] != e || !p.queued || e.reason != "" {
		return
	}
	for i, queued := range e.packets {
		if queued == p {
			copy(e.packets[i:], e.packets[i+1:])
			e.packets[len(e.packets)-1] = nil
			e.packets = e.packets[:len(e.packets)-1]
			p.queued = false
			c.pendingPackets--
			c.pendingBytes -= p.bytes
			c.stats.ResponseWait["cancelled_packets"]++
			break
		}
	}
	if len(e.packets) == 0 {
		c.triggerResponseLocked(e, "cancelled", nil)
	}
}

func (c *CallCorrelator) awaitResponse(e *correlationPending) {
	defer c.asyncWG.Done()
	c.mu.Lock()
	delay := max(time.Duration(0), e.deadline.Sub(c.waitNow()))
	after := c.waitAfter
	c.mu.Unlock()
	select {
	case <-e.wake:
	case <-after(delay):
		c.mu.Lock()
		c.triggerResponseLocked(e, "timeout", nil)
		c.mu.Unlock()
	case <-c.stop:
	}
	c.mu.Lock()
	if c.closing {
		c.discardResponseLocked(e, "shutdown_packets")
		c.mu.Unlock()
		return
	}
	seed := e.seed
	if seed == nil || seed.ctx.Err() != nil {
		seed = nil
		for _, p := range e.packets {
			if p.ctx.Err() == nil {
				// Without admitted request evidence, choose the first retained
				// response. Do not promote a mismatched request by accident.
				if p.packet.VoIPData.Status > 0 {
					seed = p
					break
				}
			}
		}
		if seed == nil {
			for _, p := range e.packets {
				if p.ctx.Err() == nil {
					// A response can cancel just as a live request/media packet
					// joins its releasing FIFO. Deliver that live observation using
					// standalone selection; absence of the response is not a reason
					// to discard another caller's admitted snapshot.
					seed = p
					break
				}
			}
		}
	}
	if seed == nil {
		c.discardResponseLocked(e, "cancelled_packets")
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	// The existing persistence protocol releases synchronous resolution on its
	// logical deadline even if the physical store owner remains blocked.
	// Once selected, this observation supplies evidence for the shared first
	// decision. A single caller cancelling cannot revoke a reservation needed
	// by other admitted snapshots; their contexts are checked at each handoff.
	decision, err := c.resolveReservedContext(context.Background(), seed.packet, seed.tasks)
	if err != nil {
		c.mu.Lock()
		reason := "cancelled_packets"
		if c.closing {
			reason = "shutdown_packets"
		}
		c.discardResponseLocked(e, reason)
		c.mu.Unlock()
		return
	}
	for {
		c.mu.Lock()
		if c.closing {
			c.discardResponseLocked(e, "shutdown_packets")
			c.mu.Unlock()
			return
		}
		if len(e.packets) == 0 {
			delete(c.responsePending, e.callID)
			c.pendingBytes -= e.bytes
			c.mu.Unlock()
			return
		}
		p := e.packets[0]
		e.packets[0] = nil
		e.packets = e.packets[1:]
		p.queued = false
		p.stop()
		r := c.records[e.callID]
		if r != nil && r.decision.token == decision.token && p != seed {
			c.observeKnown(p.packet, r, c.now())
		}
		c.mu.Unlock()
		suppressed := true
		if p.ctx.Err() == nil {
			if r != nil && r.decision.token == decision.token {
				suppressed = !c.deliverDirect(p.ctx, r, p.fn, false)
			} else {
				p.fn(decision)
				suppressed = false
			}
		}
		c.mu.Lock()
		c.pendingPackets--
		c.pendingBytes -= p.bytes
		if suppressed {
			if c.closing {
				c.stats.ResponseWait["shutdown_packets"]++
			} else {
				c.stats.ResponseWait["cancelled_packets"]++
			}
		}
		c.mu.Unlock()
	}
}

func (c *CallCorrelator) discardResponseLocked(e *correlationPending, reason string) {
	for _, p := range e.packets {
		p.stop()
		p.queued = false
		c.pendingPackets--
		c.pendingBytes -= p.bytes
		c.stats.ResponseWait[reason]++
	}
	delete(c.responsePending, e.callID)
	c.pendingBytes -= e.bytes
	e.packets, e.seed = nil, nil
}

func (c *CallCorrelator) resolveWaitingContext(ctx context.Context, pkt *types.PacketDisplay, tasks []CallCorrelationTask) (CallCorrelationDecision, error) {
	// Synchronous callers own their inputs only until return, including a
	// cancellation return. Copy every field inspected by correlation before
	// allowing that cancellation to race a worker reading the observation.
	copy, bytes := cloneCorrelationObservation(pkt)
	result := make(chan CallCorrelationDecision, 1)
	if err := c.ResolveAsync(ctx, copy, tasks, bytes, func(d CallCorrelationDecision) { result <- d }); err != nil {
		return CallCorrelationDecision{}, err
	}
	select {
	case decision := <-result:
		return decision, nil
	case <-ctx.Done():
		return CallCorrelationDecision{}, ctx.Err()
	case <-c.stop:
		return CallCorrelationDecision{}, errors.New("LI correlation closed")
	}
}

func cloneCorrelationObservation(pkt *types.PacketDisplay) (*types.PacketDisplay, int) {
	if pkt == nil {
		return nil, 0
	}
	// Retain only the packet fields correlation consumes. In particular a
	// synchronous waiter must not keep unrelated raw payloads or display strings
	// alive outside the byte accounting below.
	copy := types.PacketDisplay{Timestamp: pkt.Timestamp, SrcIP: pkt.SrcIP, DstIP: pkt.DstIP}
	bytes := 2048 + len(copy.SrcIP) + len(copy.DstIP)
	if pkt.VoIPData != nil {
		v := *pkt.VoIPData
		v.RawSIP = append([]byte(nil), v.RawSIP...)
		v.Headers = maps.Clone(v.Headers)
		v.AccessNetworkInfo = nil
		copy.VoIPData = &v
		bytes += len(v.RawSIP)
		for _, value := range []string{v.CallID, v.Method, v.CSeqMethod, v.ViaBranch, v.FromTag, v.ToTag, v.From, v.To, v.Body, v.ContentType, v.MergeFromCallID, v.User, v.IMSI, v.IMEI, v.VisitedNetworkID, v.Codec} {
			bytes += len(value)
		}
		for name, value := range v.Headers {
			bytes += 128 + len(name) + len(value)
		}
	}
	return &copy, bytes
}
