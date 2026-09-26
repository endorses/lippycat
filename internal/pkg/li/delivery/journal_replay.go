//go:build li

package delivery

import (
	"bytes"
	"sort"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
)

type replayCandidate struct {
	id    uint64
	did   uuid.UUID
	bytes int64
}

// A durable live decision is approved only in this process. Restart deliberately
// loses the approval, while retaining original bytes and FIFO identity on disk.
func (c *Client) publishLiveBacklog(j *Journal, q *destinationQueue, t PDUType, id uint64) {
	j.controlMu.Lock()
	defer j.controlMu.Unlock()
	j.Hold(id)
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.stopped.Load() {
		return
	}
	q.mu.Lock()
	stopped := q.stopped
	q.mu.Unlock()
	if stopped {
		return
	}
	j.mu.Lock()
	if e := j.entries[id]; e != nil && e.held && !e.authorized && !e.completing {
		e.authorized = true
		j.stats.ReplayPending++
		j.replayRevision++
	}
	j.mu.Unlock()
	if !j.replayStarted {
		j.replayStarted = true
		c.wg.Add(1)
		go c.replayJournalFor(j, t)
	}
}

func (j *Journal) replayCandidates() []replayCandidate {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]replayCandidate, 0, j.stats.Held)
	for id, e := range j.entries {
		if e.held && !e.completing {
			out = append(out, replayCandidate{id, e.did, e.payloadBytes})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].did == out[b].did {
			return out[a].id < out[b].id
		}
		return bytes.Compare(out[a].did[:], out[b].did[:]) < 0
	})
	return out
}

// replayJournal is a single bounded feeder. It reads a payload only when its
// destination has reserved capacity and never lets later product pass an earlier
// authorized item. Authorization remains valid across post-decision task end;
// destination replacement always returns the product to an unauthorized hold.
func (c *Client) replayJournal() { c.replayJournalFor(c.journal, PDUTypeX2) }
func (c *Client) replayJournalFor(j *Journal, t PDUType) {
	defer c.wg.Done()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var revision uint64
	var refreshed time.Time
	streams := make(map[uuid.UUID][]replayCandidate)
	for !c.stopped.Load() {
		j.controlMu.Lock()
		stats := j.Stats()
		if stats.LastError != "" || stats.ReplayPending == 0 {
			j.replayStarted = false
			j.controlMu.Unlock()
			return
		}
		j.mu.Lock()
		current := j.replayRevision
		j.mu.Unlock()
		// An outage must not repeatedly sort a growing durable backlog while
		// every transport queue is full. Rebuild at most ten times per second,
		// and retain the bounded candidate snapshot between those refreshes.
		refresh := len(streams) == 0 || time.Since(refreshed) >= 100*time.Millisecond
		if current != revision && refresh && c.replayHasCapacity(t) {
			streams = make(map[uuid.UUID][]replayCandidate)
			candidates := j.replayCandidates()
			for first := 0; first < len(candidates); {
				end := first + 1
				for end < len(candidates) && candidates[end].did == candidates[first].did {
					end++
				}
				streams[candidates[first].did] = candidates[first:end:end]
				first = end
			}
			revision = current
			refreshed = time.Now()
		}
		j.controlMu.Unlock()
		for did, items := range streams {
			// One destination can consume at most100 slots per sweep, preventing it
			// from starving other destinations while a large backlog drains.
			consumed := 0
			for len(items) > 0 && consumed < 100 {
				if c.stopped.Load() {
					return
				}
				j.controlMu.Lock()
				progress := c.feedJournalRecordFor(j, t, items[0])
				j.controlMu.Unlock()
				if !progress {
					break
				}
				items = items[1:]
				consumed++
			}
			if len(items) == 0 {
				delete(streams, did)
			} else {
				streams[did] = items
			}
		}
		<-ticker.C
	}
}

func (c *Client) replayHasCapacity(t PDUType) bool {
	c.queuesMu.RLock()
	defer c.queuesMu.RUnlock()
	if len(c.queues) == 0 {
		return true
	}
	for _, q := range c.queues {
		q.mu.Lock()
		i := queueIndex(t)
		room := !q.stopped && q.items[i].Len()+q.reserved[i] < q.capacities[i] && (q.limits[i] == 0 || q.bytes[i]+q.reservedBytes[i] < q.limits[i])
		q.mu.Unlock()
		if room {
			return true
		}
	}
	return false
}
func (c *Client) feedJournalRecord(candidate replayCandidate) bool {
	return c.feedJournalRecordFor(c.journal, PDUTypeX2, candidate)
}
func (c *Client) feedJournalRecordFor(j *Journal, t PDUType, candidate replayCandidate) bool {
	j.mu.Lock()
	entry := j.entries[candidate.id]
	retained := entry != nil && entry.held && !entry.completing
	authorized := retained && entry.authorized
	j.mu.Unlock()
	if !retained {
		return true
	}
	if !authorized {
		return false
	}
	q := c.getOrCreateQueue(candidate.did)
	if q == nil {
		return false
	}
	q.mu.Lock()
	room := !q.stopped && q.items[queueIndex(t)].Len()+q.reserved[queueIndex(t)] < q.capacities[queueIndex(t)] && (q.limits[queueIndex(t)] == 0 || candidate.bytes <= q.limits[queueIndex(t)]-q.bytes[queueIndex(t)]-q.reservedBytes[queueIndex(t)])
	q.mu.Unlock()
	if !room {
		return false
	}
	r, err := j.readRecord(candidate.id)
	if err != nil {
		j.fault(err)
		return false
	}
	dest, err := c.manager.GetDestination(r.DID)
	if err != nil || li.DestinationDeliveryGeneration(dest) != r.DestinationGeneration || !destinationAcceptsPDU(dest, t) {
		j.mu.Lock()
		if e := j.entries[r.ID]; e != nil {
			if e.authorized {
				j.stats.ReplayPending--
			}
			e.authorized = false
		}
		j.mu.Unlock()
		return false
	}
	item := &deliveryItem{pduType: t, journal: j, xid: r.XID, data: r.Data, queued: r.AdmittedAt, metadata: DeliveryMetadata{AdmittedAt: r.AdmittedAt, CapturedAt: r.CapturedAt, TaskGeneration: r.TaskGeneration, DestinationGeneration: r.DestinationGeneration, CallGeneration: r.CallGeneration, CallID: r.CallID, CallIncarnation: r.CallIncarnation, StateIncarnation: r.StateIncarnation, Deadline: r.Deadline, Provenance: r.Provenance}}
	if t == PDUTypeX3 {
		item.metadata.TaskEndAt = c.x3TaskEnd(r.XID, r.TaskGeneration)
		if !c.itemEligible(r.DID, item, false) {
			if !r.Deadline.IsZero() && !time.Now().Before(r.Deadline) {
				if err := j.Expire(r.ID); err != nil {
					j.fault(err)
					return false
				}
				return true
			}
			j.mu.Lock()
			if e := j.entries[r.ID]; e != nil && e.authorized {
				e.authorized = false
				j.stats.ReplayPending--
			}
			j.mu.Unlock()
			return false
		}
	}
	item.eligibilityDeadline = c.effectiveExpiry(item)
	item.journalID.Store(r.ID)
	item.persisted.Store(true)
	c.attachPayload(item)
	atomic.AddInt64(&c.stats.QueueDepth, 1)
	atomic.AddInt64(&c.stats.QueueBytes, int64(len(r.Data)))
	dropped, ok := j.enqueueReplay(q, item)
	if !ok {
		atomic.AddInt64(&c.stats.QueueDepth, -1)
		atomic.AddInt64(&c.stats.QueueBytes, -int64(len(r.Data)))
		item.payload.release()
		return false
	}
	if dropped != nil {
		c.resolveDrop(q, dropped, "queue_overflow")
	}
	return true
}

// enqueueReplay transfers held product to the queue before removal can return it
// to a hold. Publishing first and calling Release separately lets a concurrent
// drain call Hold while the record is still held, then clear that only owner.
func (j *Journal) enqueueReplay(q *destinationQueue, item *deliveryItem) (*deliveryItem, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	dropped, ok := q.enqueue(item)
	if ok {
		j.releaseLocked(item.journalID.Load())
	}
	return dropped, ok
}
