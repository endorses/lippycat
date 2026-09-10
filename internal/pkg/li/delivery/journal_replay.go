//go:build li

package delivery

import (
	"os"
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

func (j *Journal) replayCandidates() []replayCandidate {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]replayCandidate, 0)
	for id, e := range j.entries {
		if e.held && !e.completing {
			out = append(out, replayCandidate{id, e.did, e.payloadBytes})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].id < out[b].id })
	return out
}

// replayJournal is a single bounded feeder. It reads a payload only when its
// destination has reserved capacity and never lets later product pass an earlier
// authorized item. Authorization remains valid across post-decision task end;
// destination replacement always returns the product to an unauthorized hold.
func (c *Client) replayJournal() {
	defer c.wg.Done()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var revision uint64
	streams := make(map[uuid.UUID][]replayCandidate)
	for !c.stopped.Load() {
		c.journal.controlMu.Lock()
		stats := c.journal.Stats()
		if stats.LastError != "" || stats.ReplayPending == 0 {
			c.journal.replayStarted = false
			c.journal.controlMu.Unlock()
			return
		}
		c.journal.mu.Lock()
		current := c.journal.replayRevision
		c.journal.mu.Unlock()
		if current != revision {
			streams = make(map[uuid.UUID][]replayCandidate)
			for _, candidate := range c.journal.replayCandidates() {
				streams[candidate.did] = append(streams[candidate.did], candidate)
			}
			revision = current
		}
		c.journal.controlMu.Unlock()
		for did, items := range streams {
			// One destination can consume at most100 slots per sweep, preventing it
			// from starving other destinations while a large backlog drains.
			consumed := 0
			for len(items) > 0 && consumed < 100 {
				if c.stopped.Load() {
					return
				}
				c.journal.controlMu.Lock()
				progress := c.feedJournalRecord(items[0])
				c.journal.controlMu.Unlock()
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
func (c *Client) feedJournalRecord(candidate replayCandidate) bool {
	c.journal.mu.Lock()
	entry := c.journal.entries[candidate.id]
	retained := entry != nil && entry.held && !entry.completing
	authorized := retained && entry.authorized
	c.journal.mu.Unlock()
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
	room := !q.stopped && q.items[0].Len() < q.capacities[0] && (q.limits[0] == 0 || candidate.bytes <= q.limits[0]-q.bytes[0])
	q.mu.Unlock()
	if !room {
		return false
	}
	data, err := os.ReadFile(c.journal.path(candidate.id))
	if err != nil {
		c.journal.fault(err)
		return false
	}
	r, err := c.journal.decode(data)
	if err != nil {
		c.journal.fault(err)
		return false
	}
	dest, err := c.manager.GetDestination(r.DID)
	if err != nil || li.DestinationDeliveryGeneration(dest) != r.DestinationGeneration || !destinationAcceptsPDU(dest, PDUTypeX2) {
		c.journal.mu.Lock()
		if e := c.journal.entries[r.ID]; e != nil {
			if e.authorized {
				c.journal.stats.ReplayPending--
			}
			e.authorized = false
		}
		c.journal.mu.Unlock()
		return false
	}
	item := &deliveryItem{pduType: PDUTypeX2, xid: r.XID, data: r.Data, queued: r.AdmittedAt, metadata: DeliveryMetadata{AdmittedAt: r.AdmittedAt, CapturedAt: r.CapturedAt, TaskGeneration: r.TaskGeneration, DestinationGeneration: r.DestinationGeneration, CallGeneration: r.CallGeneration, CallID: r.CallID}}
	item.journalID.Store(r.ID)
	item.persisted.Store(true)
	c.attachPayload(item)
	atomic.AddInt64(&c.stats.QueueDepth, 1)
	atomic.AddInt64(&c.stats.QueueBytes, int64(len(r.Data)))
	dropped, ok := c.journal.enqueueReplay(q, item)
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
