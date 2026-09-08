//go:build li

package delivery

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
)

const (
	defaultReorderPacketCap = 512
	defaultReorderByteCap   = 2 << 20
)

// ReorderBuffer orders X3 RTP PDUs independently per SSRC. Delivery callbacks
// are always invoked without the buffer lock held, in committed batch order.
// A callback may discard lifecycle state, but must not recursively deliver,
// flush, stop, or wait on this same buffer: those operations may wait for it.
type ReorderBuffer struct {
	sharedWorkers      *sync.WaitGroup
	callbackWG         sync.WaitGroup
	callbackTail       <-chan struct{}
	timerWG            sync.WaitGroup
	budget             *ReorderBudget
	budgeted           bool
	onDiscard          func(int)
	mu                 sync.Mutex
	streams            map[reorderStreamKey]*rtpStream
	deliverFn          func(ReorderEntry)
	flushDelay         time.Duration
	packetCap, byteCap int
	stopped            bool
}
type bufferedPDU struct {
	seqNum  uint16
	entry   ReorderEntry
	arrived time.Time
}

// ReorderEntry carries the immutable call lifecycle identity associated with an
// X3 PDU. CallID and Generation are empty for callers using the legacy API.
type ReorderEntry struct {
	budgetCharge int64
	Metadata     li.DeliveryMetadata
	CallID       string
	Generation   uint64
	PDU          []byte
}
type reorderStreamKey struct {
	callID     string
	generation uint64
	ssrc       uint32
}
type rtpStream struct {
	budget          *ReorderBudget
	buffer          map[uint16]bufferedPDU
	bytes           int
	lastFlushed     uint16
	hasBase         bool
	timer           *time.Timer
	timerGeneration uint64
	timerDone       func()
	deadline        time.Time
	lastUsed        time.Time
}

func NewReorderBuffer(deliverFn func([]byte), flushDelay time.Duration) *ReorderBuffer {
	return NewReorderBufferWithLimits(deliverFn, flushDelay, defaultReorderPacketCap, defaultReorderByteCap)
}
func NewReorderBufferWithLimits(deliverFn func([]byte), flushDelay time.Duration, packetCap, byteCap int) *ReorderBuffer {
	return NewCallAwareReorderBufferWithLimits(func(entry ReorderEntry) { deliverFn(entry.PDU) }, flushDelay, packetCap, byteCap)
}
func NewCallAwareReorderBuffer(deliverFn func(ReorderEntry), flushDelay time.Duration) *ReorderBuffer {
	return NewCallAwareReorderBufferWithLimits(deliverFn, flushDelay, defaultReorderPacketCap, defaultReorderByteCap)
}
func NewCallAwareReorderBufferWithLimits(deliverFn func(ReorderEntry), flushDelay time.Duration, packetCap, byteCap int) *ReorderBuffer {
	if packetCap <= 0 {
		packetCap = defaultReorderPacketCap
	}
	if byteCap <= 0 {
		byteCap = defaultReorderByteCap
	}
	return &ReorderBuffer{streams: make(map[reorderStreamKey]*rtpStream), deliverFn: deliverFn, flushDelay: flushDelay, packetCap: packetCap, byteCap: byteCap}
}
func (rb *ReorderBuffer) DeliverX2(pdu []byte) { rb.deliverFn(ReorderEntry{PDU: pdu}) }
func (rb *ReorderBuffer) DeliverX3(ssrc uint32, seq uint16, pdu []byte) {
	rb.DeliverCallX3("", 0, ssrc, seq, pdu)
}
func (rb *ReorderBuffer) DeliverCallX3(callID string, generation uint64, ssrc uint32, seq uint16, pdu []byte) {
	rb.DeliverCallX3AfterCommit(callID, generation, ssrc, seq, pdu, nil)
}

// DeliverCallX3AfterCommit inserts the PDU while the caller's admission is
// still held, invokes afterCommit once the buffer mutation is complete, and
// only then invokes delivery callbacks. This lets callers release admission
// barriers before a synchronous callback re-admits around its final enqueue.
func (rb *ReorderBuffer) DeliverCallX3AfterCommit(callID string, generation uint64, ssrc uint32, seq uint16, pdu []byte, afterCommit func()) {
	rb.DeliverEntryX3AfterCommit(ReorderEntry{CallID: callID, Generation: generation, PDU: pdu, Metadata: li.DeliveryMetadata{AdmittedAt: time.Now(), CallID: callID, CallGeneration: generation}}, ssrc, seq, afterCommit)
}

// DeliverEntryX3AfterCommit preserves the producer's immutable admission metadata.
func (rb *ReorderBuffer) DeliverEntryX3AfterCommit(entry ReorderEntry, ssrc uint32, seq uint16, afterCommit func()) {
	now := time.Now()
	// Start local residence at the first reorder admission when the producer
	// has not supplied an earlier admission. Final delivery enqueue must not
	// reset the age clock after an RTP gap has delayed this entry.
	if entry.Metadata.AdmittedAt.IsZero() || entry.Metadata.AdmittedAt.After(now) {
		entry.Metadata.AdmittedAt = now
	}
	pdu := entry.PDU
	key := reorderStreamKey{callID: entry.CallID, generation: entry.Generation, ssrc: ssrc}
	rb.mu.Lock()
	if rb.stopped || len(entry.CallID) > 128 {
		rb.mu.Unlock()
		if afterCommit != nil {
			afterCommit()
		}
		if rb.onDiscard != nil {
			rb.onDiscard(1)
		}
		return
	}
	entry.CallID = strings.Clone(entry.CallID)
	entry.Metadata.CallID = entry.CallID
	entry.Metadata.CallGeneration = entry.Generation
	key.callID = entry.CallID
	charge := int64(len(pdu)) + reorderPacketCharge
	if !rb.budget.reserve(charge) {
		rb.mu.Unlock()
		if afterCommit != nil {
			afterCommit()
		}
		if rb.onDiscard != nil {
			rb.onDiscard(1)
		}
		return
	}
	if rb.budget != nil {
		entry.budgetCharge = charge
	}
	s := rb.streams[key]
	if s == nil {
		if !rb.budget.reserve(reorderStreamCharge) {
			rb.budget.release(charge)
			rb.mu.Unlock()
			if afterCommit != nil {
				afterCommit()
			}
			if rb.onDiscard != nil {
				rb.onDiscard(1)
			}
			return
		}
		s = &rtpStream{budget: rb.budget, buffer: make(map[uint16]bufferedPDU)}
		rb.streams[key] = s
	}
	s.lastUsed = now
	var out []ReorderEntry
	if !s.hasBase {
		s.hasBase = true
		s.lastFlushed = seq
		out = append(out, entry)
	} else {
		next := s.lastFlushed + 1
		switch {
		case seq == next:
			s.lastFlushed = seq
			out = append(out, entry)
			out = append(out, drainConsecutive(s)...)
			if len(s.buffer) == 0 {
				rb.disarmLocked(s)
			}
		case seqBefore(seq, next):
			out = append(out, entry)
		default:
			if _, dup := s.buffer[seq]; !dup {
				entry.PDU = append([]byte(nil), entry.PDU...)
				s.buffer[seq] = bufferedPDU{seqNum: seq, entry: entry, arrived: now}
				s.bytes += len(pdu)
			} else {
				rb.budget.release(entry.budgetCharge)
			}
			rb.armTimerLocked(key, s, now)
			if len(s.buffer) > rb.packetCap || s.bytes > rb.byteCap {
				out = append(out, drainAll(s)...)
				rb.disarmLocked(s)
			}
		}
	}
	previous, done := rb.reserveDeliveryLocked(out)
	rb.mu.Unlock()
	if afterCommit != nil {
		afterCommit()
	}
	rb.deliver(out, previous, done)
}
func drainConsecutive(s *rtpStream) (out []ReorderEntry) {
	for {
		next := s.lastFlushed + 1
		bp, ok := s.buffer[next]
		if !ok {
			return
		}
		delete(s.buffer, next)
		s.bytes -= len(bp.entry.PDU)
		s.lastFlushed = next
		out = append(out, bp.entry)
	}
}
func ordered(s *rtpStream) []bufferedPDU {
	v := make([]bufferedPDU, 0, len(s.buffer))
	for _, bp := range s.buffer {
		v = append(v, bp)
	}
	sort.Slice(v, func(i, j int) bool {
		return uint16(v[i].seqNum-(s.lastFlushed+1)) < uint16(v[j].seqNum-(s.lastFlushed+1))
	})
	return v
}
func drainAll(s *rtpStream) (out []ReorderEntry) {
	for _, bp := range ordered(s) {
		out = append(out, bp.entry)
		s.lastFlushed = bp.seqNum
	}
	clear(s.buffer)
	s.bytes = 0
	return
}
func (rb *ReorderBuffer) armTimerLocked(key reorderStreamKey, s *rtpStream, now time.Time) {
	if len(s.buffer) == 0 || s.timer != nil {
		return
	}
	oldest := now
	for _, bp := range s.buffer {
		if bp.arrived.Before(oldest) {
			oldest = bp.arrived
		}
	}
	s.deadline = oldest.Add(rb.flushDelay)
	delay := time.Until(s.deadline)
	if delay < 0 {
		delay = 0
	}
	rb.timerWG.Add(1)
	if rb.sharedWorkers != nil {
		rb.sharedWorkers.Add(1)
	}
	once := &sync.Once{}
	done := func() {
		once.Do(func() {
			rb.timerWG.Done()
			if rb.sharedWorkers != nil {
				rb.sharedWorkers.Done()
			}
		})
	}
	s.timerDone = done
	s.timerGeneration++
	generation := s.timerGeneration
	s.timer = time.AfterFunc(delay, func() { defer done(); rb.flush(key, s, generation) })
}
func (rb *ReorderBuffer) disarmLocked(s *rtpStream) {
	// A timer that already fired may still be waiting for rb.mu. Revoke that
	// invocation before a subsequent gap arms another timer on the same stream.
	s.timerGeneration++
	if s.timer != nil {
		if s.timer.Stop() {
			s.timerDone()
		}
		s.timer = nil
	}
	s.deadline = time.Time{}
}
func (rb *ReorderBuffer) flush(key reorderStreamKey, expected *rtpStream, generation uint64) {
	rb.mu.Lock()
	s := rb.streams[key]
	if s == nil || s != expected || s.timerGeneration != generation {
		rb.mu.Unlock()
		return
	}
	s.timer = nil
	s.deadline = time.Time{}
	out := drainAll(s)
	previous, done := rb.reserveDeliveryLocked(out)
	rb.mu.Unlock()
	rb.deliver(out, previous, done)
}

// reserveDeliveryLocked fixes callback order at the same point as RTP order.
// Waiting happens only after afterCommit releases producer admission barriers.
func (rb *ReorderBuffer) reserveDeliveryLocked(out []ReorderEntry) (<-chan struct{}, chan struct{}) {
	if len(out) == 0 {
		return nil, nil
	}
	previous := rb.callbackTail
	done := make(chan struct{})
	rb.callbackTail = done
	rb.callbackWG.Add(1)
	if rb.sharedWorkers != nil {
		rb.sharedWorkers.Add(1)
	}
	return previous, done
}

func (rb *ReorderBuffer) deliver(out []ReorderEntry, previous <-chan struct{}, done chan struct{}) {
	if done != nil {
		defer close(done)
		if previous != nil {
			<-previous
		}
	}
	if len(out) > 0 {
		defer rb.callbackWG.Done()
		if rb.sharedWorkers != nil {
			defer rb.sharedWorkers.Done()
		}
	}
	for _, entry := range out {
		rb.deliverFn(entry)
		rb.budget.release(entry.budgetCharge)
	}
}
func (rb *ReorderBuffer) LastUsed() time.Time {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	var latest time.Time
	for _, s := range rb.streams {
		if s.lastUsed.After(latest) {
			latest = s.lastUsed
		}
	}
	return latest
}
func (rb *ReorderBuffer) CleanupIdleStreams(maxIdle time.Duration) bool {
	now := time.Now()
	rb.mu.Lock()
	var out []ReorderEntry
	for id, s := range rb.streams {
		if now.Sub(s.lastUsed) > maxIdle {
			rb.disarmLocked(s)
			out = append(out, drainAll(s)...)
			rb.budget.release(reorderStreamCharge)
			delete(rb.streams, id)
		}
	}
	empty := len(rb.streams) == 0
	previous, done := rb.reserveDeliveryLocked(out)
	rb.mu.Unlock()
	rb.deliver(out, previous, done)
	return empty
}
func (rb *ReorderBuffer) Stop() {
	rb.mu.Lock()
	if rb.stopped {
		rb.mu.Unlock()
		return
	}
	rb.stopped = true
	var out []ReorderEntry
	for _, s := range rb.streams {
		rb.disarmLocked(s)
		out = append(out, drainAll(s)...)
		rb.budget.release(reorderStreamCharge)
	}
	if rb.budgeted {
		rb.budget.release(reorderBufferCharge)
		rb.budgeted = false
	}
	clear(rb.streams)
	previous, done := rb.reserveDeliveryLocked(out)
	rb.mu.Unlock()
	rb.deliver(out, previous, done)
}

// DiscardCall drops queued PDUs for exactly one call generation. It leaves
// other calls sharing this XID/destination buffer untouched and returns the
// number of discarded PDUs for single-owner accounting.
func (rb *ReorderBuffer) DiscardCall(callID string, generation uint64) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	discarded := 0
	for key, stream := range rb.streams {
		if key.callID != callID || key.generation != generation {
			continue
		}
		rb.disarmLocked(stream)
		discarded += len(stream.buffer)
		rb.budget.release(reorderStreamCharge + int64(stream.bytes) + int64(len(stream.buffer))*reorderPacketCharge)
		delete(rb.streams, key)
	}
	return discarded
}

// Discard stops the buffer and drops every queued PDU without invoking the
// delivery callback. Task deactivation and expiry use this path: once
// enforcement ends, packets held only for reordering must not be emitted.
func (rb *ReorderBuffer) Discard() {
	rb.DiscardCount()
}

// DiscardCount is Discard with single-owner accounting for queued PDUs.
func (rb *ReorderBuffer) DiscardCount() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.stopped {
		return 0
	}
	rb.stopped = true
	discarded := 0
	for _, s := range rb.streams {
		rb.disarmLocked(s)
		discarded += len(s.buffer)
		rb.budget.release(reorderStreamCharge + int64(s.bytes) + int64(len(s.buffer))*reorderPacketCharge)
		clear(s.buffer)
		s.bytes = 0
	}
	clear(rb.streams)
	if rb.budgeted {
		rb.budget.release(reorderBufferCharge)
		rb.budgeted = false
	}
	return discarded
}
func (rb *ReorderBuffer) Buffered() (packets, bytes int) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for _, s := range rb.streams {
		packets += len(s.buffer)
		bytes += s.bytes
	}
	return
}
func seqBefore(a, b uint16) bool { return int16(a-b) < 0 }

// Wait joins callbacks after Stop or Discard. Do not call from a delivery
// callback: lifecycle finalization uses Discard alone; processor shutdown joins.
func (rb *ReorderBuffer) Wait() { rb.timerWG.Wait(); rb.callbackWG.Wait() }

// SetWorkerGroup attaches the processor shutdown barrier before publication.
func (rb *ReorderBuffer) SetWorkerGroup(group *sync.WaitGroup) { rb.sharedWorkers = group }
