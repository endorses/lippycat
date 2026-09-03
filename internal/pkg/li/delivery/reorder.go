//go:build li

package delivery

import (
	"sort"
	"sync"
	"time"
)

const (
	defaultReorderPacketCap = 512
	defaultReorderByteCap   = 2 << 20
)

// ReorderBuffer orders X3 RTP PDUs independently per SSRC. Delivery callbacks
// are always invoked without the buffer lock held.
type ReorderBuffer struct {
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
	CallID     string
	Generation uint64
	PDU        []byte
}
type reorderStreamKey struct {
	callID     string
	generation uint64
	ssrc       uint32
}
type rtpStream struct {
	buffer      map[uint16]bufferedPDU
	bytes       int
	lastFlushed uint16
	hasBase     bool
	timer       *time.Timer
	deadline    time.Time
	lastUsed    time.Time
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
	now := time.Now()
	key := reorderStreamKey{callID: callID, generation: generation, ssrc: ssrc}
	rb.mu.Lock()
	if rb.stopped {
		rb.mu.Unlock()
		if afterCommit != nil {
			afterCommit()
		}
		return
	}
	s := rb.streams[key]
	if s == nil {
		s = &rtpStream{buffer: make(map[uint16]bufferedPDU)}
		rb.streams[key] = s
	}
	s.lastUsed = now
	entry := ReorderEntry{CallID: callID, Generation: generation, PDU: pdu}
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
		case seqBefore(seq, next):
			out = append(out, entry)
		default:
			if _, dup := s.buffer[seq]; !dup {
				s.buffer[seq] = bufferedPDU{seqNum: seq, entry: entry, arrived: now}
				s.bytes += len(pdu)
			}
			rb.armTimerLocked(key, s, now)
			if len(s.buffer) > rb.packetCap || s.bytes > rb.byteCap {
				out = append(out, drainAll(s)...)
				rb.disarmLocked(s)
			}
		}
	}
	rb.mu.Unlock()
	if afterCommit != nil {
		afterCommit()
	}
	rb.deliver(out)
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
	s.timer = time.AfterFunc(delay, func() { rb.flush(key) })
}
func (rb *ReorderBuffer) disarmLocked(s *rtpStream) {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.deadline = time.Time{}
}
func (rb *ReorderBuffer) flush(key reorderStreamKey) {
	rb.mu.Lock()
	s := rb.streams[key]
	if s == nil {
		rb.mu.Unlock()
		return
	}
	s.timer = nil
	s.deadline = time.Time{}
	out := drainAll(s)
	rb.mu.Unlock()
	rb.deliver(out)
}
func (rb *ReorderBuffer) deliver(out []ReorderEntry) {
	for _, entry := range out {
		rb.deliverFn(entry)
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
			delete(rb.streams, id)
		}
	}
	empty := len(rb.streams) == 0
	rb.mu.Unlock()
	rb.deliver(out)
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
	}
	clear(rb.streams)
	rb.mu.Unlock()
	rb.deliver(out)
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
		delete(rb.streams, key)
	}
	return discarded
}

// Discard stops the buffer and drops every queued PDU without invoking the
// delivery callback. Task deactivation and expiry use this path: once
// enforcement ends, packets held only for reordering must not be emitted.
func (rb *ReorderBuffer) Discard() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.stopped {
		return
	}
	rb.stopped = true
	for _, s := range rb.streams {
		rb.disarmLocked(s)
		clear(s.buffer)
		s.bytes = 0
	}
	clear(rb.streams)
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
