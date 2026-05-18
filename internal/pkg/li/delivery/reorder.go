//go:build li

package delivery

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// ReorderBuffer buffers X3 (RTP) PDUs per SSRC and delivers them in RTP
// sequence order. X2 (SIP/IRI) PDUs bypass the buffer entirely.
//
// The buffer holds packets for up to FlushDelay, then flushes all buffered
// packets in sequence order regardless of gaps.
type ReorderBuffer struct {
	mu         sync.Mutex
	streams    map[uint32]*rtpStream // keyed by SSRC
	deliverFn  func(pdu []byte)      // callback to deliver a PDU
	flushDelay time.Duration
	stopped    bool
}

type bufferedPDU struct {
	seqNum uint16
	pdu    []byte
}

type rtpStream struct {
	buffer      []bufferedPDU
	lastFlushed uint16
	hasBase     bool // whether lastFlushed has been initialized
	timer       *time.Timer
	lastUsed    time.Time
}

// NewReorderBuffer creates a new reorder buffer.
// deliverFn is called for each PDU in the correct order.
// flushDelay controls how long to wait for out-of-order packets (e.g., 60ms).
func NewReorderBuffer(deliverFn func(pdu []byte), flushDelay time.Duration) *ReorderBuffer {
	return &ReorderBuffer{
		streams:    make(map[uint32]*rtpStream),
		deliverFn:  deliverFn,
		flushDelay: flushDelay,
	}
}

// DeliverX2 delivers an X2 (SIP/IRI) PDU immediately without buffering.
func (rb *ReorderBuffer) DeliverX2(pdu []byte) {
	rb.deliverFn(pdu)
}

// DeliverX3 buffers an X3 (RTP/CC) PDU and delivers it in sequence order.
func (rb *ReorderBuffer) DeliverX3(ssrc uint32, rtpSeq uint16, pdu []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.stopped {
		return
	}

	stream, ok := rb.streams[ssrc]
	if !ok {
		stream = &rtpStream{}
		rb.streams[ssrc] = stream
	}
	stream.lastUsed = time.Now()

	if !stream.hasBase {
		// First packet for this stream — deliver immediately and set baseline
		stream.lastFlushed = rtpSeq
		stream.hasBase = true
		rb.deliverFn(pdu)
		rb.startFlushTimer(ssrc, stream)
		return
	}

	// Check if this is the next expected packet
	nextExpected := stream.lastFlushed + 1
	if rtpSeq == nextExpected {
		// In order — deliver and flush any consecutive buffered packets
		stream.lastFlushed = rtpSeq
		rb.deliverFn(pdu)
		rb.flushConsecutive(stream)
		rb.resetFlushTimer(ssrc, stream)
		return
	}

	// Late packet (already past this sequence)
	if seqBefore(rtpSeq, nextExpected) {
		// Deliver late packet immediately — better late than dropped
		logger.Debug("RTP reorder: late packet delivered",
			"ssrc", ssrc, "seq", rtpSeq, "expected", nextExpected)
		rb.deliverFn(pdu)
		return
	}

	// Early packet (gap — waiting for earlier packets)
	stream.buffer = append(stream.buffer, bufferedPDU{seqNum: rtpSeq, pdu: pdu})
	// Always (re)arm the flush timer when buffering — otherwise packets can
	// sit indefinitely if the previous timer already fired.
	rb.resetFlushTimer(ssrc, stream)
}

// flushConsecutive delivers all consecutive packets from the buffer starting
// from lastFlushed+1.
func (rb *ReorderBuffer) flushConsecutive(stream *rtpStream) {
	for {
		nextExpected := stream.lastFlushed + 1
		found := false
		for i, bp := range stream.buffer {
			if bp.seqNum == nextExpected {
				stream.lastFlushed = bp.seqNum
				rb.deliverFn(bp.pdu)
				// Remove from buffer
				stream.buffer = append(stream.buffer[:i], stream.buffer[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
}

// flushAll delivers all buffered packets in sequence order, regardless of gaps.
func (rb *ReorderBuffer) flushAll(ssrc uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream, ok := rb.streams[ssrc]
	if !ok || len(stream.buffer) == 0 {
		return
	}

	// Sort buffer by sequence number
	sortBuffer(stream.buffer)

	logger.Debug("RTP reorder: flush timeout, delivering buffered packets",
		"ssrc", ssrc, "count", len(stream.buffer))

	for _, bp := range stream.buffer {
		stream.lastFlushed = bp.seqNum
		rb.deliverFn(bp.pdu)
	}
	stream.buffer = stream.buffer[:0]
}

func (rb *ReorderBuffer) startFlushTimer(ssrc uint32, stream *rtpStream) {
	stream.timer = time.AfterFunc(rb.flushDelay, func() {
		rb.flushAll(ssrc)
	})
}

func (rb *ReorderBuffer) resetFlushTimer(ssrc uint32, stream *rtpStream) {
	if stream.timer != nil {
		stream.timer.Stop()
	}
	stream.timer = time.AfterFunc(rb.flushDelay, func() {
		rb.flushAll(ssrc)
	})
}

// LastUsed returns the most recent lastUsed time across all streams.
// Returns the zero time if there are no streams.
func (rb *ReorderBuffer) LastUsed() time.Time {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	var latest time.Time
	for _, stream := range rb.streams {
		if stream.lastUsed.After(latest) {
			latest = stream.lastUsed
		}
	}
	return latest
}

// CleanupIdleStreams removes streams where no packet has arrived in maxIdle
// duration, stopping their timers. Returns true if all streams were removed
// (i.e., the buffer is now empty).
func (rb *ReorderBuffer) CleanupIdleStreams(maxIdle time.Duration) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	now := time.Now()
	for ssrc, stream := range rb.streams {
		if now.Sub(stream.lastUsed) > maxIdle {
			if stream.timer != nil {
				stream.timer.Stop()
			}
			// Flush any remaining buffered packets before removing
			sortBuffer(stream.buffer)
			for _, bp := range stream.buffer {
				rb.deliverFn(bp.pdu)
			}
			delete(rb.streams, ssrc)
		}
	}
	return len(rb.streams) == 0
}

// Stop flushes all streams and stops the buffer.
func (rb *ReorderBuffer) Stop() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.stopped = true
	for _, stream := range rb.streams {
		if stream.timer != nil {
			stream.timer.Stop()
		}
		sortBuffer(stream.buffer)
		for _, bp := range stream.buffer {
			rb.deliverFn(bp.pdu)
		}
		stream.buffer = nil
	}
}

// seqBefore returns true if a comes before b in the RTP sequence space
// (handles uint16 wraparound).
func seqBefore(a, b uint16) bool {
	return int16(a-b) < 0
}

func sortBuffer(buf []bufferedPDU) {
	// Simple insertion sort — buffer is typically very small (<10 items)
	for i := 1; i < len(buf); i++ {
		for j := i; j > 0 && seqBefore(buf[j].seqNum, buf[j-1].seqNum); j-- {
			buf[j], buf[j-1] = buf[j-1], buf[j]
		}
	}
}
