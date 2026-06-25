package capture

import (
	"io"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// tcpHalfStreamBufferChunks bounds the per-stream reassembled-chunk buffer.
// Non-blocking sends mean excess chunks are dropped rather than blocking the
// capture loop (the same trade-off the legacy bufferedSIPStream made).
const tcpHalfStreamBufferChunks = 64

// TCPHalfStream adapts gopacket's connection-aware reassembly.Stream to a plain
// io.Reader, so protocol parsers (HTTP, SMTP/IMAP/POP3, DNS, TLS) can consume a
// reassembled TCP half-stream without depending on the legacy
// tcpassembly/tcpreader packages (which cannot be linked alongside reassembly —
// both register the same global flags and panic at init).
//
// Reassembled bytes are copied out of the scatter-gather (its pages are reused)
// into a bounded buffered channel, then pumped into an io.Pipe. The consumer
// reads the returned io.Reader and MUST Close it when done (see NewTCPHalfStream)
// so a pump blocked mid-write unblocks and the goroutine exits.
//
// Connection-boundary handling: ReassemblyComplete returns true so a closed
// connection is evicted from the pool; a reused TCP 4-tuple then gets a fresh
// stream instead of appending to the stale one.
type TCPHalfStream struct {
	dataChan chan []byte
	closed   int32
}

// NewTCPHalfStream creates a reassembly.Stream adapter and returns it along with
// the io.PipeReader the consumer should read (and Close on exit). A pump
// goroutine copies reassembled chunks into the pipe; it exits when the stream is
// completed (ReassemblyComplete) or the reader is closed.
func NewTCPHalfStream() (*TCPHalfStream, *io.PipeReader) {
	s := &TCPHalfStream{dataChan: make(chan []byte, tcpHalfStreamBufferChunks)}
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for b := range s.dataChan {
			if _, err := pw.Write(b); err != nil {
				// Reader closed (consumer finished/errored). Drain the rest so
				// ReassembledSG's non-blocking sends keep dropping cleanly.
				for range s.dataChan {
				}
				return
			}
		}
	}()
	return s, pr
}

// Accept implements reassembly.Stream. Accept every packet and force reassembly
// to start from the first packet seen for the connection (even mid-stream with
// no observed SYN) — passive-monitor behaviour. start has effect only on a fresh
// connection; it is ignored once a start sequence is established.
func (s *TCPHalfStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	*start = true
	return true
}

// ReassembledSG implements reassembly.Stream. Never blocks: copies the available
// bytes and does a non-blocking send (dropping on a full buffer).
func (s *TCPHalfStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	available, _ := sg.Lengths()
	if available == 0 {
		return
	}
	data := make([]byte, available)
	copy(data, sg.Fetch(available))
	select {
	case s.dataChan <- data:
	default:
		// Buffer full - drop (better than blocking the capture loop).
	}
}

// ReassemblyComplete implements reassembly.Stream. Closes the byte stream (so the
// consumer sees EOF) and returns true to evict the connection from the pool,
// which is what lets a reused TCP 4-tuple get a fresh stream.
func (s *TCPHalfStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.dataChan)
	}
	return true
}
