package voip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SIPMessageHandler processes complete SIP messages after TCP reassembly
type SIPMessageHandler interface {
	// HandleSIPMessage is called when a complete SIP message has been reassembled from TCP stream
	// Parameters:
	//   - sipMessage: complete SIP message bytes (headers + body)
	//   - callID: extracted Call-ID from message headers
	//   - srcEndpoint: source IP:port (e.g., "192.168.1.1:5060")
	//   - dstEndpoint: destination IP:port (e.g., "192.168.1.2:5060")
	//   - netFlow: network layer flow (IP addresses only) - used for TCP packet buffer lookup
	//   - transportFlow: transport layer flow (TCP ports) - used for TCP packet buffer lookup
	// Returns:
	//   - bool: true if message was accepted/matched filter (for metrics)
	HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool
}

// timestampedSIPMessageHandler lets production handlers preserve the capture
// timestamp of the TCP segment that completed a framed SIP message.
type timestampedSIPMessageHandler interface {
	HandleSIPMessageAt([]byte, string, string, string, gopacket.Flow, gopacket.Flow, time.Time) bool
}

// parsedSIPMessageHandler accepts the parser result already produced by TCP
// framing. Migrated handlers implement this to avoid parsing each message a
// second time; legacy handlers continue through the interfaces above.
type parsedSIPMessageHandler interface {
	HandleParsedSIPMessage([]byte, sharedsip.Event, string, string, gopacket.Flow, gopacket.Flow) bool
}

// bufferedSIPStream implements reassembly.Stream with a buffered channel.
// This guarantees ReassembledSG() NEVER blocks, which is critical because:
// 1. The assembler calls ReassembledSG() synchronously from the packet loop
// 2. If ReassembledSG() blocks, the entire packet capture freezes
//
// By using a buffered channel with non-blocking sends, we ensure the
// packet capture loop always continues, even if processing is slow.
// Data is dropped only when the buffer is full (better than freezing).
type bufferedSIPStream struct {
	// The assembler sees the root stream. Each TCP half has its own reader and
	// framing state; root coordinates their shared admission slot and teardown.
	root           *bufferedSIPStream
	reverse        *bufferedSIPStream
	workerMu       sync.Mutex // root only: workers, slot, and terminal metrics
	liveWorkers    int        // root only
	slotReserved   bool       // root only
	workerFailed   bool       // root only
	dataChan       chan streamChunk
	ctx            context.Context
	cancel         context.CancelFunc
	factory        *sipStreamFactory
	callIDDetector *CallIDDetector
	netFlow        gopacket.Flow // Network layer flow (IP addresses)
	transportFlow  gopacket.Flow // Transport layer flow (ports)
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
	closed         int32     // atomic flag - root is set permanently on assembler eviction
	finished       int32     // atomic flag - set once the processing goroutine has fully exited (re-arm gate)
	discard        int32     // atomic flag - set when stream is determined to be non-SIP
	lockedOnSIP    int32     // atomic flag - set once at least one SIP message has been parsed
	nonSIPBytes    int64     // atomic - bytes scanned as non-SIP since the last successful SIP message
	pendingGap     streamGap // assembler-owned; attached to the next queued chunk
	rearmPrefix    []byte    // assembler-owned; bounded start-line probe after this half exits

	// State-based timeout support (Phase 3)
	state            TCPState      // Current TCP state
	stateMu          sync.Mutex    // Protects state field
	stateChan        chan TCPState // Channel to notify timeout goroutine of state changes
	captureMu        sync.RWMutex
	capturedAt       time.Time
	messageTimestamp time.Time
}

// Buffer size for reassembled data chunks.
// Each TCP segment creates one entry, so this should handle bursts.
const streamBufferSize = 64

type streamChunk struct {
	data      []byte
	timestamp time.Time
	gap       streamGap
}

type streamGapReason uint8

const (
	streamGapNone       streamGapReason = 0
	streamGapReassembly streamGapReason = 1 << iota
	streamGapQueueOverflow
)

type streamGap struct {
	reason       streamGapReason
	missingBytes int
	droppedBytes int
}

func (g *streamGap) merge(other streamGap) {
	g.reason |= other.reason
	g.missingBytes += other.missingBytes
	g.droppedBytes += other.droppedBytes
}

// discardStream is returned by the factory when the voip.max_streams cap is hit.
// It satisfies reassembly.Stream without allocating buffers or goroutines.
type discardStream struct{}

func (d *discardStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return false
}

func (d *discardStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {}

func (d *discardStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool { return true }

// newBufferedSIPStream creates one reassembly.Stream with independent readers
// for the two TCP sequence spaces. Both readers start immediately.
// Both netFlow (IP addresses) and transportFlow (ports) are needed to construct
// proper IP:port endpoints for the SIP message handler.
func newBufferedSIPStream(parentCtx context.Context, factory *sipStreamFactory, detector *CallIDDetector, netFlow, transportFlow gopacket.Flow) *bufferedSIPStream {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &bufferedSIPStream{
		dataChan:       make(chan streamChunk, streamBufferSize),
		ctx:            ctx,
		cancel:         cancel,
		factory:        factory,
		callIDDetector: detector,
		netFlow:        netFlow,
		transportFlow:  transportFlow,
		createdAt:      time.Now(),
		state:          TCPStateOpening,
		liveWorkers:    2,
		slotReserved:   factory != nil,
	}
	reverseCtx, reverseCancel := context.WithCancel(parentCtx)
	s.reverse = &bufferedSIPStream{
		root:           s,
		dataChan:       make(chan streamChunk, streamBufferSize),
		ctx:            reverseCtx,
		cancel:         reverseCancel,
		factory:        factory,
		callIDDetector: NewCallIDDetector(),
		netFlow:        netFlow.Reverse(),
		transportFlow:  transportFlow.Reverse(),
		createdAt:      s.createdAt,
		state:          TCPStateOpening,
	}

	// Create state change channel if state-based timeouts are enabled
	if factory != nil && factory.config != nil && factory.config.EnableStateTCPTimeouts {
		s.stateChan = make(chan TCPState, 1)
		s.reverse.stateChan = make(chan TCPState, 1)
	}

	// Start processing goroutine immediately
	if factory != nil {
		factory.allWorkers.Add(2)
	}
	go s.processLoop()
	go s.reverse.processLoop()
	return s
}

func (s *bufferedSIPStream) connection() *bufferedSIPStream {
	if s.root != nil {
		return s.root
	}
	return s
}

func (s *bufferedSIPStream) half(dir reassembly.TCPFlowDirection) *bufferedSIPStream {
	if dir == reassembly.TCPDirServerToClient && s.reverse != nil {
		return s.reverse
	}
	return s
}

// Accept starts passive capture only from payload, never an orphan control.
// Connection generations and delayed SYNs are handled by the assembler; a SYN
// retransmission must not reset SIP framing or discard state in a live half.
func (s *bufferedSIPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if nextSeq < 0 && tcp != nil && !tcp.SYN && len(tcp.Payload) == 0 {
		return false
	}
	half := s.half(dir)
	if !ci.Timestamp.IsZero() {
		half.captureMu.Lock()
		half.capturedAt = ci.Timestamp
		half.captureMu.Unlock()
	}
	*start = tcp != nil && (tcp.SYN || len(tcp.Payload) != 0)
	return true
}

// ReassembledSG implements reassembly.Stream.
// Called by the assembler when TCP data is reassembled (zero-copy scatter-gather).
// NEVER BLOCKS - uses non-blocking send to buffered channel.
func (s *bufferedSIPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	// Count ALL reassembly calls immediately (before any early returns)
	IncrementReassembledCalls()

	// Permanently closed by ReassemblyComplete (gopacket has evicted the
	// connection); a reused 4-tuple gets a fresh Stream via factory.New, so there
	// is nothing to do here.
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	dir, _, _, skip := sg.Info()
	half := s.half(dir)

	// Fast drop for a still-live but condemned non-SIP stream (the bounded scan
	// decided this connection is not SIP): stop buffering entirely without even
	// copying the segment. A FINISHED stream is handled below (it may re-arm).
	if atomic.LoadInt32(&half.finished) == 0 && atomic.LoadInt32(&half.discard) != 0 {
		IncrementPreRearmDiscardedChunk()
		return
	}

	available, _ := sg.Lengths()
	gap := streamGap{}
	if skip > 0 {
		RecordReassemblyDiscontinuity(skip)
		gap = streamGap{reason: streamGapReassembly, missingBytes: skip}
	}
	if available == 0 {
		if gap.reason != streamGapNone && len(half.rearmPrefix) > 0 {
			half.rearmPrefix = nil
			IncrementRearmRejectedChunk()
		}
		half.pendingGap.merge(gap)
		IncrementReassembledEmptyData()
		return
	}

	// Copy the data out of the scatter-gather: its backing pages are reused after
	// this call returns, so anything we keep must be copied.
	data := make([]byte, available)
	copy(data, sg.Fetch(available))
	IncrementReassembledWithData()

	// 4-tuple reuse re-arm: gopacket keeps the SAME Stream object for a reused
	// inner 4-tuple until the pool evicts it, which in ESP-NULL tap mode rarely
	// happens because bare SYN/FIN/RST carry no inner payload and are never
	// delivered — so neither factory.New (fresh stream) nor ReassemblyComplete
	// (eviction) fires when a short-lived SIP-over-TCP connection is torn down and
	// its ports are reused seconds/minutes later (e.g. a target's back-to-back MO
	// SMS legs on the same ephemeral port). Meanwhile our processing goroutine has
	// already exited (idle/read-timeout, or non-SIP discard), leaving a "zombie"
	// stream: its dataChan has no reader and discard may be set, so the reused
	// connection's SIP would be silently dropped.
	//
	// When the processing goroutine has fully exited (finished) and the incoming
	// bytes begin a fresh SIP message, RE-ARM the stream — reset the per-message
	// parser state and restart the reader — so the reused connection is parsed
	// instead of dropped. An in-progress stream (finished == 0) is never re-armed,
	// so a multi-message connection's later messages keep flowing through the
	// existing, already-working per-message read loop.
	if atomic.LoadInt32(&half.finished) != 0 {
		if gap.reason != streamGapNone && len(half.rearmPrefix) > 0 {
			half.rearmPrefix = nil
			IncrementRearmRejectedChunk()
		}
		var ready bool
		data, ready = half.collectRearmStart(data)
		if !ready {
			return
		}
		if !half.rearm() {
			return
		}
	}

	// Non-blocking send - drop data if buffer is full.
	// This is better than blocking the packet capture loop.
	half.captureMu.RLock()
	capturedAt := half.capturedAt
	half.captureMu.RUnlock()
	gap.merge(half.pendingGap)
	select {
	case half.dataChan <- streamChunk{data: data, timestamp: capturedAt, gap: gap}:
		half.pendingGap = streamGap{}
		logger.Debug("TCP data queued to stream",
			"bytes", len(data),
			"flow", fmt.Sprintf("%s:%s->%s:%s", half.netFlow.Src(), half.transportFlow.Src(), half.netFlow.Dst(), half.transportFlow.Dst()))
	default:
		// Buffer full - drop this chunk (log at debug level to avoid spam)
		RecordPostReassemblyDrop(len(data))
		half.pendingGap = gap
		half.pendingGap.merge(streamGap{reason: streamGapQueueOverflow, droppedBytes: len(data)})
		logger.Debug("TCP stream buffer full, dropping data", "bytes", len(data))
	}
}

// ReassemblyComplete implements reassembly.Stream.
// Called when the TCP stream is closed (FIN/RST or flush timeout).
// Returns true so the connection is removed from the pool — this is what lets a
// reused TCP 4-tuple (new SYN after the prior connection closed) get a fresh
// Stream instead of appending to the stale one (the SIP-over-TCP port-reuse fix).
func (s *bufferedSIPStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		s.rearmPrefix = nil
		close(s.dataChan)
		if s.reverse != nil {
			s.reverse.rearmPrefix = nil
			close(s.reverse.dataChan)
		}
	}
	return true
}

// rearm resets a Stream whose processing goroutine has fully exited so it can
// parse a fresh SIP message arriving on a reused TCP 4-tuple. It must only be
// called from ReassembledSG (the single assembler goroutine) after the previous
// processing goroutine has finished (s.finished == 1), which guarantees no other
// goroutine is reading the fields reassigned here.
//
// It restores the same clean state newBufferedSIPStream would give a brand-new
// stream — fresh context, data channel, Call-ID detector and per-message parser
// flags — and restarts the processing goroutine. Metrics/goroutine accounting is
// symmetric with the previous goroutine's teardown (which already did the
// matching Done()/decrement), so a re-arm counts as a new stream.
func (s *bufferedSIPStream) rearm() bool {
	root := s.connection()
	root.workerMu.Lock()
	defer root.workerMu.Unlock()
	if atomic.LoadInt32(&root.closed) != 0 || atomic.LoadInt32(&s.finished) == 0 {
		return false
	}
	newAdmission := root.liveWorkers == 0
	if s.factory != nil {
		// Shutdown takes the same lock before starting Wait. Reserve capacity and
		// register this worker together so no rearm can begin after Wait starts.
		s.factory.lifecycleMu.Lock()
		if atomic.LoadInt32(&s.factory.closed) != 0 {
			s.factory.lifecycleMu.Unlock()
			return false
		}
		if newAdmission {
			current, reserved := s.factory.reserveStreamSlot()
			if !reserved {
				s.factory.lifecycleMu.Unlock()
				tcpStreamMetrics.mu.Lock()
				tcpStreamMetrics.droppedStreams++
				tcpStreamMetrics.mu.Unlock()
				s.factory.logStreamLimit(current)
				return false
			}
			root.slotReserved = true
		}
		s.factory.allWorkers.Add(1)
		s.factory.lifecycleMu.Unlock()
	}
	root.liveWorkers++

	parentCtx := context.Background()
	if s.factory != nil {
		parentCtx = s.factory.ctx
	}
	ctx, cancel := context.WithCancel(parentCtx)
	s.ctx = ctx
	s.cancel = cancel
	s.dataChan = make(chan streamChunk, streamBufferSize)
	s.callIDDetector = NewCallIDDetector()
	s.stateChan = nil
	if s.factory != nil && s.factory.config != nil && s.factory.config.EnableStateTCPTimeouts {
		s.stateChan = make(chan TCPState, 1)
	}
	s.createdAt = time.Now()
	s.pendingGap = streamGap{}
	s.rearmPrefix = nil

	// Reset per-message parser / lifecycle flags.
	atomic.StoreInt32(&s.discard, 0)
	atomic.StoreInt32(&s.lockedOnSIP, 0)
	atomic.StoreInt64(&s.nonSIPBytes, 0)
	atomic.StoreInt32(&s.finished, 0)
	s.stateMu.Lock()
	s.state = TCPStateOpening
	s.stateMu.Unlock()

	// A rearmed half shares the other half's connection admission. Only a fully
	// idle connection consumes a fresh slot and becomes a new active stream.
	if newAdmission {
		root.workerFailed = false
		tcpStreamMetrics.mu.Lock()
		atomic.AddInt64(&tcpStreamMetrics.activeStreams, 1)
		tcpStreamMetrics.totalStreamsCreated++
		tcpStreamMetrics.mu.Unlock()
	}

	logger.Debug("Re-arming reused TCP stream for new SIP message",
		"flow", fmt.Sprintf("%s:%s->%s:%s", s.netFlow.Src(), s.transportFlow.Src(), s.netFlow.Dst(), s.transportFlow.Dst()))

	go s.processLoop()
	return true
}

// processLoop reads from the buffered channel and processes SIP messages.
func (s *bufferedSIPStream) processLoop() {
	srcEndpoint, dstEndpoint := s.getEndpoints()
	logger.Debug("SIP stream starting", "flow", srcEndpoint+"->"+dstEndpoint)

	defer func() {
		s.cancel()
		failed := false
		if r := recover(); r != nil {
			failed = true
			logger.Error("SIP stream panic recovered",
				"panic_value", r,
				"stack_trace", string(debug.Stack()),
				"stream_context", s.ctx.Err(),
				"stream_age", time.Since(s.createdAt),
				"processed_bytes", atomic.LoadInt64(&s.processedBytes),
				"processed_messages", atomic.LoadInt64(&s.processedMsgs))
		}

		// Cleanup
		if s.callIDDetector != nil {
			s.callIDDetector.Close()
		}

		logger.Debug("TCP SIP stream completed",
			"stream_age", time.Since(s.createdAt),
			"processed_bytes", atomic.LoadInt64(&s.processedBytes),
			"processed_messages", atomic.LoadInt64(&s.processedMsgs))

		// Registration, final slot release, and rearm use the same root lock.
		// Mark this half finished only after its channel and detector are unused.
		root := s.connection()
		root.workerMu.Lock()
		if failed {
			root.workerFailed = true
		}
		atomic.StoreInt32(&s.finished, 1)
		root.liveWorkers--
		if root.liveWorkers == 0 {
			if root.slotReserved && root.factory != nil {
				atomic.AddInt64(&root.factory.activeGoroutines, -1)
				root.slotReserved = false
			}
			tcpStreamMetrics.mu.Lock()
			atomic.AddInt64(&tcpStreamMetrics.activeStreams, -1)
			if root.workerFailed {
				tcpStreamMetrics.totalStreamsFailed++
			} else {
				tcpStreamMetrics.totalStreamsCompleted++
			}
			tcpStreamMetrics.mu.Unlock()
			discardTCPBufferedPackets(root.netFlow, root.transportFlow)
		}
		root.workerMu.Unlock()
		if s.factory != nil {
			s.factory.allWorkers.Done()
		}
	}()

	reader := &streamChunkReader{stream: s, state: TCPStateOpening}
	s.processSIPFromReader(reader)
}

type streamChunkReader struct {
	stream    *bufferedSIPStream
	current   []byte
	timestamp time.Time
	gotData   bool
	state     TCPState
	pending   *streamChunk
}

// recoverableFramingError marks loss of framing without weakening SIP security
// validation. The parser may discard the incomplete message and scan for a
// later start line. replay contains a credible start already consumed with a
// malformed line and must be placed back in front of the reader.
type recoverableFramingError struct {
	reason       string
	missingBytes int
	droppedBytes int
	replay       []byte
	scannedBytes int
}

func (e *recoverableFramingError) Error() string {
	return "recoverable SIP framing discontinuity: " + e.reason
}

type contentLengthPolicyError struct{ err error }

func (e *contentLengthPolicyError) Error() string {
	return "Content-Length policy rejection: " + e.err.Error()
}
func (e *contentLengthPolicyError) Unwrap() error { return e.err }

var lastSIPParserWarningUnix atomic.Int64

var errSIPLineLimit = errors.New("SIP line exceeds bounded read limit")

func logSIPParserWarning(reason string) {
	now := time.Now().Unix()
	last := lastSIPParserWarningUnix.Load()
	if now-last < 60 || !lastSIPParserWarningUnix.CompareAndSwap(last, now) {
		return
	}
	logger.Warn("SIP TCP parser rejected malformed framing", "reason", reason)
}

// credibleSIPAfterEmbeddedCR detects a start line swallowed by ReadString when
// framing loss replaced CRLF with a lone CR. A lone CR by itself is never
// accepted as SIP syntax; only a syntactically credible complete start line is
// replayed for bounded resynchronization.
func credibleSIPAfterEmbeddedCR(line string) string {
	for offset := 0; offset < len(line); {
		rel := strings.IndexByte(line[offset:], '\r')
		if rel < 0 {
			return ""
		}
		i := offset + rel
		if i+1 < len(line) && line[i+1] != '\n' {
			suffix := line[i+1:]
			candidate := strings.TrimSuffix(strings.TrimSuffix(suffix, "\n"), "\r")
			if isSIPRequestLine(candidate) || isSIPResponseLine(candidate) {
				return suffix
			}
		}
		offset = i + 1
	}
	return ""
}

// readBoundedLine reads through the next newline without ever consuming or
// retaining more than limit bytes. bufio.Reader.ReadString cannot provide this
// guarantee because a newline-free input makes it grow until EOF.
func readBoundedLine(reader *bufio.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", errSIPLineLimit
	}

	line := make([]byte, 0, min(limit, reader.Size()))
	for len(line) < limit {
		if _, err := reader.Peek(1); err != nil {
			return string(line), err
		}
		buffered := reader.Buffered()
		chunk, err := reader.Peek(buffered)
		if err != nil {
			return string(line), err
		}
		remaining := limit - len(line)
		consume := min(len(chunk), remaining)
		if newline := bytes.IndexByte(chunk[:consume], '\n'); newline >= 0 {
			consume = newline + 1
		}
		line = append(line, chunk[:consume]...)
		if _, err := reader.Discard(consume); err != nil {
			return string(line), err
		}
		if line[len(line)-1] == '\n' {
			return string(line), nil
		}
	}
	return string(line), errSIPLineLimit
}

func (r *streamChunkReader) Read(dst []byte) (int, error) {
	for len(r.current) == 0 {
		if r.pending != nil {
			chunk := *r.pending
			r.pending = nil
			r.current, r.timestamp, r.gotData = chunk.data, chunk.timestamp, true
			if r.state == TCPStateOpening {
				r.state = TCPStateEstablished
			}
			continue
		}
		timeout := initialReadTimeout
		if r.gotData {
			timeout = r.stream.getTimeoutForState(r.state)
		}
		timer := time.NewTimer(timeout)
		select {
		case <-r.stream.ctx.Done():
			timer.Stop()
			return 0, r.stream.ctx.Err()
		case state := <-r.stream.stateChan:
			timer.Stop()
			r.state = state
			continue
		case chunk, ok := <-r.stream.dataChan:
			timer.Stop()
			if !ok {
				return 0, io.EOF
			}
			if chunk.gap.reason != streamGapNone {
				r.pending = &chunk
				return 0, &recoverableFramingError{
					reason:       "transport gap",
					missingBytes: chunk.gap.missingBytes,
					droppedBytes: chunk.gap.droppedBytes,
				}
			}
			r.current, r.timestamp, r.gotData = chunk.data, chunk.timestamp, true
			if r.state == TCPStateOpening {
				r.state = TCPStateEstablished
			}
		case <-timer.C:
			// Once this connection has carried a complete SIP message, leave
			// idle reclamation to the assembler. The assembler owns the TCP
			// sequence state and can evict the stream atomically; terminating
			// only this reader creates a zombie interval in which ReassembledSG
			// can silently discard the first message after an idle period.
			//
			// The call-aware check remains useful before SIP lock-on for streams
			// whose detector already identified a live dialog.
			if r.gotData && atomic.LoadInt32(&r.stream.lockedOnSIP) != 0 {
				IncrementEstablishedIdleRetention()
				continue
			}
			if r.gotData && r.stream.isAssociatedCallActive() {
				continue
			}
			return 0, errReadTimeout
		}
	}
	n := copy(dst, r.current)
	r.current = r.current[n:]
	return n, nil
}

func (r *streamChunkReader) Timestamp() time.Time { return r.timestamp }

// processSIPFromReader reads SIP messages from an io.Reader and processes them.
func (s *bufferedSIPStream) processSIPFromReader(reader io.Reader) {
	bufReader := bufio.NewReader(reader)
	timestamped, _ := reader.(interface{ Timestamp() time.Time })

	// Live connections release their canonical packet buffer when both halves
	// stop. Direct parser use has no connection owner to coordinate cleanup.
	if s.root == nil && s.reverse == nil {
		defer discardTCPBufferedPackets(s.netFlow, s.transportFlow)
	}

	recoveryPending := false
	defer func() {
		// A recovery attempt that ends at EOF, timeout, or a hard parser policy
		// rejection failed to find a later valid message. Administrative shutdown
		// is not parser failure and is intentionally excluded.
		if recoveryPending && s.ctx.Err() == nil {
			IncrementStreamRecoveryFailure()
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		sipMessage, err := s.readCompleteSipMessageFromReader(bufReader)
		if err != nil {
			var framingErr *recoverableFramingError
			var policyErr *contentLengthPolicyError
			if errors.As(err, &framingErr) {
				IncrementParserFramingDiscontinuity()
				recoveryPending = true
				if framingErr.reason == "transport gap" {
					// bufio may retain bytes from the incomplete pre-gap message.
					// Drop them; streamChunkReader retained the post-gap chunk.
					bufReader = bufio.NewReader(reader)
					continue
				}
				if framingErr.scannedBytes > 0 && atomic.AddInt64(&s.nonSIPBytes, int64(framingErr.scannedBytes)) >= maxNonSIPBytesBeforeDiscard {
					IncrementStreamRecoveryFailure()
					recoveryPending = false
					atomic.StoreInt32(&s.discard, 1)
					logSIPParserWarning("cumulative_resynchronization_limit")
					return
				}
				if len(framingErr.replay) > 0 {
					// ReadString consumed a credible next start line together with the
					// damaged header. Replay it without losing bytes already buffered.
					bufReader = bufio.NewReader(io.MultiReader(bytes.NewReader(framingErr.replay), bufReader))
				}
				continue
			} else if errors.As(err, &policyErr) {
				// Correctly CRLF-framed hostile Content-Length is a hard security
				// rejection, never a transport/framing recovery opportunity.
				logSIPParserWarning("content_length_policy")
				return
			} else if errors.Is(err, errNotSIP) {
				IncrementNonSIPRejection()
				// Once this flow has carried valid SIP, a later framing rejection is
				// a parser discontinuity rather than initial non-SIP classification.
				if atomic.LoadInt32(&s.lockedOnSIP) == 1 {
					IncrementParserFramingDiscontinuity()
				}
				// Recoverable discard: a connection we joined mid-message (or a
				// reused 4-tuple whose bytes precede the next SIP message) may
				// still carry SIP that only starts after the bytes seen so far.
				// Do NOT condemn the whole connection on the first non-SIP
				// result — keep reading so the bounded resync in
				// readCompleteSipMessageFromReader can lock onto a later SIP
				// message boundary. Only give up once we've scanned past the hard
				// cap of non-SIP bytes with no SIP framing, so genuinely non-SIP
				// traffic (e.g. TLS) is still discarded and buffering stops
				// (bounded — no unbounded scan or buffer).
				if atomic.LoadInt64(&s.nonSIPBytes) < maxNonSIPBytesBeforeDiscard {
					recoveryPending = true
					logger.Debug("Non-SIP data (recoverable), continuing resync",
						"non_sip_bytes", atomic.LoadInt64(&s.nonSIPBytes))
					continue
				}
				atomic.StoreInt32(&s.discard, 1)
				if recoveryPending {
					IncrementStreamRecoveryFailure()
					recoveryPending = false
				}
				logger.Debug("Non-SIP data exceeded resync cap, closing stream")
			} else if errors.Is(err, errReadTimeout) {
				// Also discard on timeout - no point buffering if nothing is being processed
				atomic.StoreInt32(&s.discard, 1)
				IncrementStreamTimeout()
				logger.Debug("Read timeout, closing stream")
			} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && s.ctx.Err() == nil {
				logger.Debug("Error reading SIP message", "error", err)
			}
			return
		}

		if len(sipMessage) == 0 {
			continue
		}
		if recoveryPending {
			IncrementStreamRecoverySuccess()
			recoveryPending = false
		}

		// A complete SIP message was parsed: this connection is confirmed SIP.
		// Lock on (so it is treated as an established SIP stream) and reset the
		// non-SIP accounting so a long-lived multi-message connection with the
		// occasional resync gap never accumulates to the discard cap.
		atomic.StoreInt32(&s.lockedOnSIP, 1)
		atomic.StoreInt64(&s.nonSIPBytes, 0)

		atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
		atomic.AddInt64(&s.processedMsgs, 1)

		var capturedAt time.Time
		if timestamped != nil {
			capturedAt = timestamped.Timestamp()
		}
		s.processSipMessage(sipMessage, capturedAt)
	}
}

// readCompleteSipMessageFromReader reads a complete SIP message from a buffered reader.
//
// It first resynchronises to the next SIP message start line (see
// readSIPStartLine): on an established connection whose first delivered line is
// already a start line this is a no-op, so established behaviour is unchanged;
// when the stream was joined mid-message (mid-stream tap start, or a reused
// 4-tuple) it scans forward within a bounded window for the next message
// boundary and resumes there instead of condemning the whole connection.
func (s *bufferedSIPStream) readCompleteSipMessageFromReader(bufReader *bufio.Reader) ([]byte, error) {
	securityConfig := DefaultSecurityConfig()
	if s.factory != nil && s.factory.config != nil {
		securityConfig = s.factory.config.Security
	}

	startLine, scanned, err := s.readSIPStartLine(bufReader)
	if err != nil {
		if errors.Is(err, errNotSIP) {
			// Account for the non-SIP bytes we scanned so the caller can decide
			// whether to keep the connection recoverable or discard it.
			atomic.AddInt64(&s.nonSIPBytes, int64(scanned))
		}
		return nil, err
	}

	var message strings.Builder
	var contentLength int
	var contentLengthSeen bool
	headersDone := false
	headerCount := 0

	// The start line has already been read and validated; seed the message with
	// it (normalising the line ending — harmless for parsing).
	message.WriteString(startLine)
	message.WriteString("\r\n")
	headerCount++

	for {
		if headersDone && contentLength == 0 {
			break
		}

		if headersDone && contentLength > 0 {
			content := make([]byte, contentLength)
			_, err := io.ReadFull(bufReader, content)
			if err != nil {
				return nil, fmt.Errorf("failed to read SIP message content: %w", err)
			}
			message.Write(content)
			break
		}

		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		default:
		}

		line, err := readBoundedLine(bufReader, maxSIPHeaderLineLength)
		if err != nil {
			if errors.Is(err, errSIPLineLimit) {
				return nil, errNotSIP
			}
			return nil, fmt.Errorf("failed to read SIP message line: %w", err)
		}

		if suffix := credibleSIPAfterEmbeddedCR(line); suffix != "" {
			return nil, &recoverableFramingError{
				reason:       "embedded carriage return before SIP start",
				replay:       []byte(suffix),
				scannedBytes: len(line) - len(suffix),
			}
		}

		message.WriteString(line)
		headerCount++

		if headerCount > maxSIPHeaders {
			return nil, errNotSIP
		}

		if !headersDone && (line == "\r\n" || line == "\n") {
			headersDone = true
			continue
		}

		if !headersDone {
			if colon := strings.IndexByte(line, ':'); colon > 0 {
				headerName := strings.ToLower(strings.TrimSpace(line[:colon]))
				if full, ok := sharedsip.CompactHeaders[headerName]; ok {
					headerName = full
				}
				if headerName != "content-length" {
					continue
				}
				lengthStr := strings.TrimSpace(line[colon+1:])
				if length, parseErr := parseContentLengthSecurely(lengthStr, securityConfig); parseErr == nil {
					if contentLengthSeen && length != contentLength {
						return nil, &contentLengthPolicyError{err: errors.New("conflicting duplicate Content-Length values")}
					}
					contentLength = length
					contentLengthSeen = true
				} else {
					return nil, &contentLengthPolicyError{err: parseErr}
				}
			}
		}
	}

	messageBytes := []byte(message.String())

	if err := validateMessageSize(len(messageBytes), securityConfig); err != nil {
		logSIPParserWarning("message_size_policy")
		return nil, fmt.Errorf("SIP message too large: %w", err)
	}

	return messageBytes, nil
}

// readSIPStartLine advances the reader to the next SIP message start line and
// returns it (trimmed of its line ending), together with the number of bytes
// consumed while scanning.
//
// On an established connection the first non-empty line is already a start line,
// so this returns immediately with only that line consumed — established
// behaviour is unchanged. When the stream was joined mid-message the leading
// bytes are mid-message headers/body (not a start line); rather than declaring
// the whole connection non-SIP, we scan forward within resyncWindowBytes for a
// start line that sits on a message boundary (i.e. follows a blank line / the
// start of stream) and resume parsing from there.
//
// errNotSIP is returned only after the entire bounded window has been scanned
// with no SIP framing, so genuine non-SIP TCP (e.g. a TLS ClientHello) is still
// rejected cheaply and without unbounded buffering.
func (s *bufferedSIPStream) readSIPStartLine(bufReader *bufio.Reader) (string, int, error) {
	scanned := 0
	// The start of the stream (and the position right after a blank line) is a
	// message boundary: a start line seen there begins a real SIP message.
	atBoundary := true

	for {
		select {
		case <-s.ctx.Done():
			return "", scanned, s.ctx.Err()
		default:
		}

		line, err := readBoundedLine(bufReader, resyncWindowBytes-scanned)
		if err != nil {
			if errors.Is(err, errSIPLineLimit) {
				return "", scanned + len(line), errNotSIP
			}
			return "", scanned, fmt.Errorf("failed to read SIP message line: %w", err)
		}
		scanned += len(line)

		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			// Blank line: a SIP keepalive (RFC 5626 CRLF keepalive) or a message
			// boundary. A live connection's packet buffer is shared by both
			// directions; clearing it here could erase packets the other half
			// still needs. Its size is bounded and it is released when both
			// readers stop. Direct parser use has no opposite half.
			if s.root == nil && s.reverse == nil {
				discardTCPBufferedPackets(s.netFlow, s.transportFlow)
			}
			atBoundary = true
			if scanned > resyncWindowBytes {
				return "", scanned, errNotSIP
			}
			continue
		}

		if atBoundary && (isSIPRequestLine(trimmed) || isSIPResponseLine(trimmed)) {
			return trimmed, scanned, nil
		}

		// Non-empty, non-start line: mid-message header/body bytes or genuine
		// non-SIP data. Keep scanning for the next boundary, bounded by the
		// window.
		atBoundary = false
		if scanned > resyncWindowBytes {
			return "", scanned, errNotSIP
		}
	}
}

// getEndpoints constructs IP:port endpoint strings from the network and transport flows
func (s *bufferedSIPStream) getEndpoints() (srcEndpoint, dstEndpoint string) {
	srcEndpoint = fmt.Sprintf("%s:%s", s.netFlow.Src().String(), s.transportFlow.Src().String())
	dstEndpoint = fmt.Sprintf("%s:%s", s.netFlow.Dst().String(), s.transportFlow.Dst().String())
	return
}

// SetState updates both readers because TCP connection state is shared by its
// two sequence spaces.
func (s *bufferedSIPStream) SetState(newState TCPState) {
	s.setHalfState(newState)
	if s.reverse != nil {
		s.reverse.setHalfState(newState)
	}
}

func (s *bufferedSIPStream) setHalfState(newState TCPState) {
	if s.stateChan == nil {
		return // State-based timeouts not enabled
	}

	s.stateMu.Lock()
	if s.state == newState {
		s.stateMu.Unlock()
		return // No change
	}
	s.state = newState
	s.stateMu.Unlock()

	// Notify timeout goroutine of state change (non-blocking)
	select {
	case s.stateChan <- newState:
	default:
	}
}

// getTimeoutForState returns the appropriate timeout for the given TCP state.
func (s *bufferedSIPStream) getTimeoutForState(state TCPState) time.Duration {
	if s.factory == nil || s.factory.config == nil || !s.factory.config.EnableStateTCPTimeouts {
		// Fall back to configured idle timeout or default
		if s.factory != nil && s.factory.config != nil && s.factory.config.TCPSIPIdleTimeout > 0 {
			return s.factory.config.TCPSIPIdleTimeout
		}
		return defaultReadTimeout
	}

	config := s.factory.config
	switch state {
	case TCPStateOpening:
		return config.TCPOpeningTimeout
	case TCPStateEstablished:
		return config.TCPEstablishedTimeout
	case TCPStateClosing:
		return config.TCPClosingTimeout
	default:
		return defaultReadTimeout
	}
}

// isAssociatedCallActive checks if the call associated with this stream is still active.
// Returns true if the call is active and the stream should remain open, false otherwise.
// Used for call-aware adaptive timeout (Phase 3.2).
func (s *bufferedSIPStream) isAssociatedCallActive() bool {
	// Check if call-aware timeout is enabled
	if s.factory == nil || s.factory.config == nil || !s.factory.config.EnableCallAwareTimeout {
		return false
	}

	// Get the Call-ID from the detector
	if s.callIDDetector == nil {
		return false
	}

	// Check if Call-ID has been detected (non-blocking)
	s.callIDDetector.mu.Lock()
	callID := s.callIDDetector.callID
	hasCallID := s.callIDDetector.set
	s.callIDDetector.mu.Unlock()

	if !hasCallID || callID == "" {
		return false
	}

	// Query the registry owned by the composition root. A missing query means no
	// call-aware extension, rather than falling back to hidden global state.
	if s.factory.callActive == nil {
		return false
	}
	return s.factory.callActive(callID)
}

// processSipMessage processes a complete SIP message (shared with bufferedSIPStream)
func (s *bufferedSIPStream) processSipMessage(sipMessage []byte, timestamps ...time.Time) {
	var capturedAt time.Time
	if len(timestamps) > 0 {
		capturedAt = timestamps[0]
	}
	srcEndpoint, dstEndpoint := s.getEndpoints()
	event, err := sharedsip.Parse(sipMessage, sharedsip.OptionsForEndpoints(capturedAt, srcEndpoint, dstEndpoint))
	if err == nil && event.CallID != "" {
		callID := event.CallID
		// Increment SIP messages detected counter (voip package)
		IncrementSIPMessagesDetected()

		if s.callIDDetector != nil {
			s.callIDDetector.SetCallID(callID)
		}

		if s.factory != nil && s.factory.handler != nil {
			if handler, ok := s.factory.handler.(parsedSIPMessageHandler); ok {
				handler.HandleParsedSIPMessage(sipMessage, event, srcEndpoint, dstEndpoint, s.netFlow, s.transportFlow)
			} else if handler, ok := s.factory.handler.(timestampedSIPMessageHandler); ok {
				handler.HandleSIPMessageAt(sipMessage, callID, srcEndpoint, dstEndpoint, s.netFlow, s.transportFlow, capturedAt)
			} else {
				s.factory.handler.HandleSIPMessage(sipMessage, callID, srcEndpoint, dstEndpoint, s.netFlow, s.transportFlow)
			}
		}
	}
}

// CallIDDetector manages Call-ID detection with timeout support.
// All state is protected by mu to avoid TOCTOU races.
type CallIDDetector struct {
	callID   string
	detected chan string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	set      bool // flag to indicate if Call-ID has been set
	closed   bool // flag to track if detector is closed (mutex-protected)
}

func NewCallIDDetector() *CallIDDetector {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallIDDetectionTimeout)
	detector := &CallIDDetector{
		detected: make(chan string, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
	return detector
}

func (c *CallIDDetector) SetCallID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check both closed and set under the same lock to avoid TOCTOU races
	if c.closed || c.set {
		return
	}

	c.callID = id
	c.set = true

	// Send to channel and close it to notify all waiters.
	// The select handles the case where channel already has a value (shouldn't happen
	// with first-wins semantics, but defensive).
	select {
	case c.detected <- id:
		close(c.detected)
	default:
		// Channel already has a value, just close it
		close(c.detected)
	}
}

func (c *CallIDDetector) Wait() string {
	// First check if callID is already set
	c.mu.Lock()
	if c.set {
		callID := c.callID
		c.mu.Unlock()
		return callID
	}
	c.mu.Unlock()

	// If not set, wait on the channel
	select {
	case callID, ok := <-c.detected:
		if ok {
			return callID
		}
		// Channel was closed, check if callID was set
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.set {
			return c.callID
		}
		return ""
	case <-c.ctx.Done():
		return ""
	}
}

func (c *CallIDDetector) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return // Already closed
	}
	c.closed = true

	// Only close the channel if SetCallID hasn't already done it.
	// If set is true, SetCallID already closed the channel.
	if !c.set {
		close(c.detected)
	}
	c.mu.Unlock()

	// Cancel context to wake up any waiters (done outside mutex to avoid holding lock)
	c.cancel()
}

// errReadTimeout is returned when a read operation times out waiting for data.
// This indicates the TCP connection has stalled mid-message.
var errReadTimeout = errors.New("read timeout: no data received")

// TCPState represents the state of a TCP SIP connection for timeout purposes.
// Used when EnableStateTCPTimeouts is enabled.
type TCPState int

const (
	// TCPStateOpening indicates a new connection that hasn't seen valid SIP data yet.
	// Uses TCPOpeningTimeout (default: 5 minutes).
	TCPStateOpening TCPState = iota

	// TCPStateEstablished indicates a connection with validated SIP traffic.
	// Uses TCPEstablishedTimeout (default: 30 minutes).
	TCPStateEstablished

	// TCPStateClosing indicates a connection that has received FIN/RST or is shutting down.
	// Uses TCPClosingTimeout (default: 5 minutes).
	TCPStateClosing
)

// Initial timeout for first data on a new TCP stream.
// SIP sends data immediately after connection - if nothing arrives quickly,
// it's likely not SIP traffic. This prevents non-SIP connections from
// holding goroutines for extended periods.
const initialReadTimeout = 2 * time.Second

// defaultReadTimeout is the fallback read timeout for TCP streams if not configured.
// Set to 120 seconds to align with RFC 5626 CRLF keep-alive interval (95-120 seconds).
// This allows SIP persistent connections to survive keep-alive intervals during long calls.
// This value can be overridden via --tcp-sip-idle-timeout flag or voip.tcp_sip_idle_timeout config.
const defaultReadTimeout = 120 * time.Second

// errNotSIP is returned when TCP stream data doesn't look like SIP protocol.
// This is not logged as an error - it's expected for non-SIP TCP traffic.
var errNotSIP = errors.New("not SIP protocol")

// SIP protocol limits for early rejection of non-SIP streams
const (
	// Maximum reasonable SIP header line length (RFC 3261 recommends support for 4KB)
	maxSIPHeaderLineLength = 4096
	// Maximum number of headers in a SIP message (reasonable limit)
	maxSIPHeaders = 200
	// resyncWindowBytes bounds how far readSIPStartLine scans forward for the
	// next SIP message boundary when a connection was joined mid-message, before
	// declaring the scanned data non-SIP. Bounds the per-attempt scan.
	resyncWindowBytes = 16 * 1024
	// maxNonSIPBytesBeforeDiscard bounds the total non-SIP bytes tolerated on a
	// connection that has never locked onto SIP before it is permanently
	// discarded (which stops ReassembledSG buffering). Generous enough that real
	// SIP locks on well within it, small enough to bound wasted work. Reset to 0
	// whenever a full SIP message is parsed.
	maxNonSIPBytesBeforeDiscard = 64 * 1024
)

// isSIPRequestLine checks if a line looks like a SIP request (e.g., "INVITE sip:... SIP/2.0")
func isSIPRequestLine(line string) bool {
	return sharedsip.IsStartLine(line) && !strings.HasPrefix(line, "SIP/2.0 ")
}

// isSIPResponseLine checks if a line looks like a SIP response (e.g., "SIP/2.0 200 OK")
func isSIPResponseLine(line string) bool {
	if len(line) < len("SIP/2.0 000 ") || !strings.HasPrefix(line, "SIP/2.0 ") {
		return false
	}
	return line[8] >= '1' && line[8] <= '6' &&
		line[9] >= '0' && line[9] <= '9' &&
		line[10] >= '0' && line[10] <= '9' && line[11] == ' '
}

// looksLikeSIPStart reports whether the first line of data is a SIP request or
// response start line. The rearm path uses collectRearmStart to handle split
// lines; this helper remains useful for bounded single-chunk checks.
func looksLikeSIPStart(data []byte) bool {
	const maxPeek = 256
	peek := data
	if len(peek) > maxPeek {
		peek = peek[:maxPeek]
	}
	for bytes.HasPrefix(peek, []byte("\r\n")) {
		peek = peek[2:]
	}
	first := peek
	if nl := bytes.IndexByte(peek, '\n'); nl >= 0 {
		first = peek[:nl]
	}
	line := strings.TrimRight(string(first), "\r")
	return isSIPRequestLine(line) || isSIPResponseLine(line)
}

// collectRearmStart retains at most one bounded start-line probe while a half
// has no reader. The assembler owns this state, so it never waits for a parser
// goroutine. Once a complete valid line arrives, it returns all retained bytes
// with the current chunk for the new reader.
func (s *bufferedSIPStream) collectRearmStart(data []byte) ([]byte, bool) {
	// readSIPStartLine accepts a complete start line through this bound.
	// Rearm must use the same limit or it can reject a message the parser accepts.
	const maxRearmPrefixBytes = resyncWindowBytes
	if len(s.rearmPrefix) == 0 && isSIPKeepaliveOnly(data) {
		IncrementRearmKeepaliveChunk()
		return nil, false
	}

	total := len(s.rearmPrefix) + len(data)
	probe := make([]byte, 0, min(total, maxRearmPrefixBytes))
	probe = append(probe, s.rearmPrefix...)
	probe = append(probe, data[:min(len(data), maxRearmPrefixBytes-len(probe))]...)
	start := probe
	for bytes.HasPrefix(start, []byte("\r\n")) {
		start = start[2:]
	}
	if len(start) == 0 && total <= maxRearmPrefixBytes {
		s.rearmPrefix = nil
		IncrementRearmKeepaliveChunk()
		return nil, false
	}
	if newline := bytes.IndexByte(start, '\n'); newline >= 0 {
		line := strings.TrimRight(string(start[:newline]), "\r")
		if isSIPRequestLine(line) || isSIPResponseLine(line) {
			if len(s.rearmPrefix) == 0 {
				return data, true
			}
			complete := append(s.rearmPrefix, data...)
			s.rearmPrefix = nil
			return complete, true
		}
		s.rearmPrefix = nil
		IncrementRearmRejectedChunk()
		return nil, false
	}
	if total >= maxRearmPrefixBytes {
		s.rearmPrefix = nil
		IncrementRearmRejectedChunk()
		return nil, false
	}
	s.rearmPrefix = append(s.rearmPrefix, data...)
	return nil, false
}

// A finished half may receive a standalone CRLF keepalive before its next
// message. It does not need a reader and must not count as a failed rearm.
func isSIPKeepaliveOnly(data []byte) bool {
	if len(data) == 0 || len(data)%2 != 0 {
		return false
	}
	for i := 0; i < len(data); i += 2 {
		if data[i] != '\r' || data[i+1] != '\n' {
			return false
		}
	}
	return true
}

// compareHeaderCI performs case-insensitive comparison without allocations
func compareHeaderCI(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		// Convert to lowercase if uppercase
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// parseContentLength safely parses the Content-Length header value
// Returns 0 for invalid or empty values
func parseContentLength(value string) int {
	// Trim whitespace and parse numeric portion
	trimmed := strings.TrimSpace(value)
	length := 0

	for _, char := range trimmed {
		if char >= '0' && char <= '9' {
			length = length*10 + int(char-'0')
		} else {
			// Stop at first non-digit
			break
		}
	}

	return length
}

// detectCallIDHeader robustly parses Call-ID headers in both full and compact form
// Optimized for zero allocations using byte-level comparisons
func detectCallIDHeader(line string, callID *string) bool {
	// Trim whitespace manually to avoid allocation
	start := 0
	end := len(line)
	for start < end && (line[start] == ' ' || line[start] == '\t' || line[start] == '\r' || line[start] == '\n') {
		start++
	}
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r' || line[end-1] == '\n') {
		end--
	}

	if start >= end {
		return false
	}

	trimmed := line[start:end]
	var extractedCallID string

	// Check for standard "Call-ID:" header (case-insensitive, zero-alloc)
	if len(trimmed) >= 8 && compareHeaderCI(trimmed[:8], "call-id:") {
		valueStart := 8
		// Skip whitespace after colon
		for valueStart < len(trimmed) && (trimmed[valueStart] == ' ' || trimmed[valueStart] == '\t') {
			valueStart++
		}
		// Trim trailing whitespace from value
		valueEnd := len(trimmed)
		for valueEnd > valueStart && (trimmed[valueEnd-1] == ' ' || trimmed[valueEnd-1] == '\t') {
			valueEnd--
		}
		extractedCallID = trimmed[valueStart:valueEnd]
	} else if len(trimmed) >= 2 && compareHeaderCI(trimmed[:2], "i:") {
		// Check for compact "i:" header
		valueStart := 2
		// Skip whitespace after colon
		for valueStart < len(trimmed) && (trimmed[valueStart] == ' ' || trimmed[valueStart] == '\t') {
			valueStart++
		}
		// Trim trailing whitespace from value
		valueEnd := len(trimmed)
		for valueEnd > valueStart && (trimmed[valueEnd-1] == ' ' || trimmed[valueEnd-1] == '\t') {
			valueEnd--
		}
		extractedCallID = trimmed[valueStart:valueEnd]
	} else {
		return false
	}

	// Validate the extracted Call-ID for security
	if err := ValidateCallIDForSecurity(extractedCallID); err != nil {
		logger.Warn("Malicious Call-ID detected and rejected",
			"call_id", SanitizeCallIDForLogging(extractedCallID),
			"error", err,
			"source", "tcp_stream")
		return false
	}

	*callID = extractedCallID
	return true
}
