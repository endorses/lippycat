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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
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
	// Returns:
	//   - bool: true if message was accepted/matched filter (for metrics)
	HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow gopacket.Flow) bool
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
	dataChan       chan []byte
	ctx            context.Context
	cancel         context.CancelFunc
	factory        *sipStreamFactory
	callIDDetector *CallIDDetector
	netFlow        gopacket.Flow // Network layer flow (IP addresses)
	transportFlow  gopacket.Flow // Transport layer flow (ports)
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
	closed         int32 // atomic flag
	discard        int32 // atomic flag - set when stream is determined to be non-SIP

	// State-based timeout support (Phase 3)
	state     TCPState      // Current TCP state
	stateMu   sync.Mutex    // Protects state field
	stateChan chan TCPState // Channel to notify timeout goroutine of state changes
}

// Buffer size for reassembled data chunks.
// Each TCP segment creates one entry, so this should handle bursts.
const streamBufferSize = 64

// newBufferedSIPStream creates a new buffered stream that implements reassembly.Stream.
// The stream immediately starts a processing goroutine.
// Both netFlow (IP addresses) and transportFlow (ports) are needed to construct
// proper IP:port endpoints for the SIP message handler.
func newBufferedSIPStream(parentCtx context.Context, factory *sipStreamFactory, detector *CallIDDetector, netFlow, transportFlow gopacket.Flow) *bufferedSIPStream {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &bufferedSIPStream{
		dataChan:       make(chan []byte, streamBufferSize),
		ctx:            ctx,
		cancel:         cancel,
		factory:        factory,
		callIDDetector: detector,
		netFlow:        netFlow,
		transportFlow:  transportFlow,
		createdAt:      time.Now(),
		state:          TCPStateOpening,
	}

	// Create state change channel if state-based timeouts are enabled
	if factory != nil && factory.config != nil && factory.config.EnableStateTCPTimeouts {
		s.stateChan = make(chan TCPState, 1)
	}

	// Start processing goroutine immediately
	if factory != nil {
		factory.allWorkers.Add(1)
	}
	go s.processLoop()
	return s
}

// Accept implements reassembly.Stream. We accept every packet for the stream and
// force reassembly to start from the first packet we see for the connection —
// even mid-stream with no observed SYN — matching the passive-monitor behaviour
// of the legacy tcpassembly path (start has effect only on a fresh connection;
// it is ignored once a start sequence is established). Connection-boundary
// handling for TCP 4-tuple reuse is done via ReassemblyComplete eviction, not here.
func (s *bufferedSIPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	*start = true
	return true
}

// ReassembledSG implements reassembly.Stream.
// Called by the assembler when TCP data is reassembled (zero-copy scatter-gather).
// NEVER BLOCKS - uses non-blocking send to buffered channel.
func (s *bufferedSIPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	// Count ALL reassembly calls immediately (before any early returns)
	IncrementReassembledCalls()

	// Check discard flag first - once we know it's not SIP, stop buffering entirely
	if atomic.LoadInt32(&s.discard) != 0 {
		return
	}

	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	available, _ := sg.Lengths()
	if available == 0 {
		IncrementReassembledEmptyData()
		return
	}

	// Copy the data out of the scatter-gather: its backing pages are reused after
	// this call returns, so anything we keep must be copied.
	data := make([]byte, available)
	copy(data, sg.Fetch(available))
	IncrementReassembledWithData()

	// Non-blocking send - drop data if buffer is full.
	// This is better than blocking the packet capture loop.
	select {
	case s.dataChan <- data:
		logger.Debug("TCP data queued to stream",
			"bytes", len(data),
			"flow", fmt.Sprintf("%s:%s->%s:%s", s.netFlow.Src(), s.transportFlow.Src(), s.netFlow.Dst(), s.transportFlow.Dst()))
	default:
		// Buffer full - drop this chunk (log at debug level to avoid spam)
		IncrementReassembledDataDropped()
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
		close(s.dataChan)
	}
	return true
}

// processLoop reads from the buffered channel and processes SIP messages.
func (s *bufferedSIPStream) processLoop() {
	srcEndpoint, dstEndpoint := s.getEndpoints()
	logger.Debug("SIP stream starting", "flow", srcEndpoint+"->"+dstEndpoint)

	defer func() {
		if s.factory != nil {
			defer s.factory.allWorkers.Done()
		}

		// Decrement goroutine counter
		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		// Update metrics
		tcpStreamMetrics.mu.Lock()
		atomic.AddInt64(&tcpStreamMetrics.activeStreams, -1)
		if r := recover(); r != nil {
			tcpStreamMetrics.totalStreamsFailed++
			logger.Error("SIP stream panic recovered",
				"panic_value", r,
				"stack_trace", string(debug.Stack()),
				"stream_context", s.ctx.Err(),
				"stream_age", time.Since(s.createdAt),
				"processed_bytes", atomic.LoadInt64(&s.processedBytes),
				"processed_messages", atomic.LoadInt64(&s.processedMsgs))
		} else {
			tcpStreamMetrics.totalStreamsCompleted++
		}
		tcpStreamMetrics.mu.Unlock()

		// Cleanup
		if s.callIDDetector != nil {
			s.callIDDetector.Close()
		}
		s.cancel()

		logger.Debug("TCP SIP stream completed",
			"stream_age", time.Since(s.createdAt),
			"processed_bytes", atomic.LoadInt64(&s.processedBytes),
			"processed_messages", atomic.LoadInt64(&s.processedMsgs))
	}()

	// Create a pipe to convert channel data to io.Reader.
	// Close pipeReader when processLoop returns so any writer goroutine
	// blocked mid-Write (e.g. because the reader exited on a parse error,
	// timeout, or EOF) unblocks with io.ErrClosedPipe and can exit cleanly.
	// Without this the writer pins its data slice (and the gopacket.Packet
	// it references) for the lifetime of the process.
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()

	// Determine if state-based timeouts are enabled
	stateTimeoutsEnabled := s.factory != nil && s.factory.config != nil && s.factory.config.EnableStateTCPTimeouts

	// Goroutine to pump data from channel to pipe with state-based timeouts
	go func() {
		defer pipeWriter.Close()

		// Start with short initial timeout for quick rejection of non-SIP traffic
		// After first valid data, switch to state-based or configured timeout
		timer := time.NewTimer(initialReadTimeout)
		defer timer.Stop()

		gotData := false
		currentState := TCPStateOpening

		for {
			// Build select based on whether state channel exists
			if s.stateChan != nil {
				select {
				case <-s.ctx.Done():
					return
				case newState := <-s.stateChan:
					// State changed - update timeout
					currentState = newState
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(s.getTimeoutForState(currentState))
					logger.Debug("TCP state changed, timeout updated",
						"state", currentState,
						"timeout", s.getTimeoutForState(currentState))
				case data, ok := <-s.dataChan:
					if !ok {
						return // Channel closed
					}
					gotData = true
					// Reset timer on data activity
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					// Transition to ESTABLISHED after first data if state-based timeouts enabled
					if stateTimeoutsEnabled && currentState == TCPStateOpening {
						currentState = TCPStateEstablished
						s.stateMu.Lock()
						s.state = TCPStateEstablished
						s.stateMu.Unlock()
					}
					timer.Reset(s.getTimeoutForState(currentState))

					if _, err := pipeWriter.Write(data); err != nil {
						return
					}
				case <-timer.C:
					if !gotData {
						// No data received in initial timeout - likely not SIP
						logger.Debug("Read timeout, closing stream (no data)")
						pipeWriter.CloseWithError(errReadTimeout)
						return
					}

					// Call-aware timeout: if the call is still active, extend timeout
					if s.isAssociatedCallActive() {
						logger.Debug("Timeout but call still active, extending timeout",
							"state", currentState,
							"timeout", s.getTimeoutForState(currentState))
						timer.Reset(s.getTimeoutForState(currentState))
						continue
					}

					// Timeout with established connection - close stream
					logger.Debug("Read timeout, closing stream",
						"state", currentState,
						"timeout", s.getTimeoutForState(currentState))
					pipeWriter.CloseWithError(errReadTimeout)
					return
				}
			} else {
				// Non-state-based path: use configured idle timeout
				// (getTimeoutForState falls back to TCPSIPIdleTimeout / defaultReadTimeout
				// when EnableStateTCPTimeouts is false).
				select {
				case <-s.ctx.Done():
					return
				case data, ok := <-s.dataChan:
					if !ok {
						return // Channel closed
					}
					gotData = true
					// Reset idle timer on data activity
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(s.getTimeoutForState(currentState))
					if _, err := pipeWriter.Write(data); err != nil {
						return
					}
				case <-timer.C:
					if !gotData {
						// No data received in initial timeout - likely not SIP
						logger.Debug("Read timeout, closing stream")
						pipeWriter.CloseWithError(errReadTimeout)
						return
					}
					// Idle past TCPSIPIdleTimeout. If the call is still active,
					// extend; otherwise close so the goroutines don't leak when
					// gopacket never observes a FIN/RST.
					if s.isAssociatedCallActive() {
						timer.Reset(s.getTimeoutForState(currentState))
						continue
					}
					logger.Debug("Read timeout (idle), closing stream")
					pipeWriter.CloseWithError(errReadTimeout)
					return
				}
			}
		}
	}()

	// Process SIP messages from the pipe
	s.processSIPFromReader(pipeReader)
}

// processSIPFromReader reads SIP messages from an io.Reader and processes them.
func (s *bufferedSIPStream) processSIPFromReader(reader io.Reader) {
	bufReader := bufio.NewReader(reader)

	// Release any per-flow buffered packets on exit. If a SIP message matched
	// and drained the buffer, the map entry was already removed and this is a
	// no-op; if the stream ended without a successful match (errNotSIP,
	// errReadTimeout, ctx cancellation, EOF), this releases the packets
	// immediately instead of waiting for TCPBufferMaxAge.
	defer discardTCPBufferedPackets(s.netFlow)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		sipMessage, err := s.readCompleteSipMessageFromReader(bufReader)
		if err != nil {
			if errors.Is(err, errNotSIP) {
				// Set discard flag so Reassembled() stops buffering data immediately
				atomic.StoreInt32(&s.discard, 1)
				IncrementNonSIPRejection()
				logger.Debug("Non-SIP data detected, closing stream")
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

		atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
		atomic.AddInt64(&s.processedMsgs, 1)

		s.processSipMessage(sipMessage)
	}
}

// readCompleteSipMessageFromReader reads a complete SIP message from a buffered reader
func (s *bufferedSIPStream) readCompleteSipMessageFromReader(bufReader *bufio.Reader) ([]byte, error) {
	var message strings.Builder
	var contentLength int
	headersDone := false
	firstLine := true
	headerCount := 0

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

		line, err := bufReader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read SIP message line: %w", err)
		}

		if len(line) > maxSIPHeaderLineLength {
			return nil, errNotSIP
		}

		if firstLine {
			trimmedLine := strings.TrimRight(line, "\r\n")
			// Skip empty lines (SIP keepalives) - RFC 5626 defines CRLF keepalives
			// These can appear before real SIP messages on persistent connections
			if trimmedLine == "" {
				// A keepalive marks an idle gap with no message in flight.
				// Release the per-flow packet buffer: anything captured before
				// the keepalive cannot belong to a future call worth
				// correlating, and on long-lived idle TCP connections this is
				// the only thing that stops the buffer growing to its cap.
				discardTCPBufferedPackets(s.netFlow)
				continue // Don't update firstLine, keep waiting for real SIP message
			}
			firstLine = false
			if !isSIPRequestLine(trimmedLine) && !isSIPResponseLine(trimmedLine) {
				return nil, errNotSIP
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
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				lengthStr := strings.TrimSpace(line[15:])
				if length, parseErr := ParseContentLengthSecurely(lengthStr); parseErr == nil {
					contentLength = length
				} else {
					logger.Warn("Content-Length security validation failed",
						"value", lengthStr,
						"error", parseErr,
						"source", "tcp_stream")
					return nil, fmt.Errorf("invalid Content-Length: %w", parseErr)
				}
			}
		}
	}

	messageBytes := []byte(message.String())

	if err := ValidateMessageSize(len(messageBytes)); err != nil {
		logger.Warn("SIP message size security validation failed",
			"size", len(messageBytes),
			"error", err,
			"source", "tcp_stream")
		return nil, fmt.Errorf("SIP message too large: %w", err)
	}

	return messageBytes, nil
}

// getEndpoints constructs IP:port endpoint strings from the network and transport flows
func (s *bufferedSIPStream) getEndpoints() (srcEndpoint, dstEndpoint string) {
	srcEndpoint = fmt.Sprintf("%s:%s", s.netFlow.Src().String(), s.transportFlow.Src().String())
	dstEndpoint = fmt.Sprintf("%s:%s", s.netFlow.Dst().String(), s.transportFlow.Dst().String())
	return
}

// SetState updates the TCP connection state for state-based timeouts.
func (s *bufferedSIPStream) SetState(newState TCPState) {
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

	// Check if the call is still active
	return IsCallActive(callID)
}

// processSipMessage processes a complete SIP message (shared with bufferedSIPStream)
func (s *bufferedSIPStream) processSipMessage(sipMessage []byte) {
	lines := bytes.Split(sipMessage, []byte("\n"))
	var callID string

	for _, line := range lines {
		if detectCallIDHeader(string(line), &callID) {
			break
		}
	}

	if callID != "" {
		// Increment SIP messages detected counter (voip package)
		IncrementSIPMessagesDetected()

		if s.callIDDetector != nil {
			s.callIDDetector.SetCallID(callID)
		}

		if s.factory != nil && s.factory.handler != nil {
			srcEndpoint, dstEndpoint := s.getEndpoints()
			s.factory.handler.HandleSIPMessage(sipMessage, callID, srcEndpoint, dstEndpoint, s.netFlow)
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
)

// isSIPRequestLine checks if a line looks like a SIP request (e.g., "INVITE sip:... SIP/2.0")
func isSIPRequestLine(line string) bool {
	// SIP requests: METHOD SP Request-URI SP SIP-Version CRLF
	// Common methods: INVITE, REGISTER, OPTIONS, ACK, BYE, CANCEL, UPDATE, REFER, SUBSCRIBE, NOTIFY, INFO, MESSAGE, PRACK
	sipMethods := []string{"INVITE ", "REGISTER ", "OPTIONS ", "ACK ", "BYE ", "CANCEL ", "UPDATE ", "REFER ", "SUBSCRIBE ", "NOTIFY ", "INFO ", "MESSAGE ", "PRACK "}
	for _, method := range sipMethods {
		if strings.HasPrefix(line, method) && strings.Contains(line, "SIP/2.0") {
			return true
		}
	}
	return false
}

// isSIPResponseLine checks if a line looks like a SIP response (e.g., "SIP/2.0 200 OK")
func isSIPResponseLine(line string) bool {
	return strings.HasPrefix(line, "SIP/2.0 ")
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
