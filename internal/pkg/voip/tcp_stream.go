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
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// SIPMessageHandler processes complete SIP messages after TCP reassembly
type SIPMessageHandler interface {
	// HandleSIPMessage is called when a complete SIP message has been reassembled from TCP stream
	// Parameters:
	//   - sipMessage: complete SIP message bytes (headers + body)
	//   - callID: extracted Call-ID from message headers
	//   - flow: network flow identifier (for associating with buffered TCP packets)
	// Returns:
	//   - bool: true if message was accepted/matched filter (for metrics)
	HandleSIPMessage(sipMessage []byte, callID string, flow gopacket.Flow) bool
}

// bufferedSIPStream implements tcpassembly.Stream with a buffered channel.
// This guarantees Reassembled() NEVER blocks, which is critical because:
// 1. tcpreader.ReaderStream uses an unbuffered channel
// 2. The assembler calls Reassembled() synchronously from the packet loop
// 3. If Reassembled() blocks, the entire packet capture freezes
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
	flow           gopacket.Flow
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
	closed         int32 // atomic flag
}

// Buffer size for reassembled data chunks.
// Each TCP segment creates one entry, so this should handle bursts.
const streamBufferSize = 64

// newBufferedSIPStream creates a new buffered stream that implements tcpassembly.Stream.
// The stream immediately starts a processing goroutine.
func newBufferedSIPStream(parentCtx context.Context, factory *sipStreamFactory, detector *CallIDDetector, flow gopacket.Flow) *bufferedSIPStream {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &bufferedSIPStream{
		dataChan:       make(chan []byte, streamBufferSize),
		ctx:            ctx,
		cancel:         cancel,
		factory:        factory,
		callIDDetector: detector,
		flow:           flow,
		createdAt:      time.Now(),
	}
	// Start processing goroutine immediately
	go s.processLoop()
	return s
}

// Reassembled implements tcpassembly.Stream.
// Called by the assembler when TCP data is reassembled.
// NEVER BLOCKS - uses non-blocking send to buffered channel.
func (s *bufferedSIPStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	for _, r := range reassemblies {
		if len(r.Bytes) == 0 {
			continue
		}
		// Copy the data since reassembly buffers may be reused
		data := make([]byte, len(r.Bytes))
		copy(data, r.Bytes)

		// Non-blocking send - drop data if buffer is full
		// This is better than blocking the packet capture loop
		select {
		case s.dataChan <- data:
			// Successfully queued
		default:
			// Buffer full - drop this chunk (log at debug level to avoid spam)
			logger.Debug("TCP stream buffer full, dropping data", "bytes", len(data))
		}
	}
}

// ReassemblyComplete implements tcpassembly.Stream.
// Called when the TCP stream is closed (FIN/RST or timeout).
func (s *bufferedSIPStream) ReassemblyComplete() {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.dataChan)
	}
}

// processLoop reads from the buffered channel and processes SIP messages.
func (s *bufferedSIPStream) processLoop() {
	logger.Debug("SIP stream starting", "flow", s.flow.String())

	defer func() {
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

	// Create a pipe to convert channel data to io.Reader
	pipeReader, pipeWriter := io.Pipe()

	// Goroutine to pump data from channel to pipe
	go func() {
		defer pipeWriter.Close()
		// Timeout for initial data - non-SIP streams send nothing useful
		initialTimer := time.NewTimer(initialReadTimeout)
		defer initialTimer.Stop()
		gotData := false

		for {
			select {
			case <-s.ctx.Done():
				return
			case data, ok := <-s.dataChan:
				if !ok {
					return // Channel closed
				}
				gotData = true
				if _, err := pipeWriter.Write(data); err != nil {
					return
				}
			case <-initialTimer.C:
				if !gotData {
					// No data received in initial timeout - likely not SIP
					logger.Debug("Read timeout, closing stream")
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

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		sipMessage, err := s.readCompleteSipMessageFromReader(bufReader)
		if err != nil {
			if errors.Is(err, errNotSIP) {
				logger.Debug("Non-SIP data detected, closing stream")
			} else if errors.Is(err, errReadTimeout) {
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
			firstLine = false
			trimmedLine := strings.TrimRight(line, "\r\n")
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
		if s.callIDDetector != nil {
			s.callIDDetector.SetCallID(callID)
		}

		if s.factory != nil && s.factory.handler != nil {
			s.factory.handler.HandleSIPMessage(sipMessage, callID, s.flow)
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

// SIPStream represents a TCP stream that processes SIP messages
type SIPStream struct {
	reader         *tcpreader.ReaderStream
	readerWrapper  *safeReader
	callIDDetector *CallIDDetector
	ctx            context.Context
	factory        *sipStreamFactory
	flow           gopacket.Flow
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
	readySignal    chan<- struct{} // closed when reader is actively listening
}

// errReadTimeout is returned when a read operation times out waiting for data.
// This indicates the TCP connection has stalled mid-message.
var errReadTimeout = errors.New("read timeout: no data received")

// Initial timeout for first data on a new TCP stream.
// SIP sends data immediately after connection - if nothing arrives quickly,
// it's likely not SIP traffic. This prevents non-SIP connections from
// holding goroutines for extended periods.
const initialReadTimeout = 2 * time.Second

// Default read timeout for TCP streams - time to wait for next data chunk
// after initial data has been received. This catches stalled connections
// mid-message while allowing idle time between messages.
const defaultReadTimeout = 10 * time.Second

// safeReader wraps a tcpreader.ReaderStream to provide interruptible reads
// without data races. The tcpreader package's Close() method races with Read(),
// so this wrapper uses an io.Pipe to decouple the underlying reader from the
// consumer. A background goroutine copies data from tcpreader to the pipe,
// and closing the pipe writer is thread-safe.
//
// The safeReader includes a watchdog that enforces read timeouts - if no data
// is received within the timeout period, the pipe is closed to unblock consumers.
type safeReader struct {
	pipeReader  *io.PipeReader
	pipeWriter  *io.PipeWriter
	bufReader   *bufio.Reader
	ctx         context.Context
	cancel      context.CancelFunc
	copyDone    chan struct{}
	closeOnce   sync.Once
	readTimeout time.Duration
}

// newSafeReader creates a safe reader wrapper with optional ready signaling.
// If readySignal is non-nil, it will be closed just before the first Read() call,
// allowing the caller to wait until the reader is actively listening.
func newSafeReader(reader *tcpreader.ReaderStream, ctx context.Context, readTimeout time.Duration, readySignal chan<- struct{}) *safeReader {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)

	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}

	sr := &safeReader{
		pipeReader:  pipeReader,
		pipeWriter:  pipeWriter,
		bufReader:   bufio.NewReader(pipeReader),
		ctx:         ctx,
		cancel:      cancel,
		copyDone:    make(chan struct{}),
		readTimeout: readTimeout,
	}

	// Channel to signal data activity from copy goroutine to watchdog
	activity := make(chan struct{}, 1)

	// Start watchdog goroutine to enforce read timeouts
	go sr.watchdog(activity)

	// Start copy goroutine that moves data from tcpreader to pipe
	go sr.copyLoop(reader, activity, readySignal)

	return sr
}

// watchdog monitors for read activity and closes the pipe if idle too long.
// This catches stalled TCP connections that stop sending data mid-message.
//
// Uses a two-phase timeout strategy:
// 1. Initial phase: Short timeout (2s) - SIP sends data immediately, non-SIP doesn't
// 2. Active phase: Longer timeout (10s) - allows gaps between SIP messages
func (sr *safeReader) watchdog(activity <-chan struct{}) {
	// Start with short initial timeout - non-SIP connections get closed quickly
	timer := time.NewTimer(initialReadTimeout)
	defer timer.Stop()

	firstActivity := true

	for {
		select {
		case <-sr.ctx.Done():
			return
		case <-activity:
			// Reset timer on activity
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			// After first activity, switch to longer timeout for subsequent reads
			if firstActivity {
				firstActivity = false
			}
			timer.Reset(sr.readTimeout)
		case <-timer.C:
			// Timeout - close pipe to unblock any pending reads
			sr.pipeWriter.CloseWithError(errReadTimeout)
			sr.cancel()
			return
		}
	}
}

// copyLoop reads from tcpreader and writes to the pipe, signaling activity.
// If readySignal is non-nil, it is closed just before the first Read() to signal
// that the reader is actively listening (critical for unbuffered channel synchronization).
func (sr *safeReader) copyLoop(reader *tcpreader.ReaderStream, activity chan<- struct{}, readySignal chan<- struct{}) {
	defer close(sr.copyDone)
	defer sr.pipeWriter.Close()

	// Handle nil reader gracefully
	if reader == nil {
		// Still signal ready even on error, so caller doesn't block forever
		if readySignal != nil {
			close(readySignal)
		}
		sr.pipeWriter.CloseWithError(fmt.Errorf("nil reader"))
		return
	}
	defer reader.Close()

	// Signal that we're ready to receive data - this happens just before
	// the first Read() call, guaranteeing the unbuffered channel is being
	// actively listened to before the assembler calls Reassembled().
	if readySignal != nil {
		close(readySignal)
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-sr.ctx.Done():
			return
		default:
		}

		n, err := reader.Read(buf)
		if n > 0 {
			// Signal activity to watchdog (non-blocking)
			select {
			case activity <- struct{}{}:
			default:
			}

			if _, writeErr := sr.pipeWriter.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				sr.pipeWriter.CloseWithError(err)
			}
			return
		}
	}
}

// shouldStop returns true if the reader should stop reading
func (sr *safeReader) shouldStop() bool {
	return sr.ctx.Err() != nil
}

// close shuts down the safe reader. The copy goroutine will exit when
// its blocked read returns (either from data arrival or stream close).
func (sr *safeReader) close() {
	sr.closeOnce.Do(func() {
		// Cancel context to signal copy goroutine to stop
		sr.cancel()
		// Close pipe reader to unblock any pending reads from consumer
		sr.pipeReader.Close()
		// Don't wait for copyDone - the copy goroutine will exit naturally
		// when its blocked read returns. Waiting here could cause a deadlock
		// if the tcpreader is blocked indefinitely waiting for data.
	})
}

// ReadString reads until the first occurrence of delim in the input.
func (sr *safeReader) ReadString(delim byte) (string, error) {
	if sr.shouldStop() {
		return "", sr.ctx.Err()
	}
	return sr.bufReader.ReadString(delim)
}

// ReadFull reads exactly len(buf) bytes from the reader.
func (sr *safeReader) ReadFull(buf []byte) (int, error) {
	if sr.shouldStop() {
		return 0, sr.ctx.Err()
	}
	return io.ReadFull(sr.bufReader, buf)
}

func (s *SIPStream) run() {
	logger.Debug("SIP stream starting", "flow", s.flow.String())

	// Create a safe reader wrapper that handles context cancellation and read timeouts.
	// The wrapper performs reads in goroutines and uses channels for coordination,
	// allowing context cancellation to properly interrupt blocking reads.
	// The read timeout catches stalled connections that stop sending data mid-message.
	// The readySignal is closed just before the first Read(), ensuring the unbuffered
	// channel is being actively listened to before this function returns.
	s.readerWrapper = newSafeReader(s.reader, s.ctx, defaultReadTimeout, s.readySignal)

	defer func() {
		// Close the reader wrapper to clean up any pending read goroutines
		s.readerWrapper.close()

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

		// Ensure resources are cleaned up
		if s.callIDDetector != nil {
			s.callIDDetector.Close()
		}

		// Log stream completion statistics
		logger.Debug("TCP SIP stream completed",
			"stream_age", time.Since(s.createdAt),
			"processed_bytes", atomic.LoadInt64(&s.processedBytes),
			"processed_messages", atomic.LoadInt64(&s.processedMsgs))
	}()

	// Determine if batch processing should be used
	batchSize := s.factory.getCurrentBatchSize()
	logger.Debug("Stream processing mode", "batch_size", batchSize)

	if batchSize > 1 {
		s.processBatched(batchSize)
	} else {
		s.processSingle()
	}
}

// processSingle handles single message processing (latency optimized)
// Loops until EOF or error to handle persistent TCP connections properly.
func (s *SIPStream) processSingle() {
	logger.Debug("processSingle starting")

	for {
		// Check context before each message
		select {
		case <-s.ctx.Done():
			logger.Debug("Context done in processSingle")
			return
		default:
		}

		// Read and buffer the complete SIP message
		sipMessage, err := s.readCompleteSipMessage()
		if err != nil {
			// Don't log errors during context cancellation (normal shutdown)
			// or for non-SIP traffic (expected when filtering)
			if errors.Is(err, errNotSIP) {
				logger.Debug("Non-SIP data detected, closing stream")
				return
			}
			if errors.Is(err, errReadTimeout) {
				logger.Debug("Read timeout, closing stream")
				return
			}
			if !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
				logger.Error("Error reading complete SIP message", "error", err)
			} else {
				logger.Debug("EOF reading SIP message")
			}
			return
		}

		if len(sipMessage) == 0 {
			logger.Debug("Empty SIP message read")
			continue
		}

		logger.Debug("Read complete SIP message", "bytes", len(sipMessage))

		// Update processing statistics atomically
		atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
		atomic.AddInt64(&s.processedMsgs, 1)

		s.processSipMessage(sipMessage)
	}
}

// MessageBatch represents a batch of SIP messages for processing
type MessageBatch struct {
	messages [][]byte
	maxSize  int
	size     int
}

// processBatched handles batch message processing (throughput optimized)
// Loops until EOF or error to handle persistent TCP connections properly.
func (s *SIPStream) processBatched(batchSize int) {
	logger.Debug("processBatched starting", "batch_size", batchSize)

	for {
		batch := &MessageBatch{
			messages: make([][]byte, 0, batchSize),
			maxSize:  batchSize,
		}

		// Fill the batch
		for batch.size < batchSize {
			select {
			case <-s.ctx.Done():
				logger.Debug("Context done in batch loop")
				// Process any messages we have before exiting
				for _, message := range batch.messages {
					s.processSipMessage(message)
				}
				return
			default:
			}

			sipMessage, err := s.readCompleteSipMessage()
			if err != nil {
				// Don't log errors during context cancellation (normal shutdown)
				// or for non-SIP traffic (expected when filtering)
				if errors.Is(err, errNotSIP) {
					logger.Debug("Non-SIP data detected, closing stream")
					// Process any messages we have before exiting
					for _, message := range batch.messages {
						s.processSipMessage(message)
					}
					return
				}
				if errors.Is(err, errReadTimeout) {
					logger.Debug("Read timeout, closing stream")
					// Process any messages we have before exiting
					for _, message := range batch.messages {
						s.processSipMessage(message)
					}
					return
				}
				if !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
					logger.Error("Error reading SIP message in batch", "error", err)
				} else {
					logger.Debug("EOF in batch read", "messages_read", batch.size)
				}
				// Process any messages we have before exiting
				for _, message := range batch.messages {
					s.processSipMessage(message)
				}
				return
			}

			if len(sipMessage) > 0 {
				logger.Debug("Read SIP message in batch", "bytes", len(sipMessage), "batch_size", batch.size+1)
				batch.messages = append(batch.messages, sipMessage)
				batch.size++
				atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
				atomic.AddInt64(&s.processedMsgs, 1)
			}
		}

		logger.Debug("Processing batch", "messages", len(batch.messages))
		// Process the entire batch
		for _, message := range batch.messages {
			s.processSipMessage(message)
		}
	}
}

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

// readCompleteSipMessage reads a complete SIP message from the TCP stream
func (s *SIPStream) readCompleteSipMessage() ([]byte, error) {
	// Check if reader wrapper is nil (defensive check for abnormal conditions)
	if s.readerWrapper == nil {
		return nil, fmt.Errorf("TCP stream reader wrapper is nil")
	}

	var message strings.Builder
	var contentLength int
	headersDone := false
	firstLine := true
	headerCount := 0

	for {
		// If headers are done and no content-length, we're done
		if headersDone && contentLength == 0 {
			break
		}

		// If headers are done and we have content to read
		if headersDone && contentLength > 0 {
			content := make([]byte, contentLength)
			_, err := s.readerWrapper.ReadFull(content)
			if err != nil {
				return nil, fmt.Errorf("failed to read SIP message content (%d bytes) from TCP stream: %w", contentLength, err)
			}
			message.Write(content)
			break
		}

		// Check if we should stop (context cancelled or close signaled)
		if s.readerWrapper.shouldStop() {
			return nil, s.ctx.Err()
		}

		line, err := s.readerWrapper.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read SIP message line from TCP stream: %w", err)
		}

		// Early rejection: line too long for SIP header (likely binary data)
		if len(line) > maxSIPHeaderLineLength {
			return nil, errNotSIP
		}

		// Validate first line is a valid SIP request or response
		// This prevents buffering non-SIP data (TLS, HTTP/2, binary protocols)
		if firstLine {
			firstLine = false
			trimmedLine := strings.TrimRight(line, "\r\n")
			if !isSIPRequestLine(trimmedLine) && !isSIPResponseLine(trimmedLine) {
				return nil, errNotSIP
			}
		}

		message.WriteString(line)
		headerCount++

		// Sanity check: too many headers indicates non-SIP or malformed data
		if headerCount > maxSIPHeaders {
			return nil, errNotSIP
		}

		// Check for end of headers (empty line)
		if !headersDone && (line == "\r\n" || line == "\n") {
			headersDone = true
			continue
		}

		// Parse Content-Length header if we haven't finished headers
		if !headersDone {
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				lengthStr := strings.TrimSpace(line[15:])
				if length, parseErr := ParseContentLengthSecurely(lengthStr); parseErr == nil {
					contentLength = length
				} else {
					// Log security validation failure and reject message
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

	// Validate total message size for security
	if err := ValidateMessageSize(len(messageBytes)); err != nil {
		logger.Warn("SIP message size security validation failed",
			"size", len(messageBytes),
			"error", err,
			"source", "tcp_stream")
		return nil, fmt.Errorf("SIP message too large: %w", err)
	}

	return messageBytes, nil
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

// processSipMessage processes a complete SIP message and extracts call information
func (s *SIPStream) processSipMessage(sipMessage []byte) {
	// Parse the SIP message for Call-ID
	lines := strings.Split(string(sipMessage), "\n")
	var callID string

	for _, line := range lines {
		if detectCallIDHeader(line, &callID) {
			break
		}
	}

	if callID != "" {
		// Notify the Call-ID detector
		if s.callIDDetector != nil {
			s.callIDDetector.SetCallID(callID)
		}

		// Delegate to the message handler
		logger.Debug("About to call handler.HandleSIPMessage",
			"call_id", callID,
			"has_factory", s.factory != nil,
			"has_handler", s.factory != nil && s.factory.handler != nil,
			"message_len", len(sipMessage))

		if s.factory != nil && s.factory.handler != nil {
			s.factory.handler.HandleSIPMessage(sipMessage, callID, s.flow)
		} else {
			logger.Warn("No handler available for SIP message",
				"call_id", callID,
				"has_factory", s.factory != nil)
		}
	}
}

// Helper function to create SIP stream for factory
func createSIPStream(reader *tcpreader.ReaderStream, detector *CallIDDetector, ctx context.Context, factory *sipStreamFactory, flow gopacket.Flow) *SIPStream {
	return &SIPStream{
		reader:         reader,
		callIDDetector: detector,
		ctx:            ctx,
		factory:        factory,
		flow:           flow,
		createdAt:      time.Now(),
	}
}
