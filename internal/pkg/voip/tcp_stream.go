package voip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// CallIDDetector manages Call-ID detection with timeout support
type CallIDDetector struct {
	callID   string
	detected chan string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	set      bool  // flag to indicate if Call-ID has been set
	closed   int32 // atomic flag to track if detector is closed
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
	// Check if the detector is already closed
	if atomic.LoadInt32(&c.closed) == 1 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Only set the call ID if it hasn't been set already (first-wins semantics)
	if !c.set {
		c.callID = id
		c.set = true

		// Send to channel and close it to notify all waiters
		if atomic.LoadInt32(&c.closed) == 0 {
			select {
			case c.detected <- id:
				close(c.detected) // Close the channel so all waiters get the value
			default:
				// Channel already has a value or is closed
			}
		}
	}
	// Call-ID already set, ignore this call
}

func (c *CallIDDetector) Wait() string {
	// First check if callID is already set
	c.mu.RLock()
	if c.set {
		callID := c.callID
		c.mu.RUnlock()
		return callID
	}
	c.mu.RUnlock()

	// If not set, wait on the channel
	select {
	case callID, ok := <-c.detected:
		if ok {
			return callID
		}
		// Channel was closed, check if callID was set
		c.mu.RLock()
		defer c.mu.RUnlock()
		if c.set {
			return c.callID
		}
		return ""
	case <-c.ctx.Done():
		return ""
	}
}

func (c *CallIDDetector) Close() {
	// Use atomic compare-and-swap to ensure Close is only executed once
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return // Already closed
	}

	// Cancel context to wake up any waiters
	c.cancel()

	// Close the channel safely - it might already be closed by SetCallID
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.detected:
		// Channel already closed, do nothing
	default:
		close(c.detected)
	}
}

// SIPStream represents a TCP stream that processes SIP messages
type SIPStream struct {
	reader         *tcpreader.ReaderStream
	callIDDetector *CallIDDetector
	ctx            context.Context
	factory        *sipStreamFactory
	flow           gopacket.Flow
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
}

func (s *SIPStream) run() {
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

	if batchSize > 1 {
		s.processBatched(batchSize)
	} else {
		s.processSingle()
	}
}

// processSingle handles single message processing (latency optimized)
func (s *SIPStream) processSingle() {
	// Read and buffer the complete SIP message
	sipMessage, err := s.readCompleteSipMessage()
	if err != nil {
		if err != io.EOF {
			logger.Error("Error reading complete SIP message", "error", err)
		}
		return
	}

	if len(sipMessage) == 0 {
		return
	}

	// Update processing statistics atomically
	atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
	atomic.AddInt64(&s.processedMsgs, 1)

	s.processSipMessage(sipMessage)
}

// MessageBatch represents a batch of SIP messages for processing
type MessageBatch struct {
	messages [][]byte
	maxSize  int
	size     int
}

// processBatched handles batch message processing (throughput optimized)
func (s *SIPStream) processBatched(batchSize int) {
	batch := &MessageBatch{
		messages: make([][]byte, 0, batchSize),
		maxSize:  batchSize,
	}

	for batch.size < batchSize {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		sipMessage, err := s.readCompleteSipMessage()
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading SIP message in batch", "error", err)
			}
			break
		}

		if len(sipMessage) > 0 {
			batch.messages = append(batch.messages, sipMessage)
			batch.size++
			atomic.AddInt64(&s.processedBytes, int64(len(sipMessage)))
			atomic.AddInt64(&s.processedMsgs, 1)
		}
	}

	// Process the entire batch
	for _, message := range batch.messages {
		s.processSipMessage(message)
	}
}

// readCompleteSipMessage reads a complete SIP message from the TCP stream
func (s *SIPStream) readCompleteSipMessage() ([]byte, error) {
	reader := bufio.NewReader(s.reader)
	var message strings.Builder
	var contentLength int
	headersDone := false

	for {
		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		message.WriteString(line)

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

		// If we've finished headers and have content to read
		if headersDone && contentLength > 0 {
			content := make([]byte, contentLength)
			_, err := io.ReadFull(reader, content)
			if err != nil {
				return nil, err
			}
			message.Write(content)
			break
		}

		// If headers are done and no content-length, we're done
		if headersDone && contentLength == 0 {
			break
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
		extractedCallID = trimmed[valueStart:]
	} else if len(trimmed) >= 2 && compareHeaderCI(trimmed[:2], "i:") {
		// Check for compact "i:" header
		valueStart := 2
		// Skip whitespace after colon
		for valueStart < len(trimmed) && (trimmed[valueStart] == ' ' || trimmed[valueStart] == '\t') {
			valueStart++
		}
		extractedCallID = trimmed[valueStart:]
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
		// Flush any buffered TCP packets to this call
		flushTCPPacketsToCall(s.flow, callID, true)

		// Notify the Call-ID detector
		if s.callIDDetector != nil {
			s.callIDDetector.SetCallID(callID)
		}

		// Process the SIP message through the VoIP handler
		handleSipMessage(sipMessage)
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
