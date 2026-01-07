package http

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// TrackerConfig holds configuration for the request tracker.
type TrackerConfig struct {
	MaxPendingRequests int           // Maximum pending requests per flow
	RequestTimeout     time.Duration // Time after which pending requests expire
	CleanupInterval    time.Duration // Interval for cleanup routine
}

// DefaultTrackerConfig returns default tracker configuration.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		MaxPendingRequests: 100,
		RequestTimeout:     30 * time.Second,
		CleanupInterval:    10 * time.Second,
	}
}

// flowKey identifies a TCP connection (normalized so direction doesn't matter).
type flowKey struct {
	ClientIP   string
	ServerIP   string
	ClientPort string
	ServerPort string
}

// pendingRequest represents a request waiting for its response.
type pendingRequest struct {
	Method    string
	Path      string
	Host      string
	Timestamp time.Time
}

// RequestTracker correlates HTTP requests with responses.
type RequestTracker struct {
	mu       sync.RWMutex
	config   TrackerConfig
	requests map[flowKey][]*pendingRequest
	done     chan struct{}

	// Statistics
	totalRequests     int64
	totalResponses    int64
	correlatedCount   int64
	uncorrelatedCount int64
	expiredCount      int64
}

// NewRequestTracker creates a new request tracker.
func NewRequestTracker(config TrackerConfig) *RequestTracker {
	t := &RequestTracker{
		config:   config,
		requests: make(map[flowKey][]*pendingRequest),
		done:     make(chan struct{}),
	}

	go t.cleanupLoop()

	return t
}

// TrackRequest records an outgoing HTTP request.
func (t *RequestTracker) TrackRequest(srcIP, dstIP, srcPort, dstPort string, metadata *types.HTTPMetadata) {
	if metadata.Type != "request" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := t.makeFlowKey(srcIP, dstIP, srcPort, dstPort)

	pending := &pendingRequest{
		Method:    metadata.Method,
		Path:      metadata.Path,
		Host:      metadata.Host,
		Timestamp: time.Now(),
	}

	// Limit pending requests per flow
	if len(t.requests[key]) >= t.config.MaxPendingRequests {
		// Remove oldest request
		t.requests[key] = t.requests[key][1:]
		t.expiredCount++
	}

	t.requests[key] = append(t.requests[key], pending)
	t.totalRequests++
}

// CorrelateResponse matches a response to a pending request.
// Returns the matched request metadata (Method, Path, Host) and RTT if matched.
func (t *RequestTracker) CorrelateResponse(srcIP, dstIP, srcPort, dstPort string, metadata *types.HTTPMetadata) bool {
	if metadata.Type != "response" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Response flows from server to client (swap src/dst)
	key := t.makeFlowKey(dstIP, srcIP, dstPort, srcPort)

	requests := t.requests[key]
	if len(requests) == 0 {
		t.uncorrelatedCount++
		return false
	}

	// Take the oldest pending request (FIFO)
	pending := requests[0]
	t.requests[key] = requests[1:]

	// Update metadata with correlation info
	metadata.CorrelatedResponse = true
	metadata.RequestResponseTimeMs = time.Since(pending.Timestamp).Milliseconds()

	// If response doesn't have host, copy from request
	if metadata.Host == "" {
		metadata.Host = pending.Host
	}

	t.totalResponses++
	t.correlatedCount++

	return true
}

// makeFlowKey creates a normalized flow key.
func (t *RequestTracker) makeFlowKey(clientIP, serverIP, clientPort, serverPort string) flowKey {
	return flowKey{
		ClientIP:   clientIP,
		ServerIP:   serverIP,
		ClientPort: clientPort,
		ServerPort: serverPort,
	}
}

// cleanupLoop periodically removes expired requests.
func (t *RequestTracker) cleanupLoop() {
	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.cleanup()
		}
	}
}

// cleanup removes expired pending requests.
func (t *RequestTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	expiredCount := int64(0)

	for key, requests := range t.requests {
		// Find first non-expired request
		validIdx := 0
		for i, req := range requests {
			if now.Sub(req.Timestamp) > t.config.RequestTimeout {
				expiredCount++
			} else {
				validIdx = i
				break
			}
		}

		if validIdx > 0 {
			t.requests[key] = requests[validIdx:]
		}

		// Remove empty flows
		if len(t.requests[key]) == 0 {
			delete(t.requests, key)
		}
	}

	t.expiredCount += expiredCount
}

// Stats returns tracker statistics.
func (t *RequestTracker) Stats() TrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	pendingCount := 0
	for _, reqs := range t.requests {
		pendingCount += len(reqs)
	}

	return TrackerStats{
		TotalRequests:     t.totalRequests,
		TotalResponses:    t.totalResponses,
		CorrelatedCount:   t.correlatedCount,
		UncorrelatedCount: t.uncorrelatedCount,
		ExpiredCount:      t.expiredCount,
		PendingCount:      int64(pendingCount),
		ActiveFlows:       int64(len(t.requests)),
	}
}

// TrackerStats holds tracker statistics.
type TrackerStats struct {
	TotalRequests     int64
	TotalResponses    int64
	CorrelatedCount   int64
	UncorrelatedCount int64
	ExpiredCount      int64
	PendingCount      int64
	ActiveFlows       int64
}

// Close shuts down the tracker.
func (t *RequestTracker) Close() {
	close(t.done)
}
