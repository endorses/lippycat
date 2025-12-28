package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc/peer"
)

// Rate limiting configuration
const (
	// DefaultMaxFailures is the maximum number of failures before blocking.
	DefaultMaxFailures = 5
	// DefaultBlockDuration is how long to block after max failures.
	DefaultBlockDuration = 60 * time.Second
	// cleanupInterval is how often to remove expired entries.
	cleanupInterval = 30 * time.Second
)

// ErrRateLimited is returned when a client is rate limited.
var ErrRateLimited = errors.New("too many authentication failures, try again later")

// failureRecord tracks authentication failures for a single client.
type failureRecord struct {
	count     int
	firstFail time.Time
	blocked   bool
	blockTime time.Time
}

// RateLimiter tracks authentication failures per client IP.
type RateLimiter struct {
	mu            sync.RWMutex
	failures      map[string]*failureRecord
	maxFailures   int
	blockDuration time.Duration
	done          chan struct{}
	wg            sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter with default settings.
func NewRateLimiter() *RateLimiter {
	return NewRateLimiterWithConfig(DefaultMaxFailures, DefaultBlockDuration)
}

// NewRateLimiterWithConfig creates a new rate limiter with custom settings.
func NewRateLimiterWithConfig(maxFailures int, blockDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		failures:      make(map[string]*failureRecord),
		maxFailures:   maxFailures,
		blockDuration: blockDuration,
		done:          make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// IsBlocked checks if a client IP is currently blocked.
// Returns true if blocked, false otherwise.
func (rl *RateLimiter) IsBlocked(ctx context.Context) bool {
	clientIP := extractClientIP(ctx)
	if clientIP == "" {
		return false // Can't rate limit without IP
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	record, ok := rl.failures[clientIP]
	if !ok {
		return false
	}

	// Check if still blocked
	if record.blocked {
		if time.Since(record.blockTime) < rl.blockDuration {
			return true
		}
		// Block expired, will be cleaned up or reset on next failure
	}

	return false
}

// RecordFailure records an authentication failure for a client IP.
// Returns true if the client is now blocked.
func (rl *RateLimiter) RecordFailure(ctx context.Context) bool {
	clientIP := extractClientIP(ctx)
	if clientIP == "" {
		return false // Can't rate limit without IP
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	record, ok := rl.failures[clientIP]
	if !ok {
		record = &failureRecord{
			count:     1,
			firstFail: now,
		}
		rl.failures[clientIP] = record
		return false
	}

	// Check if previous block has expired (reset failures)
	if record.blocked && time.Since(record.blockTime) >= rl.blockDuration {
		record.count = 1
		record.firstFail = now
		record.blocked = false
		record.blockTime = time.Time{}
		return false
	}

	// Check if failure window has expired (reset count)
	if time.Since(record.firstFail) >= rl.blockDuration {
		record.count = 1
		record.firstFail = now
		return false
	}

	// Increment failure count
	record.count++

	// Check if we've hit the limit
	if record.count >= rl.maxFailures {
		record.blocked = true
		record.blockTime = now
		logger.Warn("Client blocked due to authentication failures",
			"client_ip", clientIP,
			"failure_count", record.count)
		return true
	}

	return false
}

// RecordSuccess clears failure tracking for a client IP.
func (rl *RateLimiter) RecordSuccess(ctx context.Context) {
	clientIP := extractClientIP(ctx)
	if clientIP == "" {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, clientIP)
}

// cleanupLoop periodically removes expired entries.
func (rl *RateLimiter) cleanupLoop() {
	defer rl.wg.Done()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes expired failure records.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, record := range rl.failures {
		// Remove if block has expired or if no failures for a while
		if record.blocked {
			if now.Sub(record.blockTime) >= rl.blockDuration*2 {
				delete(rl.failures, ip)
			}
		} else if now.Sub(record.firstFail) >= rl.blockDuration*2 {
			delete(rl.failures, ip)
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.done)
	rl.wg.Wait()
}

// extractClientIP gets the client IP from the gRPC context.
func extractClientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}

	// peer.Addr.String() returns "ip:port", we just want the IP
	addr := p.Addr.String()

	// Handle IPv6 addresses like "[::1]:50051"
	if len(addr) > 0 && addr[0] == '[' {
		// IPv6 format: [ip]:port
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				return addr[1:i]
			}
		}
		return addr // Malformed, return as-is
	}

	// IPv4 format: ip:port
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr // No port found, return as-is
}
