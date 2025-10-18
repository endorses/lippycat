//go:build hunter || all

package circuitbreaker

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// State represents the circuit breaker state
type State int

const (
	StateClosed   State = iota // Normal operation
	StateOpen                  // Failing, reject requests immediately
	StateHalfOpen              // Testing if service recovered
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for connection management
type CircuitBreaker struct {
	// Configuration
	maxFailures      uint32        // Number of failures before opening circuit
	resetTimeout     time.Duration // How long to wait before trying again (half-open)
	halfOpenMaxCalls uint32        // Max calls allowed in half-open state

	// State
	state            atomic.Int32  // Current state (State enum)
	consecutiveFails atomic.Uint32 // Consecutive failures
	lastFailTime     atomic.Int64  // Unix timestamp of last failure
	halfOpenCalls    atomic.Uint32 // Number of calls in half-open state

	// Metrics
	totalAttempts   atomic.Uint64 // Total connection attempts
	totalSuccesses  atomic.Uint64 // Total successful connections
	totalFailures   atomic.Uint64 // Total failed connections
	totalRejections atomic.Uint64 // Total rejected attempts (circuit open)

	// Name for logging
	name string
	mu   sync.Mutex
}

// Config contains circuit breaker configuration
type Config struct {
	Name             string        // Circuit breaker name (for logging)
	MaxFailures      uint32        // Number of consecutive failures before opening (default: 5)
	ResetTimeout     time.Duration // Time to wait before transitioning to half-open (default: 30s)
	HalfOpenMaxCalls uint32        // Max calls in half-open state (default: 3)
}

// New creates a new circuit breaker
func New(config Config) *CircuitBreaker {
	// Set defaults
	if config.MaxFailures == 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.HalfOpenMaxCalls == 0 {
		config.HalfOpenMaxCalls = 3
	}

	cb := &CircuitBreaker{
		name:             config.Name,
		maxFailures:      config.MaxFailures,
		resetTimeout:     config.ResetTimeout,
		halfOpenMaxCalls: config.HalfOpenMaxCalls,
	}

	// Start in closed state
	cb.state.Store(int32(StateClosed))

	return cb
}

// Call attempts to execute the given function through the circuit breaker
// Returns error if circuit is open or if the function fails
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.totalAttempts.Add(1)

	// Check current state
	currentState := State(cb.state.Load())

	switch currentState {
	case StateOpen:
		// Check if we should transition to half-open
		lastFail := time.Unix(0, cb.lastFailTime.Load())
		if time.Since(lastFail) >= cb.resetTimeout {
			// Transition to half-open
			cb.toHalfOpen()
			// Allow this call to proceed
		} else {
			// Circuit is still open - reject
			cb.totalRejections.Add(1)
			return fmt.Errorf("circuit breaker '%s' is open (last failure: %v ago)",
				cb.name, time.Since(lastFail).Round(time.Second))
		}

	case StateHalfOpen:
		// Check if we've exceeded half-open call limit
		halfOpenCalls := cb.halfOpenCalls.Add(1)
		if halfOpenCalls > cb.halfOpenMaxCalls {
			// Too many calls in half-open - reject
			cb.halfOpenCalls.Add(^uint32(0)) // Decrement
			cb.totalRejections.Add(1)
			return fmt.Errorf("circuit breaker '%s' half-open limit exceeded", cb.name)
		}

	case StateClosed:
		// Normal operation - allow call
	}

	// Execute the function
	err := fn()

	// Record result
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// recordSuccess records a successful call
func (cb *CircuitBreaker) recordSuccess() {
	cb.totalSuccesses.Add(1)

	currentState := State(cb.state.Load())

	if currentState == StateHalfOpen {
		// Success in half-open state - transition to closed
		cb.toClosed()
	} else if currentState == StateClosed {
		// Reset consecutive failures on success
		cb.consecutiveFails.Store(0)
	}
}

// recordFailure records a failed call
func (cb *CircuitBreaker) recordFailure() {
	cb.totalFailures.Add(1)
	cb.lastFailTime.Store(time.Now().UnixNano())

	currentState := State(cb.state.Load())

	if currentState == StateHalfOpen {
		// Failure in half-open - immediately go back to open
		cb.toOpen()
		return
	}

	// Increment consecutive failures
	failures := cb.consecutiveFails.Add(1)

	// Check if we should open the circuit
	if failures >= cb.maxFailures {
		cb.toOpen()
	}
}

// toClosed transitions to closed state
func (cb *CircuitBreaker) toClosed() {
	oldState := State(cb.state.Swap(int32(StateClosed)))
	if oldState != StateClosed {
		logger.Info("Circuit breaker closed (service recovered)",
			"name", cb.name,
			"previous_state", oldState,
			"total_attempts", cb.totalAttempts.Load(),
			"total_successes", cb.totalSuccesses.Load())
	}
	cb.consecutiveFails.Store(0)
	cb.halfOpenCalls.Store(0)
}

// toHalfOpen transitions to half-open state
func (cb *CircuitBreaker) toHalfOpen() {
	oldState := State(cb.state.Swap(int32(StateHalfOpen)))
	if oldState != StateHalfOpen {
		logger.Info("Circuit breaker half-open (testing service)",
			"name", cb.name,
			"previous_state", oldState,
			"max_test_calls", cb.halfOpenMaxCalls)
	}
	cb.halfOpenCalls.Store(0)
}

// toOpen transitions to open state
func (cb *CircuitBreaker) toOpen() {
	oldState := State(cb.state.Swap(int32(StateOpen)))
	if oldState != StateOpen {
		logger.Warn("Circuit breaker opened (service failing)",
			"name", cb.name,
			"previous_state", oldState,
			"consecutive_failures", cb.consecutiveFails.Load(),
			"max_failures", cb.maxFailures,
			"reset_timeout", cb.resetTimeout)
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() State {
	return State(cb.state.Load())
}

// IsOpen returns true if the circuit is currently open
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.GetState() == StateOpen
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() Metrics {
	return Metrics{
		State:            cb.GetState(),
		ConsecutiveFails: cb.consecutiveFails.Load(),
		TotalAttempts:    cb.totalAttempts.Load(),
		TotalSuccesses:   cb.totalSuccesses.Load(),
		TotalFailures:    cb.totalFailures.Load(),
		TotalRejections:  cb.totalRejections.Load(),
		LastFailTime:     time.Unix(0, cb.lastFailTime.Load()),
	}
}

// Metrics contains circuit breaker statistics
type Metrics struct {
	State            State
	ConsecutiveFails uint32
	TotalAttempts    uint64
	TotalSuccesses   uint64
	TotalFailures    uint64
	TotalRejections  uint64
	LastFailTime     time.Time
}

// Reset manually resets the circuit breaker to closed state
// This should be used sparingly (e.g., operator intervention)
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	logger.Info("Circuit breaker manually reset",
		"name", cb.name,
		"previous_state", cb.GetState())

	cb.toClosed()
}

// ForceOpen manually forces the circuit breaker to open state
// This can be used for manual intervention (e.g., maintenance mode)
func (cb *CircuitBreaker) ForceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	logger.Warn("Circuit breaker manually opened",
		"name", cb.name,
		"previous_state", cb.GetState())

	cb.toOpen()
}
