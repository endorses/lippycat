package downstream

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

const (
	// Retry configuration constants
	maxRetries      = 3
	initialBackoff  = 100 * time.Millisecond
	maxBackoff      = 800 * time.Millisecond
	backoffMultiple = 2
)

// isRetryableError determines if an error is transient and should be retried.
// Returns true for connection errors, timeouts, and resource unavailable errors.
// Returns false for authorization failures, not found, invalid argument, etc.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Extract gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		// Not a gRPC error, could be network error - retry
		return true
	}

	// Retry transient errors
	switch st.Code() {
	case codes.Unavailable, // Service temporarily unavailable
		codes.DeadlineExceeded,  // Timeout
		codes.ResourceExhausted, // Too many requests, rate limited
		codes.Aborted,           // Operation aborted, may succeed on retry
		codes.Internal:          // Internal server error, may be transient
		return true

	case codes.Unauthenticated, // Auth failure - don't retry
		codes.PermissionDenied,   // Permission denied - don't retry
		codes.InvalidArgument,    // Bad request - won't succeed on retry
		codes.NotFound,           // Resource not found - won't change
		codes.AlreadyExists,      // Resource already exists - won't change
		codes.FailedPrecondition, // Precondition failed - won't change
		codes.Unimplemented,      // Operation not supported - won't change
		codes.Canceled:           // Client canceled - don't retry
		return false

	default:
		// For unknown codes, err on the side of not retrying
		return false
	}
}

// calculateBackoff calculates exponential backoff duration.
// Formula: initialBackoff * (backoffMultiple ^ attempt)
// Capped at maxBackoff (800ms).
//
// Examples:
//   - attempt 0: 100ms
//   - attempt 1: 200ms
//   - attempt 2: 400ms
//   - attempt 3: 800ms (capped)
func calculateBackoff(attempt int) time.Duration {
	backoff := initialBackoff
	for i := 0; i < attempt; i++ {
		backoff *= backoffMultiple
		if backoff > maxBackoff {
			backoff = maxBackoff
			break
		}
	}
	return backoff
}

// retryableOperation represents an operation that can be retried
type retryableOperation func() error

// withRetry executes an operation with exponential backoff retry logic.
// It retries up to maxRetries times (3) for transient errors.
// Non-retryable errors (auth failures, not found, etc.) are returned immediately.
//
// Parameters:
//   - ctx: Context for cancellation
//   - operation: Function to execute (should return error on failure)
//   - operationName: Name of operation for logging (e.g., "UpdateFilter")
//   - targetID: ID of target processor/hunter for logging
//
// Returns the last error if all retries fail, or nil on success.
func withRetry(ctx context.Context, operation retryableOperation, operationName, targetID string) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			logger.Warn("Retry aborted due to context cancellation",
				"operation", operationName,
				"target_id", targetID,
				"attempt", attempt)
			return ctx.Err()
		default:
		}

		// Execute operation
		err := operation()
		if err == nil {
			// Success
			if attempt > 0 {
				logger.Info("Operation succeeded after retry",
					"operation", operationName,
					"target_id", targetID,
					"attempts", attempt+1)
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			logger.Debug("Operation failed with non-retryable error",
				"operation", operationName,
				"target_id", targetID,
				"error", err,
				"attempt", attempt+1)
			return err
		}

		// Check if we have retries left
		if attempt >= maxRetries {
			logger.Warn("Operation failed after all retries",
				"operation", operationName,
				"target_id", targetID,
				"max_retries", maxRetries,
				"error", err)
			return err
		}

		// Calculate backoff and wait
		backoff := calculateBackoff(attempt)
		logger.Debug("Operation failed with retryable error, retrying",
			"operation", operationName,
			"target_id", targetID,
			"attempt", attempt+1,
			"backoff_ms", backoff.Milliseconds(),
			"error", err)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			logger.Warn("Retry backoff interrupted by context cancellation",
				"operation", operationName,
				"target_id", targetID)
			return ctx.Err()
		case <-time.After(backoff):
			// Continue to next attempt
		}
	}

	return lastErr
}
