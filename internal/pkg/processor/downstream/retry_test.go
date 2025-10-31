package downstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "unavailable error (retryable)",
			err:       status.Error(codes.Unavailable, "service unavailable"),
			retryable: true,
		},
		{
			name:      "deadline exceeded (retryable)",
			err:       status.Error(codes.DeadlineExceeded, "timeout"),
			retryable: true,
		},
		{
			name:      "resource exhausted (retryable)",
			err:       status.Error(codes.ResourceExhausted, "rate limited"),
			retryable: true,
		},
		{
			name:      "aborted error (retryable)",
			err:       status.Error(codes.Aborted, "operation aborted"),
			retryable: true,
		},
		{
			name:      "internal error (retryable)",
			err:       status.Error(codes.Internal, "internal server error"),
			retryable: true,
		},
		{
			name:      "unauthenticated error (non-retryable)",
			err:       status.Error(codes.Unauthenticated, "invalid token"),
			retryable: false,
		},
		{
			name:      "permission denied (non-retryable)",
			err:       status.Error(codes.PermissionDenied, "access denied"),
			retryable: false,
		},
		{
			name:      "invalid argument (non-retryable)",
			err:       status.Error(codes.InvalidArgument, "bad request"),
			retryable: false,
		},
		{
			name:      "not found (non-retryable)",
			err:       status.Error(codes.NotFound, "processor not found"),
			retryable: false,
		},
		{
			name:      "already exists (non-retryable)",
			err:       status.Error(codes.AlreadyExists, "resource exists"),
			retryable: false,
		},
		{
			name:      "failed precondition (non-retryable)",
			err:       status.Error(codes.FailedPrecondition, "precondition failed"),
			retryable: false,
		},
		{
			name:      "unimplemented (non-retryable)",
			err:       status.Error(codes.Unimplemented, "not implemented"),
			retryable: false,
		},
		{
			name:      "canceled (non-retryable)",
			err:       status.Error(codes.Canceled, "request canceled"),
			retryable: false,
		},
		{
			name:      "non-gRPC error (retryable - could be network error)",
			err:       errors.New("connection refused"),
			retryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err)
			assert.Equal(t, tt.retryable, result,
				"isRetryableError(%v) = %v, want %v", tt.err, result, tt.retryable)
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name     string
		attempt  int
		expected time.Duration
	}{
		{
			name:     "first attempt (0)",
			attempt:  0,
			expected: 100 * time.Millisecond,
		},
		{
			name:     "second attempt (1)",
			attempt:  1,
			expected: 200 * time.Millisecond,
		},
		{
			name:     "third attempt (2)",
			attempt:  2,
			expected: 400 * time.Millisecond,
		},
		{
			name:     "fourth attempt (3) - capped",
			attempt:  3,
			expected: 800 * time.Millisecond,
		},
		{
			name:     "fifth attempt (4) - still capped",
			attempt:  4,
			expected: 800 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateBackoff(tt.attempt)
			assert.Equal(t, tt.expected, result,
				"calculateBackoff(%d) = %v, want %v", tt.attempt, result, tt.expected)
		})
	}
}

func TestWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func() error {
		callCount++
		return nil
	}

	err := withRetry(ctx, operation, "TestOp", "target-1")
	require.NoError(t, err, "withRetry should succeed")
	assert.Equal(t, 1, callCount, "operation should be called once")
}

func TestWithRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func() error {
		callCount++
		if callCount < 3 {
			// Fail with retryable error first 2 times
			return status.Error(codes.Unavailable, "service unavailable")
		}
		// Succeed on 3rd attempt
		return nil
	}

	start := time.Now()
	err := withRetry(ctx, operation, "TestOp", "target-1")
	elapsed := time.Since(start)

	require.NoError(t, err, "withRetry should succeed after retries")
	assert.Equal(t, 3, callCount, "operation should be called 3 times")

	// Verify backoff delays were applied (100ms + 200ms = 300ms minimum)
	minExpectedDuration := 300 * time.Millisecond
	assert.GreaterOrEqual(t, elapsed, minExpectedDuration,
		"should wait at least %v between retries, got %v", minExpectedDuration, elapsed)
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func() error {
		callCount++
		return status.Error(codes.Unauthenticated, "invalid token")
	}

	err := withRetry(ctx, operation, "TestOp", "target-1")
	require.Error(t, err, "withRetry should fail")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Equal(t, 1, callCount, "operation should be called once (no retries)")
}

func TestWithRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func() error {
		callCount++
		return status.Error(codes.Unavailable, "service unavailable")
	}

	start := time.Now()
	err := withRetry(ctx, operation, "TestOp", "target-1")
	elapsed := time.Since(start)

	require.Error(t, err, "withRetry should fail after max retries")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, maxRetries+1, callCount,
		"operation should be called maxRetries+1 times (initial + 3 retries)")

	// Verify backoff delays were applied (100ms + 200ms + 400ms = 700ms minimum)
	minExpectedDuration := 700 * time.Millisecond
	assert.GreaterOrEqual(t, elapsed, minExpectedDuration,
		"should wait at least %v for all retries, got %v", minExpectedDuration, elapsed)
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	operation := func() error {
		callCount++
		if callCount == 1 {
			// Cancel context after first attempt
			cancel()
			return status.Error(codes.Unavailable, "service unavailable")
		}
		t.Fatal("operation should not be called after context cancellation")
		return nil
	}

	err := withRetry(ctx, operation, "TestOp", "target-1")
	require.Error(t, err, "withRetry should fail with context error")
	assert.Equal(t, context.Canceled, err, "should return context.Canceled")
	assert.Equal(t, 1, callCount, "operation should be called once before cancellation")
}

func TestWithRetry_ContextCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	callCount := 0

	operation := func() error {
		callCount++
		// Always fail with retryable error
		return status.Error(codes.Unavailable, "service unavailable")
	}

	start := time.Now()
	err := withRetry(ctx, operation, "TestOp", "target-1")
	elapsed := time.Since(start)

	require.Error(t, err, "withRetry should fail with context error")
	assert.Equal(t, context.DeadlineExceeded, err, "should return context.DeadlineExceeded")

	// Should have attempted at least once, possibly twice
	// (first attempt succeeds, second attempt may be interrupted during 200ms backoff)
	assert.GreaterOrEqual(t, callCount, 1, "should attempt at least once")
	assert.LessOrEqual(t, callCount, 2, "should not complete more than 2 attempts")

	// Should not exceed the context timeout significantly
	maxExpectedDuration := 200 * time.Millisecond // Some tolerance for scheduling
	assert.LessOrEqual(t, elapsed, maxExpectedDuration,
		"should not wait longer than context timeout + tolerance")
}

func TestWithRetry_AlternatingErrors(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func() error {
		callCount++
		if callCount%2 == 1 {
			// Odd attempts: retryable error
			return status.Error(codes.Unavailable, "service unavailable")
		}
		// Even attempts: non-retryable error
		return status.Error(codes.Unauthenticated, "invalid token")
	}

	err := withRetry(ctx, operation, "TestOp", "target-1")
	require.Error(t, err, "withRetry should fail")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Equal(t, 2, callCount,
		"operation should be called twice (first fails with retryable, second fails with non-retryable)")
}
