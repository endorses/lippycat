package proxy

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestManager_Shutdown_CancelsContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Shutdown with reasonable timeout
	mgr.Shutdown(5 * time.Second)

	// Verify context is cancelled
	select {
	case <-mgr.ctx.Done():
		// Expected: context should be cancelled
	default:
		t.Error("Manager context should be cancelled after Shutdown")
	}
}

func TestManager_Shutdown_DrainSubscriberChannels(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Register some subscribers
	ch1 := mgr.RegisterSubscriber("subscriber-1")
	ch2 := mgr.RegisterSubscriber("subscriber-2")

	// Send some updates that will be pending in channels
	for i := 0; i < 10; i++ {
		update := &management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
		}
		select {
		case ch1 <- update:
		default:
		}
		select {
		case ch2 <- update:
		default:
		}
	}

	// Shutdown should drain and close channels
	mgr.Shutdown(5 * time.Second)

	// Verify channels are closed
	_, ok1 := <-ch1
	assert.False(t, ok1, "Subscriber channel 1 should be closed")

	_, ok2 := <-ch2
	assert.False(t, ok2, "Subscriber channel 2 should be closed")

	// Verify subscribers map is empty
	mgr.subscribersMu.RLock()
	assert.Empty(t, mgr.subscribers, "Subscribers map should be empty after shutdown")
	mgr.subscribersMu.RUnlock()
}

func TestManager_Shutdown_WaitsForGoroutines(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Start some goroutines that track via wg
	var completedCount int
	var mu sync.Mutex

	for i := 0; i < 5; i++ {
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			// Simulate work
			select {
			case <-mgr.ctx.Done():
				mu.Lock()
				completedCount++
				mu.Unlock()
			case <-time.After(10 * time.Second):
				// Should not reach here
				t.Error("Goroutine did not receive cancellation signal")
			}
		}()
	}

	// Shutdown should wait for all goroutines
	start := time.Now()
	mgr.Shutdown(5 * time.Second)
	duration := time.Since(start)

	// Should complete quickly (much less than timeout) since goroutines finish immediately on cancel
	assert.Less(t, duration, 1*time.Second, "Shutdown should complete quickly when goroutines finish")

	// Verify all goroutines completed
	mu.Lock()
	assert.Equal(t, 5, completedCount, "All goroutines should have completed")
	mu.Unlock()
}

func TestManager_Shutdown_TimeoutOnSlowGoroutines(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Start a goroutine that ignores cancellation (bad behavior, but we need to handle it)
	mgr.wg.Add(1)
	go func() {
		defer mgr.wg.Done()
		// Ignore cancellation and sleep for a long time
		time.Sleep(10 * time.Second)
	}()

	// Shutdown with short timeout
	start := time.Now()
	mgr.Shutdown(500 * time.Millisecond)
	duration := time.Since(start)

	// Should timeout at approximately the timeout duration
	// Allow some margin for scheduling
	assert.GreaterOrEqual(t, duration, 500*time.Millisecond, "Should wait at least timeout duration")
	assert.Less(t, duration, 2*time.Second, "Should not wait much longer than timeout")
}

func TestManager_Shutdown_StopsBatcher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Batcher should be started in NewManager
	assert.NotNil(t, mgr.batcher, "Batcher should be initialized")
	assert.True(t, mgr.batcher.started, "Batcher should be started")

	// Shutdown should stop batcher
	mgr.Shutdown(5 * time.Second)

	// Verify batcher is stopped
	assert.False(t, mgr.batcher.started, "Batcher should be stopped after shutdown")
}

func TestManager_Shutdown_FlushPendingUpdates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Track flushed updates
	var flushedUpdates []*management.TopologyUpdate
	var mu sync.Mutex

	// Replace batcher's flush function to track flushes
	mgr.batcher.flushFunc = func(updates []*management.TopologyUpdate) {
		mu.Lock()
		flushedUpdates = append(flushedUpdates, updates...)
		mu.Unlock()
	}

	// Add some updates to batcher (but not enough to trigger immediate flush)
	for i := 0; i < 5; i++ {
		mgr.batcher.Add(&management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
		})
	}

	// Shutdown should flush pending updates
	mgr.Shutdown(5 * time.Second)

	// Wait a bit for flush goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// Verify updates were flushed
	mu.Lock()
	assert.Len(t, flushedUpdates, 5, "Should have flushed all pending updates")
	mu.Unlock()
}

func TestManager_Shutdown_Idempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Call Shutdown multiple times
	mgr.Shutdown(5 * time.Second)
	mgr.Shutdown(5 * time.Second)
	mgr.Shutdown(5 * time.Second)

	// Should not panic or cause issues
	// If we get here without panic, test passes
}

func TestManager_Shutdown_SubscriberCannotSendAfter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "test-processor")

	// Register subscriber
	ch := mgr.RegisterSubscriber("test-subscriber")

	// Shutdown
	mgr.Shutdown(5 * time.Second)

	// Channel should be closed, so receive would return false ok
	_, ok := <-ch
	assert.False(t, ok, "Channel should be closed after shutdown")
}
