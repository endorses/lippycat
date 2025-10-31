package downstream

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestManager_Shutdown_CancelsContext(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

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

func TestManager_Shutdown_WaitsForGoroutines(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

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
	mgr := NewManager(true, "", "", "", false, "")

	// Start a goroutine that ignores cancellation
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

func TestManager_Shutdown_ClosesConnections(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Manually add some mock downstream processors
	// Note: In real tests, you'd want to set up mock gRPC connections
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:   "processor-1",
		ListenAddress: "localhost:50051",
		// Note: Conn would normally be a real grpc.ClientConn
		// For this test, we're just verifying the map is cleared
	}
	mgr.downstreams["processor-2"] = &ProcessorInfo{
		ProcessorID:   "processor-2",
		ListenAddress: "localhost:50052",
	}
	mgr.mu.Unlock()

	// Shutdown should close all connections and clear map
	mgr.Shutdown(5 * time.Second)

	// Verify downstreams map is empty
	mgr.mu.RLock()
	assert.Empty(t, mgr.downstreams, "Downstreams map should be empty after shutdown")
	mgr.mu.RUnlock()
}

func TestManager_Shutdown_CancelsTopologySubscriptions(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Create mock processor with topology subscription
	ctx, cancel := context.WithCancel(mgr.ctx)
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:    "processor-1",
		ListenAddress:  "localhost:50051",
		TopologyCancel: cancel,
	}
	mgr.mu.Unlock()

	// Verify subscription context is active
	select {
	case <-ctx.Done():
		t.Error("Context should not be cancelled before shutdown")
	default:
		// Expected
	}

	// Shutdown should cancel topology subscriptions
	mgr.Shutdown(5 * time.Second)

	// Verify subscription context is cancelled
	select {
	case <-ctx.Done():
		// Expected: context should be cancelled
	default:
		t.Error("Topology subscription context should be cancelled after shutdown")
	}
}

func TestManager_Shutdown_Idempotent(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Call Shutdown multiple times
	mgr.Shutdown(5 * time.Second)
	mgr.Shutdown(5 * time.Second)
	mgr.Shutdown(5 * time.Second)

	// Should not panic or cause issues
	// If we get here without panic, test passes
}

func TestManager_Shutdown_ClearsDownstreamsMap(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Add some downstream processors without real connections
	// (we can't easily mock grpc.ClientConn since it's a concrete type)
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:   "processor-1",
		ListenAddress: "localhost:50051",
		Conn:          nil, // nil is acceptable for this test
	}
	mgr.downstreams["processor-2"] = &ProcessorInfo{
		ProcessorID:   "processor-2",
		ListenAddress: "localhost:50052",
		Conn:          nil,
	}
	mgr.mu.Unlock()

	// Shutdown
	mgr.Shutdown(5 * time.Second)

	// Verify map is cleared
	mgr.mu.RLock()
	assert.Empty(t, mgr.downstreams, "Downstreams map should be empty after shutdown")
	mgr.mu.RUnlock()
}
