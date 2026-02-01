package downstream

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		ListenAddress: "localhost:55555",
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
		ListenAddress:  "localhost:55555",
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
		ListenAddress: "localhost:55555",
		conn:          nil, // nil is acceptable for this test
	}
	mgr.downstreams["processor-2"] = &ProcessorInfo{
		ProcessorID:   "processor-2",
		ListenAddress: "localhost:50052",
		conn:          nil,
	}
	mgr.mu.Unlock()

	// Shutdown
	mgr.Shutdown(5 * time.Second)

	// Verify map is cleared
	mgr.mu.RLock()
	assert.Empty(t, mgr.downstreams, "Downstreams map should be empty after shutdown")
	mgr.mu.RUnlock()
}

// Tests for Get/GetAll operations

func TestManager_GetAll_Empty(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	procs := mgr.GetAll()
	assert.Empty(t, procs, "GetAll should return empty slice when no processors registered")
}

func TestManager_GetAll_MultipleProcessors(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Manually add processors
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:   "processor-1",
		ListenAddress: "localhost:55555",
		Version:       "1.0.0",
	}
	mgr.downstreams["processor-2"] = &ProcessorInfo{
		ProcessorID:   "processor-2",
		ListenAddress: "localhost:50052",
		Version:       "1.0.1",
	}
	mgr.mu.Unlock()

	procs := mgr.GetAll()
	assert.Len(t, procs, 2, "GetAll should return all registered processors")

	// Verify both processors are present
	ids := make([]string, len(procs))
	for i, p := range procs {
		ids[i] = p.ProcessorID
	}
	assert.Contains(t, ids, "processor-1")
	assert.Contains(t, ids, "processor-2")
}

func TestManager_Get_Existing(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Add a processor
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:   "processor-1",
		ListenAddress: "localhost:55555",
		Version:       "1.0.0",
	}
	mgr.mu.Unlock()

	proc := mgr.Get("processor-1")
	require.NotNil(t, proc, "Get should return processor when it exists")
	assert.Equal(t, "processor-1", proc.ProcessorID)
	assert.Equal(t, "localhost:55555", proc.ListenAddress)
}

func TestManager_Get_NonExistent(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	proc := mgr.Get("nonexistent")
	assert.Nil(t, proc, "Get should return nil for nonexistent processor")
}

// Tests for Unregister operations

func TestManager_Unregister_Existing(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Add a processor with topology subscription
	ctx, cancel := context.WithCancel(mgr.ctx)
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:    "processor-1",
		ListenAddress:  "localhost:55555",
		TopologyCancel: cancel,
	}
	mgr.mu.Unlock()

	// Unregister
	mgr.Unregister("processor-1")

	// Verify processor was removed
	proc := mgr.Get("processor-1")
	assert.Nil(t, proc, "Processor should be removed after Unregister")

	// Verify topology subscription was cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Topology subscription should be cancelled on Unregister")
	}
}

func TestManager_Unregister_NonExistent(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Unregister nonexistent processor - should not panic
	assert.NotPanics(t, func() {
		mgr.Unregister("nonexistent")
	})
}

// Tests for TopologyPublisher
// Note: mockTopologyPublisher is defined in manager_partition_test.go

func TestManager_SetTopologyPublisher(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	publisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(publisher)

	assert.Equal(t, publisher, mgr.topologyPublisher)
}

// Tests for performHealthCheck

func TestManager_PerformHealthCheck_ActiveStream(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Add processor with active topology stream
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:          "processor-1",
		ListenAddress:        "localhost:55555",
		LastSeen:             time.Now(),
		TopologyStreamActive: true,
	}
	mgr.mu.Unlock()

	// Perform health check - should not publish any updates
	publisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(publisher)

	mgr.performHealthCheck(30 * time.Second)

	// No updates should be published for healthy processors
	updates := publisher.GetUpdates()
	assert.Empty(t, updates, "No updates should be published for healthy processors")
}

func TestManager_PerformHealthCheck_InactiveStream(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Add processor with inactive topology stream
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:          "processor-1",
		ListenAddress:        "localhost:55555",
		LastSeen:             time.Now().Add(-5 * time.Minute),
		TopologyStreamActive: false,
		reconnectAttempts:    3,
	}
	mgr.mu.Unlock()

	// Perform health check - should publish disconnected event
	publisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(publisher)

	mgr.performHealthCheck(30 * time.Second)

	// Disconnected update should be published
	updates := publisher.GetUpdates()
	require.Len(t, updates, 1, "Should publish one update for inactive processor")
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED, updates[0].UpdateType)
	assert.Equal(t, "processor-1", updates[0].ProcessorId)
}

func TestManager_PerformHealthCheck_NoPublisher(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	// Add processor with inactive topology stream
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:          "processor-1",
		ListenAddress:        "localhost:55555",
		TopologyStreamActive: false,
	}
	mgr.mu.Unlock()

	// Perform health check without publisher - should not panic
	assert.NotPanics(t, func() {
		mgr.performHealthCheck(30 * time.Second)
	})
}

// Tests for wrapChainError

func TestManager_WrapChainError_NewError(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	originalErr := errors.New("connection refused")
	processorPath := []string{"root-processor"}

	wrapped := mgr.wrapChainError(originalErr, processorPath, "current-processor", "downstream-1", "UpdateFilter")

	require.Error(t, wrapped)
	assert.Contains(t, wrapped.Error(), "downstream-1")
}

// Tests for Close

func TestManager_Close(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Add a processor
	ctx, cancel := context.WithCancel(mgr.ctx)
	mgr.mu.Lock()
	mgr.downstreams["processor-1"] = &ProcessorInfo{
		ProcessorID:    "processor-1",
		ListenAddress:  "localhost:55555",
		TopologyCancel: cancel,
	}
	mgr.mu.Unlock()

	// Close
	mgr.Close()

	// Verify context is cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled after Close")
	}

	// Verify downstreams map is empty
	mgr.mu.RLock()
	assert.Empty(t, mgr.downstreams, "Downstreams map should be empty after Close")
	mgr.mu.RUnlock()
}

func TestManager_Close_Idempotent(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Close multiple times - should not panic
	assert.NotPanics(t, func() {
		mgr.Close()
		mgr.Close()
		mgr.Close()
	})
}

// Tests for GetPoolStats

func TestManager_GetPoolStats(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	stats := mgr.GetPoolStats()

	// Stats should be valid (empty pool)
	assert.GreaterOrEqual(t, stats.TotalConnections, 0)
	assert.GreaterOrEqual(t, stats.ActiveConnections, 0)
}

// Tests for NewManager configuration

func TestNewManager_TLSConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		tlsInsecure   bool
		tlsCertFile   string
		tlsKeyFile    string
		tlsCAFile     string
		tlsSkipVerify bool
		tlsServerName string
	}{
		{
			name:        "insecure mode",
			tlsInsecure: true,
		},
		{
			name:          "TLS with skip verify",
			tlsInsecure:   false,
			tlsSkipVerify: true,
		},
		{
			name:          "TLS with server name override",
			tlsInsecure:   false,
			tlsServerName: "processor.example.com",
		},
		{
			name:        "TLS with certificates",
			tlsInsecure: false,
			tlsCertFile: "/path/to/cert.pem",
			tlsKeyFile:  "/path/to/key.pem",
			tlsCAFile:   "/path/to/ca.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(tt.tlsInsecure, tt.tlsCertFile, tt.tlsKeyFile, tt.tlsCAFile, tt.tlsSkipVerify, tt.tlsServerName)
			defer mgr.Shutdown(time.Second)

			assert.Equal(t, tt.tlsInsecure, mgr.tlsInsecure)
			assert.Equal(t, tt.tlsCertFile, mgr.tlsCertFile)
			assert.Equal(t, tt.tlsKeyFile, mgr.tlsKeyFile)
			assert.Equal(t, tt.tlsCAFile, mgr.tlsCAFile)
			assert.Equal(t, tt.tlsSkipVerify, mgr.tlsSkipVerify)
			assert.Equal(t, tt.tlsServerName, mgr.tlsServerName)
			assert.NotNil(t, mgr.ctx)
			assert.NotNil(t, mgr.connPool)
			assert.Equal(t, DefaultHealthCheckInterval, mgr.healthCheckInterval)
		})
	}
}

// Tests for healthCheckLoop

func TestManager_HealthCheckLoop_CancelledByContext(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")

	// Wait a bit for health check loop to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown should cancel the health check loop
	start := time.Now()
	mgr.Shutdown(time.Second)
	elapsed := time.Since(start)

	// Should complete quickly
	assert.Less(t, elapsed, 500*time.Millisecond, "Health check loop should stop quickly on shutdown")
}

// Concurrency tests

func TestManager_ConcurrentAccess(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Shutdown(time.Second)

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = mgr.GetAll()
				_ = mgr.Get("processor-1")
			}
		}()
	}

	// Concurrent writes (adding/removing)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			procID := "processor-" + time.Now().Format("20060102150405.000000") + "-" + string(rune('A'+id))
			mgr.mu.Lock()
			mgr.downstreams[procID] = &ProcessorInfo{
				ProcessorID:   procID,
				ListenAddress: "localhost:55555",
			}
			mgr.mu.Unlock()

			time.Sleep(10 * time.Millisecond)

			mgr.Unregister(procID)
		}(i)
	}

	wg.Wait()
}
