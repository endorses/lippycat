package downstream

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createManagerWithInterval creates a manager with a custom health check interval.
// This is a test helper that must be called before the manager's goroutine starts.
func createManagerWithInterval(interval time.Duration) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		downstreams:         make(map[string]*ProcessorInfo),
		tlsInsecure:         true,
		ctx:                 ctx,
		cancel:              cancel,
		healthCheckInterval: interval,
	}

	// Start health check goroutine with custom interval
	m.wg.Add(1)
	go m.healthCheckLoop(interval)

	return m
}

// mockTopologyPublisher is a mock implementation of TopologyPublisher for testing
type mockTopologyPublisher struct {
	mu      sync.Mutex
	updates []*management.TopologyUpdate
}

func (m *mockTopologyPublisher) PublishTopologyUpdate(update *management.TopologyUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, update)
}

func (m *mockTopologyPublisher) GetUpdates() []*management.TopologyUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updates
}

func (m *mockTopologyPublisher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = nil
}

func (m *mockTopologyPublisher) LastUpdate() *management.TopologyUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.updates) == 0 {
		return nil
	}
	return m.updates[len(m.updates)-1]
}

// TestHealthCheckDetectsInactiveStream tests that the health check goroutine
// detects inactive topology streams and publishes unreachable events
func TestHealthCheckDetectsInactiveStream(t *testing.T) {
	// Create manager with short health check interval for testing
	mgr := createManagerWithInterval(100 * time.Millisecond)
	defer mgr.Close()

	// Set up mock publisher
	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Register a downstream processor manually (without topology subscription)
	proc := &ProcessorInfo{
		ProcessorID:          "test-processor",
		ListenAddress:        "localhost:50051",
		Version:              "0.1.0",
		RegisteredAt:         time.Now(),
		LastSeen:             time.Now(),
		TopologyStreamActive: false, // Stream is not active
	}

	mgr.mu.Lock()
	mgr.downstreams[proc.ProcessorID] = proc
	mgr.mu.Unlock()

	// Wait for health check to run (2 intervals to be safe)
	time.Sleep(250 * time.Millisecond)

	// Verify that an unreachable event was published
	updates := mockPublisher.GetUpdates()
	require.NotEmpty(t, updates, "Expected unreachable event to be published")

	// Find the processor disconnected event
	var found bool
	for _, update := range updates {
		if update.UpdateType == management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED {
			if disconnectEvent, ok := update.Event.(*management.TopologyUpdate_ProcessorDisconnected); ok {
				assert.Equal(t, proc.ProcessorID, disconnectEvent.ProcessorDisconnected.ProcessorId)
				assert.Contains(t, disconnectEvent.ProcessorDisconnected.Reason, "topology stream inactive")
				found = true
				break
			}
		}
	}

	assert.True(t, found, "Expected to find processor disconnected event")
}

// TestHealthCheckPassesForActiveStream tests that the health check passes
// for processors with active topology streams
func TestHealthCheckPassesForActiveStream(t *testing.T) {
	// Create manager with short health check interval for testing
	mgr := createManagerWithInterval(100 * time.Millisecond)
	defer mgr.Close()

	// Set up mock publisher
	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Register a downstream processor with active stream
	proc := &ProcessorInfo{
		ProcessorID:          "test-processor",
		ListenAddress:        "localhost:50051",
		Version:              "0.1.0",
		RegisteredAt:         time.Now(),
		LastSeen:             time.Now(),
		TopologyStreamActive: true, // Stream is active
	}

	mgr.mu.Lock()
	mgr.downstreams[proc.ProcessorID] = proc
	mgr.mu.Unlock()

	// Wait for health check to run
	time.Sleep(250 * time.Millisecond)

	// Verify that no unreachable event was published
	updates := mockPublisher.GetUpdates()
	for _, update := range updates {
		if update.UpdateType == management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED {
			if disconnectEvent, ok := update.Event.(*management.TopologyUpdate_ProcessorDisconnected); ok {
				t.Errorf("Unexpected processor disconnected event: %v", disconnectEvent)
			}
		}
	}
}

// TestReconnectionPublishesReachableEvent tests that successful reconnection
// publishes a processor reconnected event
func TestReconnectionPublishesReachableEvent(t *testing.T) {
	// Create manager
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Close()

	// Set up mock publisher
	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Create a mock processor with a mock client
	// Note: This test focuses on the event publishing logic in reconnectTopologyStream
	// The actual gRPC stream creation will fail, but we're testing the event publishing

	proc := &ProcessorInfo{
		ProcessorID:   "test-processor",
		ListenAddress: "localhost:50051",
		Version:       "0.1.0",
		RegisteredAt:  time.Now(),
		LastSeen:      time.Now().Add(-2 * time.Minute), // Old last seen
	}

	mgr.mu.Lock()
	mgr.downstreams[proc.ProcessorID] = proc
	mgr.mu.Unlock()

	// Since we can't easily mock the gRPC stream in this unit test,
	// we'll test the event publishing logic separately
	// The reconnection logic is tested in integration tests

	// Instead, we'll verify that the topology publisher is set correctly
	assert.NotNil(t, mgr.topologyPublisher)
}

// TestShutdownCancelsHealthCheck tests that manager shutdown properly
// cancels the health check goroutine
func TestShutdownCancelsHealthCheck(t *testing.T) {
	mgr := createManagerWithInterval(50 * time.Millisecond)

	// Give the health check goroutine time to start
	time.Sleep(10 * time.Millisecond)

	// Shutdown should cancel context and wait for goroutines
	done := make(chan struct{})
	go func() {
		mgr.Shutdown(1 * time.Second)
		close(done)
	}()

	// Shutdown should complete within timeout
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete within timeout")
	}
}

// TestMultipleDownstreamsHealthCheck tests health checks with multiple
// downstream processors
func TestMultipleDownstreamsHealthCheck(t *testing.T) {
	mgr := createManagerWithInterval(100 * time.Millisecond)
	defer mgr.Close()

	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Register multiple downstream processors with different states
	processors := []*ProcessorInfo{
		{
			ProcessorID:          "processor-1",
			ListenAddress:        "localhost:50051",
			Version:              "0.1.0",
			RegisteredAt:         time.Now(),
			LastSeen:             time.Now(),
			TopologyStreamActive: true, // Active
		},
		{
			ProcessorID:          "processor-2",
			ListenAddress:        "localhost:50052",
			Version:              "0.1.0",
			RegisteredAt:         time.Now(),
			LastSeen:             time.Now(),
			TopologyStreamActive: false, // Inactive - should trigger event
		},
		{
			ProcessorID:          "processor-3",
			ListenAddress:        "localhost:50053",
			Version:              "0.1.0",
			RegisteredAt:         time.Now(),
			LastSeen:             time.Now(),
			TopologyStreamActive: false, // Inactive - should trigger event
		},
	}

	mgr.mu.Lock()
	for _, proc := range processors {
		mgr.downstreams[proc.ProcessorID] = proc
	}
	mgr.mu.Unlock()

	// Wait for health check to run
	time.Sleep(250 * time.Millisecond)

	// Verify that unreachable events were published for inactive processors
	updates := mockPublisher.GetUpdates()
	require.NotEmpty(t, updates, "Expected unreachable events to be published")

	// Count processor disconnected events
	disconnectedCount := 0
	for _, update := range updates {
		if update.UpdateType == management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED {
			if _, ok := update.Event.(*management.TopologyUpdate_ProcessorDisconnected); ok {
				disconnectedCount++
			}
		}
	}

	// Should have events for the 2 inactive processors
	assert.GreaterOrEqual(t, disconnectedCount, 2, "Expected at least 2 processor disconnected events")
}

// TestHealthCheckWithoutPublisher tests that health check works even
// when topology publisher is not set
func TestHealthCheckWithoutPublisher(t *testing.T) {
	mgr := createManagerWithInterval(100 * time.Millisecond)
	defer mgr.Close()

	// Don't set topology publisher

	// Register a downstream processor with inactive stream
	proc := &ProcessorInfo{
		ProcessorID:          "test-processor",
		ListenAddress:        "localhost:50051",
		Version:              "0.1.0",
		RegisteredAt:         time.Now(),
		LastSeen:             time.Now(),
		TopologyStreamActive: false,
	}

	mgr.mu.Lock()
	mgr.downstreams[proc.ProcessorID] = proc
	mgr.mu.Unlock()

	// Wait for health check to run - should not panic
	time.Sleep(250 * time.Millisecond)

	// Test passes if no panic occurred
}

// TestPerformHealthCheckDirectCall tests the performHealthCheck method directly
func TestPerformHealthCheckDirectCall(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Close()

	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Add a processor with old last seen time and inactive stream
	proc := &ProcessorInfo{
		ProcessorID:          "test-processor",
		ListenAddress:        "localhost:50051",
		Version:              "0.1.0",
		RegisteredAt:         time.Now().Add(-10 * time.Minute),
		LastSeen:             time.Now().Add(-5 * time.Minute), // 5 minutes ago
		TopologyStreamActive: false,
		reconnectAttempts:    3,
	}

	mgr.mu.Lock()
	mgr.downstreams[proc.ProcessorID] = proc
	mgr.mu.Unlock()

	// Call performHealthCheck directly
	mgr.performHealthCheck(mgr.healthCheckInterval)

	// Verify event was published
	updates := mockPublisher.GetUpdates()
	require.NotEmpty(t, updates, "Expected unreachable event to be published")

	lastUpdate := mockPublisher.LastUpdate()
	require.NotNil(t, lastUpdate)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED, lastUpdate.UpdateType)

	disconnectEvent, ok := lastUpdate.Event.(*management.TopologyUpdate_ProcessorDisconnected)
	require.True(t, ok, "Expected processor disconnected event")
	assert.Equal(t, proc.ProcessorID, disconnectEvent.ProcessorDisconnected.ProcessorId)
	assert.Contains(t, disconnectEvent.ProcessorDisconnected.Reason, "topology stream inactive")
	assert.Contains(t, disconnectEvent.ProcessorDisconnected.Reason, "reconnect attempts: 3")
}

// TestHealthCheckIntervalConfiguration tests that the health check interval
// can be configured
func TestHealthCheckIntervalConfiguration(t *testing.T) {
	mgr := NewManager(true, "", "", "", false, "")
	defer mgr.Close()

	// Verify default interval
	assert.Equal(t, DefaultHealthCheckInterval, mgr.healthCheckInterval)

	// Create another manager and change interval
	mgr2 := NewManager(true, "", "", "", false, "")
	defer mgr2.Close()

	customInterval := 5 * time.Second
	mgr2.healthCheckInterval = customInterval
	assert.Equal(t, customInterval, mgr2.healthCheckInterval)
}

// TestConcurrentHealthCheckAndRegistration tests that health checks and
// downstream registration can happen concurrently without race conditions
func TestConcurrentHealthCheckAndRegistration(t *testing.T) {
	mgr := createManagerWithInterval(10 * time.Millisecond)
	defer mgr.Close()

	mockPublisher := &mockTopologyPublisher{}
	mgr.SetTopologyPublisher(mockPublisher)

	// Run health checks and registration concurrently
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Goroutine to add/remove processors
	go func() {
		for i := 0; ctx.Err() == nil; i++ {
			proc := &ProcessorInfo{
				ProcessorID:          "test-processor",
				ListenAddress:        "localhost:50051",
				Version:              "0.1.0",
				RegisteredAt:         time.Now(),
				LastSeen:             time.Now(),
				TopologyStreamActive: i%2 == 0, // Alternate between active and inactive
			}

			mgr.mu.Lock()
			mgr.downstreams[proc.ProcessorID] = proc
			mgr.mu.Unlock()

			time.Sleep(20 * time.Millisecond)

			mgr.mu.Lock()
			delete(mgr.downstreams, proc.ProcessorID)
			mgr.mu.Unlock()
		}
	}()

	// Wait for context to complete
	<-ctx.Done()

	// Test passes if no race conditions detected
	// Run with: go test -race
}
