package proxy

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTopologyCache(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()
	require.NotNil(t, cache)
	assert.NotNil(t, cache.hunters)
	assert.NotNil(t, cache.processors)
	assert.NotNil(t, cache.filters)
	assert.Empty(t, cache.hunters)
	assert.Empty(t, cache.processors)
	assert.Empty(t, cache.filters)
}

func TestTopologyCache_HunterConnected(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Create a hunter connected event
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterConnected{
			HunterConnected: &management.HunterConnectedEvent{
				Hunter: &management.ConnectedHunter{
					HunterId:   "hunter-1",
					Hostname:   "test-host",
					RemoteAddr: "192.168.1.100:12345",
					Status:     management.HunterStatus_STATUS_HEALTHY,
					Interfaces: []string{"eth0", "eth1"},
				},
			},
		},
	}

	// Apply the update
	cache.Apply(update)

	// Verify hunter was added
	hunter := cache.GetHunter("proc-1/hunter-1")
	require.NotNil(t, hunter)
	assert.Equal(t, "hunter-1", hunter.ID)
	assert.Equal(t, "proc-1", hunter.ProcessorID)
	assert.Equal(t, "192.168.1.100:12345", hunter.Address)
	assert.Equal(t, "STATUS_HEALTHY", hunter.Status)
	assert.Equal(t, "test-host", hunter.Metadata["hostname"])
	assert.Equal(t, "eth0", hunter.Metadata["interfaces"])
}

func TestTopologyCache_HunterDisconnected(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// First add a hunter
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Add a filter for this hunter
	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	// Verify hunter exists
	require.NotNil(t, cache.GetHunter("proc-1/hunter-1"))
	require.NotNil(t, cache.GetFilter("proc-1/hunter-1/filter-1"))

	// Create a hunter disconnected event
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterDisconnected{
			HunterDisconnected: &management.HunterDisconnectedEvent{
				HunterId: "hunter-1",
				Reason:   "connection closed",
			},
		},
	}

	// Apply the update
	cache.Apply(update)

	// Verify hunter was removed
	assert.Nil(t, cache.GetHunter("proc-1/hunter-1"))
	// Verify filter was also removed
	assert.Nil(t, cache.GetFilter("proc-1/hunter-1/filter-1"))
}

func TestTopologyCache_ProcessorConnected(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Create a processor connected event with hunters and filters
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       "proc-2",
					Address:           "192.168.1.200:50051",
					UpstreamProcessor: "proc-1",
					HierarchyDepth:    1,
					Reachable:         true,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
					Hunters: []*management.ConnectedHunter{
						{
							HunterId:   "hunter-2",
							Hostname:   "host-2",
							RemoteAddr: "192.168.1.101:12345",
							Status:     management.HunterStatus_STATUS_HEALTHY,
							Filters: []*management.Filter{
								{
									Id:      "filter-2",
									Type:    management.FilterType_FILTER_SIP_USER,
									Pattern: "bob",
									Enabled: true,
								},
							},
						},
					},
				},
			},
		},
	}

	// Apply the update
	cache.Apply(update)

	// Verify processor was added
	proc := cache.GetProcessor("proc-2")
	require.NotNil(t, proc)
	assert.Equal(t, "proc-2", proc.ID)
	assert.Equal(t, "192.168.1.200:50051", proc.Address)
	assert.Equal(t, "proc-1", proc.ParentID)
	assert.Equal(t, int32(1), proc.HierarchyDepth)
	assert.True(t, proc.Reachable)
	assert.Equal(t, "PROCESSOR_HEALTHY", proc.Metadata["status"])

	// Verify hunter was added
	hunter := cache.GetHunter("proc-2/hunter-2")
	require.NotNil(t, hunter)
	assert.Equal(t, "hunter-2", hunter.ID)
	assert.Equal(t, "proc-2", hunter.ProcessorID)
	assert.Equal(t, "host-2", hunter.Metadata["hostname"])

	// Verify filter was added
	filter := cache.GetFilter("proc-2/hunter-2/filter-2")
	require.NotNil(t, filter)
	assert.Equal(t, "filter-2", filter.ID)
	assert.Equal(t, "hunter-2", filter.HunterID)
	assert.Equal(t, "proc-2", filter.ProcessorID)
	assert.Equal(t, "FILTER_SIP_USER", filter.FilterType)
	assert.Equal(t, "bob", filter.Pattern)
	assert.True(t, filter.Active)
}

func TestTopologyCache_ProcessorDisconnected(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add a processor with hunters and filters
	cache.AddProcessor(&ProcessorNode{
		ID:             "proc-2",
		Address:        "192.168.1.200:50051",
		ParentID:       "proc-1",
		HierarchyDepth: 1,
		Reachable:      true,
		Metadata:       make(map[string]string),
	})

	cache.AddHunter(&HunterNode{
		ID:          "hunter-2",
		ProcessorID: "proc-2",
		Address:     "192.168.1.101:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-2",
		HunterID:    "hunter-2",
		ProcessorID: "proc-2",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "bob",
		Active:      true,
	})

	// Verify they exist
	require.NotNil(t, cache.GetProcessor("proc-2"))
	require.NotNil(t, cache.GetHunter("proc-2/hunter-2"))
	require.NotNil(t, cache.GetFilter("proc-2/hunter-2/filter-2"))

	// Create a processor disconnected event
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_ProcessorDisconnected{
			ProcessorDisconnected: &management.ProcessorDisconnectedEvent{
				ProcessorId: "proc-2",
				Address:     "192.168.1.200:50051",
				Reason:      "connection lost",
			},
		},
	}

	// Apply the update
	cache.Apply(update)

	// Verify processor, hunters, and filters were all removed
	assert.Nil(t, cache.GetProcessor("proc-2"))
	assert.Nil(t, cache.GetHunter("proc-2/hunter-2"))
	assert.Nil(t, cache.GetFilter("proc-2/hunter-2/filter-2"))
}

func TestTopologyCache_HunterStatusChanged(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add a hunter
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Verify initial status
	hunter := cache.GetHunter("proc-1/hunter-1")
	require.NotNil(t, hunter)
	assert.Equal(t, "STATUS_HEALTHY", hunter.Status)

	// Create a status changed event
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterStatusChanged{
			HunterStatusChanged: &management.HunterStatusChangedEvent{
				HunterId:  "hunter-1",
				OldStatus: management.HunterStatus_STATUS_HEALTHY,
				NewStatus: management.HunterStatus_STATUS_WARNING,
			},
		},
	}

	// Apply the update
	cache.Apply(update)

	// Verify status was updated
	hunter = cache.GetHunter("proc-1/hunter-1")
	require.NotNil(t, hunter)
	assert.Equal(t, "STATUS_WARNING", hunter.Status)
}

func TestTopologyCache_GetHuntersForProcessor(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add hunters for multiple processors
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddHunter(&HunterNode{
		ID:          "hunter-2",
		ProcessorID: "proc-1",
		Address:     "192.168.1.101:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddHunter(&HunterNode{
		ID:          "hunter-3",
		ProcessorID: "proc-2",
		Address:     "192.168.1.102:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Get hunters for proc-1
	hunters := cache.GetHuntersForProcessor("proc-1")
	assert.Len(t, hunters, 2)

	// Get hunters for proc-2
	hunters = cache.GetHuntersForProcessor("proc-2")
	assert.Len(t, hunters, 1)

	// Get hunters for non-existent processor
	hunters = cache.GetHuntersForProcessor("proc-999")
	assert.Empty(t, hunters)
}

func TestTopologyCache_GetFiltersForHunter(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add filters for multiple hunters
	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-2",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_CALL_ID",
		Pattern:     "abc123",
		Active:      true,
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-3",
		HunterID:    "hunter-2",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "bob",
		Active:      true,
	})

	// Get filters for hunter-1
	filters := cache.GetFiltersForHunter("proc-1", "hunter-1")
	assert.Len(t, filters, 2)

	// Get filters for hunter-2
	filters = cache.GetFiltersForHunter("proc-1", "hunter-2")
	assert.Len(t, filters, 1)

	// Get filters for non-existent hunter
	filters = cache.GetFiltersForHunter("proc-1", "hunter-999")
	assert.Empty(t, filters)
}

func TestTopologyCache_GetSnapshot(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add some data
	cache.AddProcessor(&ProcessorNode{
		ID:             "proc-1",
		Address:        "192.168.1.200:50051",
		ParentID:       "",
		HierarchyDepth: 0,
		Reachable:      true,
		Metadata:       make(map[string]string),
	})

	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	// Get snapshot
	snapshot := cache.GetSnapshot()
	require.NotNil(t, snapshot)
	assert.Len(t, snapshot.Processors, 1)
	assert.Len(t, snapshot.Hunters, 1)
	assert.Len(t, snapshot.Filters, 1)

	// Verify snapshot data
	assert.Equal(t, "proc-1", snapshot.Processors[0].ID)
	assert.Equal(t, "hunter-1", snapshot.Hunters[0].ID)
	assert.Equal(t, "filter-1", snapshot.Filters[0].ID)
}

func TestTopologyCache_MarkProcessorUnreachable(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add a processor
	cache.AddProcessor(&ProcessorNode{
		ID:             "proc-1",
		Address:        "192.168.1.200:50051",
		ParentID:       "",
		HierarchyDepth: 0,
		Reachable:      true,
		Metadata:       make(map[string]string),
	})

	// Verify initial state
	proc := cache.GetProcessor("proc-1")
	require.NotNil(t, proc)
	assert.True(t, proc.Reachable)
	assert.Empty(t, proc.UnreachableReason)

	// Mark as unreachable
	cache.MarkProcessorUnreachable("proc-1", "network partition")

	// Verify state changed
	proc = cache.GetProcessor("proc-1")
	require.NotNil(t, proc)
	assert.False(t, proc.Reachable)
	assert.Equal(t, "network partition", proc.UnreachableReason)
}

func TestTopologyCache_MarkProcessorReachable(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Add an unreachable processor
	cache.AddProcessor(&ProcessorNode{
		ID:                "proc-1",
		Address:           "192.168.1.200:50051",
		ParentID:          "",
		HierarchyDepth:    0,
		Reachable:         false,
		UnreachableReason: "network partition",
		Metadata:          make(map[string]string),
	})

	// Verify initial state
	proc := cache.GetProcessor("proc-1")
	require.NotNil(t, proc)
	assert.False(t, proc.Reachable)
	assert.Equal(t, "network partition", proc.UnreachableReason)

	// Mark as reachable
	cache.MarkProcessorReachable("proc-1")

	// Verify state changed
	proc = cache.GetProcessor("proc-1")
	require.NotNil(t, proc)
	assert.True(t, proc.Reachable)
	assert.Empty(t, proc.UnreachableReason)
}

func TestTopologyCache_ConcurrentAccess(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Test concurrent reads and writes
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.AddHunter(&HunterNode{
					ID:          "hunter-1",
					ProcessorID: "proc-1",
					Address:     "192.168.1.100:12345",
					Status:      "STATUS_HEALTHY",
					Metadata:    make(map[string]string),
				})
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_ = cache.GetHunter("proc-1/hunter-1")
				_ = cache.GetSnapshot()
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Verify cache is in valid state
	hunter := cache.GetHunter("proc-1/hunter-1")
	assert.NotNil(t, hunter)
}

func TestTopologyCache_NilUpdates(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Apply nil update - should not panic
	cache.Apply(nil)

	// Apply update with nil event - should not panic
	update := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: 1234567890,
		ProcessorId: "proc-1",
		Event:       nil,
	}
	cache.Apply(update)

	// Verify cache is still empty
	assert.Empty(t, cache.hunters)
}

func TestTopologyCache_RemoveNonExistent(t *testing.T) {
	cache := NewTopologyCache()
	defer cache.Close()

	// Remove non-existent hunter - should not panic
	cache.RemoveHunter("proc-1", "hunter-999")

	// Remove non-existent processor - should not panic
	cache.RemoveProcessor("proc-999")

	// Remove non-existent filter - should not panic
	cache.RemoveFilter("proc-1", "hunter-1", "filter-999")

	// Verify cache is still empty
	assert.Empty(t, cache.hunters)
	assert.Empty(t, cache.processors)
	assert.Empty(t, cache.filters)
}

// TestTopologyCache_TTLExpiration tests that entries expire after the TTL period
func TestTopologyCache_TTLExpiration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 100*time.Millisecond, 50*time.Millisecond)
	defer cache.Close()

	// Add a hunter
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Verify hunter exists immediately
	hunter := cache.GetHunter("proc-1/hunter-1")
	require.NotNil(t, hunter)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Hunter should now return nil (expired)
	hunter = cache.GetHunter("proc-1/hunter-1")
	assert.Nil(t, hunter, "Hunter should be nil after TTL expiration")

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Verify hunter was removed from internal map
	cache.mu.RLock()
	_, exists := cache.hunters["proc-1/hunter-1"]
	cache.mu.RUnlock()
	assert.False(t, exists, "Hunter should be removed from internal map after cleanup")
}

// TestTopologyCache_ProcessorTTLExpiration tests processor expiration
func TestTopologyCache_ProcessorTTLExpiration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 100*time.Millisecond, 50*time.Millisecond)
	defer cache.Close()

	// Add a processor with a hunter and filter
	cache.AddProcessor(&ProcessorNode{
		ID:             "proc-1",
		Address:        "192.168.1.200:50051",
		ParentID:       "",
		HierarchyDepth: 0,
		Reachable:      true,
		Metadata:       make(map[string]string),
	})

	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	// Verify all exist
	require.NotNil(t, cache.GetProcessor("proc-1"))
	require.NotNil(t, cache.GetHunter("proc-1/hunter-1"))
	require.NotNil(t, cache.GetFilter("proc-1/hunter-1/filter-1"))

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// All should return nil (expired)
	assert.Nil(t, cache.GetProcessor("proc-1"))
	assert.Nil(t, cache.GetHunter("proc-1/hunter-1"))
	assert.Nil(t, cache.GetFilter("proc-1/hunter-1/filter-1"))

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Verify all were removed from internal maps
	cache.mu.RLock()
	assert.Empty(t, cache.processors)
	assert.Empty(t, cache.hunters)
	assert.Empty(t, cache.filters)
	cache.mu.RUnlock()
}

// TestTopologyCache_FilterTTLExpiration tests filter expiration
func TestTopologyCache_FilterTTLExpiration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 100*time.Millisecond, 50*time.Millisecond)
	defer cache.Close()

	// Add a filter
	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	// Verify filter exists immediately
	filter := cache.GetFilter("proc-1/hunter-1/filter-1")
	require.NotNil(t, filter)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Filter should now return nil (expired)
	filter = cache.GetFilter("proc-1/hunter-1/filter-1")
	assert.Nil(t, filter, "Filter should be nil after TTL expiration")

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Verify filter was removed from internal map
	cache.mu.RLock()
	_, exists := cache.filters["proc-1/hunter-1/filter-1"]
	cache.mu.RUnlock()
	assert.False(t, exists, "Filter should be removed from internal map after cleanup")
}

// TestTopologyCache_CleanupRemovesExpiredHunterFilters tests that filters are removed when their hunter expires
func TestTopologyCache_CleanupRemovesExpiredHunterFilters(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 100*time.Millisecond, 50*time.Millisecond)
	defer cache.Close()

	// Add a hunter with a filter
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	cache.AddFilter(&FilterNode{
		ID:          "filter-1",
		HunterID:    "hunter-1",
		ProcessorID: "proc-1",
		FilterType:  "FILTER_SIP_USER",
		Pattern:     "alice",
		Active:      true,
	})

	// Verify both exist
	require.NotNil(t, cache.GetHunter("proc-1/hunter-1"))
	require.NotNil(t, cache.GetFilter("proc-1/hunter-1/filter-1"))

	// Wait for TTL to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Verify both hunter and filter were removed
	cache.mu.RLock()
	assert.Empty(t, cache.hunters)
	assert.Empty(t, cache.filters)
	cache.mu.RUnlock()
}

// TestTopologyCache_IsExpired tests the IsExpired helper method
func TestTopologyCache_IsExpired(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 5*time.Minute, 1*time.Minute)
	defer cache.Close()

	// Recent timestamp should not be expired
	recent := time.Now().Add(-1 * time.Minute)
	assert.False(t, cache.IsExpired(recent))

	// Old timestamp should be expired
	old := time.Now().Add(-10 * time.Minute)
	assert.True(t, cache.IsExpired(old))

	// Near but before TTL boundary (edge case - with 1 second buffer to avoid timing issues)
	boundary := time.Now().Add(-5*time.Minute + 1*time.Second)
	assert.False(t, cache.IsExpired(boundary))

	// Just past TTL boundary
	justPast := time.Now().Add(-5*time.Minute - 1*time.Millisecond)
	assert.True(t, cache.IsExpired(justPast))
}

// TestTopologyCache_CleanupLoop tests that the cleanup loop runs periodically
func TestTopologyCache_CleanupLoop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 50*time.Millisecond, 100*time.Millisecond)
	defer cache.Close()

	// Add a hunter
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Verify hunter exists
	require.NotNil(t, cache.GetHunter("proc-1/hunter-1"))

	// Wait for entry to expire and cleanup to run (TTL=50ms, cleanup=100ms)
	// We need to wait: TTL expiry (50ms) + cleanup interval (100ms) + buffer
	time.Sleep(200 * time.Millisecond)

	// Verify hunter was removed by cleanup loop
	cache.mu.RLock()
	_, exists := cache.hunters["proc-1/hunter-1"]
	cache.mu.RUnlock()
	assert.False(t, exists, "Cleanup loop should have removed expired hunter")
}

// TestTopologyCache_Close tests graceful shutdown
func TestTopologyCache_Close(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewTopologyCacheWithConfig(log, 5*time.Minute, 1*time.Minute)

	// Add some data
	cache.AddHunter(&HunterNode{
		ID:          "hunter-1",
		ProcessorID: "proc-1",
		Address:     "192.168.1.100:12345",
		Status:      "STATUS_HEALTHY",
		Metadata:    make(map[string]string),
	})

	// Close should not hang
	done := make(chan struct{})
	go func() {
		cache.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success - Close() completed
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}
}
