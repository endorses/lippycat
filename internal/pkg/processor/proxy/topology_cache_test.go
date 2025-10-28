package proxy

import (
	"sync"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTopologyCache(t *testing.T) {
	cache := NewTopologyCache()
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
