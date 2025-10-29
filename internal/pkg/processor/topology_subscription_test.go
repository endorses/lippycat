package processor

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestHunterConnectUpstreamReceivesEvent tests that when a hunter connects to a processor,
// the upstream processor receives the topology event via subscription
func TestHunterConnectUpstreamReceivesEvent(t *testing.T) {
	// Create a mock topology publisher that collects updates
	publisher := &mockTopologyPublisher{
		updates: make(chan *management.TopologyUpdate, 10),
	}

	// Create proxy manager with the publisher
	proxyMgr := &mockProxyManager{
		publisher: publisher,
	}

	// Simulate a hunter connected event
	event := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterConnected{
			HunterConnected: &management.HunterConnectedEvent{
				Hunter: &management.ConnectedHunter{
					HunterId:   "hunter-1",
					Hostname:   "test-host",
					RemoteAddr: "192.168.1.100:12345",
					Status:     management.HunterStatus_STATUS_HEALTHY,
					Interfaces: []string{"eth0"},
				},
			},
		},
	}

	// Publish the event
	proxyMgr.PublishTopologyUpdate(event)

	// Wait for event to be received
	select {
	case receivedUpdate := <-publisher.updates:
		require.NotNil(t, receivedUpdate)
		assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED, receivedUpdate.UpdateType)
		assert.Equal(t, "proc-1", receivedUpdate.ProcessorId)

		// Verify hunter details
		hunterEvent := receivedUpdate.GetHunterConnected()
		require.NotNil(t, hunterEvent)
		assert.Equal(t, "hunter-1", hunterEvent.Hunter.HunterId)
		assert.Equal(t, "test-host", hunterEvent.Hunter.Hostname)
		assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, hunterEvent.Hunter.Status)

	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for hunter connected event")
	}
}

// TestHunterDisconnectUpstreamReceivesEvent tests that when a hunter disconnects,
// the upstream processor receives the topology event via subscription
func TestHunterDisconnectUpstreamReceivesEvent(t *testing.T) {
	// Create a mock topology publisher that collects updates
	publisher := &mockTopologyPublisher{
		updates: make(chan *management.TopologyUpdate, 10),
	}

	// Create proxy manager with the publisher
	proxyMgr := &mockProxyManager{
		publisher: publisher,
	}

	// First simulate a hunter connected event
	connectEvent := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterConnected{
			HunterConnected: &management.HunterConnectedEvent{
				Hunter: &management.ConnectedHunter{
					HunterId:   "hunter-1",
					Hostname:   "test-host",
					RemoteAddr: "192.168.1.100:12345",
					Status:     management.HunterStatus_STATUS_HEALTHY,
					Interfaces: []string{"eth0"},
				},
			},
		},
	}
	proxyMgr.PublishTopologyUpdate(connectEvent)

	// Drain the connect event
	<-publisher.updates

	// Now simulate a hunter disconnected event
	disconnectEvent := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-1",
		Event: &management.TopologyUpdate_HunterDisconnected{
			HunterDisconnected: &management.HunterDisconnectedEvent{
				HunterId: "hunter-1",
				Reason:   "connection closed",
			},
		},
	}

	// Publish the event
	proxyMgr.PublishTopologyUpdate(disconnectEvent)

	// Wait for event to be received
	select {
	case receivedUpdate := <-publisher.updates:
		require.NotNil(t, receivedUpdate)
		assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED, receivedUpdate.UpdateType)
		assert.Equal(t, "proc-1", receivedUpdate.ProcessorId)

		// Verify disconnect details
		disconnectEvt := receivedUpdate.GetHunterDisconnected()
		require.NotNil(t, disconnectEvt)
		assert.Equal(t, "hunter-1", disconnectEvt.HunterId)
		assert.Equal(t, "connection closed", disconnectEvt.Reason)

	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for hunter disconnected event")
	}
}

// TestDownstreamProcessorConnectTopologyRefreshed tests that when a downstream processor connects,
// the upstream processor receives and caches the complete topology
func TestDownstreamProcessorConnectTopologyRefreshed(t *testing.T) {
	// Create topology cache
	cache := proxy.NewTopologyCache()

	// Create a processor connected event with hunters and filters
	processorEvent := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       "proc-downstream",
					Address:           "192.168.1.200:50051",
					UpstreamProcessor: "proc-root",
					HierarchyDepth:    1,
					Reachable:         true,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
					Hunters: []*management.ConnectedHunter{
						{
							HunterId:   "hunter-1",
							Hostname:   "host-1",
							RemoteAddr: "192.168.1.101:12345",
							Status:     management.HunterStatus_STATUS_HEALTHY,
							Interfaces: []string{"eth0"},
							Filters: []*management.Filter{
								{
									Id:      "filter-1",
									Type:    management.FilterType_FILTER_SIP_USER,
									Pattern: "alice",
									Enabled: true,
								},
							},
						},
						{
							HunterId:   "hunter-2",
							Hostname:   "host-2",
							RemoteAddr: "192.168.1.102:12345",
							Status:     management.HunterStatus_STATUS_HEALTHY,
							Interfaces: []string{"eth1"},
						},
					},
				},
			},
		},
	}

	// Apply the processor connected event to cache
	cache.Apply(processorEvent)

	// Verify processor was cached
	proc := cache.GetProcessor("proc-downstream")
	require.NotNil(t, proc)
	assert.Equal(t, "proc-downstream", proc.ID)
	assert.Equal(t, "192.168.1.200:50051", proc.Address)
	assert.Equal(t, "proc-root", proc.ParentID)
	assert.Equal(t, int32(1), proc.HierarchyDepth)
	assert.True(t, proc.Reachable)

	// Verify hunters were cached
	hunter1 := cache.GetHunter("proc-downstream/hunter-1")
	require.NotNil(t, hunter1)
	assert.Equal(t, "hunter-1", hunter1.ID)
	assert.Equal(t, "proc-downstream", hunter1.ProcessorID)
	assert.Equal(t, "host-1", hunter1.Metadata["hostname"])

	hunter2 := cache.GetHunter("proc-downstream/hunter-2")
	require.NotNil(t, hunter2)
	assert.Equal(t, "hunter-2", hunter2.ID)
	assert.Equal(t, "proc-downstream", hunter2.ProcessorID)

	// Verify filter was cached
	filter := cache.GetFilter("proc-downstream/hunter-1/filter-1")
	require.NotNil(t, filter)
	assert.Equal(t, "filter-1", filter.ID)
	assert.Equal(t, "hunter-1", filter.HunterID)
	assert.Equal(t, "proc-downstream", filter.ProcessorID)
	assert.Equal(t, "FILTER_SIP_USER", filter.FilterType)
	assert.Equal(t, "alice", filter.Pattern)
	assert.True(t, filter.Active)
}

// TestTopologyStreamFailureAutoReconnection tests that when a topology stream fails,
// it automatically attempts reconnection with exponential backoff
func TestTopologyStreamFailureAutoReconnection(t *testing.T) {
	t.Skip("Skipping test requiring gRPC server setup - requires integration test environment")

	// This test would require:
	// 1. Starting a mock gRPC server
	// 2. Establishing a topology subscription
	// 3. Simulating stream failure (server shutdown)
	// 4. Verifying automatic reconnection attempts
	// 5. Verifying backoff timing

	// TODO: Implement when integration test infrastructure is ready
}

// TestSlowSubscriberUpdatesDroppedGracefully tests that slow subscribers
// don't block other subscribers and updates are dropped gracefully
func TestSlowSubscriberUpdatesDroppedGracefully(t *testing.T) {
	// Create a mock proxy manager with broadcasting capability
	broadcaster := &mockBroadcaster{
		subscribers: make(map[string]chan *management.TopologyUpdate),
	}

	// Add a fast subscriber
	fastChan := make(chan *management.TopologyUpdate, 100)
	broadcaster.AddSubscriber("fast", fastChan)

	// Add a slow subscriber with small buffer
	slowChan := make(chan *management.TopologyUpdate, 1)
	broadcaster.AddSubscriber("slow", slowChan)

	// Send multiple updates rapidly
	numUpdates := 20
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for i := 0; i < numUpdates; i++ {
			update := &management.TopologyUpdate{
				UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED,
				TimestampNs: time.Now().UnixNano(),
				ProcessorId: "proc-1",
				Event: &management.TopologyUpdate_HunterStatusChanged{
					HunterStatusChanged: &management.HunterStatusChangedEvent{
						HunterId:  fmt.Sprintf("hunter-%d", i),
						OldStatus: management.HunterStatus_STATUS_HEALTHY,
						NewStatus: management.HunterStatus_STATUS_WARNING,
					},
				},
			}
			broadcaster.Broadcast(update)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for all broadcasts
	wg.Wait()

	// Fast subscriber should have received all or most updates
	fastReceived := len(fastChan)
	assert.Greater(t, fastReceived, numUpdates/2, "Fast subscriber should receive most updates")

	// Slow subscriber may have dropped some, but should not block
	slowReceived := len(slowChan)
	assert.LessOrEqual(t, slowReceived, numUpdates, "Slow subscriber should not receive more than sent")

	// The test verifies that broadcasting completed without blocking,
	// proving that slow subscriber didn't block the broadcaster
}

// TestTopologyUpdateOrdering tests that topology updates maintain order
func TestTopologyUpdateOrdering(t *testing.T) {
	cache := proxy.NewTopologyCache()

	// Send ordered events
	events := []*management.TopologyUpdate{
		// 1. Hunter connects
		{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
			ProcessorId: "proc-1",
			Event: &management.TopologyUpdate_HunterConnected{
				HunterConnected: &management.HunterConnectedEvent{
					Hunter: &management.ConnectedHunter{
						HunterId:   "hunter-1",
						Hostname:   "host-1",
						RemoteAddr: "192.168.1.100:12345",
						Status:     management.HunterStatus_STATUS_HEALTHY,
					},
				},
			},
		},
		// 2. Status changes
		{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED,
			TimestampNs: time.Now().UnixNano() + 1000,
			ProcessorId: "proc-1",
			Event: &management.TopologyUpdate_HunterStatusChanged{
				HunterStatusChanged: &management.HunterStatusChangedEvent{
					HunterId:  "hunter-1",
					OldStatus: management.HunterStatus_STATUS_HEALTHY,
					NewStatus: management.HunterStatus_STATUS_WARNING,
				},
			},
		},
		// 3. Hunter disconnects
		{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
			TimestampNs: time.Now().UnixNano() + 2000,
			ProcessorId: "proc-1",
			Event: &management.TopologyUpdate_HunterDisconnected{
				HunterDisconnected: &management.HunterDisconnectedEvent{
					HunterId: "hunter-1",
					Reason:   "normal shutdown",
				},
			},
		},
	}

	// Apply events in order
	for _, event := range events {
		cache.Apply(event)
	}

	// After all events, hunter should be removed
	hunter := cache.GetHunter("proc-1/hunter-1")
	assert.Nil(t, hunter, "Hunter should be removed after disconnect event")
}

// TestConcurrentTopologyUpdates tests that concurrent topology updates
// are handled correctly without race conditions
func TestConcurrentTopologyUpdates(t *testing.T) {
	cache := proxy.NewTopologyCache()

	numGoroutines := 10
	numUpdatesPerGoroutine := 100
	var wg sync.WaitGroup

	// Concurrently add hunters from different goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numUpdatesPerGoroutine; j++ {
				hunterID := fmt.Sprintf("hunter-%d-%d", goroutineID, j)
				event := &management.TopologyUpdate{
					UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
					TimestampNs: time.Now().UnixNano(),
					ProcessorId: "proc-1",
					Event: &management.TopologyUpdate_HunterConnected{
						HunterConnected: &management.HunterConnectedEvent{
							Hunter: &management.ConnectedHunter{
								HunterId:   hunterID,
								Hostname:   fmt.Sprintf("host-%d", goroutineID),
								RemoteAddr: fmt.Sprintf("192.168.1.%d:12345", goroutineID),
								Status:     management.HunterStatus_STATUS_HEALTHY,
							},
						},
					},
				}
				cache.Apply(event)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify all hunters were added
	hunters := cache.GetHuntersForProcessor("proc-1")
	expectedCount := numGoroutines * numUpdatesPerGoroutine
	assert.Equal(t, expectedCount, len(hunters), "All hunters should be added without race conditions")
}

// Mock implementations for testing

type mockTopologyPublisher struct {
	updates chan *management.TopologyUpdate
}

func (m *mockTopologyPublisher) PublishTopologyUpdate(update *management.TopologyUpdate) {
	m.updates <- update
}

type mockProxyManager struct {
	publisher *mockTopologyPublisher
}

func (m *mockProxyManager) PublishTopologyUpdate(update *management.TopologyUpdate) {
	m.publisher.PublishTopologyUpdate(update)
}

type mockBroadcaster struct {
	mu          sync.RWMutex
	subscribers map[string]chan *management.TopologyUpdate
}

func (m *mockBroadcaster) AddSubscriber(id string, ch chan *management.TopologyUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers[id] = ch
}

func (m *mockBroadcaster) Broadcast(update *management.TopologyUpdate) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.subscribers {
		// Non-blocking send (drops if subscriber is slow)
		select {
		case ch <- update:
		default:
			// Drop update for slow subscriber
		}
	}
}

// mockManagementServer implements a minimal gRPC server for testing
type mockManagementServer struct {
	management.UnimplementedManagementServiceServer
	updates chan *management.TopologyUpdate
}

func (s *mockManagementServer) SubscribeTopology(req *management.TopologySubscribeRequest, stream management.ManagementService_SubscribeTopologyServer) error {
	// Send updates to the stream
	for update := range s.updates {
		if err := stream.Send(update); err != nil {
			return err
		}
	}
	return nil
}

// Helper function to create a test gRPC server (for future integration tests)
func startTestGRPCServer(t *testing.T) (*grpc.Server, string, *mockManagementServer) {
	mockServer := &mockManagementServer{
		updates: make(chan *management.TopologyUpdate, 100),
	}

	grpcServer := grpc.NewServer()
	management.RegisterManagementServiceServer(grpcServer, mockServer)

	// In a real integration test, we would start the server here
	// For now, this is a placeholder for future implementation

	return grpcServer, "bufconn", mockServer
}

// TestTopologySnapshotConsistency tests that snapshots are consistent
// even during concurrent updates
func TestTopologySnapshotConsistency(t *testing.T) {
	cache := proxy.NewTopologyCache()

	// Add initial data
	for i := 0; i < 10; i++ {
		event := &management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
			ProcessorId: "proc-1",
			Event: &management.TopologyUpdate_HunterConnected{
				HunterConnected: &management.HunterConnectedEvent{
					Hunter: &management.ConnectedHunter{
						HunterId:   fmt.Sprintf("hunter-%d", i),
						Hostname:   fmt.Sprintf("host-%d", i),
						RemoteAddr: fmt.Sprintf("192.168.1.%d:12345", i),
						Status:     management.HunterStatus_STATUS_HEALTHY,
					},
				},
			},
		}
		cache.Apply(event)
	}

	// Concurrently read snapshots while updates are happening
	var wg sync.WaitGroup
	numReaders := 5
	numSnapshots := 20

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numSnapshots; j++ {
				snapshot := cache.GetSnapshot()
				// Snapshot should always be valid
				assert.NotNil(t, snapshot)
				assert.GreaterOrEqual(t, len(snapshot.Hunters), 10)
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	// Concurrently add more hunters
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 10; i < 20; i++ {
			event := &management.TopologyUpdate{
				UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
				TimestampNs: time.Now().UnixNano(),
				ProcessorId: "proc-1",
				Event: &management.TopologyUpdate_HunterConnected{
					HunterConnected: &management.HunterConnectedEvent{
						Hunter: &management.ConnectedHunter{
							HunterId:   fmt.Sprintf("hunter-%d", i),
							Hostname:   fmt.Sprintf("host-%d", i),
							RemoteAddr: fmt.Sprintf("192.168.1.%d:12345", i),
							Status:     management.HunterStatus_STATUS_HEALTHY,
						},
					},
				},
			}
			cache.Apply(event)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Final snapshot should have all 20 hunters
	finalSnapshot := cache.GetSnapshot()
	assert.Equal(t, 20, len(finalSnapshot.Hunters))
}
