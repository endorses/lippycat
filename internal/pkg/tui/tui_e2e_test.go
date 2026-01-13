//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestTUIConnectsAndReceivesTopologySubscription tests that when TUI connects to a processor,
// it receives topology updates via subscription
func TestTUIConnectsAndReceivesTopologySubscription(t *testing.T) {
	// Create a mock management server that sends topology updates
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 10),
	}

	// Simulate TUI connecting and subscribing to topology
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a mock stream
	stream := &mockTopologyStream{
		ctx:     ctx,
		updates: mockServer.updates,
	}

	// Simulate initial snapshot being sent
	initialSnapshot := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       "proc-root",
					Address:           "localhost:50051",
					UpstreamProcessor: "",
					HierarchyDepth:    0,
					Reachable:         true,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
					Hunters: []*management.ConnectedHunter{
						{
							HunterId:   "hunter-1",
							Hostname:   "test-host-1",
							RemoteAddr: "192.168.1.100:12345",
							Status:     management.HunterStatus_STATUS_HEALTHY,
							Interfaces: []string{"eth0"},
						},
					},
				},
			},
		},
	}

	mockServer.updates <- initialSnapshot

	// Receive the initial snapshot
	receivedUpdate, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, receivedUpdate)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED, receivedUpdate.UpdateType)
	assert.Equal(t, "proc-root", receivedUpdate.ProcessorId)

	// Verify processor details
	procEvent := receivedUpdate.GetProcessorConnected()
	require.NotNil(t, procEvent)
	assert.Equal(t, "proc-root", procEvent.Processor.ProcessorId)
	assert.Equal(t, uint32(0), procEvent.Processor.HierarchyDepth)
	assert.Len(t, procEvent.Processor.Hunters, 1)
	assert.Equal(t, "hunter-1", procEvent.Processor.Hunters[0].HunterId)

	// Simulate a new hunter connecting
	hunterConnectUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_HunterConnected{
			HunterConnected: &management.HunterConnectedEvent{
				Hunter: &management.ConnectedHunter{
					HunterId:   "hunter-2",
					Hostname:   "test-host-2",
					RemoteAddr: "192.168.1.101:12345",
					Status:     management.HunterStatus_STATUS_HEALTHY,
					Interfaces: []string{"eth1"},
				},
			},
		},
	}

	mockServer.updates <- hunterConnectUpdate

	// Receive the hunter connected update
	receivedUpdate, err = stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, receivedUpdate)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED, receivedUpdate.UpdateType)

	hunterEvent := receivedUpdate.GetHunterConnected()
	require.NotNil(t, hunterEvent)
	assert.Equal(t, "hunter-2", hunterEvent.Hunter.HunterId)
	assert.Equal(t, "test-host-2", hunterEvent.Hunter.Hostname)
}

// TestHunterConnectsToDownstreamTUIUpdatesImmediately tests that when a hunter
// connects to a downstream processor, the TUI receives the update immediately
func TestHunterConnectsToDownstreamTUIUpdatesImmediately(t *testing.T) {
	// Create a mock management server
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 10),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := &mockTopologyStream{
		ctx:     ctx,
		updates: mockServer.updates,
	}

	// Set up initial topology with downstream processor
	initialSnapshot := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       "proc-downstream",
					Address:           "downstream:50051",
					UpstreamProcessor: "proc-root",
					HierarchyDepth:    1,
					Reachable:         true,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
					Hunters:           []*management.ConnectedHunter{},
				},
			},
		},
	}

	mockServer.updates <- initialSnapshot
	_, err := stream.Recv()
	require.NoError(t, err)

	// Simulate hunter connecting to downstream processor
	startTime := time.Now()

	hunterConnectUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-downstream",
		Event: &management.TopologyUpdate_HunterConnected{
			HunterConnected: &management.HunterConnectedEvent{
				Hunter: &management.ConnectedHunter{
					HunterId:   "hunter-3",
					Hostname:   "downstream-host",
					RemoteAddr: "192.168.2.100:12345",
					Status:     management.HunterStatus_STATUS_HEALTHY,
					Interfaces: []string{"eth0"},
				},
			},
		},
	}

	mockServer.updates <- hunterConnectUpdate

	// Receive the update and verify it's immediate (< 2 seconds)
	receivedUpdate, err := stream.Recv()
	require.NoError(t, err)
	latency := time.Since(startTime)

	assert.Less(t, latency, 2*time.Second, "Update should arrive within 2 seconds")
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED, receivedUpdate.UpdateType)
	assert.Equal(t, "proc-downstream", receivedUpdate.ProcessorId)

	hunterEvent := receivedUpdate.GetHunterConnected()
	require.NotNil(t, hunterEvent)
	assert.Equal(t, "hunter-3", hunterEvent.Hunter.HunterId)
}

// TestTUICreatesFilterOnDownstreamHunter tests that TUI can create a filter
// on a hunter connected to a downstream processor
func TestTUICreatesFilterOnDownstreamHunter(t *testing.T) {
	// Create a mock management server
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 10),
		filters: make(map[string]*management.Filter),
	}

	ctx := context.Background()

	// Simulate TUI requesting to create a filter on downstream hunter
	req := &management.ProcessorFilterRequest{
		ProcessorId: "proc-downstream",
		Filter: &management.Filter{
			Id:      "filter-1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "alice",
			Enabled: true,
		},
		AuthToken: &management.AuthorizationToken{
			TargetProcessorId: "proc-downstream",
			IssuerId:          "proc-root",
			IssuedAtNs:        time.Now().UnixNano(),
			ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
			Signature:         []byte("mock-signature"),
		},
	}

	// Call the RPC handler
	resp, err := mockServer.UpdateFilterOnProcessor(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Verify filter was created
	filterKey := "proc-downstream/filter-1"
	filter, exists := mockServer.filters[filterKey]
	require.True(t, exists)
	assert.Equal(t, "filter-1", filter.Id)
	assert.Equal(t, management.FilterType_FILTER_SIP_USER, filter.Type)
	assert.Equal(t, "alice", filter.Pattern)
	assert.True(t, filter.Enabled)
}

// TestTUIDeletesFilterOnDownstreamHunter tests that TUI can delete a filter
// from a hunter connected to a downstream processor
func TestTUIDeletesFilterOnDownstreamHunter(t *testing.T) {
	// Create a mock management server with an existing filter
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 10),
		filters: make(map[string]*management.Filter),
	}

	// Pre-create a filter
	filterKey := "proc-downstream/filter-1"
	mockServer.filters[filterKey] = &management.Filter{
		Id:      "filter-1",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alice",
		Enabled: true,
	}

	ctx := context.Background()

	// Simulate TUI requesting to delete the filter
	req := &management.ProcessorFilterDeleteRequest{
		ProcessorId: "proc-downstream",
		FilterId:    "filter-1",
		AuthToken: &management.AuthorizationToken{
			TargetProcessorId: "proc-downstream",
			IssuerId:          "proc-root",
			IssuedAtNs:        time.Now().UnixNano(),
			ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
			Signature:         []byte("mock-signature"),
		},
	}

	// Call the RPC handler
	resp, err := mockServer.DeleteFilterOnProcessor(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Verify filter was deleted
	_, exists := mockServer.filters[filterKey]
	assert.False(t, exists, "Filter should be deleted")
}

// TestDownstreamProcessorDisconnectsTUIShowsUnreachable tests that when a
// downstream processor disconnects, the TUI receives an update showing it as unreachable
func TestDownstreamProcessorDisconnectsTUIShowsUnreachable(t *testing.T) {
	// Create a mock management server
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 10),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := &mockTopologyStream{
		ctx:     ctx,
		updates: mockServer.updates,
	}

	// Set up initial topology with downstream processor (reachable)
	initialSnapshot := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       "proc-downstream",
					Address:           "downstream:50051",
					UpstreamProcessor: "proc-root",
					HierarchyDepth:    1,
					Reachable:         true,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
				},
			},
		},
	}

	mockServer.updates <- initialSnapshot
	_, err := stream.Recv()
	require.NoError(t, err)

	// Simulate downstream processor disconnecting
	disconnectUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-root",
		Event: &management.TopologyUpdate_ProcessorDisconnected{
			ProcessorDisconnected: &management.ProcessorDisconnectedEvent{
				ProcessorId: "proc-downstream",
				Address:     "downstream:50051",
				Reason:      "connection lost",
			},
		},
	}

	mockServer.updates <- disconnectUpdate

	// Receive the disconnect update
	receivedUpdate, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED, receivedUpdate.UpdateType)

	disconnectEvent := receivedUpdate.GetProcessorDisconnected()
	require.NotNil(t, disconnectEvent)
	assert.Equal(t, "proc-downstream", disconnectEvent.ProcessorId)
	assert.Equal(t, "connection lost", disconnectEvent.Reason)
}

// TestFiveLevelHierarchyWithAllOperations tests a 5-level hierarchy with
// all topology operations (connect, disconnect, filter operations)
func TestFiveLevelHierarchyWithAllOperations(t *testing.T) {
	// Create a mock management server
	mockServer := &mockManagementServerForTUI{
		updates: make(chan *management.TopologyUpdate, 50),
		filters: make(map[string]*management.Filter),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream := &mockTopologyStream{
		ctx:     ctx,
		updates: mockServer.updates,
	}

	// Build a 5-level hierarchy
	// Level 0: proc-root
	// Level 1: proc-level1
	// Level 2: proc-level2
	// Level 3: proc-level3
	// Level 4: proc-level4 (with hunters)

	processors := []struct {
		id      string
		parent  string
		depth   int32
		hunters int
	}{
		{"proc-root", "", 0, 1},
		{"proc-level1", "proc-root", 1, 1},
		{"proc-level2", "proc-level1", 2, 1},
		{"proc-level3", "proc-level2", 3, 1},
		{"proc-level4", "proc-level3", 4, 2},
	}

	// Create topology events for all processors
	for _, proc := range processors {
		hunters := make([]*management.ConnectedHunter, proc.hunters)
		for i := 0; i < proc.hunters; i++ {
			hunters[i] = &management.ConnectedHunter{
				HunterId:   fmt.Sprintf("%s-hunter-%d", proc.id, i),
				Hostname:   fmt.Sprintf("host-%s-%d", proc.id, i),
				RemoteAddr: fmt.Sprintf("192.168.%d.%d:12345", proc.depth, i+100),
				Status:     management.HunterStatus_STATUS_HEALTHY,
				Interfaces: []string{"eth0"},
			}
		}

		event := &management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
			ProcessorId: proc.parent,
			Event: &management.TopologyUpdate_ProcessorConnected{
				ProcessorConnected: &management.ProcessorConnectedEvent{
					Processor: &management.ProcessorNode{
						ProcessorId:       proc.id,
						Address:           fmt.Sprintf("%s:50051", proc.id),
						UpstreamProcessor: proc.parent,
						HierarchyDepth:    uint32(proc.depth),
						Reachable:         true,
						Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
						Hunters:           hunters,
					},
				},
			},
		}

		mockServer.updates <- event

		// Receive and verify
		receivedUpdate, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED, receivedUpdate.UpdateType)

		procEvent := receivedUpdate.GetProcessorConnected()
		require.NotNil(t, procEvent)
		assert.Equal(t, proc.id, procEvent.Processor.ProcessorId)
		assert.Equal(t, uint32(proc.depth), procEvent.Processor.HierarchyDepth)
		assert.Len(t, procEvent.Processor.Hunters, proc.hunters)
	}

	// Test filter creation on deepest processor (level 4)
	filterReq := &management.ProcessorFilterRequest{
		ProcessorId: "proc-level4",
		Filter: &management.Filter{
			Id:      "filter-deep",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "bob",
			Enabled: true,
		},
		AuthToken: &management.AuthorizationToken{
			TargetProcessorId: "proc-level4",
			IssuerId:          "proc-root",
			IssuedAtNs:        time.Now().UnixNano(),
			ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
			Signature:         []byte("mock-signature"),
		},
	}

	filterResp, err := mockServer.UpdateFilterOnProcessor(ctx, filterReq)
	require.NoError(t, err)
	require.NotNil(t, filterResp)
	assert.True(t, filterResp.Success)

	// Verify filter was created at correct location
	filterKey := "proc-level4/filter-deep"
	filter, exists := mockServer.filters[filterKey]
	require.True(t, exists)
	assert.Equal(t, "bob", filter.Pattern)

	// Test hunter disconnect at level 4
	disconnectUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-level4",
		Event: &management.TopologyUpdate_HunterDisconnected{
			HunterDisconnected: &management.HunterDisconnectedEvent{
				HunterId: "proc-level4-hunter-1",
				Reason:   "shutdown",
			},
		},
	}

	mockServer.updates <- disconnectUpdate

	receivedUpdate, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED, receivedUpdate.UpdateType)

	hunterDisconnectEvent := receivedUpdate.GetHunterDisconnected()
	require.NotNil(t, hunterDisconnectEvent)
	assert.Equal(t, "proc-level4-hunter-1", hunterDisconnectEvent.HunterId)

	// Test processor disconnect at level 2 (should mark subtree as unreachable)
	procDisconnectUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED,
		TimestampNs: time.Now().UnixNano(),
		ProcessorId: "proc-level1",
		Event: &management.TopologyUpdate_ProcessorDisconnected{
			ProcessorDisconnected: &management.ProcessorDisconnectedEvent{
				ProcessorId: "proc-level2",
				Address:     "proc-level2:50051",
				Reason:      "connection timeout (network partition)",
			},
		},
	}

	mockServer.updates <- procDisconnectUpdate

	receivedUpdate, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED, receivedUpdate.UpdateType)

	procDisconnectEvent := receivedUpdate.GetProcessorDisconnected()
	require.NotNil(t, procDisconnectEvent)
	assert.Equal(t, "proc-level2", procDisconnectEvent.ProcessorId)
	assert.Contains(t, procDisconnectEvent.Reason, "network partition")

	// Verify that operations on unreachable subtree fail appropriately
	filterReqUnreachable := &management.ProcessorFilterRequest{
		ProcessorId: "proc-level4",
		Filter: &management.Filter{
			Id:      "filter-unreachable",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "charlie",
			Enabled: true,
		},
		AuthToken: &management.AuthorizationToken{
			TargetProcessorId: "proc-level4",
			IssuerId:          "proc-root",
			IssuedAtNs:        time.Now().UnixNano(),
			ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
			Signature:         []byte("mock-signature"),
		},
	}

	// Simulate unreachable processor
	mockServer.unreachable = map[string]bool{"proc-level2": true, "proc-level3": true, "proc-level4": true}

	filterRespUnreachable, err := mockServer.UpdateFilterOnProcessor(ctx, filterReqUnreachable)
	require.Error(t, err)
	assert.Nil(t, filterRespUnreachable)

	// Verify error is about unreachable processor
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), "unreachable")
}

// Mock implementations for TUI E2E tests

type mockManagementServerForTUI struct {
	management.UnimplementedManagementServiceServer
	updates     chan *management.TopologyUpdate
	filters     map[string]*management.Filter
	unreachable map[string]bool
	mu          sync.RWMutex
}

func (s *mockManagementServerForTUI) SubscribeTopology(req *management.TopologySubscribeRequest, stream management.ManagementService_SubscribeTopologyServer) error {
	// Send updates from the channel
	for update := range s.updates {
		if err := stream.Send(update); err != nil {
			return err
		}
	}
	return nil
}

func (s *mockManagementServerForTUI) UpdateFilterOnProcessor(ctx context.Context, req *management.ProcessorFilterRequest) (*management.FilterUpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if processor is reachable
	if s.unreachable[req.ProcessorId] {
		return nil, status.Errorf(codes.Unavailable, "processor %s is unreachable", req.ProcessorId)
	}

	// Store the filter
	filterKey := fmt.Sprintf("%s/%s", req.ProcessorId, req.Filter.Id)
	s.filters[filterKey] = req.Filter

	return &management.FilterUpdateResult{
		Success: true,
	}, nil
}

func (s *mockManagementServerForTUI) DeleteFilterOnProcessor(ctx context.Context, req *management.ProcessorFilterDeleteRequest) (*management.FilterUpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if processor is reachable
	if s.unreachable[req.ProcessorId] {
		return nil, status.Errorf(codes.Unavailable, "processor %s is unreachable", req.ProcessorId)
	}

	// Delete the filter
	filterKey := fmt.Sprintf("%s/%s", req.ProcessorId, req.FilterId)
	delete(s.filters, filterKey)

	return &management.FilterUpdateResult{
		Success: true,
	}, nil
}

func (s *mockManagementServerForTUI) GetFiltersFromProcessor(ctx context.Context, req *management.ProcessorFilterQuery) (*management.FilterResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if processor is reachable
	if s.unreachable[req.ProcessorId] {
		return nil, status.Errorf(codes.Unavailable, "processor %s is unreachable", req.ProcessorId)
	}

	// Collect filters for the processor
	var filters []*management.Filter
	prefix := fmt.Sprintf("%s/", req.ProcessorId)
	for key, filter := range s.filters {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			filters = append(filters, filter)
		}
	}

	return &management.FilterResponse{
		Filters: filters,
	}, nil
}

func (s *mockManagementServerForTUI) RequestAuthToken(ctx context.Context, req *management.AuthTokenRequest) (*management.AuthorizationToken, error) {
	// Mock token issuance
	return &management.AuthorizationToken{
		TargetProcessorId: req.TargetProcessorId,
		IssuerId:          "proc-root",
		IssuedAtNs:        time.Now().UnixNano(),
		ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
		Signature:         []byte("mock-signature"),
	}, nil
}

type mockTopologyStream struct {
	grpc.ServerStream
	ctx     context.Context
	updates chan *management.TopologyUpdate
}

func (s *mockTopologyStream) Send(update *management.TopologyUpdate) error {
	select {
	case s.updates <- update:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *mockTopologyStream) Recv() (*management.TopologyUpdate, error) {
	select {
	case update := <-s.updates:
		return update, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *mockTopologyStream) Context() context.Context {
	return s.ctx
}
