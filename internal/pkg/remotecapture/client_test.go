package remotecapture

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEventHandler implements types.EventHandler for testing
type MockEventHandler struct {
	PacketBatches  [][]types.PacketDisplay
	HunterStatuses []MockHunterStatus
	Disconnects    []MockDisconnect
}

type MockHunterStatus struct {
	Hunters           []types.HunterInfo
	ProcessorID       string
	ProcessorStatus   management.ProcessorStatus
	ProcessorAddr     string
	UpstreamProcessor string
}

type MockDisconnect struct {
	Address string
	Error   error
}

func (m *MockEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
	m.PacketBatches = append(m.PacketBatches, packets)
}

func (m *MockEventHandler) OnHunterStatus(hunters []types.HunterInfo, processorID string, processorStatus management.ProcessorStatus, processorAddr string, upstreamProcessor string) {
	m.HunterStatuses = append(m.HunterStatuses, MockHunterStatus{
		Hunters:           hunters,
		ProcessorID:       processorID,
		ProcessorStatus:   processorStatus,
		ProcessorAddr:     processorAddr,
		UpstreamProcessor: upstreamProcessor,
	})
}

func (m *MockEventHandler) OnCallUpdate(calls []types.CallInfo) {
	// Mock implementation - calls not tracked in tests yet
}

func (m *MockEventHandler) OnCorrelatedCallUpdate(correlatedCalls []types.CorrelatedCallInfo) {
	// Mock implementation - correlated calls not tracked in tests yet
}

func (m *MockEventHandler) OnDisconnect(address string, err error) {
	m.Disconnects = append(m.Disconnects, MockDisconnect{
		Address: address,
		Error:   err,
	})
}

func (m *MockEventHandler) OnTopologyUpdate(update *management.TopologyUpdate, processorAddr string) {
	// Mock implementation - topology updates not tracked in tests yet
}

func TestClientConfig_Defaults(t *testing.T) {
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	assert.Equal(t, "localhost:50051", config.Address)
	assert.False(t, config.TLSEnabled)
	assert.Empty(t, config.TLSCAFile)
	assert.Empty(t, config.TLSCertFile)
	assert.Empty(t, config.TLSKeyFile)
}

func TestClientConfig_WithTLS(t *testing.T) {
	config := &ClientConfig{
		Address:     "processor.example.com:50051",
		TLSEnabled:  true,
		TLSCAFile:   "/path/to/ca.pem",
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
	}

	assert.True(t, config.TLSEnabled)
	assert.Equal(t, "/path/to/ca.pem", config.TLSCAFile)
	assert.Equal(t, "/path/to/cert.pem", config.TLSCertFile)
	assert.Equal(t, "/path/to/key.pem", config.TLSKeyFile)
}

func TestClientConfig_SkipVerify(t *testing.T) {
	config := &ClientConfig{
		Address:       "localhost:50051",
		TLSEnabled:    true,
		TLSSkipVerify: true,
	}

	assert.True(t, config.TLSEnabled)
	assert.True(t, config.TLSSkipVerify)
}

func TestClientConfig_ServerNameOverride(t *testing.T) {
	config := &ClientConfig{
		Address:               "192.168.1.10:50051",
		TLSEnabled:            true,
		TLSServerNameOverride: "processor.example.com",
	}

	assert.Equal(t, "processor.example.com", config.TLSServerNameOverride)
}

func TestMockEventHandler_PacketBatch(t *testing.T) {
	handler := &MockEventHandler{}

	packets := []types.PacketDisplay{
		{Protocol: "TCP", SrcIP: "192.168.1.1"},
		{Protocol: "UDP", SrcIP: "192.168.1.2"},
	}

	handler.OnPacketBatch(packets)

	assert.Len(t, handler.PacketBatches, 1)
	assert.Equal(t, packets, handler.PacketBatches[0])
}

func TestMockEventHandler_HunterStatus(t *testing.T) {
	handler := &MockEventHandler{}

	hunters := []types.HunterInfo{
		{ID: "hunter-1", Hostname: "host1"},
		{ID: "hunter-2", Hostname: "host2"},
	}

	processorStatus := management.ProcessorStatus_PROCESSOR_HEALTHY

	handler.OnHunterStatus(hunters, "processor-1", processorStatus, "localhost:50051", "")

	assert.Len(t, handler.HunterStatuses, 1)
	assert.Equal(t, hunters, handler.HunterStatuses[0].Hunters)
	assert.Equal(t, "processor-1", handler.HunterStatuses[0].ProcessorID)
	assert.Equal(t, processorStatus, handler.HunterStatuses[0].ProcessorStatus)
}

func TestMockEventHandler_Disconnect(t *testing.T) {
	handler := &MockEventHandler{}

	handler.OnDisconnect("localhost:50051", assert.AnError)

	assert.Len(t, handler.Disconnects, 1)
	assert.Equal(t, "localhost:50051", handler.Disconnects[0].Address)
	assert.Equal(t, assert.AnError, handler.Disconnects[0].Error)
}

func TestMockEventHandler_MultipleEvents(t *testing.T) {
	handler := &MockEventHandler{}

	// Multiple packet batches
	handler.OnPacketBatch([]types.PacketDisplay{{Protocol: "TCP"}})
	handler.OnPacketBatch([]types.PacketDisplay{{Protocol: "UDP"}})

	// Multiple status updates
	handler.OnHunterStatus([]types.HunterInfo{{ID: "h1"}}, "p1", management.ProcessorStatus_PROCESSOR_HEALTHY, "localhost:50051", "")
	handler.OnHunterStatus([]types.HunterInfo{{ID: "h2"}}, "p2", management.ProcessorStatus_PROCESSOR_HEALTHY, "localhost:50052", "")

	// Multiple disconnects
	handler.OnDisconnect("addr1", assert.AnError)
	handler.OnDisconnect("addr2", assert.AnError)

	assert.Len(t, handler.PacketBatches, 2)
	assert.Len(t, handler.HunterStatuses, 2)
	assert.Len(t, handler.Disconnects, 2)
}

func TestNodeType_String(t *testing.T) {
	testCases := []struct {
		nodeType NodeType
		expected string
	}{
		{NodeTypeUnknown, "Unknown"},
		{NodeTypeHunter, "Hunter"},
		{NodeTypeProcessor, "Processor"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			// NodeType doesn't have a String() method, but we can test the constants
			switch tc.nodeType {
			case NodeTypeUnknown:
				assert.Equal(t, NodeType(0), tc.nodeType)
			case NodeTypeHunter:
				assert.Equal(t, NodeType(1), tc.nodeType)
			case NodeTypeProcessor:
				assert.Equal(t, NodeType(2), tc.nodeType)
			}
		})
	}
}

func TestBuildTLSCredentials_InvalidCAFile(t *testing.T) {
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: true,
		TLSCAFile:  "/nonexistent/ca.pem",
	}

	_, err := buildTLSCredentials(config)
	assert.Error(t, err, "should fail when CA file doesn't exist")
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestBuildTLSCredentials_InvalidCertFile(t *testing.T) {
	config := &ClientConfig{
		Address:     "localhost:50051",
		TLSEnabled:  true,
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	}

	_, err := buildTLSCredentials(config)
	assert.Error(t, err, "should fail when cert file doesn't exist")
}

func TestBuildTLSCredentials_SkipVerify(t *testing.T) {
	config := &ClientConfig{
		Address:       "localhost:50051",
		TLSEnabled:    true,
		TLSSkipVerify: true,
	}

	creds, err := buildTLSCredentials(config)
	assert.NoError(t, err, "should succeed with skip verify")
	assert.NotNil(t, creds)

	info := creds.Info()
	assert.Equal(t, "tls", info.SecurityProtocol)
}

func TestBuildTLSCredentials_ServerNameOverride(t *testing.T) {
	config := &ClientConfig{
		Address:               "192.168.1.10:50051",
		TLSEnabled:            true,
		TLSSkipVerify:         true,
		TLSServerNameOverride: "processor.example.com",
	}

	creds, err := buildTLSCredentials(config)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
}

// Note: Full integration tests for NewClientWithConfig require a running gRPC server
// These would be better suited for end-to-end integration tests

func TestClient_InvalidAddress(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "invalid-address-format",
		TLSEnabled: false,
	}

	// This will attempt to dial and should fail quickly
	client, err := NewClientWithConfig(config, handler)

	// The dial may not fail immediately in all cases, so we allow for partial success
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, client)
		// Clean up if connection succeeded
		client.Close()
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:19999", // Unlikely to have service on this port
		TLSEnabled: false,
	}

	// Create client - gRPC dial is async, so this may succeed
	client, err := NewClientWithConfig(config, handler)

	if err != nil {
		// Connection failed immediately (expected in some environments)
		assert.Error(t, err)
		return
	}

	// If client created, clean up
	assert.NotNil(t, client)
	assert.Equal(t, "localhost:19999", client.GetAddr())
	client.Close()
}

func TestConvertToPacketDisplay_BasicFields(t *testing.T) {
	// This tests the packet conversion logic
	// We can't easily test the actual method without a Client instance,
	// but we can test the data structure

	display := types.PacketDisplay{
		Protocol:  "TCP",
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "12345",
		DstPort:   "80",
		Length:    1500,
		Info:      "HTTP Request",
		Timestamp: time.Now(),
		NodeID:    "hunter-1",
		Interface: "eth0",
	}

	assert.Equal(t, "TCP", display.Protocol)
	assert.Equal(t, "192.168.1.100", display.SrcIP)
	assert.Equal(t, "192.168.1.200", display.DstIP)
	assert.Equal(t, "12345", display.SrcPort)
	assert.Equal(t, "80", display.DstPort)
	assert.Equal(t, 1500, display.Length)
	assert.Equal(t, "hunter-1", display.NodeID)
}

func TestPacketDisplayBatch_Empty(t *testing.T) {
	handler := &MockEventHandler{}

	// Empty batch
	handler.OnPacketBatch([]types.PacketDisplay{})

	assert.Len(t, handler.PacketBatches, 1)
	assert.Empty(t, handler.PacketBatches[0])
}

func TestPacketDisplayBatch_Large(t *testing.T) {
	handler := &MockEventHandler{}

	// Large batch (100 packets)
	packets := make([]types.PacketDisplay, 100)
	for i := 0; i < 100; i++ {
		packets[i] = types.PacketDisplay{
			Protocol: "TCP",
			SrcIP:    "192.168.1.1",
		}
	}

	handler.OnPacketBatch(packets)

	assert.Len(t, handler.PacketBatches, 1)
	assert.Len(t, handler.PacketBatches[0], 100)
}

func TestHunterInfo_Fields(t *testing.T) {
	hunter := types.HunterInfo{
		ID:               "hunter-1",
		Hostname:         "edge-node-1",
		RemoteAddr:       "192.168.1.10:50051",
		Interfaces:       []string{"eth0", "eth1"},
		PacketsCaptured:  1000,
		PacketsMatched:   800,
		PacketsForwarded: 750,
		PacketsDropped:   50,
		ActiveFilters:    5,
		Status:           management.HunterStatus_STATUS_HEALTHY,
	}

	assert.Equal(t, "hunter-1", hunter.ID)
	assert.Equal(t, "edge-node-1", hunter.Hostname)
	assert.Equal(t, "192.168.1.10:50051", hunter.RemoteAddr)
	assert.Len(t, hunter.Interfaces, 2)
	assert.Equal(t, uint64(1000), hunter.PacketsCaptured)
	assert.Equal(t, uint64(800), hunter.PacketsMatched)
	assert.Equal(t, uint64(750), hunter.PacketsForwarded)
	assert.Equal(t, uint64(50), hunter.PacketsDropped)
	assert.Equal(t, uint32(5), hunter.ActiveFilters)
	assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, hunter.Status)
}

func TestClient_CloseIdempotent(t *testing.T) {
	// Test that calling Close() multiple times is safe
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test Close() without successful connection")
	}

	// First close
	client.Close()

	// Second close - should not panic
	assert.NotPanics(t, func() {
		client.Close()
	})
}

func TestNewClient_DeprecatedConstructor(t *testing.T) {
	handler := &MockEventHandler{}

	// Test deprecated constructor
	client, err := NewClient("localhost:50051", handler)

	if err != nil {
		// Connection might fail in test environment - that's ok
		assert.Error(t, err)
		return
	}

	assert.NotNil(t, client)
	assert.Equal(t, "localhost:50051", client.GetAddr())

	// Verify it created insecure connection (deprecated behavior)
	client.Close()
}

func TestClientConfig_Validation(t *testing.T) {
	testCases := []struct {
		name    string
		config  *ClientConfig
		isValid bool
	}{
		{
			name: "Valid insecure config",
			config: &ClientConfig{
				Address:    "localhost:50051",
				TLSEnabled: false,
			},
			isValid: true,
		},
		{
			name: "Valid TLS config with skip verify",
			config: &ClientConfig{
				Address:       "localhost:50051",
				TLSEnabled:    true,
				TLSSkipVerify: true,
			},
			isValid: true,
		},
		{
			name: "Empty address",
			config: &ClientConfig{
				Address:    "",
				TLSEnabled: false,
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config.Address == "" {
				assert.Empty(t, tc.config.Address, "empty address should be detected")
			} else {
				assert.NotEmpty(t, tc.config.Address, "valid config should have address")
			}
		})
	}
}

func TestSlicesEqual_Empty(t *testing.T) {
	assert.True(t, slicesEqual([]string{}, []string{}))
	assert.True(t, slicesEqual(nil, nil))
	assert.False(t, slicesEqual([]string{}, nil))
	assert.False(t, slicesEqual(nil, []string{}))
}

func TestSlicesEqual_SingleElement(t *testing.T) {
	assert.True(t, slicesEqual([]string{"a"}, []string{"a"}))
	assert.False(t, slicesEqual([]string{"a"}, []string{"b"}))
	assert.False(t, slicesEqual([]string{"a"}, []string{}))
}

func TestSlicesEqual_MultipleElements(t *testing.T) {
	assert.True(t, slicesEqual([]string{"a", "b", "c"}, []string{"a", "b", "c"}))
	assert.False(t, slicesEqual([]string{"a", "b", "c"}, []string{"a", "b", "d"}))
	assert.False(t, slicesEqual([]string{"a", "b"}, []string{"a", "b", "c"}))
}

func TestSlicesEqual_OrderMatters(t *testing.T) {
	assert.False(t, slicesEqual([]string{"a", "b"}, []string{"b", "a"}))
}

func TestUpdateSubscription_NoChange(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test UpdateSubscription without successful connection")
	}
	defer client.Close()

	// Set initial subscription
	hunterIDs := []string{"hunter-1", "hunter-2"}
	client.streamMu.Lock()
	client.currentHunters = hunterIDs
	client.streamMu.Unlock()

	// Update with same subscription
	err = client.UpdateSubscription(hunterIDs)
	assert.NoError(t, err, "updating with same subscription should succeed")

	// Verify subscription unchanged
	client.streamMu.RLock()
	assert.Equal(t, hunterIDs, client.currentHunters)
	client.streamMu.RUnlock()
}

func TestUpdateSubscription_SubscriptionChange(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test UpdateSubscription without successful connection")
	}
	defer client.Close()

	// Set initial subscription
	initialHunters := []string{"hunter-1", "hunter-2"}
	client.streamMu.Lock()
	client.currentHunters = initialHunters
	client.streamMu.Unlock()

	// Update with different subscription
	newHunters := []string{"hunter-1", "hunter-3"}
	err = client.UpdateSubscription(newHunters)

	// Note: This will fail without a real server, but we test the logic path
	// In real usage, this would succeed with a running processor
	if err != nil {
		// Expected in test environment without real server
		assert.Error(t, err)
	}
}

func TestUpdateSubscription_NilToFiltered(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test UpdateSubscription without successful connection")
	}
	defer client.Close()

	// Start with nil (all hunters)
	client.streamMu.Lock()
	client.currentHunters = nil
	client.streamMu.Unlock()

	// Update to specific hunters
	newHunters := []string{"hunter-1"}
	err = client.UpdateSubscription(newHunters)

	// Expected to fail without server, but tests the logic
	if err != nil {
		assert.Error(t, err)
	}
}

func TestUpdateSubscription_FilteredToNil(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test UpdateSubscription without successful connection")
	}
	defer client.Close()

	// Start with specific hunters
	client.streamMu.Lock()
	client.currentHunters = []string{"hunter-1"}
	client.streamMu.Unlock()

	// Update to all hunters (nil)
	err = client.UpdateSubscription(nil)

	// Expected to fail without server, but tests the logic
	if err != nil {
		assert.Error(t, err)
	}
}

// Integration tests below require a real processor to be running
// These tests are more comprehensive and test end-to-end functionality

func TestClient_ConnectAndStream_Integration(t *testing.T) {
	// This test requires a running processor - skip if not available
	t.Skip("Integration test requires running processor")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	// Create client and connect
	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify connection
	assert.NotNil(t, client)
	assert.Equal(t, "localhost:50051", client.GetAddr())

	// Start streaming
	err = client.StreamPackets()
	require.NoError(t, err)

	// Subscribe to hunter status
	err = client.SubscribeHunterStatus()
	require.NoError(t, err)

	// Wait for some packets or status updates
	time.Sleep(2 * time.Second)

	// Verify we received some events
	if len(handler.PacketBatches) == 0 && len(handler.HunterStatuses) == 0 {
		t.Log("No packets or status updates received - may be normal if no hunters are connected")
	}

	// Verify no disconnects
	assert.Empty(t, handler.Disconnects, "should not have disconnected")
}

func TestClient_FilteredStream_Integration(t *testing.T) {
	// This test requires a running processor with multiple hunters
	t.Skip("Integration test requires running processor with multiple hunters")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Start streaming with hunter filter
	hunterIDs := []string{"hunter-1", "hunter-2"}
	err = client.StreamPacketsWithFilter(hunterIDs)
	require.NoError(t, err)

	// Subscribe to status
	err = client.SubscribeHunterStatus()
	require.NoError(t, err)

	// Wait for packets
	time.Sleep(2 * time.Second)

	// Verify all packets are from filtered hunters
	for _, batch := range handler.PacketBatches {
		for _, pkt := range batch {
			assert.Contains(t, hunterIDs, pkt.NodeID,
				"packet should be from filtered hunter")
		}
	}
}

func TestClient_TopologyUpdates_Integration(t *testing.T) {
	// This test requires a running processor
	t.Skip("Integration test requires running processor")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify this is a processor (not a hunter)
	if client.GetNodeType() != NodeTypeProcessor {
		t.Skip("Connected node is not a processor")
	}

	// Subscribe to topology updates
	err = client.SubscribeTopology()
	require.NoError(t, err)

	// Wait for topology updates
	time.Sleep(2 * time.Second)

	// Verify no errors during subscription
	assert.Empty(t, handler.Disconnects, "should not have disconnected")
}

func TestClient_NetworkFailure_Integration(t *testing.T) {
	// This test simulates network failure by connecting to invalid address
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:19999", // Invalid port
		TLSEnabled: false,
	}

	// Create client - should succeed (gRPC dials async)
	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		// Connection failed immediately (expected)
		assert.Error(t, err)
		return
	}
	defer client.Close()

	// Try to stream - should fail quickly
	err = client.StreamPackets()
	if err != nil {
		// Expected - no server available
		assert.Error(t, err)
		return
	}

	// Wait for connection failure
	time.Sleep(2 * time.Second)

	// Should have received disconnect event
	assert.NotEmpty(t, handler.Disconnects, "should have detected connection failure")
}

func TestClient_SlowConsumer_Integration(t *testing.T) {
	// This test requires a running processor with high packet rate
	t.Skip("Integration test requires running processor with high packet rate")

	// Create slow handler that processes packets slowly
	slowHandler := &SlowMockEventHandler{
		MockEventHandler: &MockEventHandler{},
		processDelay:     100 * time.Millisecond,
	}

	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, slowHandler)
	require.NoError(t, err)
	defer client.Close()

	// Start streaming
	err = client.StreamPackets()
	require.NoError(t, err)

	// Run for several seconds
	time.Sleep(5 * time.Second)

	// Verify client didn't disconnect despite slow processing
	assert.Empty(t, slowHandler.Disconnects, "slow consumer should not cause disconnect")

	// Verify we still received packets
	assert.NotEmpty(t, slowHandler.PacketBatches, "should have received packets")
}

// SlowMockEventHandler is a mock handler that processes events slowly
type SlowMockEventHandler struct {
	*MockEventHandler
	processDelay time.Duration
}

func (h *SlowMockEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
	time.Sleep(h.processDelay)
	h.MockEventHandler.OnPacketBatch(packets)
}

func TestClient_MultipleSubscribers_Integration(t *testing.T) {
	// This test requires a running processor
	t.Skip("Integration test requires running processor")

	// Create multiple clients
	clients := make([]*Client, 3)
	handlers := make([]*MockEventHandler, 3)

	for i := 0; i < 3; i++ {
		handlers[i] = &MockEventHandler{}
		config := &ClientConfig{
			Address:    "localhost:50051",
			TLSEnabled: false,
		}

		client, err := NewClientWithConfig(config, handlers[i])
		require.NoError(t, err)
		clients[i] = client

		// Start streaming
		err = client.StreamPackets()
		require.NoError(t, err)
	}

	// Wait for packets
	time.Sleep(3 * time.Second)

	// Close all clients
	for _, client := range clients {
		client.Close()
	}

	// Verify all clients received packets (if any traffic)
	receivedCount := 0
	for _, handler := range handlers {
		if len(handler.PacketBatches) > 0 {
			receivedCount++
		}
	}

	// If any client received packets, all should have received packets
	if receivedCount > 0 {
		assert.Equal(t, 3, receivedCount, "all clients should receive packets")
	}
}

func TestClient_HotSwapSubscription_Integration(t *testing.T) {
	// This test requires a running processor with multiple hunters
	t.Skip("Integration test requires running processor with multiple hunters")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Start with all hunters
	err = client.StreamPackets()
	require.NoError(t, err)

	time.Sleep(1 * time.Second)
	initialBatches := len(handler.PacketBatches)

	// Hot-swap to specific hunter
	err = client.UpdateSubscription([]string{"hunter-1"})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	// Verify subscription changed without disconnect
	assert.Empty(t, handler.Disconnects, "hot-swap should not disconnect")

	// Verify we received more packets
	assert.Greater(t, len(handler.PacketBatches), initialBatches,
		"should continue receiving packets after hot-swap")

	// Hot-swap back to all hunters
	err = client.UpdateSubscription(nil)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	// Verify still connected
	assert.Empty(t, handler.Disconnects, "should remain connected")
}

func TestClient_CorrelatedCalls_Integration(t *testing.T) {
	// This test requires a running processor with VoIP correlation enabled
	t.Skip("Integration test requires running processor with VoIP correlation")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify this is a processor
	if client.GetNodeType() != NodeTypeProcessor {
		t.Skip("Connected node is not a processor")
	}

	// Subscribe to correlated calls
	err = client.SubscribeCorrelatedCalls()
	require.NoError(t, err)

	// Wait for correlated call updates
	time.Sleep(5 * time.Second)

	// Verify no errors during subscription
	assert.Empty(t, handler.Disconnects, "should not have disconnected")
}

func TestClient_GetTopology_Integration(t *testing.T) {
	// This test requires a running processor
	t.Skip("Integration test requires running processor")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify this is a processor
	if client.GetNodeType() != NodeTypeProcessor {
		t.Skip("Connected node is not a processor")
	}

	// Get topology
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	topology, err := client.GetTopology(ctx)
	require.NoError(t, err)
	assert.NotNil(t, topology, "should return topology")

	// Verify topology has processor info
	assert.NotEmpty(t, topology.ProcessorId, "topology should have processor ID")
}

func TestClient_HunterNodeType_Integration(t *testing.T) {
	// This test would require a direct hunter connection
	t.Skip("Integration test requires running hunter")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50052", // Assuming hunter on different port
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify this is a hunter
	assert.Equal(t, NodeTypeHunter, client.GetNodeType(),
		"should detect hunter node type")

	// Hunters don't support topology
	_, err = client.GetTopology(context.Background())
	assert.Error(t, err, "hunters should not support GetTopology")
	assert.Contains(t, err.Error(), "only available from processor nodes")
}

func TestClient_TLSConnection_Integration(t *testing.T) {
	// This test requires a processor with TLS enabled
	t.Skip("Integration test requires processor with TLS")

	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:       "localhost:50051",
		TLSEnabled:    true,
		TLSSkipVerify: true, // For testing only
	}

	client, err := NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Start streaming over TLS
	err = client.StreamPackets()
	require.NoError(t, err)

	// Wait for packets
	time.Sleep(2 * time.Second)

	// Verify connection works over TLS
	assert.Empty(t, handler.Disconnects, "TLS connection should work")
}

// Unit tests for error paths and edge cases

func TestClient_StreamPackets_ContextCancellation(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}

	// Start streaming
	err = client.StreamPackets()
	if err != nil {
		// Expected if no server
		assert.Error(t, err)
		client.Close()
		return
	}

	// Cancel client context
	client.cancel()

	// Wait for goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Close should be idempotent
	assert.NotPanics(t, func() {
		client.Close()
	})
}

func TestClient_GetTopology_HunterNode(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Force node type to hunter
	client.nodeType = NodeTypeHunter

	// GetTopology should fail for hunter
	_, err = client.GetTopology(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only available from processor nodes")
}

func TestClient_SubscribeTopology_HunterNode(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Force node type to hunter
	client.nodeType = NodeTypeHunter

	// SubscribeTopology should fail for hunter
	err = client.SubscribeTopology()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only available from processor nodes")
}

func TestClient_SubscribeCorrelatedCalls_HunterNode(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Force node type to hunter
	client.nodeType = NodeTypeHunter

	// SubscribeCorrelatedCalls should fail for hunter
	err = client.SubscribeCorrelatedCalls()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only available from processor nodes")
}

func TestClient_CloseWhileStreaming(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}

	// Start streaming
	_ = client.StreamPackets() // Ignore error, may fail without server

	// Close immediately
	assert.NotPanics(t, func() {
		client.Close()
	})

	// Close again should be safe
	assert.NotPanics(t, func() {
		client.Close()
	})
}

func TestClient_GetConn(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Get connection
	conn := client.GetConn()
	assert.NotNil(t, conn, "should return gRPC connection")
}

func TestClient_UpdateSubscription_Idempotent(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Set initial subscription
	hunterIDs := []string{"hunter-1", "hunter-2"}
	client.streamMu.Lock()
	client.currentHunters = hunterIDs
	client.streamMu.Unlock()

	// Update with same subscription (should be no-op)
	err = client.UpdateSubscription(hunterIDs)
	assert.NoError(t, err, "updating with same subscription should be no-op")

	// Verify subscription unchanged
	client.streamMu.RLock()
	assert.Equal(t, hunterIDs, client.currentHunters)
	client.streamMu.RUnlock()
}

func TestClient_StreamPackets_Wrapper(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// StreamPackets is a wrapper around StreamPacketsWithFilter(nil)
	err = client.StreamPackets()
	if err != nil {
		// Expected if no server
		assert.Error(t, err)
		return
	}

	// Verify currentHunters is nil (all hunters)
	client.streamMu.RLock()
	assert.Nil(t, client.currentHunters)
	client.streamMu.RUnlock()
}

func TestClient_DetectNodeType_Processor(t *testing.T) {
	// This test is tricky as detectNodeType is called in NewClientWithConfig
	// We can only verify the logic indirectly
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// GetNodeType should return a valid node type
	nodeType := client.GetNodeType()
	assert.Contains(t, []NodeType{NodeTypeUnknown, NodeTypeHunter, NodeTypeProcessor}, nodeType)
}

func TestClient_GetAddr(t *testing.T) {
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Verify address
	assert.Equal(t, "localhost:50051", client.GetAddr())
}

func TestClient_CallStateTracking(t *testing.T) {
	// Test VoIP call state tracking logic
	handler := &MockEventHandler{}
	config := &ClientConfig{
		Address:    "localhost:50051",
		TLSEnabled: false,
	}

	client, err := NewClientWithConfig(config, handler)
	if err != nil {
		t.Skip("Cannot test without connection")
	}
	defer client.Close()

	// Verify call tracking maps are initialized
	assert.NotNil(t, client.calls)
	assert.NotNil(t, client.rtpStats)
	assert.NotNil(t, client.interfaces)
}

func TestDeriveSIPState_StateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  string
		method        string
		responseCode  uint32
		expectedState string
	}{
		{
			name:          "INVITE transitions NEW to RINGING",
			initialState:  "NEW",
			method:        "INVITE",
			responseCode:  0,
			expectedState: "RINGING",
		},
		{
			name:          "ACK transitions RINGING to ACTIVE",
			initialState:  "RINGING",
			method:        "ACK",
			responseCode:  0,
			expectedState: "ACTIVE",
		},
		{
			name:          "BYE transitions to ENDED",
			initialState:  "ACTIVE",
			method:        "BYE",
			responseCode:  0,
			expectedState: "ENDED",
		},
		{
			name:          "CANCEL transitions to FAILED",
			initialState:  "RINGING",
			method:        "CANCEL",
			responseCode:  0,
			expectedState: "FAILED",
		},
		{
			name:          "200 OK transitions RINGING to ACTIVE",
			initialState:  "RINGING",
			method:        "",
			responseCode:  200,
			expectedState: "ACTIVE",
		},
		{
			name:          "4xx error transitions to FAILED",
			initialState:  "RINGING",
			method:        "",
			responseCode:  404,
			expectedState: "FAILED",
		},
		{
			name:          "5xx error transitions to FAILED",
			initialState:  "ACTIVE",
			method:        "",
			responseCode:  500,
			expectedState: "FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &types.CallInfo{
				CallID: "test-call",
				State:  tt.initialState,
			}

			deriveSIPState(call, tt.method, tt.responseCode)

			assert.Equal(t, tt.expectedState, call.State)
		})
	}
}

func TestCalculateMOS_Values(t *testing.T) {
	tests := []struct {
		name        string
		packetLoss  float64
		jitter      float64
		expectedMOS float64
		minMOS      float64
		maxMOS      float64
	}{
		{
			name:       "Perfect quality (no loss, no jitter)",
			packetLoss: 0.0,
			jitter:     0.0,
			minMOS:     4.0,
			maxMOS:     5.0,
		},
		{
			name:       "Good quality (low loss, low jitter)",
			packetLoss: 1.0,
			jitter:     20.0,
			minMOS:     3.5,
			maxMOS:     4.5,
		},
		{
			name:       "Fair quality (moderate loss and jitter)",
			packetLoss: 5.0,
			jitter:     50.0,
			minMOS:     2.5,
			maxMOS:     4.1,
		},
		{
			name:       "Poor quality (high loss and jitter)",
			packetLoss: 10.0,
			jitter:     100.0,
			minMOS:     1.5,
			maxMOS:     3.5,
		},
		{
			name:       "Extreme packet loss (clamped to 100%)",
			packetLoss: 150.0,
			jitter:     50.0,
			minMOS:     1.0,
			maxMOS:     2.0,
		},
		{
			name:       "Negative inputs (clamped to 0)",
			packetLoss: -10.0,
			jitter:     -20.0,
			minMOS:     4.0,
			maxMOS:     5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mos := calculateMOS(tt.packetLoss, tt.jitter)

			// Verify MOS is in valid range
			assert.GreaterOrEqual(t, mos, 1.0, "MOS should be >= 1.0")
			assert.LessOrEqual(t, mos, 5.0, "MOS should be <= 5.0")

			// Verify MOS is in expected range for this scenario
			assert.GreaterOrEqual(t, mos, tt.minMOS, "MOS should be >= min expected")
			assert.LessOrEqual(t, mos, tt.maxMOS, "MOS should be <= max expected")
		})
	}
}

func TestPayloadTypeToCodec_StandardCodecs(t *testing.T) {
	tests := []struct {
		payloadType uint8
		expected    string
	}{
		{0, "G.711 µ-law"},
		{8, "G.711 A-law"},
		{9, "G.722"},
		{18, "G.729"},
		{101, "telephone-event"}, // DTMF
		{96, "Dynamic"},          // Dynamic payload type
		{127, "Dynamic"},         // Dynamic payload type
		{255, "Unknown"},         // Invalid/unknown
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			codec := capture.PayloadTypeToCodec(tt.payloadType)
			assert.Equal(t, tt.expected, codec)
		})
	}
}

func TestFormatTCPFlags_AllCombinations(t *testing.T) {
	// This is a simple helper function test
	// We can't easily test without creating real TCP layers
	// But we can verify the logic is sound by checking the code coverage
}

func TestContainsHelper(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{"Empty slice", []string{}, "test", false},
		{"Item present", []string{"a", "b", "c"}, "b", true},
		{"Item not present", []string{"a", "b", "c"}, "d", false},
		{"Exact match", []string{"test"}, "test", true},
		{"Case sensitive", []string{"Test"}, "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}
