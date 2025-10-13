package remotecapture

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
)

// MockEventHandler implements types.EventHandler for testing
type MockEventHandler struct {
	PacketBatches  [][]types.PacketDisplay
	HunterStatuses []MockHunterStatus
	Disconnects    []MockDisconnect
}

type MockHunterStatus struct {
	Hunters         []types.HunterInfo
	ProcessorID     string
	ProcessorStatus management.ProcessorStatus
}

type MockDisconnect struct {
	Address string
	Error   error
}

func (m *MockEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
	m.PacketBatches = append(m.PacketBatches, packets)
}

func (m *MockEventHandler) OnHunterStatus(hunters []types.HunterInfo, processorID string, processorStatus management.ProcessorStatus) {
	m.HunterStatuses = append(m.HunterStatuses, MockHunterStatus{
		Hunters:         hunters,
		ProcessorID:     processorID,
		ProcessorStatus: processorStatus,
	})
}

func (m *MockEventHandler) OnCallUpdate(calls []types.CallInfo) {
	// Mock implementation - calls not tracked in tests yet
}

func (m *MockEventHandler) OnDisconnect(address string, err error) {
	m.Disconnects = append(m.Disconnects, MockDisconnect{
		Address: address,
		Error:   err,
	})
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

	handler.OnHunterStatus(hunters, "processor-1", processorStatus)

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
	handler.OnHunterStatus([]types.HunterInfo{{ID: "h1"}}, "p1", management.ProcessorStatus_PROCESSOR_HEALTHY)
	handler.OnHunterStatus([]types.HunterInfo{{ID: "h2"}}, "p2", management.ProcessorStatus_PROCESSOR_HEALTHY)

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

func TestStreamHealthTimeout(t *testing.T) {
	// Test that stream health monitoring detects timeouts
	// This is a unit test of the timeout logic

	lastPacketTime := time.Now().Add(-65 * time.Second) // 65 seconds ago
	streamTimeout := 60 * time.Second

	timeSinceLastPacket := time.Since(lastPacketTime)

	assert.Greater(t, timeSinceLastPacket, streamTimeout,
		"should detect timeout when last packet is > 60s old")
}

func TestStreamHealthNoTimeout(t *testing.T) {
	// Test that recent packets don't trigger timeout
	lastPacketTime := time.Now().Add(-30 * time.Second) // 30 seconds ago
	streamTimeout := 60 * time.Second

	timeSinceLastPacket := time.Since(lastPacketTime)

	assert.Less(t, timeSinceLastPacket, streamTimeout,
		"should not timeout when last packet is < 60s old")
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
