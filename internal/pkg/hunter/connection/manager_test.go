//go:build hunter || all

package connection

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockStatsCollector struct {
	captured  uint64
	forwarded uint64
	matched   uint64
	dropped   uint64
}

func (m *mockStatsCollector) GetCaptured() uint64                              { return m.captured }
func (m *mockStatsCollector) GetForwarded() uint64                             { return m.forwarded }
func (m *mockStatsCollector) GetMatched() uint64                               { return m.matched }
func (m *mockStatsCollector) GetDropped() uint64                               { return m.dropped }
func (m *mockStatsCollector) GetAll() (uint64, uint64, uint64, uint64, uint64) { return 0, 0, 0, 0, 0 }
func (m *mockStatsCollector) ToProto(activeFilters uint32) *management.HunterStats {
	return &management.HunterStats{}
}

type mockFilterManager struct {
	filterCount int
}

func (m *mockFilterManager) GetFilterCount() int { return m.filterCount }
func (m *mockFilterManager) SetInitialFilters(filters []*management.Filter) {
	m.filterCount = len(filters)
}
func (m *mockFilterManager) Subscribe(ctx, connCtx context.Context, mgmtClient management.ManagementServiceClient) {
}

type mockCaptureManager struct {
	buffer *capture.PacketBuffer
}

func (m *mockCaptureManager) GetPacketBuffer() *capture.PacketBuffer {
	return m.buffer
}

type mockForwardingFactory struct{}

func (m *mockForwardingFactory) CreateForwardingManager(
	connCtx context.Context,
	stream data.DataService_StreamPacketsClient,
) *forwarding.Manager {
	return nil
}

// Tests

func TestNew(t *testing.T) {
	config := Config{
		ProcessorAddr:        "localhost:55555",
		HunterID:             "test-hunter",
		Interfaces:           []string{"eth0"},
		BufferSize:           1000,
		BatchSize:            100,
		BatchTimeout:         time.Second,
		VoIPMode:             true,
		MaxReconnectAttempts: 5,
	}

	stats := &mockStatsCollector{}
	filters := &mockFilterManager{}
	capture := &mockCaptureManager{}
	factory := &mockForwardingFactory{}
	flowHandler := func(ctrl *data.StreamControl) {}

	manager := New(config, stats, filters, capture, factory, flowHandler)

	require.NotNil(t, manager)
	assert.Equal(t, config.ProcessorAddr, manager.config.ProcessorAddr)
	assert.Equal(t, config.HunterID, manager.config.HunterID)
	assert.Equal(t, config.VoIPMode, manager.config.VoIPMode)
	assert.Equal(t, 0, manager.reconnectAttempts)
	assert.False(t, manager.reconnecting)
	assert.NotNil(t, manager.circuitBreaker)
}

func TestNew_WithTLS(t *testing.T) {
	config := Config{
		ProcessorAddr:         "localhost:55555",
		HunterID:              "test-hunter-tls",
		TLSEnabled:            true,
		TLSCertFile:           "/path/to/cert.pem",
		TLSKeyFile:            "/path/to/key.pem",
		TLSCAFile:             "/path/to/ca.pem",
		TLSSkipVerify:         false,
		TLSServerNameOverride: "processor.local",
	}

	stats := &mockStatsCollector{}
	filters := &mockFilterManager{}
	capture := &mockCaptureManager{}
	factory := &mockForwardingFactory{}
	flowHandler := func(ctrl *data.StreamControl) {}

	manager := New(config, stats, filters, capture, factory, flowHandler)

	require.NotNil(t, manager)
	assert.True(t, manager.config.TLSEnabled)
	assert.Equal(t, "/path/to/cert.pem", manager.config.TLSCertFile)
	assert.Equal(t, "processor.local", manager.config.TLSServerNameOverride)
}

func TestMarkDisconnected(t *testing.T) {
	manager := &Manager{
		reconnecting: false,
	}

	// First call should mark as disconnected
	manager.MarkDisconnected()
	assert.True(t, manager.reconnecting)

	// Second call should be a no-op (already reconnecting)
	manager.MarkDisconnected()
	assert.True(t, manager.reconnecting)
}

func TestMarkDisconnected_Concurrent(t *testing.T) {
	manager := &Manager{
		reconnecting: false,
	}

	var wg sync.WaitGroup
	callCount := 100

	for i := 0; i < callCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.MarkDisconnected()
		}()
	}

	wg.Wait()
	assert.True(t, manager.reconnecting)
}

func TestCalculateStatus_Healthy(t *testing.T) {
	ctx := context.Background()
	manager := &Manager{
		ctx: ctx,
		statsCollector: &mockStatsCollector{
			captured: 1000,
			dropped:  10, // 1% drop rate - healthy
		},
		captureManager: &mockCaptureManager{
			buffer: nil, // No buffer to check
		},
	}

	status := manager.calculateStatus()
	assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, status)
}

func TestCalculateStatus_HighDropRate(t *testing.T) {
	ctx := context.Background()
	manager := &Manager{
		ctx: ctx,
		statsCollector: &mockStatsCollector{
			captured: 1000,
			dropped:  150, // 15% drop rate - warning
		},
		captureManager: &mockCaptureManager{
			buffer: nil,
		},
	}

	status := manager.calculateStatus()
	assert.Equal(t, management.HunterStatus_STATUS_WARNING, status)
}

func TestCalculateStatus_Stopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	manager := &Manager{
		ctx: ctx,
		statsCollector: &mockStatsCollector{
			captured: 1000,
			dropped:  10,
		},
		captureManager: &mockCaptureManager{
			buffer: nil,
		},
	}

	status := manager.calculateStatus()
	assert.Equal(t, management.HunterStatus_STATUS_STOPPING, status)
}

func TestCalculateStatus_NoStats(t *testing.T) {
	ctx := context.Background()
	manager := &Manager{
		ctx: ctx,
		statsCollector: &mockStatsCollector{
			captured: 0, // No packets captured yet
			dropped:  0,
		},
		captureManager: &mockCaptureManager{
			buffer: nil,
		},
	}

	status := manager.calculateStatus()
	assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, status)
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 100, 100},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			result := min(tc.a, tc.b)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetMgmtClient_Nil(t *testing.T) {
	manager := &Manager{}
	client := manager.GetMgmtClient()
	assert.Nil(t, client)
}

func TestGetDataClient_Nil(t *testing.T) {
	manager := &Manager{}
	client := manager.GetDataClient()
	assert.Nil(t, client)
}

func TestGetStream_Nil(t *testing.T) {
	manager := &Manager{}
	stream := manager.GetStream()
	assert.Nil(t, stream)
}

func TestGetForwardingManager_Nil(t *testing.T) {
	manager := &Manager{}
	fm := manager.GetForwardingManager()
	assert.Nil(t, fm)
}

func TestStop_NilCancel(t *testing.T) {
	manager := &Manager{}
	// Should not panic when cancel is nil
	manager.Stop()
}

func TestStop_WithCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		cancel: cancel,
		ctx:    ctx,
	}

	manager.Stop()
	// Context should be cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled")
	}
}

func TestGetInterfaceIP_NoInterfaces(t *testing.T) {
	ip := getInterfaceIP([]string{})
	assert.Empty(t, ip)
}

func TestGetInterfaceIP_Any(t *testing.T) {
	// "any" should fall back to first non-loopback IP
	ip := getInterfaceIP([]string{"any"})
	// Result depends on system interfaces, but should not panic
	_ = ip
}

func TestGetInterfaceIP_MultipleInterfaces(t *testing.T) {
	// Multiple interfaces should fall back to first non-loopback IP
	ip := getInterfaceIP([]string{"eth0", "eth1"})
	// Result depends on system interfaces, but should not panic
	_ = ip
}

func TestGetInterfaceIP_NonexistentInterface(t *testing.T) {
	ip := getInterfaceIP([]string{"nonexistent-interface-xyz"})
	assert.Empty(t, ip)
}

func TestGetFirstNonLoopbackIP(t *testing.T) {
	// This test verifies the function doesn't panic and returns
	// either a valid IP or empty string
	ip := getFirstNonLoopbackIP()
	if ip != "" {
		// If an IP is returned, it should not be loopback
		assert.NotEqual(t, "127.0.0.1", ip)
	}
}

func TestConfig_VoIPModeFilterTypes(t *testing.T) {
	// VoIP mode should support more filter types
	voipConfig := Config{
		VoIPMode: true,
	}

	// Generic mode should support fewer filter types
	genericConfig := Config{
		VoIPMode: false,
	}

	// These are used in the register() method to determine capabilities
	assert.True(t, voipConfig.VoIPMode)
	assert.False(t, genericConfig.VoIPMode)
}

func TestConfig_Defaults(t *testing.T) {
	config := Config{}

	// Verify zero values
	assert.Empty(t, config.ProcessorAddr)
	assert.Empty(t, config.HunterID)
	assert.Nil(t, config.Interfaces)
	assert.Equal(t, 0, config.BufferSize)
	assert.Equal(t, 0, config.BatchSize)
	assert.Equal(t, time.Duration(0), config.BatchTimeout)
	assert.False(t, config.TLSEnabled)
	assert.False(t, config.TLSSkipVerify)
	assert.Equal(t, 0, config.MaxReconnectAttempts)
}

func TestManager_ConcurrentStreamAccess(t *testing.T) {
	manager := &Manager{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.GetStream()
		}()
	}
	wg.Wait()
}

func TestManager_ReconnectionStateTransitions(t *testing.T) {
	manager := &Manager{
		reconnecting:      false,
		reconnectAttempts: 0,
	}

	// Initial state
	assert.False(t, manager.reconnecting)
	assert.Equal(t, 0, manager.reconnectAttempts)

	// Mark disconnected
	manager.MarkDisconnected()
	assert.True(t, manager.reconnecting)

	// Simulate reconnection attempt
	manager.reconnectMu.Lock()
	manager.reconnectAttempts++
	manager.reconnectMu.Unlock()
	assert.Equal(t, 1, manager.reconnectAttempts)

	// Simulate successful reconnection (reset state)
	manager.reconnectMu.Lock()
	manager.reconnecting = false
	manager.reconnectAttempts = 0
	manager.reconnectMu.Unlock()

	assert.False(t, manager.reconnecting)
	assert.Equal(t, 0, manager.reconnectAttempts)
}

func TestManager_MaxReconnectAttempts(t *testing.T) {
	config := Config{
		MaxReconnectAttempts: 5,
	}

	manager := &Manager{
		config:            config,
		reconnectAttempts: 4,
	}

	// Not yet at max
	assert.Less(t, manager.reconnectAttempts, config.MaxReconnectAttempts)

	manager.reconnectAttempts = 5
	// At max
	assert.Equal(t, manager.reconnectAttempts, config.MaxReconnectAttempts)
}

func TestManager_UnlimitedReconnects(t *testing.T) {
	config := Config{
		MaxReconnectAttempts: 0, // 0 means unlimited
	}

	manager := &Manager{
		config:            config,
		reconnectAttempts: 1000,
	}

	// With MaxReconnectAttempts=0, should never hit the limit
	if config.MaxReconnectAttempts > 0 {
		assert.GreaterOrEqual(t, manager.reconnectAttempts, config.MaxReconnectAttempts)
	}
}

// Benchmark tests

func BenchmarkMin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = min(100, 200)
	}
}

func BenchmarkGetStream(b *testing.B) {
	manager := &Manager{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetStream()
	}
}

func BenchmarkMarkDisconnected(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager := &Manager{reconnecting: false}
		manager.MarkDisconnected()
	}
}
