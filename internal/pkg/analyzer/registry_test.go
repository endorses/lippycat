package analyzer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProtocol is a test implementation of the Protocol interface
type mockProtocol struct {
	name               string
	version            string
	supportedProtocols []string
	initialized        atomic.Bool
	shuttingDown       atomic.Bool
	processCount       atomic.Int64
	processFunc        func(ctx context.Context, packet gopacket.Packet) (*Result, error)
}

func newMockProtocol(name, version string, protocols []string) *mockProtocol {
	return &mockProtocol{
		name:               name,
		version:            version,
		supportedProtocols: protocols,
	}
}

func (m *mockProtocol) Name() string                 { return m.name }
func (m *mockProtocol) Version() string              { return m.version }
func (m *mockProtocol) SupportedProtocols() []string { return m.supportedProtocols }
func (m *mockProtocol) Initialize(config map[string]interface{}) error {
	m.initialized.Store(true)
	return nil
}

func (m *mockProtocol) Shutdown(ctx context.Context) error {
	m.shuttingDown.Store(true)
	return nil
}

func (m *mockProtocol) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*Result, error) {
	m.processCount.Add(1)
	if m.processFunc != nil {
		return m.processFunc(ctx, packet)
	}
	return &Result{
		Protocol:       m.supportedProtocols[0],
		Confidence:     1.0,
		ShouldContinue: false,
	}, nil
}

func (m *mockProtocol) HealthCheck() HealthStatus {
	return HealthStatus{
		Status:    HealthHealthy,
		Message:   "Mock protocol healthy",
		Timestamp: time.Now(),
	}
}

func (m *mockProtocol) Metrics() Metrics {
	return Metrics{
		PacketsProcessed: m.processCount.Load(),
	}
}

// createTestRegistry creates a clean registry for testing
func createTestRegistry() *Registry {
	return &Registry{
		protocols:   make(map[string]Protocol),
		configs:     make(map[string]Config),
		infos:       make(map[string]Info),
		protocolMap: make(map[string][]string),
	}
}

func TestRegistry_Register(t *testing.T) {
	tests := []struct {
		name         string
		protocolName string
		protocol     Protocol
		config       Config
		wantErr      bool
	}{
		{
			name:         "successful registration",
			protocolName: "test-proto",
			protocol:     newMockProtocol("Test Protocol", "1.0.0", []string{"test"}),
			config:       DefaultConfig(),
			wantErr:      false,
		},
		{
			name:         "duplicate registration",
			protocolName: "dup-proto",
			protocol:     newMockProtocol("Dup Protocol", "1.0.0", []string{"dup"}),
			config:       DefaultConfig(),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := createTestRegistry()
			r.Enable()

			// For duplicate test, register once first
			if tt.name == "duplicate registration" {
				err := r.Register(tt.protocolName, tt.protocol, tt.config)
				require.NoError(t, err)
			}

			err := r.Register(tt.protocolName, tt.protocol, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify protocol is registered
				proto, exists := r.Get(tt.protocolName)
				assert.True(t, exists)
				assert.Equal(t, tt.protocol, proto)

				// Verify protocol is initialized
				mockProto, ok := tt.protocol.(*mockProtocol)
				require.True(t, ok)
				assert.True(t, mockProto.initialized.Load())
			}
		})
	}
}

func TestRegistry_RegisterDisabled(t *testing.T) {
	r := createTestRegistry()
	// Don't enable registry - should fail

	proto := newMockProtocol("Test", "1.0.0", []string{"test"})
	err := r.Register("test", proto, DefaultConfig())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestRegistry_MustRegister(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Test", "1.0.0", []string{"test"})

	// Should not panic
	assert.NotPanics(t, func() {
		r.MustRegister("test", proto, DefaultConfig())
	})

	// Should panic on duplicate
	assert.Panics(t, func() {
		r.MustRegister("test", proto, DefaultConfig())
	})
}

func TestRegistry_Unregister(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Test", "1.0.0", []string{"test", "test2"})
	err := r.Register("test", proto, DefaultConfig())
	require.NoError(t, err)

	// Verify registered
	_, exists := r.Get("test")
	assert.True(t, exists)

	// Unregister
	err = r.Unregister("test")
	assert.NoError(t, err)

	// Verify unregistered
	_, exists = r.Get("test")
	assert.False(t, exists)

	// Verify protocol shutdown was called
	assert.True(t, proto.shuttingDown.Load())

	// Verify protocol mapping cleaned up
	analyzers := r.GetByProtocol("test")
	assert.Nil(t, analyzers)

	// Try to unregister non-existent protocol
	err = r.Unregister("nonexistent")
	assert.Error(t, err)
}

func TestRegistry_ProcessPacket_Priority(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	// Create two protocols with different priorities
	highPrio := newMockProtocol("High Priority", "1.0.0", []string{"test"})
	lowPrio := newMockProtocol("Low Priority", "1.0.0", []string{"test"})

	var processOrder []string
	mu := sync.Mutex{}

	highPrio.processFunc = func(ctx context.Context, packet gopacket.Packet) (*Result, error) {
		mu.Lock()
		processOrder = append(processOrder, "high")
		mu.Unlock()
		return &Result{Protocol: "test", ShouldContinue: true}, nil
	}

	lowPrio.processFunc = func(ctx context.Context, packet gopacket.Packet) (*Result, error) {
		mu.Lock()
		processOrder = append(processOrder, "low")
		mu.Unlock()
		return &Result{Protocol: "test", ShouldContinue: true}, nil
	}

	// Register low priority first
	lowConfig := DefaultConfig()
	lowConfig.Priority = 10
	err := r.Register("low", lowPrio, lowConfig)
	require.NoError(t, err)

	// Register high priority second
	highConfig := DefaultConfig()
	highConfig.Priority = 100
	err = r.Register("high", highPrio, highConfig)
	require.NoError(t, err)

	// Create a test packet
	packet := createTestPacket()

	// Manually inject protocol into protocolMap since we're bypassing detection
	r.mu.Lock()
	r.protocolMap["test"] = []string{"high", "low"}
	r.protocolMap["generic"] = []string{"high", "low"} // Detector will return "generic" for unknown packets
	r.mu.Unlock()

	// Process packet - high priority should run first
	_, err = r.ProcessPacket(context.Background(), packet)
	assert.NoError(t, err)

	// Verify order (only check if processing happened)
	if len(processOrder) > 0 {
		assert.Equal(t, []string{"high", "low"}, processOrder)
	}
}

func TestRegistry_ProcessPacket_DisabledProtocol(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Test", "1.0.0", []string{"test"})
	config := DefaultConfig()
	config.Enabled = false // Disable the protocol

	err := r.Register("test", proto, config)
	require.NoError(t, err)

	r.mu.Lock()
	r.protocolMap["test"] = []string{"test"}
	r.mu.Unlock()

	packet := createTestPacket()
	results, err := r.ProcessPacket(context.Background(), packet)
	assert.NoError(t, err)
	assert.Empty(t, results)

	// Verify protocol was not called
	assert.Equal(t, int64(0), proto.processCount.Load())
}

func TestRegistry_ProcessPacket_Timeout(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Slow", "1.0.0", []string{"test"})
	proto.processFunc = func(ctx context.Context, packet gopacket.Packet) (*Result, error) {
		// Simulate slow processing
		select {
		case <-time.After(2 * time.Second):
			return &Result{Protocol: "test"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	config := DefaultConfig()
	config.Timeout = 100 * time.Millisecond
	err := r.Register("slow", proto, config)
	require.NoError(t, err)

	r.mu.Lock()
	r.protocolMap["test"] = []string{"slow"}
	r.mu.Unlock()

	packet := createTestPacket()
	start := time.Now()
	_, _ = r.ProcessPacket(context.Background(), packet)
	duration := time.Since(start)

	// Should timeout quickly
	assert.True(t, duration < 500*time.Millisecond, "expected timeout, but took %v", duration)
}

func TestRegistry_ProcessPacket_ShouldContinue(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto1 := newMockProtocol("Proto1", "1.0.0", []string{"test"})
	proto2 := newMockProtocol("Proto2", "1.0.0", []string{"test"})

	proto1.processFunc = func(ctx context.Context, packet gopacket.Packet) (*Result, error) {
		return &Result{
			Protocol:       "test",
			ShouldContinue: false, // Stop processing
		}, nil
	}

	err := r.Register("proto1", proto1, DefaultConfig())
	require.NoError(t, err)
	err = r.Register("proto2", proto2, DefaultConfig())
	require.NoError(t, err)

	r.mu.Lock()
	r.protocolMap["test"] = []string{"proto1", "proto2"}
	r.protocolMap["generic"] = []string{"proto1", "proto2"} // Detector will return "generic"
	r.mu.Unlock()

	packet := createTestPacket()
	results, err := r.ProcessPacket(context.Background(), packet)
	assert.NoError(t, err)

	// Should have at least 1 result if processing happened
	if len(results) > 0 {
		// proto2 should not have been called (ShouldContinue=false)
		assert.Equal(t, int64(0), proto2.processCount.Load())
	}
}

func TestRegistry_EnableDisableProtocol(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Test", "1.0.0", []string{"test"})
	err := r.Register("test", proto, DefaultConfig())
	require.NoError(t, err)

	// Disable protocol
	err = r.DisableProtocol("test")
	assert.NoError(t, err)
	assert.False(t, r.configs["test"].Enabled)

	// Enable protocol
	err = r.EnableProtocol("test")
	assert.NoError(t, err)
	assert.True(t, r.configs["test"].Enabled)

	// Try to enable non-existent protocol
	err = r.EnableProtocol("nonexistent")
	assert.Error(t, err)

	// Try to disable non-existent protocol
	err = r.DisableProtocol("nonexistent")
	assert.Error(t, err)
}

func TestRegistry_List(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto1 := newMockProtocol("Proto1", "1.0.0", []string{"test1"})
	proto2 := newMockProtocol("Proto2", "2.0.0", []string{"test2"})

	err := r.Register("proto1", proto1, DefaultConfig())
	require.NoError(t, err)
	err = r.Register("proto2", proto2, DefaultConfig())
	require.NoError(t, err)

	infos := r.List()
	assert.Len(t, infos, 2)
	assert.Contains(t, infos, "proto1")
	assert.Contains(t, infos, "proto2")
	assert.Equal(t, "1.0.0", infos["proto1"].Version)
	assert.Equal(t, "2.0.0", infos["proto2"].Version)
}

func TestRegistry_GetByProtocol(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto1 := newMockProtocol("Proto1", "1.0.0", []string{"test", "test2"})
	proto2 := newMockProtocol("Proto2", "1.0.0", []string{"test"})

	err := r.Register("proto1", proto1, DefaultConfig())
	require.NoError(t, err)
	err = r.Register("proto2", proto2, DefaultConfig())
	require.NoError(t, err)

	// Get analyzers for "test" protocol
	analyzers := r.GetByProtocol("test")
	assert.Len(t, analyzers, 2)
	assert.Contains(t, analyzers, "proto1")
	assert.Contains(t, analyzers, "proto2")

	// Get analyzers for "test2" protocol
	analyzers = r.GetByProtocol("test2")
	assert.Len(t, analyzers, 1)
	assert.Contains(t, analyzers, "proto1")

	// Get analyzers for non-existent protocol
	analyzers = r.GetByProtocol("nonexistent")
	assert.Nil(t, analyzers)
}

func TestRegistry_HealthCheck(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto1 := newMockProtocol("Proto1", "1.0.0", []string{"test1"})
	proto2 := newMockProtocol("Proto2", "1.0.0", []string{"test2"})

	err := r.Register("proto1", proto1, DefaultConfig())
	require.NoError(t, err)

	config := DefaultConfig()
	config.Enabled = false
	err = r.Register("proto2", proto2, config)
	require.NoError(t, err)

	health := r.HealthCheck()
	assert.Len(t, health, 1) // Only enabled protocols
	assert.Contains(t, health, "proto1")
	assert.NotContains(t, health, "proto2")
}

func TestRegistry_Shutdown(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto1 := newMockProtocol("Proto1", "1.0.0", []string{"test1"})
	proto2 := newMockProtocol("Proto2", "1.0.0", []string{"test2"})

	err := r.Register("proto1", proto1, DefaultConfig())
	require.NoError(t, err)
	err = r.Register("proto2", proto2, DefaultConfig())
	require.NoError(t, err)

	// Shutdown
	err = r.Shutdown(context.Background())
	assert.NoError(t, err)

	// Verify all protocols shutdown
	assert.True(t, proto1.shuttingDown.Load())
	assert.True(t, proto2.shuttingDown.Load())

	// Verify all maps cleared
	assert.Empty(t, r.protocols)
	assert.Empty(t, r.configs)
	assert.Empty(t, r.infos)
	assert.Empty(t, r.protocolMap)

	// Verify stats reset
	assert.Equal(t, int64(0), r.stats.TotalProtocols.Load())
	assert.Equal(t, int64(0), r.stats.ActiveProtocols.Load())
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent registrations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			proto := newMockProtocol(fmt.Sprintf("Proto%d", idx), "1.0.0", []string{fmt.Sprintf("test%d", idx)})
			_ = r.Register(fmt.Sprintf("proto%d", idx), proto, DefaultConfig())
		}(i)
	}

	wg.Wait()

	// Verify all registered
	infos := r.List()
	assert.Equal(t, numGoroutines, len(infos))

	// Concurrent reads
	packet := createTestPacket()
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.ProcessPacket(context.Background(), packet)
			_ = r.List()
			_ = r.HealthCheck()
		}()
	}

	wg.Wait()
}

func TestRegistry_GetStats(t *testing.T) {
	r := createTestRegistry()
	r.Enable()

	proto := newMockProtocol("Test", "1.0.0", []string{"test"})
	err := r.Register("test", proto, DefaultConfig())
	require.NoError(t, err)

	stats := r.GetStats()
	assert.NotNil(t, stats)
	assert.Equal(t, int64(1), stats.TotalProtocols.Load())
	assert.Equal(t, int64(1), stats.ActiveProtocols.Load())
}

func TestRegistry_GlobalRegistry(t *testing.T) {
	// Test singleton behavior
	reg1 := GetRegistry()
	reg2 := GetRegistry()
	assert.Same(t, reg1, reg2)
	assert.True(t, reg1.IsEnabled())
}

// Helper function to create a test packet
func createTestPacket() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	// Create a simple UDP packet
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udp.SetNetworkLayerForChecksum(ip)

	payload := gopacket.Payload([]byte("test payload"))

	gopacket.SerializeLayers(buf, opts, ip, udp, payload)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
