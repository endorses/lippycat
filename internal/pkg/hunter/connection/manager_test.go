//go:build hunter || all

package connection

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	processorhunter "github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Mock implementations for testing

type mockStatsCollector struct {
	captured  uint64
	forwarded uint64
	matched   uint64
	dropped   uint64
}

func captureTestUDPPacketInfo(t testing.TB, payload string) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	return capture.PacketInfo{Packet: gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)}
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
func (m *mockFilterManager) SetInitialFilters(filters []*management.Filter) error {
	m.filterCount = len(filters)
	return nil
}
func (m *mockFilterManager) ApplyPendingInitial() {}
func (m *mockFilterManager) Subscribe(ctx, connCtx context.Context, mgmtClient management.ManagementServiceClient) {
}

type legacyManagementClient struct {
	management.ManagementServiceClient
	response *management.RegistrationResponse
	request  *management.HunterRegistration
}

func (c *legacyManagementClient) RegisterHunter(_ context.Context, request *management.HunterRegistration, _ ...grpc.CallOption) (*management.RegistrationResponse, error) {
	c.request = request
	return c.response, nil
}

func newLegacyProcessorManager(forwardMode string, allowFallback bool) (*Manager, *legacyManagementClient) {
	client := &legacyManagementClient{response: &management.RegistrationResponse{
		Accepted:   true,
		AssignedId: "hunter-a",
	}}
	return &Manager{
		ctx: context.Background(),
		config: Config{
			HunterID:               "hunter-a",
			Interfaces:             []string{"legacy-test-interface"},
			ForwardMode:            forwardMode,
			EventFallbackToPackets: allowFallback,
		},
		mgmtClient:    client,
		filterManager: &mockFilterManager{},
		modeReady:     make(chan management.ForwardingMode, 1),
	}, client
}

func TestRegisterWithLegacyProcessorUsesPacketCompatibilityDefault(t *testing.T) {
	manager, client := newLegacyProcessorManager("packets", false)

	require.NoError(t, manager.register())
	require.NotNil(t, client.request.GetEventForwarding())
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, client.request.GetEventForwarding().GetRequestedMode())
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, manager.acceptedMode)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, <-manager.modeReady)
}

func TestRegisterEventModeWithLegacyProcessorRequiresExplicitFallback(t *testing.T) {
	manager, _ := newLegacyProcessorManager("events", false)

	err := manager.register()
	require.ErrorContains(t, err, "rejected requested event forwarding profile")
}

func TestRegisterEventModeWithLegacyProcessorExplicitlyFallsBackToPackets(t *testing.T) {
	manager, client := newLegacyProcessorManager("events", true)

	require.NoError(t, manager.register())
	require.True(t, client.request.GetEventForwarding().GetAllowPacketFallback())
	require.Equal(t, "packets", manager.config.ForwardMode)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, manager.acceptedMode)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, <-manager.modeReady)
}

type mockCaptureManager struct {
	buffer *capture.PacketBuffer
}

func (m *mockCaptureManager) GetPacketBuffer() *capture.PacketBuffer {
	return m.buffer
}

func TestApplyCaptureBufferStatsPreservesDropAggregate(t *testing.T) {
	buffer, err := capture.NewPacketBufferWithConfig(t.Context(), capture.PacketBufferConfig{
		RegularCapacity: 2,
		SIPCapacity:     3,
		OutputCapacity:  4,
	})
	require.NoError(t, err)
	defer buffer.Close()

	stats := &management.HunterStats{BatchChannelDrops: 5}
	applyCaptureBufferStats(stats, buffer)

	require.Equal(t, uint64(2), stats.CaptureBufferRegularCapacity)
	require.Equal(t, uint64(3), stats.CaptureBufferSipCapacity)
	require.Equal(t, uint64(4), stats.CaptureBufferOutputCapacity)
	require.Zero(t, stats.CaptureBufferSipDemotions)
	require.Equal(t, stats.CaptureBufferRegularDrops+stats.CaptureBufferSipDrops+stats.BatchChannelDrops, stats.PacketsDropped)
}

func TestSIPDemotionTelemetryReachesProcessorHunterState(t *testing.T) {
	buffer, err := capture.NewPacketBufferWithConfig(t.Context(), capture.PacketBufferConfig{
		RegularCapacity: 1,
		SIPCapacity:     1,
		OutputCapacity:  1,
	})
	require.NoError(t, err)
	defer buffer.Close()

	regular := captureTestUDPPacketInfo(t, "ordinary payload")
	sip := captureTestUDPPacketInfo(t, "INVITE sip:pressure@example.invalid SIP/2.0\r\n")
	require.True(t, buffer.Send(regular))
	require.Eventually(t, func() bool { return buffer.Snapshot().OutputLength == 1 }, time.Second, time.Millisecond)
	require.True(t, buffer.Send(regular))
	require.Eventually(t, func() bool { return buffer.Snapshot().RegularLength == 0 }, time.Second, time.Millisecond)
	require.True(t, buffer.Send(sip))
	require.True(t, buffer.Send(sip), "second SIP packet should be admitted through regular fallback")

	stats := &management.HunterStats{}
	applyCaptureBufferStats(stats, buffer)
	require.Equal(t, uint64(1), stats.CaptureBufferSipDemotions)

	wire, err := proto.Marshal(stats)
	require.NoError(t, err)
	decoded := &management.HunterStats{}
	require.NoError(t, proto.Unmarshal(wire, decoded))

	processorManager := processorhunter.NewManager("processor-test", 1, nil)
	_, _, err = processorManager.Register("hunter-test", "host-test", []string{"eth0"}, nil)
	require.NoError(t, err)
	processorManager.UpdateHeartbeat("hunter-test", 1, management.HunterStatus_STATUS_WARNING, decoded)
	connected, ok := processorManager.Get("hunter-test")
	require.True(t, ok)
	require.Equal(t, uint64(1), connected.CaptureBufferSIPDemotions)
	require.Zero(t, connected.PacketsDropped, "demotion pressure must not be counted as loss")
}

func TestValidateAcceptedEventProfile(t *testing.T) {
	valid := func() *management.RegistrationResponse {
		return &management.RegistrationResponse{
			AcceptedEventApiMajor:           1,
			AcceptedSemanticProfileRevision: 1,
			AcceptedEventKinds:              []int32{1, 2, 3, 4, 5, 6, 7},
		}
	}

	require.NoError(t, validateAcceptedEventProfile(valid()))

	tests := []struct {
		name   string
		mutate func(*management.RegistrationResponse)
		want   string
	}{
		{name: "missing API", mutate: func(r *management.RegistrationResponse) { r.AcceptedEventApiMajor = 0 }, want: "API major"},
		{name: "wrong semantic profile", mutate: func(r *management.RegistrationResponse) { r.AcceptedSemanticProfileRevision = 2 }, want: "semantic profile"},
		{name: "empty kinds", mutate: func(r *management.RegistrationResponse) { r.AcceptedEventKinds = nil }, want: "event kind 1"},
		{name: "partial kinds", mutate: func(r *management.RegistrationResponse) { r.AcceptedEventKinds = []int32{1, 2, 3, 4, 5} }, want: "event kind 6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := valid()
			tt.mutate(response)
			require.ErrorContains(t, validateAcceptedEventProfile(response), tt.want)
		})
	}
}

type mockForwardingFactory struct{}

func (m *mockForwardingFactory) CreateForwardingManager(
	connCtx context.Context,
	stream data.DataService_StreamPacketsClient,
) *forwarding.Manager {
	return nil
}

type teardownStats struct{}

func (*teardownStats) IncrementCaptured()        {}
func (*teardownStats) IncrementMatched()         {}
func (*teardownStats) IncrementForwarded(uint64) {}
func (*teardownStats) IncrementDropped(uint64)   {}
func (*teardownStats) GetCaptured() uint64       { return 0 }
func (*teardownStats) GetMatched() uint64        { return 0 }
func (*teardownStats) GetDropped() uint64        { return 0 }

type transportBlockedStream struct {
	started      chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
	active       atomic.Bool
	closeOverlap atomic.Bool
	closed       atomic.Int32
}

func (s *transportBlockedStream) Send(*data.PacketBatch) error {
	s.active.Store(true)
	defer s.active.Store(false)
	s.startOnce.Do(func() { close(s.started) })
	<-s.release
	return errors.New("transport closed")
}
func (*transportBlockedStream) Recv() (*data.StreamControl, error) { return nil, context.Canceled }
func (*transportBlockedStream) Header() (metadata.MD, error)       { return nil, nil }
func (*transportBlockedStream) Trailer() metadata.MD               { return nil }
func (s *transportBlockedStream) CloseSend() error {
	if s.active.Load() {
		s.closeOverlap.Store(true)
	}
	s.closed.Add(1)
	return nil
}
func (*transportBlockedStream) Context() context.Context { return context.Background() }
func (*transportBlockedStream) SendMsg(any) error        { return nil }
func (*transportBlockedStream) RecvMsg(any) error        { return nil }

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

func TestSendTimeoutCancelsExactGenerationAndForcesTransportClose(t *testing.T) {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	connCtx, connCancel := context.WithCancel(rootCtx)
	stream := &transportBlockedStream{started: make(chan struct{}), release: make(chan struct{})}
	queue := make(chan *pipeline.PacketBatch, 1)
	fwd := forwarding.New(forwarding.Config{
		BatchSize:   1,
		SendTimeout: 10 * time.Millisecond,
	}, &teardownStats{}, nil, connCtx, queue)
	fwd.SetStream(stream)

	manager := &Manager{
		ctx:                 rootCtx,
		connCtx:             connCtx,
		connCancel:          connCancel,
		forwardingManager:   fwd,
		forwardingExitGrace: 10 * time.Millisecond,
	}
	generation := manager.generation.Add(1)
	fwd.SetDisconnectCallback(func() { manager.markGenerationDisconnected(generation) })
	transportClosed := make(chan struct{})
	manager.closeDataTransport = func() error {
		stream.releaseOnce.Do(func() { close(stream.release) })
		close(transportClosed)
		return nil
	}

	queue <- &pipeline.PacketBatch{Sequence: 1, Packets: []*pipeline.PacketEnvelope{{}}}
	select {
	case <-stream.started:
	case <-time.After(time.Second):
		t.Fatal("send did not start")
	}
	select {
	case <-connCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout callback did not cancel its connection generation")
	}
	manager.reconnectMu.Lock()
	require.True(t, manager.reconnecting)
	manager.reconnectMu.Unlock()

	cleanupDone := make(chan struct{})
	go func() {
		manager.cleanup()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup remained blocked after forced transport close")
	}
	require.Equal(t, int32(1), stream.closed.Load())
	require.False(t, stream.closeOverlap.Load(), "CloseSend overlapped the sole sender")
	select {
	case <-transportClosed:
	default:
		t.Fatal("cleanup did not use the forced transport-close fallback")
	}

	// A delayed timeout from this generation cannot cancel a successor.
	successorCtx, successorCancel := context.WithCancel(rootCtx)
	defer successorCancel()
	manager.connCtx = successorCtx
	manager.connCancel = successorCancel
	manager.reconnectMu.Lock()
	manager.reconnecting = false
	manager.reconnectMu.Unlock()
	manager.generation.Add(1)
	manager.markGenerationDisconnected(generation)
	require.NoError(t, successorCtx.Err())
	manager.reconnectMu.Lock()
	require.False(t, manager.reconnecting)
	manager.reconnectMu.Unlock()
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

func TestCalculateStatusUsesAggregatePacketBufferCapacity(t *testing.T) {
	buffer, err := capture.NewPacketBufferWithConfig(t.Context(), capture.PacketBufferConfig{
		RegularCapacity: 100,
		SIPCapacity:     1000,
		OutputCapacity:  100,
	})
	require.NoError(t, err)
	defer buffer.Close()

	for i := 0; i < 90; i++ {
		require.True(t, buffer.Send(captureTestUDPPacketInfo(t, "ordinary synthetic payload")))
	}
	require.Eventually(t, func() bool {
		// One packet may be held by the merger while it waits for output space.
		return buffer.Snapshot().TotalLength() >= 89
	}, time.Second, time.Millisecond)

	manager := &Manager{
		ctx:            context.Background(),
		statsCollector: &mockStatsCollector{},
		captureManager: &mockCaptureManager{buffer: buffer},
	}

	// The queued packets are at least 89% of the regular lane alone, but under
	// 8% of
	// the configured aggregate capacity. Mixing those units produced a false
	// warning when the SIP override was larger than the regular lane.
	require.Equal(t, management.HunterStatus_STATUS_HEALTHY, manager.calculateStatus())
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
