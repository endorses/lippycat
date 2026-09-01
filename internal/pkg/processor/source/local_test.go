package source

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLocalSourceConfig(t *testing.T) {
	cfg := DefaultLocalSourceConfig()

	assert.Equal(t, 100, cfg.BatchSize)
	assert.Equal(t, 100*time.Millisecond, cfg.BatchTimeout)
	assert.Equal(t, 10000, cfg.BufferSize)
	assert.Equal(t, 1000, cfg.BatchBuffer)
	assert.False(t, cfg.IncludeHTTPHeaders)
}

func TestNewLocalSource_AppliesDefaults(t *testing.T) {
	// Empty config should get defaults applied
	cfg := LocalSourceConfig{
		Interfaces: []string{"eth0"},
	}

	s := NewLocalSource(cfg)
	require.NotNil(t, s)

	assert.Equal(t, 100, s.config.BatchSize)
	assert.Equal(t, 100*time.Millisecond, s.config.BatchTimeout)
	assert.Equal(t, 10000, s.config.BufferSize)
	assert.Equal(t, 1000, s.config.BatchBuffer)
	assert.Equal(t, []string{"eth0"}, s.config.Interfaces)
}

func TestInjectedPacketCompletionMovesWithBatchWithoutRunning(t *testing.T) {
	cfg := DefaultLocalSourceConfig()
	cfg.BatchSize = 1
	s := NewLocalSource(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.ctx = ctx
	injected := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injected)
	input := make(chan capture.PacketInfo)
	done := make(chan struct{})
	go func() {
		s.batchingWorker(input)
		close(done)
	}()

	var completed atomic.Bool
	injected <- InjectedPacket{
		PacketInfo:   buildTCPPacket(t, 1),
		AfterProcess: func() { completed.Store(true) },
	}

	select {
	case batch := <-s.Batches():
		require.False(t, completed.Load(), "batching must not complete the call")
		require.Len(t, batch.AfterProcess, 1)
		batch.RunAfterProcess()
		require.True(t, completed.Load())
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for injected packet batch")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batching worker did not stop")
	}
}

func TestNonInjectionWorkerDoesNotConsumeReassembledPackets(t *testing.T) {
	cfg := DefaultLocalSourceConfig()
	s := NewLocalSource(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.ctx = ctx

	injected := make(chan InjectedPacket, 1)
	injected <- InjectedPacket{PacketInfo: buildTCPPacket(t, 1)}
	s.SetTCPInjectionChannel(injected)
	input := make(chan capture.PacketInfo)
	close(input)

	done := make(chan struct{})
	go func() {
		s.batchingWorkerWithInjection(input, false)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("non-injection worker did not stop")
	}
	require.Len(t, injected, 1, "only the designated worker may consume ordered TCP injections")
}

func TestDroppedBatchRunsDeferredCompletion(t *testing.T) {
	cfg := DefaultLocalSourceConfig()
	cfg.BatchBuffer = 1
	s := NewLocalSource(cfg)

	// Occupy the only channel slot so sendBatch takes its definitive-drop path.
	s.batches <- &PacketBatch{}
	var completions atomic.Int32
	s.batchMu.Lock()
	s.currentBatch = append(s.currentBatch, &pipeline.PacketEnvelope{Data: []byte("terminal")})
	s.currentBatchAfterProcess = append(s.currentBatchAfterProcess, func() { completions.Add(1) })
	s.batchMu.Unlock()

	s.sendBatch()
	require.Equal(t, int32(1), completions.Load())
}

func TestFilteredInjectedPacketRunsDeferredCompletion(t *testing.T) {
	cfg := DefaultLocalSourceConfig()
	s := NewLocalSource(cfg)
	s.SetApplicationFilter(&mockAppFilter{matchAll: false})
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	injected := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injected)
	input := make(chan capture.PacketInfo)
	done := make(chan struct{})
	go func() {
		s.batchingWorker(input)
		close(done)
	}()

	var completions atomic.Int32
	injected <- InjectedPacket{
		PacketInfo: buildTCPPacket(t, 1),
		Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{
			CallId: "filtered-terminal",
		}},
		AfterProcess: func() { completions.Add(1) },
	}

	require.Eventually(t, func() bool { return completions.Load() == 1 }, time.Second, time.Millisecond)
	select {
	case batch := <-s.Batches():
		t.Fatalf("filtered packet unexpectedly produced batch: %+v", batch)
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batching worker did not stop")
	}
	require.Equal(t, int32(1), completions.Load())
}

func TestNewLocalSource_PreservesCustomConfig(t *testing.T) {
	cfg := LocalSourceConfig{
		Interfaces:   []string{"eth0", "eth1"},
		BPFFilter:    "port 5060",
		BatchSize:    200,
		BatchTimeout: 50 * time.Millisecond,
		BufferSize:   5000,
		BatchBuffer:  500,
	}

	s := NewLocalSource(cfg)
	require.NotNil(t, s)

	assert.Equal(t, 200, s.config.BatchSize)
	assert.Equal(t, 50*time.Millisecond, s.config.BatchTimeout)
	assert.Equal(t, 5000, s.config.BufferSize)
	assert.Equal(t, 500, s.config.BatchBuffer)
	assert.Equal(t, []string{"eth0", "eth1"}, s.config.Interfaces)
	assert.Equal(t, "port 5060", s.config.BPFFilter)
}

func TestLocalSource_SourceID(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())
	assert.Equal(t, "local", s.SourceID())
}

func TestLocalSource_IsStarted(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	// Initially not started
	assert.False(t, s.IsStarted())
}

func TestLocalSource_Stats(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	stats := s.Stats()
	assert.Equal(t, uint64(0), stats.PacketsCaptured)
	assert.Equal(t, uint64(0), stats.PacketsForwarded)
	assert.Equal(t, uint64(0), stats.PacketsDropped)
	assert.Equal(t, uint64(0), stats.BytesReceived)
	assert.Equal(t, uint64(0), stats.BatchesReceived)
}

func TestLocalSource_Stats_IncludesCaptureBufferDrops(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	pb := capture.NewPacketBuffer(t.Context(), 1)
	defer pb.Close()
	s.packetBuffer.Store(pb)

	// Nothing drains the buffer, so sends overflow into the drop counter.
	for i := 0; i < 100; i++ {
		pb.Send(buildUDPPacket(t, 12345, "not sip"))
	}
	require.Positive(t, pb.GetDropped())

	s.stats.AddDropped(5) // batch channel overflow

	stats := s.Stats()
	assert.Equal(t, uint64(pb.GetDropped()), stats.CaptureBufferRegularDrops)
	assert.Zero(t, stats.CaptureBufferSIPDrops)
	assert.Equal(t, uint64(5), stats.BatchChannelDrops)
	assert.Equal(t, stats.CaptureBufferRegularDrops+stats.CaptureBufferSIPDrops+stats.BatchChannelDrops, stats.PacketsDropped)
}

func TestLocalSource_SetBPFFilter_BeforeStart(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{
		Interfaces: []string{"eth0"},
		BPFFilter:  "port 5060",
	})

	// Update filter before start
	err := s.SetBPFFilter("port 5061")
	require.NoError(t, err)

	// Filter should be updated
	assert.Equal(t, "port 5061", s.config.BPFFilter)
}

func TestLocalSource_SetBPFFilter_UnchangedDoesNotRestartCapture(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{
		Interfaces: []string{"eth0"},
		BPFFilter:  "port 5060",
	})

	// Model a running source without opening a privileged live capture. A
	// redundant update must leave the capture generation untouched.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.started = true
	s.captureCtx = ctx
	s.captureCancel = cancel

	require.NoError(t, s.SetBPFFilter("port 5060"))
	assert.Same(t, ctx, s.captureCtx)
	assert.NoError(t, ctx.Err())
}

func TestLocalSource_Batches_ReturnsChannel(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	ch := s.Batches()
	require.NotNil(t, ch)

	// Channel should be readable
	select {
	case <-ch:
		t.Error("expected channel to be empty")
	default:
		// Expected: channel is empty
	}
}

func TestLocalSource_SetApplicationFilter(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	// Create a mock filter
	mockFilter := &mockAppFilter{matchAll: true}

	// Set filter
	s.SetApplicationFilter(mockFilter)

	// Get filter back (indirectly through internal state)
	s.mu.Lock()
	filter := s.appFilter
	s.mu.Unlock()

	assert.Equal(t, mockFilter, filter)

	// Set to nil
	s.SetApplicationFilter(nil)

	s.mu.Lock()
	filter = s.appFilter
	s.mu.Unlock()

	assert.Nil(t, filter)
}

func TestLocalSource_Stop_BeforeStart(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())

	// Should not panic when stopped before start
	s.Stop()
	assert.False(t, s.IsStarted())
}

func TestLocalSourceShutdownWithFullWorkerChannels(t *testing.T) {
	viper.Set("processor.detection_workers", 2)
	t.Cleanup(viper.Reset)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s := NewLocalSource(LocalSourceConfig{
		BatchSize:    100,
		BatchTimeout: time.Hour,
		BufferSize:   detectionWorkerChanBuffer + 64,
		BatchBuffer:  1,
	})
	s.ctx = ctx
	s.cancel = cancel

	blocker := &blockingTCPAssembler{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(blocker.Release)
	s.SetTCPAssembler(blocker)

	pb := capture.NewPacketBuffer(ctx, detectionWorkerChanBuffer+64)
	t.Cleanup(pb.Close)
	s.packetBuffer.Store(pb)

	for i := 0; i < detectionWorkerChanBuffer+32; i++ {
		require.True(t, pb.Send(buildTCPPacket(t, uint32(1000+i))), "packet %d should enqueue", i)
	}

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		s.batchingLoop()
		close(done)
	}()

	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("blocking assembler was not reached")
	}

	time.Sleep(20 * time.Millisecond)
	cancel()
	blocker.Release()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batchingLoop did not exit after cancellation")
	}
}

func TestLocalSourceTCPFlowRoutingPreservesBidirectionalOrder(t *testing.T) {
	viper.Set("processor.detection_workers", 4)
	t.Cleanup(viper.Reset)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewLocalSource(LocalSourceConfig{BatchSize: 100, BatchTimeout: time.Hour, BufferSize: 16, BatchBuffer: 1})
	s.ctx = ctx
	s.cancel = cancel
	recorder := &orderedTCPAssembler{}
	s.SetTCPAssembler(recorder)
	pb := capture.NewPacketBuffer(ctx, 16)
	s.packetBuffer.Store(pb)

	packets := []capture.PacketInfo{
		buildTCPFlowPacket(t, "192.0.2.10", "192.0.2.20", 5060, 5080, 1),
		buildTCPFlowPacket(t, "192.0.2.20", "192.0.2.10", 5080, 5060, 2),
		buildTCPFlowPacket(t, "192.0.2.10", "192.0.2.20", 5060, 5080, 3),
		buildTCPFlowPacket(t, "192.0.2.20", "192.0.2.10", 5080, 5060, 4),
	}
	for _, pkt := range packets {
		require.True(t, pb.Send(pkt))
	}
	pb.CloseInputs()

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		s.batchingLoop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batchingLoop did not drain")
	}
	assert.Equal(t, []uint32{1, 2, 3, 4}, recorder.Sequences())
	assert.Equal(t, int32(1), recorder.MaxConcurrency(), "opposite directions of one flow must stay on one worker")
}

func TestLocalSourceTCPIndependentFlowsExecuteConcurrently(t *testing.T) {
	const workers = 2
	viper.Set("processor.detection_workers", workers)
	t.Cleanup(viper.Reset)

	var packets [workers]capture.PacketInfo
	found := [workers]bool{}
	for port := uint16(10000); port < 20000 && (!found[0] || !found[1]); port++ {
		pkt := buildTCPFlowPacket(t, "192.0.2.10", "192.0.2.20", port, 5060, uint32(port))
		idx := pipeline.FlowShard(pkt.Packet.NetworkLayer().NetworkFlow(), pkt.Packet.TransportLayer().TransportFlow(), workers)
		if !found[idx] {
			packets[idx] = pkt
			found[idx] = true
		}
	}
	require.True(t, found[0] && found[1], "test flows must cover both workers")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewLocalSource(LocalSourceConfig{BatchSize: 100, BatchTimeout: time.Hour, BufferSize: 4, BatchBuffer: 1})
	s.ctx = ctx
	s.cancel = cancel
	assembler := newConcurrentTCPAssembler(2)
	t.Cleanup(assembler.Release)
	s.SetTCPAssembler(assembler)
	pb := capture.NewPacketBuffer(ctx, 4)
	s.packetBuffer.Store(pb)
	require.True(t, pb.Send(packets[0]))
	require.True(t, pb.Send(packets[1]))
	pb.CloseInputs()

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		s.batchingLoop()
		close(done)
	}()
	select {
	case <-assembler.allEntered:
		// Both workers reached the assembler before either was released.
	case <-time.After(time.Second):
		t.Fatal("independent TCP flows did not execute concurrently")
	}
	assembler.Release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batchingLoop did not drain")
	}
}

func TestLocalSource_StartMultipleTimes(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{
		Interfaces: []string{"lo"}, // Use loopback for test
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Start in goroutine (will block on first call)
	started := make(chan struct{})
	go func() {
		close(started)
		_ = s.Start(ctx)
	}()

	<-started
	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Second start should return immediately (already started)
	done := make(chan struct{})
	go func() {
		_ = s.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Expected: second start returns immediately
	case <-time.After(100 * time.Millisecond):
		t.Error("second Start() should return immediately")
	}

	// Cleanup
	cancel()
	time.Sleep(50 * time.Millisecond) // Allow goroutines to exit
}

// mockAppFilter is a test mock for ApplicationFilter
type mockAppFilter struct {
	matchAll bool
	calls    int
}

type blockingTCPAssembler struct {
	entered     chan struct{}
	release     chan struct{}
	once        atomic.Bool
	releaseOnce sync.Once
}

type orderedTCPAssembler struct {
	mu        sync.Mutex
	sequences []uint32
	active    atomic.Int32
	maxActive atomic.Int32
}

func (a *orderedTCPAssembler) AssemblePacket(pkt capture.PacketInfo) bool {
	active := a.active.Add(1)
	for old := a.maxActive.Load(); active > old && !a.maxActive.CompareAndSwap(old, active); old = a.maxActive.Load() {
	}
	defer a.active.Add(-1)
	// Give an incorrectly routed reverse-direction packet time to overlap.
	time.Sleep(10 * time.Millisecond)
	tcp := pkt.Packet.TransportLayer().(*layers.TCP)
	a.mu.Lock()
	a.sequences = append(a.sequences, tcp.Seq)
	a.mu.Unlock()
	return true
}

func (a *orderedTCPAssembler) MaxConcurrency() int32 { return a.maxActive.Load() }

func (a *orderedTCPAssembler) Sequences() []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint32(nil), a.sequences...)
}

type concurrentTCPAssembler struct {
	entered     atomic.Int32
	want        int32
	allEntered  chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newConcurrentTCPAssembler(want int32) *concurrentTCPAssembler {
	return &concurrentTCPAssembler{want: want, allEntered: make(chan struct{}), release: make(chan struct{})}
}

func (a *concurrentTCPAssembler) AssemblePacket(_ capture.PacketInfo) bool {
	if a.entered.Add(1) == a.want {
		a.enterOnce.Do(func() { close(a.allEntered) })
	}
	<-a.release
	return true
}

func (a *concurrentTCPAssembler) Release() {
	a.releaseOnce.Do(func() { close(a.release) })
}

func (b *blockingTCPAssembler) AssemblePacket(_ capture.PacketInfo) bool {
	if b.once.CompareAndSwap(false, true) {
		close(b.entered)
	}
	<-b.release
	return true
}

func (b *blockingTCPAssembler) Release() {
	b.releaseOnce.Do(func() {
		close(b.release)
	})
}

func buildTCPPacket(t *testing.T, seq uint32) capture.PacketInfo {
	return buildTCPFlowPacket(t, "192.0.2.10", "192.0.2.20", 5060, 5060, seq)
}

func buildTCPFlowPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq uint32) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: seq, ACK: true, PSH: true, Window: 8192}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"))))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	return capture.PacketInfo{LinkType: layers.LinkTypeEthernet, Packet: pkt, Interface: "test"}
}

func (m *mockAppFilter) MatchPacket(_ gopacket.Packet) bool {
	m.calls++
	return m.matchAll
}

func (m *mockAppFilter) MatchPacketWithIDs(_ gopacket.Packet) (bool, []string) {
	m.calls++
	return m.matchAll, nil
}

func (m *mockAppFilter) MatchPacketLevelWithIDs(packet gopacket.Packet) (bool, []string) {
	return m.MatchPacketWithIDs(packet)
}

func TestLocalSource_ImplementsPacketSource(t *testing.T) {
	// Compile-time check is in the source file, but let's verify at runtime too
	var _ PacketSource = (*LocalSource)(nil)
}

func TestConvertPacketInfo(t *testing.T) {
	// Test with nil packet
	t.Run("handles nil packet data", func(t *testing.T) {
		// This would require more complex setup with actual gopacket
		// For now, we just verify the function doesn't panic
	})
}
