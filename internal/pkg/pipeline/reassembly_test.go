package pipeline

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testReassemblyFactory struct {
	shutdowns atomic.Int32
	completed atomic.Int32
	err       error
}

func (f *testReassemblyFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, reassembly.AssemblerContext) reassembly.Stream {
	return testReassemblyStream{factory: f}
}
func (f *testReassemblyFactory) Shutdown() error {
	f.shutdowns.Add(1)
	return f.err
}

type testReassemblyStream struct{ factory *testReassemblyFactory }

func (testReassemblyStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true
	return true
}
func (testReassemblyStream) ReassembledSG(reassembly.ScatterGather, reassembly.AssemblerContext) {}
func (s testReassemblyStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
	if s.factory != nil {
		s.factory.completed.Add(1)
	}
	return true
}

func testTCPPacket(seq uint32) (gopacket.Flow, *layers.TCP) {
	return gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}), &layers.TCP{
		SrcPort: 5060, DstPort: 5060, Seq: seq, SYN: seq == 1,
	}
}

func TestReassemblyEngineCloseIsIdempotent(t *testing.T) {
	factory := &testReassemblyFactory{}
	engine := NewReassemblyEngine(factory, DefaultReassemblyConfig())
	require.NoError(t, engine.Close())
	require.NoError(t, engine.Close())
	assert.Equal(t, int32(1), factory.shutdowns.Load())
	flow, tcp := testTCPPacket(1)
	assert.ErrorIs(t, engine.AssembleTCP(flow, tcp, time.Now()), ErrReassemblyClosed)
}

func TestReassemblyEngineReturnsFactoryShutdownError(t *testing.T) {
	factory := &testReassemblyFactory{err: errors.New("factory failed")}
	engine := NewReassemblyEngine(factory, DefaultReassemblyConfig())
	err := engine.Close()
	require.Error(t, err)
	assert.ErrorContains(t, err, "factory failed")
	assert.Equal(t, err, engine.Close())
}

func TestReassemblyEngineConcurrentAssembleCancelAndClose(t *testing.T) {
	factory := &testReassemblyFactory{}
	engine := NewReassemblyEngine(factory, ReassemblyConfig{
		FlushInterval: time.Millisecond,
		IdleTimeout:   time.Millisecond,
	})
	ctx := context.Background()
	runDone := make(chan error, 1)
	go func() { runDone <- engine.Run(ctx) }()

	var wg sync.WaitGroup
	workerErrs := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(offset uint32) {
			defer wg.Done()
			for i := uint32(1); i < 100; i++ {
				flow, tcp := testTCPPacket(i + offset)
				err := engine.AssembleTCP(flow, tcp, time.Unix(int64(i), 0))
				if errors.Is(err, ErrReassemblyClosed) {
					return
				}
				if err != nil {
					workerErrs <- err
					return
				}
			}
		}(uint32(worker * 1000))
	}
	require.NoError(t, engine.Close())
	wg.Wait()
	require.NoError(t, <-runDone)
	close(workerErrs)
	for err := range workerErrs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), factory.shutdowns.Load())
}

func TestReassemblyEngineCancellationStopsRun(t *testing.T) {
	engine := NewReassemblyEngine(&testReassemblyFactory{}, DefaultReassemblyConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	cancel()
	require.NoError(t, <-done)
	require.NoError(t, engine.Close())
}

type manualTicker struct{ ch chan time.Time }

func (t *manualTicker) C() <-chan time.Time { return t.ch }
func (*manualTicker) Stop()                 {}

type manualClock struct {
	mu     sync.Mutex
	now    time.Time
	ticker *manualTicker
}

func (c *manualClock) Now() time.Time { return c.now }
func (c *manualClock) NewTicker(time.Duration) Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticker = &manualTicker{ch: make(chan time.Time, 1)}
	return c.ticker
}
func (c *manualClock) Ticker() *manualTicker {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ticker
}

func TestReassemblyEngineOfflineTimestampAging(t *testing.T) {
	clock := &manualClock{now: time.Unix(0, 0)}
	factory := &testReassemblyFactory{}
	engine := NewReassemblyEngine(factory, ReassemblyConfig{
		FlushInterval: time.Second,
		IdleTimeout:   time.Minute,
		Clock:         clock,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	require.Eventually(t, func() bool { return clock.Ticker() != nil }, time.Second, time.Millisecond)

	first := serializedTCPEnvelope(t, time.Unix(3600, 0), 1, SourcePCAPReplay)
	second := serializedTCPEnvelope(t, time.Unix(3720, 0), 2, SourcePCAPReplay)
	require.NoError(t, engine.Assemble(first))
	require.NoError(t, engine.Assemble(second))
	clock.Ticker().ch <- clock.now
	require.Eventually(t, func() bool {
		engine.stateMu.RLock()
		defer engine.stateMu.RUnlock()
		return engine.captureTimeAging && engine.latestCaptureTime.Equal(second.CaptureTime)
	}, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return factory.completed.Load() >= 1 }, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	require.NoError(t, engine.Close())
}

func serializedTCPEnvelope(t *testing.T, ts time.Time, lastIP byte, kind SourceKind) *PacketEnvelope {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []byte{10, 0, 0, lastIP}, DstIP: []byte{10, 0, 1, lastIP}}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, SYN: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp))
	return &PacketEnvelope{Data: buf.Bytes(), LinkType: layers.LinkTypeEthernet, CaptureTime: ts, Source: SourceProvenance{Kind: kind}}
}

func TestReassemblyEnginePreservesConfiguredBounds(t *testing.T) {
	engine := NewReassemblyEngine(&testReassemblyFactory{}, ReassemblyConfig{
		MaxBufferedPagesPerConnection: 7,
		MaxBufferedPagesTotal:         19,
	})
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	perConnection, total := engine.BufferedPageLimits()
	assert.Equal(t, 7, perConnection)
	assert.Equal(t, 19, total)
}
