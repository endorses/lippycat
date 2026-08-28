package voip

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lifecycleSIPHandler struct{}

func (lifecycleSIPHandler) HandleSIPMessage([]byte, string, string, string, gopacket.Flow, gopacket.Flow) bool {
	return true
}

type countingLifecycleSIPHandler struct{ messages atomic.Int64 }

func (h *countingLifecycleSIPHandler) HandleSIPMessage([]byte, string, string, string, gopacket.Flow, gopacket.Flow) bool {
	h.messages.Add(1)
	return true
}

type lifecycleScatterGather struct{ data []byte }

func (s *lifecycleScatterGather) Lengths() (int, int)     { return len(s.data), 0 }
func (s *lifecycleScatterGather) Fetch(length int) []byte { return s.data[:length] }
func (*lifecycleScatterGather) KeepFrom(int)              {}
func (*lifecycleScatterGather) CaptureInfo(int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}
}
func (*lifecycleScatterGather) Info() (reassembly.TCPFlowDirection, bool, bool, int) {
	return reassembly.TCPDirClientToServer, false, false, 0
}
func (*lifecycleScatterGather) Stats() reassembly.TCPAssemblyStats {
	return reassembly.TCPAssemblyStats{}
}

func TestSipStreamFactoryGoroutineMonitoring(t *testing.T) {
	t.Run("Factory initialization", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		factory := NewSipStreamFactory(ctx, NewLocalFileHandler())
		defer factory.(*sipStreamFactory).Shutdown()
		sipFactory, ok := factory.(*sipStreamFactory)
		assert.True(t, ok, "Factory should be of correct type")

		// Initially no active goroutines
		assert.Equal(t, int64(0), sipFactory.GetActiveGoroutines())
		assert.Equal(t, int64(DefaultGoroutineLimit), sipFactory.GetMaxGoroutines())

		// Test monitoring methods exist and return valid values
		assert.True(t, sipFactory.GetMaxGoroutines() > 0)
		assert.True(t, sipFactory.GetActiveGoroutines() >= 0)

		factory.(*sipStreamFactory).Close()
	})

	t.Run("Goroutine limit configuration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		factory := NewSipStreamFactory(ctx, NewLocalFileHandler())
		defer factory.(*sipStreamFactory).Shutdown()
		sipFactory, ok := factory.(*sipStreamFactory)
		assert.True(t, ok, "Factory should be of correct type")

		// Test that we can set different limits
		sipFactory.config.MaxGoroutines = 500
		assert.Equal(t, int64(500), sipFactory.GetMaxGoroutines())

		sipFactory.config.MaxGoroutines = 100
		assert.Equal(t, int64(100), sipFactory.GetMaxGoroutines())

		factory.(*sipStreamFactory).Close()
	})
}

func TestSIPReassemblyStreamLifecycleBaseline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	factory := NewSipStreamFactory(ctx, lifecycleSIPHandler{}).(*sipStreamFactory)
	metricsBefore := GetTCPStreamMetrics()
	payload := []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: lifecycle\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")

	for i := 0; i < 64; i++ {
		netFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(192, 0, 2, byte(i+1)).To4(), net.IPv4(198, 51, 100, 1).To4())
		srcPort := layers.NewTCPPortEndpoint(layers.TCPPort(20000 + i))
		dstPort := layers.NewTCPPortEndpoint(5060)
		transportFlow := gopacket.NewFlow(layers.EndpointTCPPort, srcPort.Raw(), dstPort.Raw())
		stream := factory.New(netFlow, transportFlow, &layers.TCP{}, nil).(*bufferedSIPStream)
		stream.ReassembledSG(&lifecycleScatterGather{data: append([]byte(nil), payload...)}, nil)
		stream.ReassemblyComplete(nil)
	}
	factory.Close()
	metricsAfter := GetTCPStreamMetrics()
	require.Equal(t, int64(0), factory.GetActiveGoroutines(), "factory close must wait for every SIP stream worker")
	require.Equal(t, metricsBefore.ActiveStreams, metricsAfter.ActiveStreams, "SIP stream metrics must return to their pre-test baseline")
	require.GreaterOrEqual(t, metricsAfter.TotalStreamsCreated-metricsBefore.TotalStreamsCreated, int64(64))
}

func TestSIPReassemblyRetainedHeapBaseline(t *testing.T) {
	before := liveHeapBytes()
	for cycle := 0; cycle < 20; cycle++ {
		ctx, cancel := context.WithCancel(context.Background())
		factory := NewSipStreamFactory(ctx, lifecycleSIPHandler{}).(*sipStreamFactory)
		assembler := capture.NewTCPAssemblerWithLimits(factory, 3, 256)
		for i := 0; i < 128; i++ {
			netFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(192, 0, 2, byte(i%250+1)).To4(), net.IPv4(198, 51, 100, 1).To4())
			base := uint32(1000 + i*1000)
			assembleLifecycleTCP(t, assembler, netFlow, layers.TCPPort(20000+i), base, true, nil, time.Unix(int64(cycle+1), 0))
			// Retain out-of-order data behind a missing segment, then require the
			// assembler/factory shutdown path to release it all.
			assembleLifecycleTCP(t, assembler, netFlow, layers.TCPPort(20000+i), base+3, false, []byte("partial-sip"), time.Unix(int64(cycle+1), int64(i+1)))
		}
		assembler.FlushAll()
		factory.Close()
		cancel()
		require.Zero(t, factory.GetActiveGoroutines())
	}
	after := liveHeapBytes()
	const maxRetainedGrowth = uint64(8 << 20)
	if after > before+maxRetainedGrowth {
		t.Fatalf("SIP reassembly retained heap grew by %d bytes, limit %d", after-before, maxRetainedGrowth)
	}
}

func TestBoundedTCPAssemblerSIPLifecycleBaseline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	handler := &countingLifecycleSIPHandler{}
	factory := NewSipStreamFactory(ctx, handler).(*sipStreamFactory)
	assembler := capture.NewTCPAssemblerWithLimits(factory, 3, 64)
	metricsBefore := GetTCPStreamMetrics()
	payload := []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: assembler-lifecycle\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")

	for i := 0; i < 32; i++ {
		netFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(192, 0, 2, byte(i+1)).To4(), net.IPv4(198, 51, 100, 1).To4())
		base := uint32(1000 + i*1000)
		assembleLifecycleTCP(t, assembler, netFlow, layers.TCPPort(20000+i), base, true, nil, time.Unix(int64(i+1), 0))
		cut := len(payload) / 2
		assembleLifecycleTCP(t, assembler, netFlow, layers.TCPPort(20000+i), base+1, false, payload[:cut], time.Unix(int64(i+1), 100))
		assembleLifecycleTCP(t, assembler, netFlow, layers.TCPPort(20000+i), base+1+uint32(cut), false, payload[cut:], time.Unix(int64(i+1), 200))
	}

	// Exercise bounded retention with a real SIP factory behind the assembler.
	// These out-of-order pages leave gaps and must be released by the finite
	// per-connection limit rather than retained until shutdown.
	gapFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(203, 0, 113, 1).To4(), net.IPv4(198, 51, 100, 1).To4())
	assembleLifecycleTCP(t, assembler, gapFlow, 30000, 50000, true, nil, time.Unix(100, 0))
	for i := uint32(0); i < 4; i++ {
		assembleLifecycleTCP(t, assembler, gapFlow, 30000, 50003+i*2, false, []byte{'x'}, time.Unix(100, int64(i+1)))
	}
	require.Eventually(t, func() bool { return handler.messages.Load() >= 32 }, time.Second, time.Millisecond)
	require.NotZero(t, assembler.LimitStats().BufferedPageLimitReleases)

	assembler.FlushAll()
	factory.Close()
	cancel()
	metricsAfter := GetTCPStreamMetrics()
	require.Zero(t, factory.GetActiveGoroutines())
	require.Equal(t, metricsBefore.ActiveStreams, metricsAfter.ActiveStreams)
}

func assembleLifecycleTCP(t *testing.T, assembler *capture.TCPAssembler, netFlow gopacket.Flow, srcPort layers.TCPPort, seq uint32, syn bool, payload []byte, timestamp time.Time) {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP(netFlow.Src().Raw()), DstIP: net.IP(netFlow.Dst().Raw())}
	tcpToEncode := &layers.TCP{
		SrcPort: srcPort, DstPort: 5060, Seq: seq, SYN: syn, ACK: !syn,
	}
	require.NoError(t, tcpToEncode.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcpToEncode, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	assembler.Assemble(netFlow, tcp, timestamp)
}

func liveHeapBytes() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}
