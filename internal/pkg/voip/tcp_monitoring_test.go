package voip

import (
	"context"
	"net"
	"testing"
	"time"

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
