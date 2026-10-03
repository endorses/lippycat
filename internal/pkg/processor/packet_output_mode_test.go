//go:build processor || tap || all

package processor

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestProcessBatchWithoutOutputsSkipsProjection(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "idle"})
	require.NoError(t, err)
	require.False(t, p.needsPacketProcessing())
	require.Nil(t, p.eventRuntime)
	completed := 0
	batch := &source.PacketBatch{
		SourceID: "local",
		// Invalid projection would fail if the idle path attempted conversion.
		Envelopes:    []*pipeline.PacketEnvelope{nil},
		AfterProcess: []func(){func() { completed++ }},
	}
	p.processBatch(batch)
	require.Equal(t, uint64(1), p.packetsReceived.Load())
	require.Equal(t, 1, completed)
	require.Empty(t, batch.AfterProcess)
	require.Empty(t, p.callAggregator.GetCalls())
}

type demandCallStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *demandCallStream) Context() context.Context              { return s.ctx }
func (s *demandCallStream) Send(*data.CorrelatedCallUpdate) error { return nil }

func TestCorrelatedCallSubscriptionCreatesPacketDemand(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "calls"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- p.SubscribeCorrelatedCalls(&data.SubscribeRequest{}, &demandCallStream{ctx: ctx})
	}()
	require.Eventually(t, func() bool { return p.correlatedCallSubscribers.Load() == 1 }, time.Second, time.Millisecond)
	require.True(t, p.needsPacketProcessing())
	require.False(t, p.hasPacketSubscribers(), "call monitoring does not need raw packet serialization")
	require.False(t, p.wantsEventAnalysis())
	p.processBatch(source.FromProtoBatch(&data.PacketBatch{
		HunterId: "hunter", TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				SrcIp: "192.0.2.1", DstIp: "192.0.2.2", Transport: "udp",
				SrcPort: 5060, DstPort: 5060,
				Sip: &data.SIPMetadata{CallId: "monitored", Method: "INVITE", FromUser: "alice", ToUser: "bob"},
			},
		}},
	}))
	require.Len(t, p.callAggregator.GetCalls(), 1)
	cancel()
	require.NoError(t, <-done)
	require.False(t, p.needsPacketProcessing())
}

func TestProcessBatchEventModeSkipsPacketOutputs(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "events"})
	require.NoError(t, err)
	p.upstreamManager = upstream.NewManager(upstream.Config{ForwardMode: "events"}, nil)
	require.NoError(t, p.initializeEventAnalysis())
	packets := p.subscriberManager.Add("packet-client")
	require.True(t, p.needsPacketProcessing())
	require.False(t, p.needsPacketOutput())
	batch := source.FromProtoBatch(&data.PacketBatch{
		HunterId: "hunter", TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				SrcIp: "192.0.2.1", DstIp: "192.0.2.2", Transport: "udp",
				SrcPort: 5060, DstPort: 5060,
				Sip: &data.SIPMetadata{CallId: "event-only", Method: "INVITE"},
			},
		}},
	})
	p.processBatch(batch)
	require.Equal(t, uint64(1), p.eventRuntime.Stats().Observed)
	require.Empty(t, p.callAggregator.GetCalls())
	select {
	case <-packets:
		t.Fatal("event mode published a packet batch")
	default:
	}
}

func TestPacketDemandTracksOutputs(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "demand"})
	require.NoError(t, err)
	require.False(t, p.needsPacketProcessing())
	p.subscriberManager.Add("packet-client")
	require.True(t, p.needsPacketProcessing())
	p.subscriberManager.Remove("packet-client")
	require.False(t, p.needsPacketProcessing())
	p.upstreamManager = upstream.NewManager(upstream.Config{ForwardMode: "packets"}, nil)
	require.True(t, p.needsPacketOutput())
	require.False(t, p.wantsEventAnalysis())
	p.upstreamManager = nil
	p.config.WriteFile = "explicit-local.pcap"
	require.True(t, p.needsPacketProcessing())
	require.False(t, p.wantsEventAnalysis())
}
