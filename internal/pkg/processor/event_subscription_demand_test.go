//go:build processor || tap || all

package processor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func startDemandSubscription(t *testing.T, p *Processor) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 8)}
	done := make(chan error, 1)
	go func() {
		done <- p.eventService.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1}, stream)
	}()
	waitEventMessage(t, stream.notify)
	return cancel, done
}

func TestEventSubscriptionControlsStandaloneAnalysis(t *testing.T) {
	for _, mode := range []string{"packets", "events"} {
		t.Run(mode, func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "demand", UpstreamForwardMode: mode})
			require.NoError(t, err)
			require.False(t, p.wantsEventAnalysis())
			require.Nil(t, p.eventRuntime)
			cancelFirst, firstDone := startDemandSubscription(t, p)
			cancelSecond, secondDone := startDemandSubscription(t, p)
			require.Equal(t, mode == "events", p.wantsEventAnalysis())
			require.Equal(t, mode == "events", p.needsPacketProcessing())
			require.False(t, p.needsPacketOutput())
			cancelFirst()
			require.NoError(t, <-firstDone)
			require.Equal(t, mode == "events", p.wantsEventAnalysis(), "remaining subscriber keeps analysis alive")
			cancelSecond()
			require.NoError(t, <-secondDone)
			require.False(t, p.wantsEventAnalysis())
			require.False(t, p.needsPacketProcessing())
			require.Nil(t, p.eventRuntime, "last subscriber releases runtime and expiry worker")
		})
	}
}

func TestEventSubscriptionReleasePreservesConfiguredOutput(t *testing.T) {
	for _, output := range []string{"local", "upstream"} {
		t.Run(output, func(t *testing.T) {
			cfg := Config{ListenAddr: ":0", ProcessorID: "demand", UpstreamForwardMode: "events"}
			if output == "upstream" {
				cfg.UpstreamAddr = "upstream:55555"
				cfg.UpstreamEventSpoolDirectory = t.TempDir()
			}
			p, err := newTestProcessor(t, cfg)
			require.NoError(t, err)
			if output == "local" {
				require.NoError(t, p.RegisterEventSink(&collectingSink{}, events.KindDNS))
			}
			cancel, done := startDemandSubscription(t, p)
			cancel()
			require.NoError(t, <-done)
			require.True(t, p.wantsEventAnalysis())
			require.NotNil(t, p.eventRuntime)
		})
	}
}

func TestRejectedEventSubscriptionDoesNotStartAnalysis(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "demand", UpstreamForwardMode: "events"})
	require.NoError(t, err)
	stream := &eventSubscriptionTestStream{ctx: context.Background(), notify: make(chan struct{}, 1)}
	require.Error(t, p.eventService.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 99}, stream))
	require.Error(t, p.eventService.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, IncludeSensitiveFields: true}, stream))
	require.Nil(t, p.eventRuntime)
	require.False(t, p.needsPacketProcessing())
}

func TestEventSubscriptionAnalysisLifecycleConcurrentReaders(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "demand", UpstreamForwardMode: "events"})
	require.NoError(t, err)
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	ctx, stop := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		packet := &data.CapturedPacket{TimestampNs: time.Now().UnixNano(), Metadata: &data.PacketMetadata{
			SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 53000, DstPort: 53, Transport: "udp",
			Dns: &data.DNSMetadata{QueryName: "example.test", QueryType: "A", QueryClass: "IN"},
		}}
		for ctx.Err() == nil {
			p.emitProtocolEvents("demand-local", []*data.CapturedPacket{packet})
			p.eventAnalysisStats()
			p.needsPacketProcessing()
			if err := p.resetEventAnalysis(); err != nil {
				t.Errorf("reset analysis: %v", err)
				return
			}
		}
	}()
	defer func() { stop(); workers.Wait() }()
	for i := 0; i < 8; i++ {
		cancel, done := startDemandSubscription(t, p)
		cancel()
		require.NoError(t, <-done)
	}
	cancel, done := startDemandSubscription(t, p)
	require.NoError(t, p.Shutdown())
	cancel()
	require.NoError(t, <-done)
	require.False(t, p.wantsEventAnalysis())
	require.Nil(t, p.eventRuntime)
	require.Error(t, p.RegisterEventSink(&collectingSink{}))
}
