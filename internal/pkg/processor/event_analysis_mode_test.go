//go:build processor || tap || all

package processor

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/stretchr/testify/require"
)

func TestEventAnalysisRequiresConfiguredOutput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		mode     string
		logStage string
		want     bool
	}{
		{name: "standalone defaults"},
		{name: "standalone event mode without destination", mode: "events"},
		{name: "packet forwarding", upstream: "upstream:55555", mode: "packets"},
		{name: "event forwarding", upstream: "upstream:55555", mode: "events", want: true},
		{name: "terminal structured logs", logStage: "terminal", want: true},
		{name: "forwarding structured logs", upstream: "upstream:55555", mode: "packets", logStage: "all", want: true},
		{name: "terminal logs suppressed on relay", upstream: "upstream:55555", mode: "packets", logStage: "terminal"},
		{name: "explicitly disabled logs", logStage: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ListenAddr: ":0", ProcessorID: "mode-test", EventQueueSize: 16,
				UpstreamAddr: tc.upstream, UpstreamForwardMode: tc.mode,
				UpstreamEventSpoolDirectory: t.TempDir()}
			if tc.logStage != "" {
				cfg.LogConfig = &StructuredLogConfig{Enabled: true, Directory: t.TempDir(), EmitStage: tc.logStage, QueueSize: 16}
			}
			p, err := newTestProcessor(t, cfg)
			require.NoError(t, err)
			require.Equal(t, tc.want, p.eventRuntime != nil)
			require.Equal(t, tc.want, p.wantsEventAnalysis())
			// Normalized ingress remains available without creating a packet analyzer.
			require.NotNil(t, p.eventDispatcher)
			require.NotNil(t, p.eventService)
			require.NotNil(t, p.eventIngress)
		})
	}
}

func TestEventSubscriptionDoesNotEnablePacketAnalysis(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "mode-test", EventQueueSize: 16})
	require.NoError(t, err)
	subscription, err := p.eventBroadcaster.Subscribe(broadcast.Options{QueueSize: 1, Kinds: []events.Kind{events.KindDNS}})
	require.NoError(t, err)
	defer subscription.Close()
	require.Nil(t, p.eventRuntime)
	require.False(t, p.wantsEventAnalysis())
	p.emitProtocolEvents("local", []*data.CapturedPacket{{}})
	require.Nil(t, p.eventRuntime)
}

func TestRegisterEventSinkOptsIntoLocalAnalysis(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "mode-test", EventQueueSize: 16})
	require.NoError(t, err)
	require.Nil(t, p.eventRuntime)
	require.NoError(t, p.RegisterEventSink(&collectingSink{}, events.KindDNS))
	require.NotNil(t, p.eventRuntime)
	require.True(t, p.localEventAnalysis)
	require.True(t, p.wantsEventAnalysis())
}

func TestRejectedEventSinkDoesNotEnableLocalAnalysis(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "mode-test", EventQueueSize: 16})
	require.NoError(t, err)
	require.Error(t, p.RegisterEventSink(nil))
	require.Nil(t, p.eventRuntime)
	require.False(t, p.wantsEventAnalysis())
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	require.ErrorIs(t, p.RegisterEventSink(&collectingSink{}), events.ErrDispatcherStarted)
	require.Nil(t, p.eventRuntime)
	require.False(t, p.wantsEventAnalysis())
}

func TestEffectivePacketModeDisablesUpstreamEventAnalysis(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "mode-test", EventQueueSize: 16,
		UpstreamAddr: "upstream:55555", UpstreamForwardMode: "packets"})
	require.NoError(t, err)
	// The processor retains the requested mode while its manager holds the
	// negotiated packet fallback. No live connection is needed to check routing.
	p.config.UpstreamForwardMode = "events"
	require.NoError(t, p.initializeEventAnalysis())
	require.False(t, p.wantsEventAnalysis())
	before := p.eventRuntime.Stats()
	p.emitProtocolEvents("local", []*data.CapturedPacket{{}})
	require.Equal(t, before, p.eventRuntime.Stats())

	require.NoError(t, p.RegisterEventSink(&collectingSink{}))
	require.True(t, p.wantsEventAnalysis(), "packet fallback must preserve explicitly configured local outputs")
}
