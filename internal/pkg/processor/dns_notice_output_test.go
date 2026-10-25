//go:build processor || tap || all

package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
)

func TestDNSNoticeSlowSubscriberAndFailedLogAreIndependent(t *testing.T) {
	for _, failLog := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-log-%t", failLog), func(t *testing.T) {
			dir := t.TempDir()
			if failLog {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "notice.log"), 0o700))
			}
			p, err := newTestProcessor(t, Config{ProcessorID: "notices", ListenAddr: "127.0.0.1:0", EventAnalysis: dnsNoticeIntegrationPolicy(), EventQueueSize: 64, LogConfig: &StructuredLogConfig{Enabled: true, Directory: dir, Format: "json", Streams: []string{"notice"}, QueueSize: 64}})
			require.NoError(t, err)
			slow, err := p.eventBroadcaster.Subscribe(broadcast.Options{QueueSize: 1, Kinds: []events.Kind{events.KindNotice}})
			require.NoError(t, err)
			defer slow.Close()
			require.NoError(t, p.logSink.Start(context.Background()))
			require.NoError(t, p.eventDispatcher.Start(context.Background()))
			flow := p.flowController.Determine()
			for i := range 8 {
				p.emitProtocolEventsWithScope("origin", fmt.Sprint(i), []*data.CapturedPacket{dnsNoticeIntegrationPacket(t, time.Duration(i)*time.Second)})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, p.eventDispatcher.Flush(ctx))
			require.EqualValues(t, 8, p.GetNoticeStats().Emitted)
			require.EqualValues(t, 7, slow.Stats().Dropped)
			require.Equal(t, flow, p.flowController.Determine(), "subscriber pressure must not become hunter backpressure")
			if failLog {
				require.EqualValues(t, 8, p.dnsNoticeStatusProto().LogErrors)
				require.Zero(t, p.logSink.Stats().Written)
			} else {
				contents, err := os.ReadFile(filepath.Join(dir, "notice.log"))
				require.NoError(t, err)
				require.Len(t, strings.Split(strings.TrimSpace(string(contents)), "\n"), 8)
				require.EqualValues(t, 8, p.logSink.Stats().Written)
			}
		})
	}
}

func TestDNSNoticeNegotiationRequiresProductionWhenConfigured(t *testing.T) {
	old := eventForwardingCapabilities(1, 2, 3, 4, 5, 6, 7)
	generic := &Processor{}
	mode, _, _, _, _, err := generic.negotiateEventForwarding(old)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	owner := &Processor{config: Config{EventAnalysis: dnsNoticeIntegrationPolicy()}}
	_, _, _, _, _, err = owner.negotiateEventForwarding(old)
	require.ErrorContains(t, err, "NOTICE")
	old.AllowPacketFallback = true
	mode, _, _, _, reason, err := owner.negotiateEventForwarding(old)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, mode)
	require.Contains(t, reason, "explicit packet fallback")
	codecOnly := eventForwardingCapabilities(protoadapter.SupportedKindIDs(false)...)
	_, _, _, _, _, err = owner.negotiateEventForwarding(codecOnly)
	require.ErrorContains(t, err, "NOTICE")
	codecOnly.StatefulAnalysisFeatures = append(codecOnly.StatefulAnalysisFeatures, protoadapter.DNSNoticeProductionFeature)
	mode, _, kinds, _, _, err := owner.negotiateEventForwarding(codecOnly)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	require.Contains(t, kinds, int32(eventsv1.EventKind_EVENT_KIND_NOTICE))
	// Logging received notices alone does not authorize packet fallback that
	// would silently yield an empty stream with the detector disabled locally.
	consumer := &Processor{config: Config{LogConfig: &StructuredLogConfig{Enabled: true, Streams: []string{"notice"}}}}
	_, _, _, _, _, err = consumer.negotiateEventForwarding(nil)
	require.ErrorContains(t, err, "notice-producing")
	old.AllowPacketFallback = true
	_, _, _, _, _, err = consumer.negotiateEventForwarding(old)
	require.ErrorContains(t, err, "NOTICE")
}
