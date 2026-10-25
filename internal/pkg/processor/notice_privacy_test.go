//go:build processor || tap || all

package processor

import (
	"context"
	"testing"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestNoticeSubscriptionsRedactEvidenceWithoutChangingDecisionOrIdentity(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "authorized evidence"}[sensitive], func(t *testing.T) {
			b := broadcast.New()
			service, err := NewEventService(b, EventSubscriptionPolicy{AllowSensitiveFields: true})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 8)}
			done := make(chan error, 1)
			go func() {
				done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, IncludeSensitiveFields: sensitive, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_NOTICE}}, stream)
			}()
			waitEventMessage(t, stream.notify)
			original := noticefixture.Event()
			require.NoError(t, b.HandleEvent(context.Background(), original))
			waitEventMessage(t, stream.notify)
			cancel()
			require.NoError(t, <-done)
			messages := stream.snapshot()
			require.Len(t, messages, 2)
			require.Contains(t, messages[0].GetControl().SupportedEventKinds, eventsv1.EventKind_EVENT_KIND_NOTICE)
			decoded, omission, err := protoadapter.FromProto(messages[1].GetBatch().Events[0])
			require.NoError(t, err)
			require.Nil(t, omission)
			notice := decoded.(events.NoticeEvent)
			require.Equal(t, original.Envelope(), notice.Envelope())
			require.Equal(t, original.DetectorNodeID, notice.DetectorNodeID)
			require.Equal(t, original.DNS.Score, notice.DNS.Score)
			require.Equal(t, original.DNS.Queries, notice.DNS.Queries)
			require.Equal(t, !sensitive, notice.EvidenceRedacted)
			require.False(t, notice.EvidenceTruncated)
			require.False(t, notice.DNS.SourceIPsTruncated)
			if sensitive {
				require.Equal(t, original, notice)
			} else {
				require.Empty(t, notice.Evidence)
				require.Empty(t, notice.DNS.SourceIPs)
			}
			require.Len(t, original.Evidence, 2)
			require.Len(t, original.DNS.SourceIPs, 2)
		})
	}
}
