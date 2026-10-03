package eventcoalesce

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNetworkMessagesPassThroughImmediately(t *testing.T) {
	ctx := context.Background()
	next := &collectingSink{}
	coalescer, err := New(next, Config{})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("fixture")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 16, SinkQueueSize: 16, Producer: producer})
	require.NoError(t, err)
	require.NoError(t, d.Register(coalescer, events.KindDHCP, events.KindNTP))
	r, err := eventanalysis.New(eventanalysis.Config{Dispatcher: d})
	require.NoError(t, err)
	require.NoError(t, d.Start(ctx))
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for i, info := range packets {
		require.NoError(t, r.ObservePacket(eventanalysis.Source{NodeID: "fixture", CaptureSource: "fixture0"}, info))
		require.NoError(t, d.Flush(ctx))
		require.Len(t, next.snapshot(), i+1, "a response/retransmission cannot consume an earlier message")
	}
	eventfixture.AssertNetworkMessages(t, next.snapshot())
	r.Close()
	require.NoError(t, d.Close(ctx))
	require.Len(t, next.snapshot(), 5)
}
