package broadcast

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadcasterSlowSubscriberDoesNotAffectOthers(t *testing.T) {
	b := New()
	slow, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)
	fast, err := b.Subscribe(Options{QueueSize: 4})
	require.NoError(t, err)

	for sequence := uint64(1); sequence <= 3; sequence++ {
		require.NoError(t, b.HandleEvent(context.Background(), dnsEvent("node-a", sequence)))
	}

	assert.Equal(t, SubscriberStats{Enqueued: 1, Dropped: 2}, slow.Stats())
	assert.Equal(t, SubscriberStats{Enqueued: 3}, fast.Stats())
	for sequence := uint64(1); sequence <= 3; sequence++ {
		assert.Equal(t, sequence, (<-fast.Events()).Envelope().EventSequence)
	}
	assert.Equal(t, []Loss{{SourceNodeID: "node-a", Cause: LossCauseSubscriberOverflow, Count: 2, Ranges: []SequenceRange{{First: 2, Last: 3}}}}, slow.ConsumeLosses())
	assert.Empty(t, slow.ConsumeLosses())
}

func TestBroadcasterSortsAndMergesOutOfOrderDispatcherLosses(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)

	for _, sequence := range []uint64{3, 2, 5, 4, 2} {
		b.LockDropBoundary()
		b.HandleDroppedEventLocked(dnsEvent("node-a", sequence), time.Time{})
		b.UnlockDropBoundary()
	}

	assert.Equal(t, []Loss{{
		SourceNodeID: "node-a",
		Cause:        LossCauseDispatcherOverflow,
		Count:        5,
		Ranges:       []SequenceRange{{First: 2, Last: 5}},
	}}, sub.ConsumeLosses())
}

func TestBroadcasterDropBoundarySerializesSubscriberAdmission(t *testing.T) {
	b := New()
	b.LockDropBoundary()

	started := make(chan struct{})
	type subscribeResult struct {
		sub *Subscription
		err error
	}
	result := make(chan subscribeResult, 1)
	go func() {
		close(started)
		sub, err := b.Subscribe(Options{QueueSize: 1})
		result <- subscribeResult{sub: sub, err: err}
	}()
	<-started

	b.HandleDroppedEventLocked(dnsEvent("node-a", 1), time.Time{})
	b.UnlockDropBoundary()

	got := <-result
	require.NoError(t, got.err)
	assert.Empty(t, got.sub.ConsumeLosses())
}

func TestBroadcasterFiltersAndProjectsBeforeEnqueue(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{
		QueueSize:        1,
		Kinds:            []events.Kind{events.KindDNS},
		NodeIDs:          []string{"hunter-a"},
		ProcessorNodeIDs: []string{"processor-a"},
		Project: func(event events.Event) (events.Event, bool, error) {
			dns := event.(events.DNSEvent)
			dns.Query = "redacted"
			return dns, true, nil
		},
	})
	require.NoError(t, err)

	require.NoError(t, b.HandleEvent(context.Background(), dnsEvent("other", 1)))
	wrongProcessor := dnsEvent("hunter-a", 2)
	require.NoError(t, b.HandleEvent(context.Background(), wrongProcessor))
	match := dnsEvent("hunter-a", 3)
	match.EventEnvelope.Provenance.ProcessorNodeIDs = []string{"processor-a"}
	require.NoError(t, b.HandleEvent(context.Background(), match))

	got := (<-sub.Events()).(events.DNSEvent)
	assert.Equal(t, "redacted", got.Query)
	assert.Equal(t, uint64(3), got.Envelope().EventSequence)
	assert.Equal(t, SubscriberStats{Enqueued: 1}, sub.Stats())
}

func TestBroadcasterProjectionErrorIsIsolated(t *testing.T) {
	b := New()
	bad, err := b.Subscribe(Options{QueueSize: 1, Project: func(events.Event) (events.Event, bool, error) {
		return nil, false, errors.New("denied")
	}})
	require.NoError(t, err)
	good, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)

	require.NoError(t, b.HandleEvent(context.Background(), dnsEvent("node", 1)))
	assert.Equal(t, uint64(1), good.Stats().Enqueued)
	assert.Equal(t, uint64(1), bad.Stats().ProjectionErrors)
	assert.Equal(t, uint64(1), b.Stats().ProjectionErrors)
}

func TestBroadcasterAlwaysExcludesFileContent(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1, Kinds: []events.Kind{events.KindFileContent}})
	require.NoError(t, err)

	content := events.NewFileContentEvent(events.Envelope{NodeID: "node", EventSequence: 1})
	require.NoError(t, b.HandleEvent(context.Background(), content))
	assert.Empty(t, sub.Events())
	assert.Zero(t, b.Stats().Published)
}

func TestBroadcasterReportsDispatcherDeliveryDrops(t *testing.T) {
	b := New()
	matching, err := b.Subscribe(Options{QueueSize: 1, Kinds: []events.Kind{events.KindDNS}, NodeIDs: []string{"node-a"}})
	require.NoError(t, err)
	filtered, err := b.Subscribe(Options{QueueSize: 1, Kinds: []events.Kind{events.KindHTTP}})
	require.NoError(t, err)

	b.LockDropBoundary()
	b.HandleDroppedEventLocked(dnsEvent("node-a", 7), time.Time{})
	b.UnlockDropBoundary()

	assert.Equal(t, []Loss{{SourceNodeID: "node-a", Cause: LossCauseDispatcherOverflow, Count: 1, Ranges: []SequenceRange{{First: 7, Last: 7}}}}, matching.ConsumeLosses())
	assert.Empty(t, filtered.ConsumeLosses())
	assert.Equal(t, uint64(1), matching.Stats().Dropped)
	assert.Equal(t, uint64(1), b.Stats().Dropped)
}

func TestBroadcasterBoundsLossRangesAndSeparatesProducerSessions(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)

	for i := uint64(0); i < maxLossSequenceRanges+20; i++ {
		event := dnsEvent("node-a", i*2+1)
		event.EventEnvelope.ProducerSessionID = "session-a"
		b.LockDropBoundary()
		b.HandleDroppedEventLocked(event, time.Time{})
		b.UnlockDropBoundary()
	}
	event := dnsEvent("node-a", 1)
	event.EventEnvelope.ProducerSessionID = "session-b"
	b.LockDropBoundary()
	b.HandleDroppedEventLocked(event, time.Time{})
	b.UnlockDropBoundary()

	losses := sub.ConsumeLosses()
	require.Len(t, losses, 2)
	for _, loss := range losses {
		switch loss.ProducerSessionID {
		case "session-a":
			assert.Equal(t, uint64(maxLossSequenceRanges+20), loss.Count)
			assert.Len(t, loss.Ranges, maxLossSequenceRanges)
		case "session-b":
			assert.Equal(t, uint64(1), loss.Count)
			assert.Len(t, loss.Ranges, 1)
		default:
			t.Fatalf("unexpected producer session %q", loss.ProducerSessionID)
		}
	}
}

func TestBroadcasterBoundsDetailedLossRecords(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)

	for i := 0; i < maxDetailedLossRecords+20; i++ {
		event := dnsEvent("node-a", 1)
		event.EventEnvelope.ProducerSessionID = fmt.Sprintf("session-%d", i)
		b.LockDropBoundary()
		b.HandleDroppedEventLocked(event, time.Time{})
		b.UnlockDropBoundary()
	}

	losses := sub.ConsumeLosses()
	assert.LessOrEqual(t, len(losses), maxDetailedLossRecords+1)
	var count uint64
	var catchAll *Loss
	for _, loss := range losses {
		count += loss.Count
		if loss.SourceNodeID == "" && loss.ProducerSessionID == "" {
			loss := loss
			catchAll = &loss
		}
	}
	assert.Equal(t, uint64(maxDetailedLossRecords+20), count)
	require.NotNil(t, catchAll)
	assert.Equal(t, uint64(20), catchAll.Count)
	assert.Empty(t, catchAll.Ranges)
}

func TestSubscriptionCloseCleansUp(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)
	sub.Close()
	sub.Close()
	assert.Equal(t, 0, b.Stats().Subscribers)
	_, open := <-sub.Events()
	assert.False(t, open)
	require.NoError(t, b.HandleEvent(context.Background(), dnsEvent("node", 1)))
}

func TestBroadcasterCloseClosesSubscribersAndRejectsNewOnes(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)
	require.NoError(t, b.Close(context.Background()))
	require.NoError(t, b.Close(context.Background()))
	_, open := <-sub.Events()
	assert.False(t, open)
	_, err = b.Subscribe(Options{QueueSize: 1})
	assert.ErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, b.HandleEvent(context.Background(), dnsEvent("node", 1)), ErrClosed)
}

func TestConcurrentPublishAndClose(t *testing.T) {
	b := New()
	sub, err := b.Subscribe(Options{QueueSize: 64})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sequence := uint64(1); sequence <= 1000; sequence++ {
			_ = b.HandleEvent(context.Background(), dnsEvent("node", sequence))
		}
	}()
	sub.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publisher did not finish")
	}
}

func TestSubscribeValidatesQueueSize(t *testing.T) {
	_, err := New().Subscribe(Options{})
	assert.EqualError(t, err, "subscriber queue size must be positive")
}

func TestSubscriptionRecordsAdmissionTime(t *testing.T) {
	before := time.Now().UTC()
	sub, err := New().Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)
	after := time.Now().UTC()
	assert.False(t, sub.AdmittedAt().Before(before))
	assert.False(t, sub.AdmittedAt().After(after))
}

func TestAdmissionAwareDeliveryExcludesQueuedPreAdmissionEvent(t *testing.T) {
	b := New()
	admittedBeforeSubscription := time.Now().UTC()
	sub, err := b.Subscribe(Options{QueueSize: 1})
	require.NoError(t, err)

	require.NoError(t, b.HandleEventAdmitted(context.Background(), dnsEvent("node", 1), admittedBeforeSubscription))
	select {
	case <-sub.Events():
		t.Fatal("received event admitted before live subscription boundary")
	default:
	}

	require.NoError(t, b.HandleEventAdmitted(context.Background(), dnsEvent("node", 2), time.Now().UTC()))
	select {
	case event := <-sub.Events():
		assert.Equal(t, uint64(2), event.Envelope().EventSequence)
	case <-time.After(time.Second):
		t.Fatal("did not receive event admitted after live subscription boundary")
	}
}

func dnsEvent(node string, sequence uint64) events.DNSEvent {
	event := events.NewDNSEvent(events.Envelope{NodeID: node, EventSequence: sequence})
	event.Query = "private.example"
	return event
}
