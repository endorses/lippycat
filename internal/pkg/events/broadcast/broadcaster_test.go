package broadcast

import (
	"context"
	"errors"
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
	assert.Equal(t, []Loss{{SourceNodeID: "node-a", Count: 2, Ranges: []SequenceRange{{First: 2, Last: 3}}}}, slow.ConsumeLosses())
	assert.Empty(t, slow.ConsumeLosses())
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

func dnsEvent(node string, sequence uint64) events.DNSEvent {
	event := events.NewDNSEvent(events.Envelope{NodeID: node, EventSequence: sequence})
	event.Query = "private.example"
	return event
}
