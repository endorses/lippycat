//go:build tui || all

package store

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEvent(id, source string, kind events.Kind) events.Event {
	env := events.Envelope{Timestamp: time.Unix(1, 0), EventID: id, ProducerSessionID: "session", EventSequence: 1, NodeID: "node", Provenance: events.SourceProvenance{CaptureSource: source}}
	switch kind {
	case events.KindDNS:
		return events.NewDNSEvent(env)
	case events.KindHTTP:
		return events.NewHTTPEvent(env)
	case events.KindFileContent:
		return events.NewFileContentEvent(env)
	default:
		return events.NewConnEvent(env)
	}
}

func TestEventStoreSelectionSurvivesAppendAndEviction(t *testing.T) {
	store := NewEventStore(2)
	require.True(t, store.AddEvent(testEvent("one", "a", events.KindDNS)))
	require.True(t, store.AddEvent(testEvent("two", "a", events.KindHTTP)))
	require.True(t, store.SelectByID("two"))
	require.True(t, store.AddEvent(testEvent("three", "b", events.KindConn)))
	assert.Equal(t, "two", store.SelectedID())
	items := store.Events()
	require.Len(t, items, 2)
	assert.Equal(t, uint64(2), items[0].ArrivalSequence)
	assert.Equal(t, uint64(3), items[1].ArrivalSequence)
	assert.Equal(t, uint64(1), store.Stats().Evicted)

	require.True(t, store.AddEvent(testEvent("four", "b", events.KindConn)))
	assert.Equal(t, "three", store.SelectedID(), "evicted selection moves to the closest retained arrival")
}

func TestEventStoreFollowsLatestUntilUserNavigatesAway(t *testing.T) {
	store := NewEventStore(10)
	store.AddBatch([]events.Event{
		testEvent("one", "a", events.KindDNS),
		testEvent("two", "a", events.KindDNS),
	})
	assert.Equal(t, "two", store.SelectedID())

	store.AddEvent(testEvent("three", "a", events.KindDNS))
	assert.Equal(t, "three", store.SelectedID())

	store.SelectPrevious()
	assert.Equal(t, "two", store.SelectedID())
	store.AddEvent(testEvent("four", "a", events.KindDNS))
	assert.Equal(t, "two", store.SelectedID())

	store.SelectLast()
	store.AddEvent(testEvent("five", "a", events.KindDNS))
	assert.Equal(t, "five", store.SelectedID())
}

func TestEventStorePauseResetFiltersAndLoss(t *testing.T) {
	store := NewEventStore(4)
	store.SetPaused(true)
	assert.False(t, store.AddEvent(testEvent("paused", "a", events.KindDNS)))
	store.SetPaused(false)
	store.AddBatch([]events.Event{testEvent("dns", "a", events.KindDNS), testEvent("http", "b", events.KindHTTP)})
	assert.False(t, store.AddEvent(testEvent("content", "a", events.KindFileContent)))

	store.SetKindFilter([]events.Kind{events.KindHTTP})
	require.Len(t, store.Events(), 1)
	assert.Equal(t, "http", store.SelectedID())
	store.SetSourceFilter([]string{"a"})
	assert.Empty(t, store.Events())
	assert.Empty(t, store.SelectedID())

	store.RecordTransportLoss("subscriber_overflow", 3)
	stats := store.Stats()
	assert.Equal(t, uint64(3), stats.TransportLost)
	assert.Equal(t, uint64(1), stats.Paused)
	assert.Equal(t, uint64(3), stats.Arrived)
	assert.Equal(t, uint64(3), stats.TransportLossByKind["subscriber_overflow"])

	store.Reset()
	assert.Equal(t, EventStoreStats{TransportLossByKind: map[string]uint64{}}, store.Stats())
}

func TestEventStoreKindAndSourceProjections(t *testing.T) {
	store := NewEventStore(4)
	store.AddBatch([]events.Event{testEvent("one", "pcap", events.KindDNS), testEvent("two", "pcap", events.KindDNS), testEvent("three", "eth0", events.KindConn)})
	assert.Equal(t, uint64(2), store.CountByKind()[events.KindDNS])
	assert.Equal(t, uint64(2), store.CountBySource()["pcap"])
}
