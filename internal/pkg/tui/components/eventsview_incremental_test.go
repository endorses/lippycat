//go:build tui || all

package components

import (
	"math/rand"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventsViewIncrementalMatchesFullProjection(t *testing.T) {
	rng := rand.New(rand.NewSource(57))
	pool := benchmarkEventItems(83)
	incremental, full := NewEventsView(), NewEventsView()
	incremental.SetSize(140, 16)
	full.SetSize(140, 16)
	var retained []EventItem
	for step := 0; step < 3000; step++ {
		switch rng.Intn(6) {
		case 0:
			count := rng.Intn(len(retained) + 3)
			incremental.TrimOldEvents(count)
			retained = retained[min(count, len(retained)):]
			full.SetEvents(retained)
		case 1:
			if len(retained) > 0 {
				id := retained[rng.Intn(len(retained))].Event.Envelope().EventID
				incremental.SetSelectedID(id)
				full.SetSelectedID(id)
			}
		case 2:
			// Generation changes intentionally rebuild both projections.
			rng.Shuffle(len(retained), func(i, j int) { retained[i], retained[j] = retained[j], retained[i] })
			incremental.SetEvents(retained)
			full.SetEvents(retained)
		default:
			batch := make([]EventItem, rng.Intn(7))
			for i := range batch {
				batch[i] = pool[rng.Intn(len(pool))]
			}
			retained = append(retained, batch...)
			incremental.AppendEvents(batch)
			full.SetEvents(retained)
		}
		require.Equal(t, full.items, incremental.items, "step %d", step)
		require.Equal(t, full.selectedID, incremental.selectedID, "step %d", step)
		require.Equal(t, full.offset, incremental.offset, "step %d", step)
		for i, item := range retained {
			id := item.Event.Envelope().EventID
			first := i
			for j := 0; j < i; j++ {
				if retained[j].Event.Envelope().EventID == id {
					first = j
					break
				}
			}
			require.Equal(t, first, incremental.indexByID(id), "step %d", step)
		}
	}
}

func TestEventsViewIncrementalPreservesDetailsAndReleasesTrimmedRows(t *testing.T) {
	view := NewEventsView()
	items := benchmarkEventItems(60)
	view.SetEvents(items[:40])
	view.SetSelectedID(items[20].Event.Envelope().EventID)
	view.PrepareLayout(120, 15, 80, 12)
	view.ScrollDetailsToBottom()
	scroll := view.detailsViewport.YOffset
	require.Positive(t, scroll)
	backing := view.itemStorage
	view.TrimOldEvents(10)
	view.AppendEvents(items[40:50])
	view.PrepareLayout(120, 15, 80, 12)
	assert.Equal(t, scroll, view.detailsViewport.YOffset)
	for _, item := range backing[:10] {
		assert.Nil(t, item.Event)
	}
	selected, ok := view.Selected()
	require.True(t, ok)
	assert.Equal(t, items[20], selected)
	// A full trim resets selection and cached content even when IDs are reused.
	view.TrimOldEvents(1000)
	require.Empty(t, view.SelectedID())
	view.PrepareLayout(120, 15, 80, 12)
	require.Empty(t, view.detailsSelectedID)
	view.AppendEvents(items[20:21])
	view.PrepareLayout(120, 15, 80, 12)
	assert.Zero(t, view.detailsViewport.YOffset)
	view.SetEvents(nil)
	for _, item := range view.itemStorage[:cap(view.itemStorage)] {
		assert.Nil(t, item.Event)
	}
	assert.Empty(t, view.positions)
	assert.Empty(t, view.nextDuplicate)
}

type indexCountingEvent struct {
	events.Event
	envelopeReads *int
}

func (e indexCountingEvent) Envelope() events.Envelope {
	*e.envelopeReads++
	return e.Event.Envelope()
}

func TestEventsViewIncrementalIndexWorkIsBoundedByDelta(t *testing.T) {
	for _, capacity := range []int{1000, 10000} {
		reads := 0
		items := benchmarkEventItems(capacity + 1)
		for i := range items {
			items[i].Event = indexCountingEvent{Event: items[i].Event, envelopeReads: &reads}
		}
		view := NewEventsView()
		view.SetEvents(items[:capacity])
		reads = 0
		// Cycle enough times to compact backing storage repeatedly.
		for i := 0; i < 3*capacity; i++ {
			next := (capacity + i) % len(items)
			view.TrimOldEvents(1)
			view.AppendEvents(items[next : next+1])
			view.SetSelectedID(items[next].Event.Envelope().EventID)
			_, ok := view.Selected()
			require.True(t, ok)
		}
		assert.LessOrEqual(t, reads, 12*capacity, "index maintenance must read only trimmed/appended rows")
		assert.LessOrEqual(t, cap(view.itemStorage), 4*capacity)
		assert.Len(t, view.positions, capacity)
	}
}

func TestEventsViewDeltaReintroducingSelectedIDPreservesDetails(t *testing.T) {
	for _, remaining := range []int{0, 1} {
		view := NewEventsView()
		items := benchmarkEventItems(2)
		view.SetEvents(items[:1+remaining])
		view.SetSelectedID(items[0].Event.Envelope().EventID)
		view.PrepareLayout(120, 15, 80, 12)
		view.ScrollDetailsToBottom()
		scroll := view.detailsViewport.YOffset
		require.Positive(t, scroll)
		view.AppendEvents(items[:1])
		view.TrimOldEvents(1)
		view.SetSelectedID(items[0].Event.Envelope().EventID)
		view.PrepareLayout(120, 15, 80, 12)
		assert.Equal(t, scroll, view.detailsViewport.YOffset)
	}
}

func TestEventsViewAtomicDeltaMatchesFullProjection(t *testing.T) {
	rng := rand.New(rand.NewSource(513))
	pool := benchmarkEventItems(31) // Deliberately repeat immutable stable IDs.
	incremental, full := NewEventsView(), NewEventsView()
	retained := append([]EventItem(nil), pool[:20]...)
	for _, view := range []*EventsView{incremental, full} {
		view.SetEvents(retained)
		view.SetSize(140, 12)
	}
	for step := 0; step < 5000; step++ {
		// Selection can be pinned above the bottom of the viewport.
		if len(retained) > 0 {
			for _, view := range []*EventsView{incremental, full} {
				view.SetSelectedID(retained[len(retained)-1].Event.Envelope().EventID)
			}
			selected := retained[rng.Intn(len(retained))].Event.Envelope().EventID
			incremental.SetSelectedID(selected)
			full.SetSelectedID(selected)
		}
		batch := make([]EventItem, rng.Intn(12))
		for i := range batch {
			batch[i] = pool[rng.Intn(len(pool))]
		}
		trim := rng.Intn(len(retained) + 1)
		// Append before trimming retains the old selected occurrence as the
		// viewport anchor, even if it is replaced by a duplicate within the delta.
		incremental.AppendEvents(batch)
		incremental.TrimOldEvents(trim)
		retained = append(retained[trim:], batch...)
		full.SetEvents(retained)
		require.Equal(t, full.items, incremental.items, "step %d", step)
		require.Equal(t, full.selectedID, incremental.selectedID, "step %d", step)
		require.Equal(t, full.offset, incremental.offset, "step %d", step)
	}
}
