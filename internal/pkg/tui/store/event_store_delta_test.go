//go:build tui || all

package store

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestEventStoreIncrementalProjectionReference(t *testing.T) {
	for _, capacity := range []int{1, 7, 31} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			s := NewEventStore(capacity)
			rng := rand.New(rand.NewSource(825))
			var cursor EventCursor
			var projection []components.EventItem
			for step := 0; step < 3000; step++ {
				switch rng.Intn(12) {
				case 0:
					s.SetKindFilter([]events.Kind{events.KindDNS})
				case 1:
					s.SetKindFilter(nil)
				case 2:
					s.SetSourceFilter([]string{"a"})
				case 3:
					s.SetSourceFilter(nil)
				case 4:
					require.NoError(t, s.AddUserFilter("kind:dns"))
				case 5:
					s.RemoveLastUserFilter()
				case 6:
					s.Reset()
				case 7:
					s.SetPaused(!s.Paused())
				case 8:
					s.SelectOffset(rng.Intn(9) - 4)
				default:
					batch := make([]events.Event, rng.Intn(capacity*2+1))
					for i := range batch {
						kind, source := events.KindDNS, "a"
						if rng.Intn(2) == 0 {
							kind = events.KindHTTP
						}
						if rng.Intn(2) == 0 {
							source = "b"
						}
						batch[i] = testEvent(fmt.Sprintf("%d-%d", step, i), source, kind)
					}
					s.AddBatch(batch)
				}
				// Some refreshes deliberately miss multiple operations.
				if rng.Intn(4) == 0 {
					continue
				}
				delta := s.GetNewEvents(cursor)
				if delta.FullRefresh {
					projection = delta.Items
				} else {
					require.LessOrEqual(t, delta.Trimmed, len(projection), "step %d", step)
					projection = append(projection[delta.Trimmed:], delta.Items...)
				}
				cursor = delta.Cursor
				// Independent full projection evaluates current predicates from scratch.
				reference := []components.EventItem{}
				for i := 0; i < s.count; i++ {
					item := s.itemLocked(i)
					if s.visibleLocked(item.Event) {
						reference = append(reference, item)
					}
				}
				require.Equal(t, reference, append([]components.EventItem{}, projection...), "step %d", step)
				require.Equal(t, s.SelectedID(), delta.SelectedID)
			}
		})
	}
}

func TestEventStorePacketIncrementalDecisionEquivalence(t *testing.T) {
	for _, capacity := range []int{1, 4, 17} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			es, ps := NewEventStore(capacity), NewPacketStore(capacity)
			cursor := es.GetNewEvents(EventCursor{}).Cursor
			var packetCursor int64
			for _, size := range []int{0, 1, 0, 2, 3, 1, 0, 4, 1, 19, 1, 0, 2} {
				batch := make([]events.Event, size)
				packets := make([]components.PacketDisplay, size)
				for i := range batch {
					batch[i] = testEvent(fmt.Sprintf("%d-%d", packetCursor, i), "a", events.KindDNS)
				}
				es.AddBatch(batch)
				ps.AddPacketBatch(packets)
				delta := es.GetNewEvents(cursor)
				newPackets, total, full := ps.GetNewPackets(packetCursor)
				require.Equal(t, full, delta.FullRefresh)
				if !full {
					require.Len(t, delta.Items, len(newPackets))
				}
				require.Equal(t, uint64(total), delta.Cursor.ArrivalSequence)
				cursor, packetCursor = delta.Cursor, total
			}
		})
	}
}

func TestEventStoreDeltaCachedFiltersAndTrim(t *testing.T) {
	s := NewEventStore(4)
	calls := 0
	s.userFilters = []eventUserFilter{{predicate: func(event events.Event) bool { calls++; return event.Kind() == events.KindDNS }}}
	s.ensureVisibleSelectionLocked()
	s.AddBatch([]events.Event{testEvent("one", "a", events.KindDNS), testEvent("two", "a", events.KindHTTP), testEvent("three", "a", events.KindDNS), testEvent("four", "a", events.KindHTTP)})
	first := s.GetNewEvents(EventCursor{})
	require.True(t, first.FullRefresh)
	require.Len(t, first.Items, 2)
	require.Equal(t, 4, calls)
	s.AddEvent(testEvent("five", "a", events.KindHTTP))
	delta := s.GetNewEvents(first.Cursor)
	require.False(t, delta.FullRefresh)
	require.Equal(t, 1, delta.Trimmed)
	require.Empty(t, delta.Items)
	require.Equal(t, 5, calls)
	s.SelectFirst()
	delta = s.GetNewEvents(delta.Cursor)
	require.False(t, delta.FullRefresh)
	require.Empty(t, delta.Items)
	require.Zero(t, delta.Trimmed)
	require.Equal(t, "three", delta.SelectedID)
	s.SelectLast()
	s.SelectPrevious()
	s.SelectByID("three")
	s.Selected()
	require.Equal(t, 5, calls, "navigation uses cached visibility")
}

func TestEventStoreDeltaInvalidation(t *testing.T) {
	s := NewEventStore(4)
	s.AddEvent(testEvent("one", "a", events.KindDNS))
	initial := s.GetNewEvents(EventCursor{})
	require.True(t, initial.FullRefresh)
	require.NoError(t, s.AddUserFilter("kind:dns"))
	require.True(t, s.GetNewEvents(initial.Cursor).FullRefresh)
	cursor := s.GetNewEvents(EventCursor{}).Cursor
	require.Error(t, s.AddUserFilter("unknown:value"))
	require.False(t, s.GetNewEvents(cursor).FullRefresh)
	s.Reset()
	s.AddEvent(testEvent("two", "a", events.KindDNS))
	delta := s.GetNewEvents(cursor)
	require.True(t, delta.FullRefresh)
	require.Equal(t, "two", delta.Items[0].Event.Envelope().EventID)
	require.Equal(t, initial.Cursor.ArrivalSequence, delta.Cursor.ArrivalSequence)
}

func BenchmarkEventStoreIncrementalProjection(b *testing.B) {
	for _, capacity := range []int{1000, 10000} {
		for _, filtered := range []bool{false, true} {
			b.Run(fmt.Sprintf("capacity=%d/filtered=%t", capacity, filtered), func(b *testing.B) {
				s := NewEventStore(capacity)
				fixtures := benchmarkEvents(capacity + 1)
				if filtered {
					s.SetKindFilter([]events.Kind{events.KindDNS})
				}
				s.AddBatch(fixtures[:capacity])
				cursor := s.GetNewEvents(EventCursor{}).Cursor
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s.AddEvent(fixtures[(capacity+i)%len(fixtures)])
					delta := s.GetNewEvents(cursor)
					if delta.FullRefresh {
						b.Fatal("ordinary append required full refresh")
					}
					cursor = delta.Cursor
				}
			})
		}
	}
}

func TestEventStoreUnchangedFiltersPreserveCursor(t *testing.T) {
	s := NewEventStore(5)
	cursor := s.GetNewEvents(EventCursor{}).Cursor
	s.SetKindFilter(nil)
	s.SetSourceFilter(nil)
	s.ClearUserFilters()
	require.False(t, s.GetNewEvents(cursor).FullRefresh)
	s.SetKindFilter([]events.Kind{})
	require.True(t, s.GetNewEvents(cursor).FullRefresh, "empty filter differs from all")
	s.SetKindFilter([]events.Kind{events.KindDNS, events.KindHTTP})
	s.SetSourceFilter([]string{"a", "b"})
	cursor = s.GetNewEvents(EventCursor{}).Cursor
	s.SetKindFilter([]events.Kind{events.KindHTTP, events.KindDNS, events.KindHTTP})
	s.SetSourceFilter([]string{"b", "b", "a"})
	require.False(t, s.GetNewEvents(cursor).FullRefresh)
	s.SetSourceFilter([]string{"a"})
	require.True(t, s.GetNewEvents(cursor).FullRefresh)
}

func TestEventStoreIdleAndInvisibleDeltaDoNotAllocate(t *testing.T) {
	s := NewEventStore(1000)
	s.SetKindFilter([]events.Kind{events.KindDNS})
	cursor := s.GetNewEvents(EventCursor{}).Cursor
	event := testEvent("invisible", "a", events.KindHTTP)
	require.Zero(t, testing.AllocsPerRun(100, func() {
		s.AddEvent(event)
		delta := s.GetNewEvents(cursor)
		if delta.FullRefresh || len(delta.Items) != 0 {
			panic("unexpected delta")
		}
		cursor = delta.Cursor
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() { s.GetNewEvents(cursor) }))
}
