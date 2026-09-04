//go:build tui || all

package components

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
)

func benchmarkEventItems(count int) []EventItem {
	items := make([]EventItem, count)
	for i := range items {
		event := events.NewDNSEvent(events.Envelope{
			Timestamp: time.Unix(int64(i), 0),
			EventID:   fmt.Sprintf("event-%d", i),
			NodeID:    "processor-1",
			Flow: events.FlowTuple{
				SourceAddress:      netip.MustParseAddr("192.0.2.1"),
				SourcePort:         53000,
				DestinationAddress: netip.MustParseAddr("198.51.100.2"),
				DestinationPort:    53,
				Protocol:           17,
			},
		})
		event.Query = "benchmark.example"
		event.QType = 1
		items[i] = EventItem{
			Event:           event,
			ArrivalSequence: uint64(i + 1),
			ArrivedAt:       time.Unix(int64(i), 0),
		}
	}
	return items
}

func BenchmarkEventsViewAppendViaSetEvents(b *testing.B) {
	for _, retained := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("retained_%d", retained), func(b *testing.B) {
			// Slide over a cyclic pool larger than retention so every refresh
			// appends a new event and evicts the oldest without duplicate IDs.
			items := benchmarkEventItems(retained + 1)
			windows := append(append(make([]EventItem, 0, 2*len(items)), items...), items...)
			view := NewEventsView()
			view.SetEvents(items[:retained])
			view.SetSelectedID(items[retained-1].Event.Envelope().EventID)
			next := 1
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				window := windows[next : next+retained]
				view.SetEvents(window)
				view.SetSelectedID(window[retained-1].Event.Envelope().EventID)
				next = (next + 1) % len(items)
			}
		})
	}
}

func BenchmarkEventsViewRenderTimeline(b *testing.B) {
	for _, retained := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("retained_%d", retained), func(b *testing.B) {
			items := benchmarkEventItems(retained)
			view := NewEventsView()
			view.SetEvents(items)
			view.SetSelectedID(items[retained-1].Event.Envelope().EventID)
			view.RenderTimeline(160, 40, true)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = view.RenderTimeline(160, 40, true)
			}
		})
	}
}

func BenchmarkEventsViewAppendIncremental(b *testing.B) {
	for _, retained := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("retained_%d", retained), func(b *testing.B) {
			items := benchmarkEventItems(retained + 1)
			view := NewEventsView()
			view.SetEvents(items[:retained])
			view.SetSelectedID(items[retained-1].Event.Envelope().EventID)
			next := retained
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				view.AppendEvents(items[next : next+1])
				view.TrimOldEvents(1)
				view.SetSelectedID(items[next].Event.Envelope().EventID)
				next = (next + 1) % len(items)
			}
		})
	}
}
