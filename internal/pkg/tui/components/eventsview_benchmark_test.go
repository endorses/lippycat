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
			items := benchmarkEventItems(retained + 1)
			view := NewEventsView()
			view.SetEvents(items[:retained])
			view.SetSelectedID(items[retained-1].Event.Envelope().EventID)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				view.SetEvents(items)
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
