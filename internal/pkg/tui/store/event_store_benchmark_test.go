//go:build tui || all

package store

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
)

const eventStoreBenchmarkBatchSize = 128

func benchmarkEvents(count int) []events.Event {
	result := make([]events.Event, count)
	for i := range result {
		source := "eth0"
		kind := events.KindDNS
		if i%2 == 1 {
			source = "pcap"
			kind = events.KindHTTP
		}
		result[i] = testEvent(fmt.Sprintf("event-%d", i), source, kind)
	}
	return result
}

func BenchmarkEventStoreAddEventBelowCapacity(b *testing.B) {
	eventsToAdd := benchmarkEvents(1024)
	store := NewEventStore(len(eventsToAdd) + 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && i%len(eventsToAdd) == 0 {
			b.StopTimer()
			store.Reset()
			b.StartTimer()
		}
		store.AddEvent(eventsToAdd[i%len(eventsToAdd)])
	}
}

func BenchmarkEventStoreAddBatchBelowCapacity(b *testing.B) {
	batch := benchmarkEvents(eventStoreBenchmarkBatchSize)
	store := NewEventStore(eventStoreBenchmarkBatchSize*8 + 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && i%8 == 0 {
			b.StopTimer()
			store.Reset()
			b.StartTimer()
		}
		store.AddBatch(batch)
	}
}

func BenchmarkEventStoreAddBatchWithEviction(b *testing.B) {
	for _, capacity := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("capacity_%d", capacity), func(b *testing.B) {
			seed := benchmarkEvents(capacity)
			batch := benchmarkEvents(eventStoreBenchmarkBatchSize)
			store := NewEventStore(capacity)
			store.AddBatch(seed)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				store.AddBatch(batch)
			}
		})
	}
}

func BenchmarkEventStoreVisibleProjection(b *testing.B) {
	for _, capacity := range []int{1000, 10000} {
		for _, filtered := range []bool{false, true} {
			name := fmt.Sprintf("capacity_%d/unfiltered", capacity)
			if filtered {
				name = fmt.Sprintf("capacity_%d/filtered", capacity)
			}
			b.Run(name, func(b *testing.B) {
				store := NewEventStore(capacity)
				store.AddBatch(benchmarkEvents(capacity))
				if filtered {
					store.SetKindFilter([]events.Kind{events.KindHTTP})
					store.SetSourceFilter([]string{"pcap"})
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = store.Events()
				}
			})
		}
	}
}

func BenchmarkEventStoreSelectionMaintenance(b *testing.B) {
	for _, followLatest := range []bool{true, false} {
		name := "follow_latest"
		if !followLatest {
			name = "pinned_history"
		}
		b.Run(name, func(b *testing.B) {
			const capacity = 1000
			seed := benchmarkEvents(capacity)
			incoming := testEvent("incoming", "eth0", events.KindDNS)
			store := NewEventStore(capacity)
			prepare := func() {
				store.Reset()
				store.AddBatch(seed)
				if !followLatest {
					store.SelectByID(seed[capacity/2].Envelope().EventID)
				}
			}
			prepare()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i > 0 && i%(capacity/2) == 0 {
					b.StopTimer()
					prepare()
					b.StartTimer()
				}
				store.AddEvent(incoming)
			}
		})
	}
}
