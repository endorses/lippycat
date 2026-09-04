//go:build tui || all

package store

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventStorePacketRingRetentionEquivalence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		capacity int
		batches  []int
	}{
		{"empty", 4, []int{0}},
		{"partial", 4, []int{1, 0, 2}},
		{"exact_capacity", 4, []int{4}},
		{"fill_in_batches", 4, []int{1, 3}},
		{"wraparound", 4, []int{3, 2, 3, 1, 4}},
		{"oversized_empty", 4, []int{13}},
		{"oversized_wrapped", 4, []int{3, 2, 13, 1}},
		{"capacity_one", 1, []int{1, 0, 1, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es, ps := NewEventStore(tc.capacity), NewPacketStore(tc.capacity)
			total := 0
			for _, size := range tc.batches {
				batch := make([]events.Event, size)
				packets := make([]components.PacketDisplay, size)
				for i := range batch {
					id := fmt.Sprintf("event-%d", total+i+1)
					batch[i] = testEvent(id, "pcap", events.KindDNS)
					packets[i].Info = id
				}
				require.Equal(t, size, es.AddBatch(batch))
				ps.AddPacketBatch(packets)
				total += size
				gotEvents, gotPackets := es.Events(), ps.GetPacketsInOrder()
				retained := min(total, tc.capacity)
				require.Len(t, gotEvents, retained)
				require.Len(t, gotPackets, retained)
				for i, item := range gotEvents {
					sequence := total - retained + i + 1
					assert.Equal(t, fmt.Sprintf("event-%d", sequence), item.Event.Envelope().EventID)
					assert.Equal(t, gotPackets[i].Info, item.Event.Envelope().EventID)
					assert.Equal(t, uint64(sequence), item.ArrivalSequence)
					assert.False(t, item.ArrivedAt.IsZero())
				}
				assert.Equal(t, uint64(total), es.Stats().Arrived)
				assert.Equal(t, uint64(retained), es.Stats().Retained)
				assert.Equal(t, uint64(total-retained), es.Stats().Evicted)
				if total > 0 {
					assert.Equal(t, fmt.Sprintf("event-%d", total), es.SelectedID())
				}
			}
		})
	}
}

func TestEventStoreBulkPauseRejectionAndReset(t *testing.T) {
	s := NewEventStore(2)
	batch := []events.Event{nil, testEvent("content", "pcap", events.KindFileContent), testEvent("one", "pcap", events.KindDNS), testEvent("two", "pcap", events.KindHTTP)}
	s.SetPaused(true)
	assert.Zero(t, s.AddBatch(batch))
	assert.Equal(t, uint64(2), s.Stats().Arrived)
	assert.Equal(t, uint64(2), s.Stats().Paused)
	assert.Empty(t, s.Events())
	s.SetPaused(false)
	require.Equal(t, 2, s.AddBatch(batch))
	require.True(t, s.AddEvent(testEvent("three", "eth0", events.KindHTTP)))
	assert.Equal(t, uint64(2), s.Events()[0].ArrivalSequence, "paused and unsupported arrivals do not consume retention sequences")
	assert.Equal(t, map[events.Kind]uint64{events.KindHTTP: 2}, s.CountByKind())
	assert.Equal(t, map[string]uint64{"pcap": 1, "eth0": 1}, s.CountBySource())
	s.RecordTransportLoss("overflow", 7)
	stats := s.Stats()
	assert.Equal(t, EventStoreStats{Arrived: 5, Retained: 2, Evicted: 1, Paused: 2, TransportLost: 7, TransportLossByKind: map[string]uint64{"overflow": 7}}, stats)
	stats.TransportLossByKind["overflow"] = 99
	assert.Equal(t, uint64(7), s.Stats().TransportLossByKind["overflow"])

	s.SetKindFilter([]events.Kind{events.KindHTTP})
	s.SetSourceFilter([]string{"pcap"})
	require.NoError(t, s.AddUserFilter("kind:http"))
	s.SetPaused(true)
	s.Reset()
	assert.True(t, s.Paused(), "reset preserves pause and filters")
	assert.Equal(t, 1, s.UserFilterCount())
	assert.Equal(t, EventStoreStats{TransportLossByKind: map[string]uint64{}}, s.Stats())
	assert.Empty(t, s.Events())
	assert.Empty(t, s.SelectedID())
	s.SetPaused(false)
	require.Equal(t, 3, s.AddBatch([]events.Event{testEvent("hidden-kind", "pcap", events.KindDNS), testEvent("hidden-source", "eth0", events.KindHTTP), testEvent("visible", "pcap", events.KindHTTP)}))
	require.Len(t, s.Events(), 1)
	assert.Equal(t, uint64(3), s.Events()[0].ArrivalSequence)
	assert.Equal(t, "visible", s.SelectedID())
	assert.Equal(t, uint64(1), s.Stats().Evicted)
}

func TestEventStoreBulkFilteredSelectionEviction(t *testing.T) {
	s := NewEventStore(4)
	s.SetKindFilter([]events.Kind{events.KindHTTP})
	s.SetSourceFilter([]string{"pcap"})
	require.NoError(t, s.AddUserFilter("kind:http"))
	s.AddBatch([]events.Event{testEvent("one", "pcap", events.KindHTTP), testEvent("two", "pcap", events.KindHTTP), testEvent("three", "pcap", events.KindHTTP)})
	require.True(t, s.SelectByID("two"))
	s.AddBatch([]events.Event{testEvent("hidden", "eth0", events.KindHTTP), testEvent("four", "pcap", events.KindHTTP)})
	assert.Equal(t, "two", s.SelectedID(), "retained history selection stays pinned")
	s.AddBatch([]events.Event{testEvent("dns", "pcap", events.KindDNS), testEvent("five", "pcap", events.KindHTTP)})
	assert.Equal(t, "four", s.SelectedID(), "evicted history selection falls back to the oldest visible retained event")
	selected, ok := s.Selected()
	require.True(t, ok)
	assert.Equal(t, "four", selected.Event.Envelope().EventID)
	s.SelectLast()
	s.AddBatch([]events.Event{testEvent("six", "pcap", events.KindHTTP), testEvent("hidden-last", "eth0", events.KindHTTP)})
	assert.Equal(t, "six", s.SelectedID(), "follow latest skips hidden batch tails")
	s.AddBatch([]events.Event{testEvent("a", "eth0", events.KindHTTP), testEvent("b", "eth0", events.KindHTTP), testEvent("c", "eth0", events.KindHTTP), testEvent("d", "eth0", events.KindHTTP)})
	assert.Empty(t, s.SelectedID())
	_, ok = s.Selected()
	assert.False(t, ok)
	s.AddBatch([]events.Event{testEvent("seven", "pcap", events.KindHTTP), testEvent("eight", "pcap", events.KindHTTP)})
	assert.Equal(t, "eight", s.SelectedID())
}

func TestEventStoreBulkConcurrentReadersAndWriters(t *testing.T) {
	const writers, batches, batchSize, capacity = 4, 40, 7, 31
	s := NewEventStore(capacity)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for writer := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for batch := range batches {
				items := make([]events.Event, batchSize)
				for i := range items {
					items[i] = testEvent(fmt.Sprintf("%d-%d-%d", writer, batch, i), "pcap", events.KindDNS)
				}
				assert.Equal(t, batchSize, s.AddBatch(items))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range batches * writers {
			items := s.Events()
			for i := 1; i < len(items); i++ {
				assert.Equal(t, items[i-1].ArrivalSequence+1, items[i].ArrivalSequence)
			}
			s.Selected()
			s.SelectPrevious()
			s.SelectLast()
			s.CountByKind()
			s.CountBySource()
			s.RecordTransportLoss("overflow", 1)
			stats := s.Stats()
			assert.Equal(t, stats.Arrived, stats.Retained+stats.Evicted)
		}
	}()
	close(start)
	wg.Wait()
	stats := s.Stats()
	assert.Equal(t, uint64(writers*batches*batchSize), stats.Arrived)
	assert.Equal(t, uint64(capacity), stats.Retained)
	assert.Equal(t, uint64(writers*batches*batchSize-capacity), stats.Evicted)
	assert.Equal(t, uint64(batches*writers), stats.TransportLost)
}

// Batch boundaries must not change observable retention, filtering, or selection
// compared with delivering the same arrivals individually.
func TestEventStoreBulkMatchesSingletonDelivery(t *testing.T) {
	for _, capacity := range []int{1, 3, 11} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			bulk, single := NewEventStore(capacity), NewEventStore(capacity)
			rng := rand.New(rand.NewSource(42))
			serial := 0
			for step := range 500 {
				switch rng.Intn(12) {
				case 0:
					paused := rng.Intn(2) == 0
					bulk.SetPaused(paused)
					single.SetPaused(paused)
				case 1:
					bulk.Reset()
					single.Reset()
				case 2:
					var kinds []events.Kind
					if rng.Intn(2) == 0 {
						kinds = []events.Kind{events.KindHTTP}
					}
					bulk.SetKindFilter(kinds)
					single.SetKindFilter(kinds)
				case 3:
					var sources []string
					if rng.Intn(2) == 0 {
						sources = []string{"pcap"}
					}
					bulk.SetSourceFilter(sources)
					single.SetSourceFilter(sources)
				case 4:
					bulk.SelectFirst()
					single.SelectFirst()
				case 5:
					bulk.SelectLast()
					single.SelectLast()
				case 6:
					delta := rng.Intn(7) - 3
					bulk.SelectOffset(delta)
					single.SelectOffset(delta)
				case 7:
					if bulk.HasUserFilters() {
						bulk.ClearUserFilters()
						single.ClearUserFilters()
					} else {
						require.NoError(t, bulk.AddUserFilter("kind:http"))
						require.NoError(t, single.AddUserFilter("kind:http"))
					}
				default:
					batch := make([]events.Event, rng.Intn(capacity*3+1))
					accepted := 0
					for i := range batch {
						serial++
						if rng.Intn(5) != 0 {
							kind := []events.Kind{events.KindDNS, events.KindHTTP, events.KindFileContent}[rng.Intn(3)]
							source := []string{"pcap", "eth0"}[rng.Intn(2)]
							batch[i] = testEvent(fmt.Sprintf("event-%d", serial), source, kind)
						}
						if single.AddEvent(batch[i]) {
							accepted++
						}
					}
					require.Equal(t, accepted, bulk.AddBatch(batch), "step %d", step)
				}
				require.Equal(t, single.Stats(), bulk.Stats(), "step %d", step)
				require.Equal(t, single.SelectedID(), bulk.SelectedID(), "step %d", step)
				require.Equal(t, single.CountByKind(), bulk.CountByKind(), "step %d", step)
				require.Equal(t, single.CountBySource(), bulk.CountBySource(), "step %d", step)
				want, got := single.Events(), bulk.Events()
				require.Len(t, got, len(want), "step %d", step)
				for i := range want {
					require.Equal(t, want[i].ArrivalSequence, got[i].ArrivalSequence, "step %d", step)
					require.Equal(t, want[i].Event.Envelope().EventID, got[i].Event.Envelope().EventID, "step %d", step)
				}
			}
		})
	}
}

func TestEventStoreBulkSteadyStateAllocations(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprintf("filtered_%t", filtered), func(t *testing.T) {
			const capacity, batchSize = 128, 17
			s := NewEventStore(capacity)
			// More distinct IDs than retention avoids false selection matches when
			// the prebuilt fixtures cycle during allocation measurement.
			pool := make([]events.Event, capacity+batchSize)
			for i := range pool {
				kind := events.KindHTTP
				if i%2 == 0 {
					kind = events.KindDNS
				}
				pool[i] = testEvent(fmt.Sprintf("event-%d", i), "pcap", kind)
			}
			if filtered {
				s.SetKindFilter([]events.Kind{events.KindHTTP})
			}
			s.AddBatch(pool[:capacity])
			s.SelectFirst()
			batch := make([]events.Event, batchSize)
			next := capacity
			allocations := testing.AllocsPerRun(100, func() {
				for i := range batch {
					batch[i] = pool[next]
					next = (next + 1) % len(pool)
				}
				s.AddBatch(batch)
			})
			assert.Zero(t, allocations, "steady-state batch insertion and pinned-selection eviction should allocate no projections or backing slices")
		})
	}
}

func TestEventStoreResetReleasesRetainedReferences(t *testing.T) {
	s := NewEventStore(3)
	s.AddBatch([]events.Event{testEvent("one", "pcap", events.KindDNS), testEvent("two", "pcap", events.KindHTTP), testEvent("three", "pcap", events.KindDNS), testEvent("four", "pcap", events.KindHTTP)})
	s.Reset()
	for i, item := range s.items[:cap(s.items)] {
		assert.Nil(t, item.Event, "backing slot %d still retains an event after reset", i)
		assert.Zero(t, item.ArrivalSequence)
		assert.True(t, item.ArrivedAt.IsZero())
	}
}

func TestEventStoreBulkRepeatedEventIdentity(t *testing.T) {
	// Redelivery repeats the same immutable event, including its identity and
	// filter metadata. Duplicate IDs can remain in the ring across wraparound.
	pool := []events.Event{
		testEvent("dns", "pcap", events.KindDNS),
		testEvent("http", "pcap", events.KindHTTP),
		testEvent("remote", "eth0", events.KindHTTP),
		testEvent("other-http", "pcap", events.KindHTTP),
	}
	bulk, single := NewEventStore(5), NewEventStore(5)
	for step, indices := range [][]int{
		{0, 1, 1, 2, 3},
		{1, 0, 1},
		{2, 1, 3, 1},
		{0, 2, 3, 3, 1, 0, 1, 2},
		{1, 3, 1, 0},
		{2, 3, 3, 0, 1, 3},
	} {
		for _, s := range []*EventStore{bulk, single} {
			switch step {
			case 1:
				s.SetKindFilter([]events.Kind{events.KindHTTP})
				require.True(t, s.SelectByID("http"))
			case 2:
				s.SetSourceFilter([]string{"pcap"})
				s.SelectLast()
			case 3:
				require.NoError(t, s.AddUserFilter("source:pcap"))
				s.SelectFirst()
			case 4:
				s.SetKindFilter(nil)
				s.SelectNext()
			case 5:
				s.SetSourceFilter(nil)
				s.ClearUserFilters()
				s.SelectLast()
			}
		}
		batch := make([]events.Event, len(indices))
		for i, index := range indices {
			batch[i] = pool[index]
			require.True(t, single.AddEvent(pool[index]))
		}
		require.Equal(t, len(batch), bulk.AddBatch(batch))
		require.Equal(t, single.Stats(), bulk.Stats(), "step %d", step)
		require.Equal(t, single.SelectedID(), bulk.SelectedID(), "step %d", step)
		want, got := single.Events(), bulk.Events()
		require.Len(t, got, len(want))
		for i := range want {
			assert.Equal(t, want[i].Event, got[i].Event, "step %d", step)
			assert.Equal(t, want[i].ArrivalSequence, got[i].ArrivalSequence, "step %d", step)
		}
	}
}
