//go:build tui || all

package store

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

type EventStoreStats struct {
	Arrived, Retained, Evicted, Paused uint64
	TransportLost                      uint64
	TransportLossByKind                map[string]uint64
}

// EventStore is a bounded, concurrency-safe arrival-ordered event buffer.
// Events are immutable after ingestion; a stable EventID identifies the same
// event metadata on repeated delivery, including all fields used by filters.
//
// The ring follows PacketStore.AddPacketBatch: items has exactly capacity slots,
// head names the next write slot, and count is bounded by capacity. Before the
// first wrap, live slots start at zero; when full, head is also the oldest slot.
// Ordered materialization starts at (head-count+capacity)%capacity. PacketStore's
// GetNewPackets uses the same rule for the newest n slots, starting at head-n,
// and requires a full refresh when arrivals since its cursor reach capacity.
// ArrivalSequence records accepted, unpaused arrivals independently of wrap.
//
// visible caches the current filters for each live slot. Its first/last indices
// let ingestion repair selection without scanning the retained projection. When
// the first visible slot is evicted, advancing to its successor visits each
// intervening slot at most once during that slot's retained lifetime. Thus ring
// insertion and selection maintenance are amortized O(1) per arrival. Filter
// changes rebuild the cache; filtering and navigation may still scan the ring.
type EventStore struct {
	mu                                           sync.RWMutex
	capacity                                     int
	items                                        []components.EventItem
	head, count                                  int
	visible                                      []bool
	firstVisible, lastVisible                    int
	nextArrival                                  uint64
	selectedID                                   string
	followLatest                                 bool
	paused                                       bool
	arrived, evicted, pausedCount, transportLost uint64
	lossByKind                                   map[string]uint64
	kinds                                        map[events.Kind]struct{}
	sources                                      map[string]struct{}
	userFilters                                  []eventUserFilter
}

type eventUserFilter struct {
	description string
	predicate   eventquery.Predicate
}

func NewEventStore(capacity int) *EventStore {
	if capacity < 1 {
		capacity = 1
	}
	return &EventStore{
		capacity: capacity, items: make([]components.EventItem, capacity),
		visible: make([]bool, capacity), firstVisible: -1, lastVisible: -1,
		followLatest: true, lossByKind: make(map[string]uint64),
	}
}

func (s *EventStore) AddEvent(event events.Event) bool {
	return s.AddBatch([]events.Event{event}) == 1
}

// AddBatch applies one ordered delivery under a single lock. Selection transitions
// are tracked locally, including intermediate evictions in oversized batches,
// then committed once so batching preserves singleton ingestion behavior.
func (s *EventStore) AddBatch(batch []events.Event) int {
	if len(batch) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	added, oldCount := 0, s.count
	selectedID := s.selectedID
	for _, event := range batch {
		if event == nil || event.Kind() == events.KindFileContent {
			continue
		}
		s.arrived++
		if s.paused {
			s.pausedCount++
			continue
		}

		full := s.count == s.capacity
		evictedID := ""
		if full {
			evictedID = s.items[s.head].Event.Envelope().EventID
			if s.visible[s.head] {
				s.visible[s.head] = false
				if s.firstVisible == s.lastVisible {
					s.firstVisible, s.lastVisible = -1, -1
				} else {
					next := (s.head + 1) % s.capacity
					for !s.visible[next] {
						next = (next + 1) % s.capacity
					}
					s.firstVisible = next
				}
			}
		} else {
			s.count++
		}

		s.nextArrival++
		s.items[s.head] = components.EventItem{Event: event, ArrivalSequence: s.nextArrival, ArrivedAt: time.Now()}
		isVisible := s.visibleLocked(event)
		s.visible[s.head] = isVisible
		if isVisible {
			if s.firstVisible < 0 {
				s.firstVisible = s.head
			}
			s.lastVisible = s.head
		}
		s.head = (s.head + 1) % s.capacity
		added++

		// Existing selections are visible until overwritten. Preserve the old
		// physical-oldest fallback before applying the visible-boundary repair;
		// followLatest can still select an older row after a filter is broadened.
		selectionVisible := true
		if selectedID == "" || (s.followLatest && isVisible) {
			selectedID = event.Envelope().EventID
			selectionVisible = isVisible
		}
		if full && selectedID == evictedID {
			selectedID = s.items[s.head].Event.Envelope().EventID
			selectionVisible = s.visible[s.head]
		}
		if !selectionVisible {
			index := s.firstVisible
			if s.followLatest {
				index = s.lastVisible
			}
			selectedID = ""
			if index >= 0 {
				selectedID = s.items[index].Event.Envelope().EventID
			}
		}
	}
	// Every accepted item counts, including items overwritten within this batch.
	// The ring bounds retention as it writes; accounting is applied once.
	s.evicted += uint64(oldCount + added - s.count)
	s.selectedID = selectedID
	return added
}

func (s *EventStore) SetPaused(paused bool) { s.mu.Lock(); s.paused = paused; s.mu.Unlock() }
func (s *EventStore) TogglePaused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = !s.paused
	return s.paused
}
func (s *EventStore) Paused() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.paused }

func (s *EventStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.items)
	clear(s.visible)
	s.head, s.count = 0, 0
	s.firstVisible, s.lastVisible = -1, -1
	s.selectedID = ""
	s.followLatest = true
	s.nextArrival = 0
	s.arrived = 0
	s.evicted = 0
	s.pausedCount = 0
	s.transportLost = 0
	clear(s.lossByKind)
}

func (s *EventStore) SetKindFilter(kinds []events.Kind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kinds = nil
	if kinds != nil {
		s.kinds = make(map[events.Kind]struct{}, len(kinds))
		for _, kind := range kinds {
			s.kinds[kind] = struct{}{}
		}
	}
	s.ensureVisibleSelectionLocked()
}

func (s *EventStore) SetSourceFilter(sources []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = nil
	if sources != nil {
		s.sources = make(map[string]struct{}, len(sources))
		for _, source := range sources {
			s.sources[source] = struct{}{}
		}
	}
	s.ensureVisibleSelectionLocked()
}

// AddUserFilter compiles and stacks a local event query with AND semantics.
// Compilation happens before mutation so invalid queries leave the projection unchanged.
func (s *EventStore) AddUserFilter(description string) error {
	predicate, err := eventquery.Compile(description)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userFilters = append(s.userFilters, eventUserFilter{description: description, predicate: predicate})
	s.ensureVisibleSelectionLocked()
	return nil
}

func (s *EventStore) RemoveLastUserFilter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.userFilters) == 0 {
		return false
	}
	s.userFilters = s.userFilters[:len(s.userFilters)-1]
	s.ensureVisibleSelectionLocked()
	return true
}

func (s *EventStore) ClearUserFilters() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userFilters = nil
	s.ensureVisibleSelectionLocked()
}

func (s *EventStore) HasUserFilters() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.userFilters) > 0
}

func (s *EventStore) UserFilterCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.userFilters)
}

func (s *EventStore) UserFilterDescriptions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	descriptions := make([]string, len(s.userFilters))
	for i := range s.userFilters {
		descriptions[i] = s.userFilters[i].description
	}
	return descriptions
}

func (s *EventStore) Events() []components.EventItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.visibleItemsLocked()
}

func (s *EventStore) Selected() (components.EventItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == s.selectedID {
			return item, true
		}
	}
	return components.EventItem{}, false
}
func (s *EventStore) SelectedID() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.selectedID }
func (s *EventStore) SelectByID(id string) bool {
	return s.selectByID(id, false)
}

// SelectByIDFollowingLatest selects an event and enables live-edge following
// when that event is the last visible item. Mouse selection uses this to match
// PacketList.SetCursor behavior.
func (s *EventStore) SelectByIDFollowingLatest(id string) bool {
	return s.selectByID(id, true)
}

func (s *EventStore) selectByID(id string, followWhenLast bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	visible := s.visibleItemsLocked()
	for i, item := range visible {
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == id {
			s.selectedID = id
			s.followLatest = followWhenLast && i == len(visible)-1
			return true
		}
	}
	return false
}
func (s *EventStore) SelectNext()            { s.moveSelection(1) }
func (s *EventStore) SelectPrevious()        { s.moveSelection(-1) }
func (s *EventStore) SelectFirst()           { s.selectBoundary(false) }
func (s *EventStore) SelectLast()            { s.selectBoundary(true) }
func (s *EventStore) SelectOffset(delta int) { s.moveSelection(delta) }

func (s *EventStore) selectBoundary(last bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	visible := s.visibleItemsLocked()
	if len(visible) == 0 {
		s.selectedID = ""
		return
	}
	index := 0
	if last {
		index = len(visible) - 1
	}
	s.selectedID = visible[index].Event.Envelope().EventID
	s.followLatest = last
}

func (s *EventStore) moveSelection(delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	visible := s.visibleItemsLocked()
	if len(visible) == 0 {
		s.selectedID = ""
		return
	}
	index := 0
	for i := range visible {
		if visible[i].Event.Envelope().EventID == s.selectedID {
			index = i
			break
		}
	}
	index += delta
	if index < 0 {
		index = 0
	}
	if index >= len(visible) {
		index = len(visible) - 1
	}
	s.selectedID = visible[index].Event.Envelope().EventID
	s.followLatest = index == len(visible)-1
}

func (s *EventStore) RecordTransportLoss(kind string, count uint64) {
	if count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transportLost += count
	s.lossByKind[kind] += count
}

func (s *EventStore) Stats() EventStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	losses := make(map[string]uint64, len(s.lossByKind))
	for kind, count := range s.lossByKind {
		losses[kind] = count
	}
	return EventStoreStats{Arrived: s.arrived, Retained: uint64(s.count), Evicted: s.evicted, Paused: s.pausedCount, TransportLost: s.transportLost, TransportLossByKind: losses}
}

func (s *EventStore) CountByKind() map[events.Kind]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[events.Kind]uint64)
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		result[item.Event.Kind()]++
	}
	return result
}
func (s *EventStore) CountBySource() map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]uint64)
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		result[item.Event.Envelope().Provenance.CaptureSource]++
	}
	return result
}

func (s *EventStore) visibleLocked(event events.Event) bool {
	if s.kinds != nil {
		if _, ok := s.kinds[event.Kind()]; !ok {
			return false
		}
	}
	if s.sources != nil {
		if _, ok := s.sources[event.Envelope().Provenance.CaptureSource]; !ok {
			return false
		}
	}
	for _, filter := range s.userFilters {
		if !filter.predicate(event) {
			return false
		}
	}
	return true
}
func (s *EventStore) visibleItemsLocked() []components.EventItem {
	result := make([]components.EventItem, 0, s.count)
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		if s.visibleLocked(item.Event) {
			result = append(result, item)
		}
	}
	return result
}

// itemLocked returns the logical arrival-ordered item, never an unused slot.
func (s *EventStore) itemLocked(index int) components.EventItem {
	return s.items[(s.head-s.count+s.capacity+index)%s.capacity]
}

func (s *EventStore) ensureVisibleSelectionLocked() {
	// All callers change filters, so refresh visibility before repairing the
	// selected ID. Ingestion maintains this cache directly for new arrivals.
	clear(s.visible)
	s.firstVisible, s.lastVisible = -1, -1
	for i := 0; i < s.count; i++ {
		index := (s.head - s.count + s.capacity + i) % s.capacity
		if s.visibleLocked(s.items[index].Event) {
			s.visible[index] = true
			if s.firstVisible < 0 {
				s.firstVisible = index
			}
			s.lastVisible = index
		}
	}
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == s.selectedID {
			return
		}
	}
	visible := s.visibleItemsLocked()
	if len(visible) > 0 {
		index := 0
		if s.followLatest {
			index = len(visible) - 1
		}
		s.selectedID = visible[index].Event.Envelope().EventID
		return
	}
	s.selectedID = ""
}
