//go:build tui || all

package store

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

type EventStoreStats struct {
	Arrived, Retained, Evicted, Paused uint64
	TransportLost                      uint64
	TransportLossByKind                map[string]uint64
}

// EventStore is a bounded, concurrency-safe arrival-ordered event buffer.
type EventStore struct {
	mu                                           sync.RWMutex
	capacity                                     int
	items                                        []components.EventItem
	nextArrival                                  uint64
	selectedID                                   string
	paused                                       bool
	arrived, evicted, pausedCount, transportLost uint64
	lossByKind                                   map[string]uint64
	kinds                                        map[events.Kind]struct{}
	sources                                      map[string]struct{}
}

func NewEventStore(capacity int) *EventStore {
	if capacity < 1 {
		capacity = 1
	}
	return &EventStore{capacity: capacity, items: make([]components.EventItem, 0, capacity), lossByKind: make(map[string]uint64)}
}

func (s *EventStore) AddEvent(event events.Event) bool {
	if event == nil || event.Kind() == events.KindFileContent {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arrived++
	if s.paused {
		s.pausedCount++
		return false
	}
	s.nextArrival++
	s.items = append(s.items, components.EventItem{Event: event, ArrivalSequence: s.nextArrival, ArrivedAt: time.Now()})
	if s.selectedID == "" {
		s.selectedID = event.Envelope().EventID
	}
	if len(s.items) > s.capacity {
		evicted := s.items[0].Event.Envelope().EventID
		copy(s.items, s.items[1:])
		s.items = s.items[:s.capacity]
		s.evicted++
		if s.selectedID == evicted {
			s.selectedID = s.items[0].Event.Envelope().EventID
		}
	}
	s.ensureVisibleSelectionLocked()
	return true
}

func (s *EventStore) AddBatch(batch []events.Event) int {
	added := 0
	for _, event := range batch {
		if s.AddEvent(event) {
			added++
		}
	}
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
	s.items = s.items[:0]
	s.selectedID = ""
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

func (s *EventStore) Events() []components.EventItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.visibleItemsLocked()
}

func (s *EventStore) Selected() (components.EventItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.items {
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == s.selectedID {
			return item, true
		}
	}
	return components.EventItem{}, false
}
func (s *EventStore) SelectedID() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.selectedID }
func (s *EventStore) SelectByID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == id {
			s.selectedID = id
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
	return EventStoreStats{Arrived: s.arrived, Retained: uint64(len(s.items)), Evicted: s.evicted, Paused: s.pausedCount, TransportLost: s.transportLost, TransportLossByKind: losses}
}

func (s *EventStore) CountByKind() map[events.Kind]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[events.Kind]uint64)
	for _, item := range s.items {
		result[item.Event.Kind()]++
	}
	return result
}
func (s *EventStore) CountBySource() map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]uint64)
	for _, item := range s.items {
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
	return true
}
func (s *EventStore) visibleItemsLocked() []components.EventItem {
	result := make([]components.EventItem, 0, len(s.items))
	for _, item := range s.items {
		if s.visibleLocked(item.Event) {
			result = append(result, item)
		}
	}
	return result
}
func (s *EventStore) ensureVisibleSelectionLocked() {
	for _, item := range s.items {
		if s.visibleLocked(item.Event) && item.Event.Envelope().EventID == s.selectedID {
			return
		}
	}
	for _, item := range s.items {
		if s.visibleLocked(item.Event) {
			s.selectedID = item.Event.Envelope().EventID
			return
		}
	}
	s.selectedID = ""
}
