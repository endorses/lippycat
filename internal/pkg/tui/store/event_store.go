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

// EventCursor identifies a synchronized projection. Callers retain the entire
// cursor returned by GetNewEvents; its zero value requests an initial snapshot.
type EventCursor struct {
	ArrivalSequence uint64
	Revision        uint64
	VisibleEvicted  uint64
}

// EventDelta is an atomic projection update. FullRefresh replaces the projection
// with Items; otherwise callers append Items and remove Trimmed oldest rows.
// Appending first preserves the view's stable-ID anchor across repeated delivery.
// SelectedID is authoritative even when no rows have changed.
type EventDelta struct {
	Items       []components.EventItem
	Cursor      EventCursor
	FullRefresh bool
	Trimmed     int
	SelectedID  string
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
	projectionRevision, visibleEvicted           uint64
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
		projectionRevision: 1,
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
				s.visibleEvicted++
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
	s.projectionRevision++
	s.visibleEvicted = 0
	s.arrived = 0
	s.evicted = 0
	s.pausedCount = 0
	s.transportLost = 0
	clear(s.lossByKind)
}

func (s *EventStore) SetKindFilter(kinds []events.Kind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sameEventFilter(s.kinds, kinds) {
		return
	}
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
	if sameEventFilter(s.sources, sources) {
		return
	}
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
	if len(s.userFilters) == 0 {
		return
	}
	s.userFilters = nil
	s.ensureVisibleSelectionLocked()
}

// sameEventFilter compares set membership while preserving nil (all) versus an
// empty non-nil filter (none). Duplicate requested values do not change a set.
func sameEventFilter[T comparable](current map[T]struct{}, requested []T) bool {
	if current == nil || requested == nil {
		return current == nil && requested == nil
	}
	for _, value := range requested {
		if _, ok := current[value]; !ok {
			return false
		}
	}
	for value := range current {
		found := false
		for _, candidate := range requested {
			if candidate == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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

// GetNewEvents mirrors PacketStore.GetNewPackets: fewer than capacity arrivals
// can be read directly from the newest ring slots; capacity or more requires a
// recovery snapshot. Filter changes and reset also invalidate the cursor.
// Cached visibility avoids evaluating filters again, and the eviction counter
// identifies old visible rows to trim without traversing retained history.
func (s *EventStore) GetNewEvents(cursor EventCursor) EventDelta {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := EventDelta{
		Cursor:     EventCursor{s.nextArrival, s.projectionRevision, s.visibleEvicted},
		SelectedID: s.selectedID,
	}
	if cursor.Revision != s.projectionRevision || cursor.ArrivalSequence > s.nextArrival ||
		cursor.VisibleEvicted > s.visibleEvicted || s.nextArrival-cursor.ArrivalSequence >= uint64(s.capacity) {
		result.FullRefresh = true
		result.Items = s.visibleItemsLocked()
		return result
	}
	result.Trimmed = int(s.visibleEvicted - cursor.VisibleEvicted)
	count := int(s.nextArrival - cursor.ArrivalSequence)
	// Allocate only matching rows, including no allocation for invisible arrivals.
	for i := 0; i < count; i++ {
		index := (s.head - count + s.capacity + i) % s.capacity
		if s.visible[index] {
			result.Items = append(result.Items, s.items[index])
		}
	}
	return result
}

func (s *EventStore) Selected() (components.EventItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := 0; i < s.count; i++ {
		item := s.itemLocked(i)
		if s.visible[(s.head-s.count+s.capacity+i)%s.capacity] && item.Event.Envelope().EventID == s.selectedID {
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
	for i := 0; i < s.count; i++ {
		index := (s.head - s.count + s.capacity + i) % s.capacity
		if s.visible[index] && s.items[index].Event.Envelope().EventID == id {
			s.selectedID = id
			s.followLatest = followWhenLast && index == s.lastVisible
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
	index := s.firstVisible
	if last {
		index = s.lastVisible
	}
	if index < 0 {
		s.selectedID = ""
		return
	}
	s.selectedID = s.items[index].Event.Envelope().EventID
	s.followLatest = last
}

func (s *EventStore) moveSelection(delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstVisible < 0 {
		s.selectedID = ""
		return
	}
	// Explicit navigation scans cached visibility without constructing a full
	// projection or evaluating predicates. Select the first matching stable ID,
	// preserving repeated-delivery behavior.
	visibleCount, selected := 0, 0
	found := false
	for i := 0; i < s.count; i++ {
		index := (s.head - s.count + s.capacity + i) % s.capacity
		if !s.visible[index] {
			continue
		}
		if !found && s.items[index].Event.Envelope().EventID == s.selectedID {
			selected, found = visibleCount, true
		}
		visibleCount++
	}
	target := max(0, min(visibleCount-1, selected+delta))
	visibleIndex := 0
	for i := 0; i < s.count; i++ {
		index := (s.head - s.count + s.capacity + i) % s.capacity
		if !s.visible[index] {
			continue
		}
		if visibleIndex == target {
			s.selectedID = s.items[index].Event.Envelope().EventID
			s.followLatest = target == visibleCount-1
			return
		}
		visibleIndex++
	}
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
		index := (s.head - s.count + s.capacity + i) % s.capacity
		if s.visible[index] {
			result = append(result, s.items[index])
		}
	}
	return result
}

// itemLocked returns the logical arrival-ordered item, never an unused slot.
func (s *EventStore) itemLocked(index int) components.EventItem {
	return s.items[(s.head-s.count+s.capacity+index)%s.capacity]
}

func (s *EventStore) ensureVisibleSelectionLocked() {
	s.projectionRevision++
	s.visibleEvicted = 0
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
		if s.visible[(s.head-s.count+s.capacity+i)%s.capacity] && item.Event.Envelope().EventID == s.selectedID {
			return
		}
	}
	index := s.firstVisible
	if s.followLatest {
		index = s.lastVisible
	}
	if index >= 0 {
		s.selectedID = s.items[index].Event.Envelope().EventID
		return
	}
	s.selectedID = ""
}
