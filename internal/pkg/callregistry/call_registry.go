// Package callregistry defines protocol-domain call lifecycle contracts without
// depending on analyzers, transports, or output resources.
package callregistry

import (
	"container/list"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Lifetime identifies one registry session and one immutable call incarnation.
// It is independent of recency and survives updates to an existing call.
type Lifetime struct{ Session, Generation uint64 }

var registrySessions atomic.Uint64

type Call struct {
	Lifetime    Lifetime
	CallID      string
	State       string
	From        string
	To          string
	Created     time.Time
	LastUpdated time.Time
}

type EndReason string

const (
	EndCompleted EndReason = "completed"
	EndTimeout   EndReason = "timeout"
	EndEvicted   EndReason = "evicted"
	EndShutdown  EndReason = "shutdown"
)

// CompletingObserver is optional: completion grace begins before final removal.
// Implementations receive exact-lifetime snapshots outside registry locks.
type CompletingObserver interface {
	OnCallCompleting(Call)
}

type LifecycleObserver interface {
	OnCallStarted(Call)
	OnCallEnded(Call, EndReason)
}

// SelectionInput describes one parsed message's selection context. Filtering
// remains topology-specific; this contract decides how a direct verdict and a
// previously selected dialog combine.
type SelectionInput struct {
	FilterConfigured   bool
	DirectMatch        bool
	PreviouslySelected bool
}

// SelectionPolicy decides whether a message belongs to selected output.
type SelectionPolicy interface {
	Select(SelectionInput) bool
}

// StickySelectionPolicy selects all messages when no filter is configured and,
// with filtering enabled, preserves selection for the rest of a dialog after
// any message directly matches.
type StickySelectionPolicy struct{}

func (StickySelectionPolicy) Select(input SelectionInput) bool {
	return !input.FilterConfigured || input.DirectMatch || input.PreviouslySelected
}

type Registry interface {
	ActiveCalls() []Call
	ActiveCallCount() int
	EndpointAssociationCount() int
	Call(callID string) (Call, bool)
	CallIDsForEndpoint(endpoint string) []string
	ResolveMediaEndpoints(sourceEndpoint, destinationEndpoint string) MediaResolution
	AssociateEndpoint(callID, endpoint string)
	CompleteCall(callID string)
	Close()
}

// MediaResolutionStatus describes whether exact packet endpoints prove a
// single active call owns a media packet.
type MediaResolutionStatus uint8

const (
	MediaUnresolved MediaResolutionStatus = iota
	MediaResolved
	MediaAmbiguous
)

// MediaResolution is an attribution result, not a candidate list. CallID is
// populated only when Status is MediaResolved.
type MediaResolution struct {
	// Lifetime is captured atomically with ownership; callers must not look up
	// a potentially reused Call-ID later to inherit selection.
	Lifetime Lifetime
	Status   MediaResolutionStatus
	CallID   string
}

// Config bounds the state owned by a Core. Limits are hard limits; an
// association rejected because of a limit is not partially installed.
// EndpointObservation is an owned, ordered snapshot of accepted associations.
// Observers run outside registry locks and may reenter the registry. Concurrent
// delivery can reorder callbacks; consumers must compare Revision and Lifetime.
type EndpointObservation struct {
	Call      Call
	Revision  uint64
	Endpoints []string
}

type EndpointObserver interface{ OnEndpointsChanged(EndpointObservation) }

type Config struct {
	EndpointObservers       []EndpointObserver
	MaxCalls                int
	MaxEndpointsPerCall     int
	MaxEndpointAssociations int
	Observers               []LifecycleObserver
	// EvictionPriority ranks unpinned calls; larger values are evicted first.
	EvictionPriority func(Call) int
}

// Core is the shared, instance-owned call lifecycle and endpoint-association
// registry. It deliberately stores only protocol-neutral call data; analyzers
// retain their topology-specific metadata beside it.
type Core struct {
	session           uint64
	nextLifetime      uint64
	nextObservation   uint64
	mu                sync.RWMutex
	calls             map[string]Call
	endpointCalls     map[string][]string
	endpointWinner    map[string]string
	callEndpoints     map[string]map[string]struct{}
	associationCount  int
	recency           *list.List
	recencyIndex      map[string]*list.Element
	recencyGeneration map[string]uint64
	nextGeneration    uint64
	config            Config
	closed            bool
	pins              map[string]int
}

func New(config Config) *Core {
	if config.MaxCalls <= 0 {
		config.MaxCalls = 1
	}
	if config.MaxEndpointsPerCall <= 0 {
		config.MaxEndpointsPerCall = 1
	}
	if config.MaxEndpointAssociations <= 0 {
		config.MaxEndpointAssociations = config.MaxCalls * config.MaxEndpointsPerCall
	}
	config.Observers = append([]LifecycleObserver(nil), config.Observers...)
	config.EndpointObservers = append([]EndpointObserver(nil), config.EndpointObservers...)
	return &Core{
		session:           registrySessions.Add(1),
		calls:             make(map[string]Call),
		endpointCalls:     make(map[string][]string),
		endpointWinner:    make(map[string]string),
		callEndpoints:     make(map[string]map[string]struct{}),
		recency:           list.New(),
		recencyIndex:      make(map[string]*list.Element),
		recencyGeneration: make(map[string]uint64),
		pins:              make(map[string]int),
		config:            config,
	}
}

func (c *Core) AddObserver(observer LifecycleObserver) {
	if observer == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.config.Observers = append(c.config.Observers, observer)
	}
}

// Upsert adds or replaces a call and makes it most recently used. Lifecycle
// callbacks are synchronous and ordered after the mutation. It returns false
// after Close or for an empty Call-ID.
func (c *Core) Upsert(call Call) bool {
	accepted, _ := c.UpsertWithEviction(call)
	return accepted
}

// UpsertWithEviction has the same mutation and observer ordering as Upsert.
// It reports the call removed by this mutation so callers can discard their
// associated state without taking and comparing full registry snapshots.
func (c *Core) UpsertWithEviction(call Call) (accepted bool, evictedID string) {
	if call.CallID == "" {
		return false, ""
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, ""
	}
	previous, existed := c.calls[call.CallID]
	if existed {
		call.Lifetime = previous.Lifetime
		c.calls[call.CallID] = call
		c.touchLocked(call.CallID)
		c.mu.Unlock()
		return true, ""
	}
	var evicted *Call
	if len(c.calls) >= c.config.MaxCalls {
		oldest := c.evictionCandidateLocked()
		if oldest != nil {
			removed := c.removeLocked(oldest.Value.(string))
			evicted = &removed
			evictedID = removed.CallID
		}
		if oldest == nil {
			c.mu.Unlock()
			return false, ""
		}
	}
	c.nextLifetime++
	call.Lifetime = Lifetime{Session: c.session, Generation: c.nextLifetime}
	c.calls[call.CallID] = call
	c.recencyIndex[call.CallID] = c.recency.PushFront(call.CallID)
	c.markRecentLocked(call.CallID)
	observers := append([]LifecycleObserver(nil), c.config.Observers...)
	c.mu.Unlock()
	if evicted != nil {
		notifyEnded(observers, *evicted, EndEvicted)
	}
	for _, observer := range observers {
		observer.OnCallStarted(call)
	}
	return true, evictedID
}

func (c *Core) evictionCandidateLocked() *list.Element {
	var candidate *list.Element
	bestPriority := -1
	for elem := c.recency.Back(); elem != nil; elem = elem.Prev() {
		id := elem.Value.(string)
		if c.pins[id] > 0 {
			continue
		}
		// Without custom priorities every candidate has equal rank; the first
		// unpinned entry from the LRU end is already the final answer.
		if c.config.EvictionPriority == nil {
			return elem
		}
		priority := 0
		if c.config.EvictionPriority != nil {
			priority = c.config.EvictionPriority(c.calls[id])
		}
		if candidate == nil || priority > bestPriority {
			candidate, bestPriority = elem, priority
		}
	}
	return candidate
}

func (c *Core) Pin(callID string) {
	if callID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.pins[callID]++
	}
}

func (c *Core) Unpin(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pins[callID] <= 1 {
		delete(c.pins, callID)
	} else {
		c.pins[callID]--
	}
}

func (c *Core) IsPinned(callID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pins[callID] > 0
}

func (c *Core) touchLocked(callID string) {
	if elem := c.recencyIndex[callID]; elem != nil {
		c.recency.MoveToFront(elem)
	}
	c.markRecentLocked(callID)
}

func (c *Core) markRecentLocked(callID string) {
	c.nextGeneration++
	c.recencyGeneration[callID] = c.nextGeneration
	for endpoint := range c.callEndpoints[callID] {
		c.endpointWinner[endpoint] = callID
	}
}

// Touch refreshes recency and LastUpdated for an existing call.
func (c *Core) Touch(callID string, at time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	call, ok := c.calls[callID]
	if !ok || c.closed {
		return false
	}
	call.LastUpdated = at
	c.calls[callID] = call
	c.touchLocked(callID)
	return true
}

func (c *Core) ActiveCalls() []Call {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]Call, 0, len(c.calls))
	for elem := c.recency.Front(); elem != nil; elem = elem.Next() {
		result = append(result, c.calls[elem.Value.(string)])
	}
	return result
}

// ActiveCallCount returns the number of calls without materializing the active
// call collection.
func (c *Core) ActiveCallCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.calls)
}

// EndpointAssociationCount returns the number of endpoint-to-call
// associations. A shared endpoint contributes one association for each call
// that owns it.
func (c *Core) EndpointAssociationCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.associationCount
}

func (c *Core) Call(callID string) (Call, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	call, ok := c.calls[callID]
	return call, ok
}

// AssociateEndpoint adds a deduplicated, multi-owner endpoint association.
func (c *Core) TryAssociateEndpoint(callID, endpoint string) bool {
	return c.tryAssociateEndpoint(callID, Lifetime{}, endpoint)
}

// TryAssociateEndpointForLifetime prevents a delayed promotion from mutating a
// different incarnation of a reused Call-ID. Zero lifetime is never accepted.
func (c *Core) TryAssociateEndpointForLifetime(callID string, lifetime Lifetime, endpoint string) bool {
	if lifetime == (Lifetime{}) {
		return false
	}
	return c.tryAssociateEndpoint(callID, lifetime, endpoint)
}

func (c *Core) tryAssociateEndpoint(callID string, lifetime Lifetime, endpoint string) bool {
	if callID == "" || endpoint == "" {
		return false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	if call, ok := c.calls[callID]; !ok || (lifetime != (Lifetime{}) && call.Lifetime != lifetime) {
		c.mu.Unlock()
		return false
	}
	if _, ok := c.callEndpoints[callID][endpoint]; ok {
		c.mu.Unlock()
		return true
	}
	if len(c.callEndpoints[callID]) >= c.config.MaxEndpointsPerCall || c.associationCount >= c.config.MaxEndpointAssociations {
		c.mu.Unlock()
		return false
	}
	if c.callEndpoints[callID] == nil {
		c.callEndpoints[callID] = make(map[string]struct{})
	}
	c.callEndpoints[callID][endpoint] = struct{}{}
	c.endpointCalls[endpoint] = append(c.endpointCalls[endpoint], callID)
	if winner := c.endpointWinner[endpoint]; winner == "" || c.recencyGeneration[callID] > c.recencyGeneration[winner] {
		c.endpointWinner[endpoint] = callID
	}
	c.associationCount++
	observation, observers := c.endpointObservationLocked(callID)
	c.mu.Unlock()
	notifyEndpoints(observers, observation)
	return true
}

func (c *Core) AddEndpointObserver(observer EndpointObserver) {
	if observer == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.config.EndpointObservers = append(c.config.EndpointObservers, observer)
	}
}

func (c *Core) endpointObservationLocked(callID string) (EndpointObservation, []EndpointObserver) {
	// Disabled consumers impose no snapshot allocation on the normal hot path.
	if len(c.config.EndpointObservers) == 0 {
		return EndpointObservation{}, nil
	}
	c.nextObservation++
	observation := EndpointObservation{Call: c.calls[callID], Revision: c.nextObservation}
	for endpoint := range c.callEndpoints[callID] {
		observation.Endpoints = append(observation.Endpoints, endpoint)
	}
	sort.Strings(observation.Endpoints)
	return observation, append([]EndpointObserver(nil), c.config.EndpointObservers...)
}

func notifyEndpoints(observers []EndpointObserver, observation EndpointObservation) {
	for _, observer := range observers {
		snapshot := observation
		snapshot.Endpoints = append([]string(nil), observation.Endpoints...)
		observer.OnEndpointsChanged(snapshot)
	}
}

func (c *Core) AssociateEndpoint(callID, endpoint string) {
	c.TryAssociateEndpoint(callID, endpoint)
}

func (c *Core) CallIDsForEndpoint(endpoint string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.endpointCalls[endpoint]...)
}

// ResolveMediaEndpoints atomically snapshots the active owners of two exact
// IP:port endpoints. When both sides have owners their intersection is the
// candidate set; otherwise the non-empty side is used. No registry or caller
// lock may be held while calling this method.
func (c *Core) ResolveMediaEndpoints(sourceEndpoint, destinationEndpoint string) MediaResolution {
	c.mu.RLock()
	defer c.mu.RUnlock()

	source := c.endpointCalls[sourceEndpoint]
	destination := c.endpointCalls[destinationEndpoint]
	candidateCount := 0
	resolvedID := ""
	if len(source) > 0 && len(destination) > 0 {
		destinationOwners := make(map[string]struct{}, len(destination))
		for _, callID := range destination {
			if _, active := c.calls[callID]; active {
				destinationOwners[callID] = struct{}{}
			}
		}
		for _, callID := range source {
			if _, active := c.calls[callID]; !active {
				continue
			}
			if _, ownsDestination := destinationOwners[callID]; ownsDestination {
				candidateCount++
				resolvedID = callID
			}
		}
	} else {
		owners := source
		if len(owners) == 0 {
			owners = destination
		}
		for _, callID := range owners {
			if _, active := c.calls[callID]; active {
				candidateCount++
				resolvedID = callID
			}
		}
	}

	switch candidateCount {
	case 0:
		return MediaResolution{Status: MediaUnresolved}
	case 1:
		return MediaResolution{Status: MediaResolved, CallID: resolvedID, Lifetime: c.calls[resolvedID].Lifetime}
	default:
		return MediaResolution{Status: MediaAmbiguous}
	}
}

// MostRecentCallIDForEndpoint is a presentation heuristic for diagnostics and
// UI display. Recency does not prove media ownership; this result is unsuitable
// for filtering, output attribution, Call-ID stamping, or LI correlation.
func (c *Core) MostRecentCallIDForEndpoint(endpoint string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	callID, ok := c.endpointWinner[endpoint]
	return callID, ok
}

// EndpointsForCall returns an owned snapshot in lexical order so presentation
// and offline comparisons do not depend on map iteration order.
func (c *Core) EndpointsForCall(callID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	endpoints := c.callEndpoints[callID]
	result := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		result = append(result, endpoint)
	}
	sort.Strings(result)
	return result
}

// ExpiredUnpinned returns calls whose registry activity predates cutoff. The
// caller remains responsible for removing them so protocol-specific lifecycle
// side effects can be ordered around removal.
func (c *Core) ExpiredUnpinned(cutoff time.Time) []Call {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]Call, 0)
	for elem := c.recency.Back(); elem != nil; elem = elem.Prev() {
		id := elem.Value.(string)
		call := c.calls[id]
		if c.pins[id] == 0 && call.LastUpdated.Before(cutoff) {
			result = append(result, call)
		}
	}
	return result
}

// TryDissociateEndpointsForLifetime releases only the requested endpoint
// ownerships for an exact live call incarnation. Missing endpoints are an
// accepted no-op. The call lifecycle and pins remain unchanged.
func (c *Core) TryDissociateEndpointsForLifetime(callID string, lifetime Lifetime, endpoints []string) bool {
	if callID == "" || lifetime == (Lifetime{}) {
		return false
	}
	c.mu.Lock()
	call, exists := c.calls[callID]
	if c.closed || !exists || call.Lifetime != lifetime {
		c.mu.Unlock()
		return false
	}
	changed := false
	for _, endpoint := range endpoints {
		if _, owned := c.callEndpoints[callID][endpoint]; !owned {
			continue
		}
		delete(c.callEndpoints[callID], endpoint)
		c.endpointCalls[endpoint] = withoutCallID(c.endpointCalls[endpoint], callID)
		if len(c.endpointCalls[endpoint]) == 0 {
			delete(c.endpointCalls, endpoint)
			delete(c.endpointWinner, endpoint)
		} else if c.endpointWinner[endpoint] == callID {
			c.recomputeEndpointWinnerLocked(endpoint)
		}
		c.associationCount--
		changed = true
	}
	if len(c.callEndpoints[callID]) == 0 {
		delete(c.callEndpoints, callID)
	}
	var observation EndpointObservation
	var observers []EndpointObserver
	if changed {
		observation, observers = c.endpointObservationLocked(callID)
	}
	c.mu.Unlock()
	notifyEndpoints(observers, observation)
	return true
}

// DissociateEndpoints releases every endpoint owned by callID while retaining
// the call lifecycle record (for example during a trailing-media grace period).
func (c *Core) DissociateEndpoints(callID string) {
	c.mu.Lock()
	_, exists := c.calls[callID]
	c.dissociateEndpointsLocked(callID)
	delete(c.pins, callID)
	var observation EndpointObservation
	var observers []EndpointObserver
	if exists {
		observation, observers = c.endpointObservationLocked(callID)
	}
	c.mu.Unlock()
	notifyEndpoints(observers, observation)
}

func (c *Core) Remove(callID string, reason EndReason) bool {
	c.mu.Lock()
	if _, ok := c.calls[callID]; !ok {
		c.mu.Unlock()
		return false
	}
	call := c.removeLocked(callID)
	observers := append([]LifecycleObserver(nil), c.config.Observers...)
	c.mu.Unlock()
	notifyEnded(observers, call, reason)
	return true
}

// NotifyCallCompleting publishes the beginning of authoritative completion grace.
// A reused Call-ID cannot receive delayed completion from its prior incarnation.
// Observer callbacks may reenter the registry and must validate their captured
// lifetime again before changing any external ownership.
func (c *Core) NotifyCallCompleting(callID string, lifetime Lifetime) bool {
	c.mu.RLock()
	call, exists := c.calls[callID]
	if !exists || call.Lifetime != lifetime {
		c.mu.RUnlock()
		return false
	}
	observers := append([]LifecycleObserver(nil), c.config.Observers...)
	c.mu.RUnlock()
	for _, observer := range observers {
		if completing, ok := observer.(CompletingObserver); ok {
			completing.OnCallCompleting(call)
		}
	}
	return true
}

func (c *Core) CompleteCall(callID string) { c.Remove(callID, EndCompleted) }

func (c *Core) removeLocked(callID string) Call {
	call := c.calls[callID]
	delete(c.calls, callID)
	if elem := c.recencyIndex[callID]; elem != nil {
		c.recency.Remove(elem)
		delete(c.recencyIndex, callID)
	}
	c.dissociateEndpointsLocked(callID)
	delete(c.recencyGeneration, callID)
	return call
}

func (c *Core) recomputeEndpointWinnerLocked(endpoint string) {
	var winner string
	var winnerGeneration uint64
	for _, callID := range c.endpointCalls[endpoint] {
		if generation := c.recencyGeneration[callID]; winner == "" || generation > winnerGeneration {
			winner = callID
			winnerGeneration = generation
		}
	}
	if winner == "" {
		delete(c.endpointWinner, endpoint)
		return
	}
	c.endpointWinner[endpoint] = winner
}

func (c *Core) dissociateEndpointsLocked(callID string) {
	for endpoint := range c.callEndpoints[callID] {
		c.endpointCalls[endpoint] = withoutCallID(c.endpointCalls[endpoint], callID)
		if len(c.endpointCalls[endpoint]) == 0 {
			delete(c.endpointCalls, endpoint)
			delete(c.endpointWinner, endpoint)
		} else if c.endpointWinner[endpoint] == callID {
			c.recomputeEndpointWinnerLocked(endpoint)
		}
		c.associationCount--
	}
	delete(c.callEndpoints, callID)
}

func (c *Core) clear(reason EndReason, closeRegistry bool) {
	c.mu.Lock()
	if closeRegistry && c.closed {
		c.mu.Unlock()
		return
	}
	calls := make([]Call, 0, len(c.calls))
	for elem := c.recency.Front(); elem != nil; elem = elem.Next() {
		calls = append(calls, c.calls[elem.Value.(string)])
	}
	c.calls = make(map[string]Call)
	c.endpointCalls = make(map[string][]string)
	c.endpointWinner = make(map[string]string)
	c.callEndpoints = make(map[string]map[string]struct{})
	c.associationCount = 0
	c.recency.Init()
	c.recencyIndex = make(map[string]*list.Element)
	c.recencyGeneration = make(map[string]uint64)
	c.nextGeneration = 0
	c.pins = make(map[string]int)
	c.closed = closeRegistry
	observers := append([]LifecycleObserver(nil), c.config.Observers...)
	c.mu.Unlock()
	for _, call := range calls {
		notifyEnded(observers, call, reason)
	}
}

func (c *Core) Clear() { c.clear(EndCompleted, false) }
func (c *Core) Close() { c.clear(EndShutdown, true) }

func notifyEnded(observers []LifecycleObserver, call Call, reason EndReason) {
	for _, observer := range observers {
		observer.OnCallEnded(call, reason)
	}
}

func withoutCallID(callIDs []string, removed string) []string {
	for index, callID := range callIDs {
		if callID == removed {
			return append(callIDs[:index], callIDs[index+1:]...)
		}
	}
	return callIDs
}

var _ Registry = (*Core)(nil)

// EndpointSnapshot returns call identity and accepted endpoints atomically.
// Revision is a registry-wide sequence; a later snapshot supersedes earlier
// callbacks for the same lifetime even if concurrent delivery reorders them.
func (c *Core) EndpointSnapshot(callID string) (EndpointObservation, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	call, ok := c.calls[callID]
	if !ok {
		return EndpointObservation{}, false
	}
	snapshot := EndpointObservation{Call: call, Revision: c.nextObservation}
	for endpoint := range c.callEndpoints[callID] {
		snapshot.Endpoints = append(snapshot.Endpoints, endpoint)
	}
	sort.Strings(snapshot.Endpoints)
	return snapshot, true
}

// WithEndpointSnapshots holds the registry read lock through a bounded consumer
// operation, so a complete reconciliation cannot publish an already superseded
// lifetime or endpoint set. The callback must not reenter or mutate this registry.
// Missing calls are omitted; callers must verify every requested lifetime exists.
func (c *Core) WithEndpointSnapshots(callIDs []string, consume func([]EndpointObservation) error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	observations := make([]EndpointObservation, 0, len(callIDs))
	for _, id := range callIDs {
		call, ok := c.calls[id]
		if !ok {
			continue
		}
		observation := EndpointObservation{Call: call, Revision: c.nextObservation}
		for endpoint := range c.callEndpoints[id] {
			observation.Endpoints = append(observation.Endpoints, endpoint)
		}
		sort.Strings(observation.Endpoints)
		observations = append(observations, observation)
	}
	return consume(observations)
}
