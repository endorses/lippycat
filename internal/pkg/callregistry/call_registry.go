// Package callregistry defines protocol-domain call lifecycle contracts without
// depending on analyzers, transports, or output resources.
package callregistry

import (
	"container/list"
	"sync"
	"time"
)

type Call struct {
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
	AssociateEndpoint(callID, endpoint string)
	CompleteCall(callID string)
	Close()
}

// Config bounds the state owned by a Core. Limits are hard limits; an
// association rejected because of a limit is not partially installed.
type Config struct {
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
	return &Core{
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
	if call.CallID == "" {
		return false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	_, existed := c.calls[call.CallID]
	if existed {
		c.calls[call.CallID] = call
		c.touchLocked(call.CallID)
		c.mu.Unlock()
		return true
	}
	var evicted *Call
	if len(c.calls) >= c.config.MaxCalls {
		oldest := c.evictionCandidateLocked()
		if oldest != nil {
			removed := c.removeLocked(oldest.Value.(string))
			evicted = &removed
		}
		if oldest == nil {
			c.mu.Unlock()
			return false
		}
	}
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
	return true
}

func (c *Core) evictionCandidateLocked() *list.Element {
	var candidate *list.Element
	bestPriority := -1
	for elem := c.recency.Back(); elem != nil; elem = elem.Prev() {
		id := elem.Value.(string)
		if c.pins[id] > 0 {
			continue
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
	if callID == "" || endpoint == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if _, ok := c.calls[callID]; !ok {
		return false
	}
	if _, ok := c.callEndpoints[callID][endpoint]; ok {
		return true
	}
	if len(c.callEndpoints[callID]) >= c.config.MaxEndpointsPerCall || c.associationCount >= c.config.MaxEndpointAssociations {
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
	return true
}

func (c *Core) AssociateEndpoint(callID, endpoint string) {
	c.TryAssociateEndpoint(callID, endpoint)
}

func (c *Core) CallIDsForEndpoint(endpoint string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.endpointCalls[endpoint]...)
}

// MostRecentCallIDForEndpoint resolves an ambiguous shared endpoint using call
// activity rather than association insertion order.
func (c *Core) MostRecentCallIDForEndpoint(endpoint string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	callID, ok := c.endpointWinner[endpoint]
	return callID, ok
}

func (c *Core) EndpointsForCall(callID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	endpoints := c.callEndpoints[callID]
	result := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		result = append(result, endpoint)
	}
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

// DissociateEndpoints releases every endpoint owned by callID while retaining
// the call lifecycle record (for example during a trailing-media grace period).
func (c *Core) DissociateEndpoints(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	delete(c.pins, callID)
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
