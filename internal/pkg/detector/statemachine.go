package detector

import (
	"container/list"
	"sync"
	"time"
)

const (
	stateCleanupInterval  = time.Second
	stateCleanupBatchSize = 2048
)

// StateMachine provides a framework for tracking stateful protocol interactions
type StateMachine struct {
	states          map[string]*ProtocolState
	ttl             time.Duration
	cleanupOrder    *list.List
	cleanupElements map[string]*list.Element
	mu              sync.RWMutex
	done            chan struct{}
	closeOnce       sync.Once
	cleanupDone     chan struct{}
}

// ProtocolState represents the state of a protocol interaction
type ProtocolState struct {
	Key        string
	Data       interface{}
	Created    time.Time
	LastUpdate time.Time
}

// NewStateMachine creates a new state machine
func NewStateMachine(ttl time.Duration) *StateMachine {
	sm := &StateMachine{
		states:          make(map[string]*ProtocolState),
		ttl:             ttl,
		cleanupOrder:    list.New(),
		cleanupElements: make(map[string]*list.Element),
		done:            make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go sm.cleanup()

	return sm
}

// Set stores or updates protocol state
func (sm *StateMachine) Set(key string, data interface{}) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	if existing, ok := sm.states[key]; ok {
		existing.Data = data
		existing.LastUpdate = now
	} else {
		sm.states[key] = &ProtocolState{
			Key:        key,
			Data:       data,
			Created:    now,
			LastUpdate: now,
		}
		sm.cleanupElements[key] = sm.cleanupOrder.PushBack(key)
	}
}

// Get retrieves protocol state
func (sm *StateMachine) Get(key string) (interface{}, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if state, ok := sm.states[key]; ok {
		return state.Data, true
	}
	return nil, false
}

// Delete removes protocol state
func (sm *StateMachine) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.deleteLocked(key)
}

func (sm *StateMachine) deleteLocked(key string) {
	delete(sm.states, key)
	if element, ok := sm.cleanupElements[key]; ok {
		sm.cleanupOrder.Remove(element)
		delete(sm.cleanupElements, key)
	}
}

// Clear removes all states
func (sm *StateMachine) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.states = make(map[string]*ProtocolState)
	sm.cleanupOrder.Init()
	clear(sm.cleanupElements)
}

// Size returns the number of tracked states
func (sm *StateMachine) Size() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.states)
}

// cleanup periodically removes expired states
func (sm *StateMachine) cleanup() {
	ticker := time.NewTicker(stateCleanupInterval)
	defer ticker.Stop()
	defer close(sm.cleanupDone)

	for {
		select {
		case <-ticker.C:
			sm.cleanupExpired(time.Now(), stateCleanupBatchSize)
		case <-sm.done:
			return
		}
	}
}

// cleanupExpired examines at most limit states in round-robin order, bounding
// the exclusive lock hold while ensuring every live state is revisited.
func (sm *StateMachine) cleanupExpired(now time.Time, limit int) int {
	if limit <= 0 {
		return 0
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if scheduled := sm.cleanupOrder.Len(); limit > scheduled {
		limit = scheduled
	}

	removed := 0
	for i := 0; i < limit; i++ {
		element := sm.cleanupOrder.Front()
		key := element.Value.(string)
		state, ok := sm.states[key]
		if !ok {
			sm.cleanupOrder.Remove(element)
			delete(sm.cleanupElements, key)
			continue
		}
		if now.Sub(state.LastUpdate) > sm.ttl {
			sm.deleteLocked(key)
			removed++
			continue
		}
		sm.cleanupOrder.MoveToBack(element)
	}
	return removed
}

// Close stops the cleanup goroutine and waits for it to exit. It is safe to
// call concurrently or repeatedly.
func (sm *StateMachine) Close() {
	sm.closeOnce.Do(func() { close(sm.done) })
	<-sm.cleanupDone
}

// HTTPState tracks HTTP request/response pairs
type HTTPState struct {
	Method      string
	Path        string
	Host        string
	RequestTime time.Time
	UserAgent   string
}

// DNSState tracks DNS queries awaiting responses
type DNSState struct {
	TransactionID uint16
	QueryName     string
	QueryType     string
	QueryTime     time.Time
	SourceIP      string
	SourcePort    uint16
}
