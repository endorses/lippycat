package detector

import (
	"sync"
	"time"
)

// StateMachine provides a framework for tracking stateful protocol interactions
type StateMachine struct {
	states map[string]*ProtocolState
	ttl    time.Duration
	mu     sync.RWMutex
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
		states: make(map[string]*ProtocolState),
		ttl:    ttl,
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

	delete(sm.states, key)
}

// Clear removes all states
func (sm *StateMachine) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.states = make(map[string]*ProtocolState)
}

// Size returns the number of tracked states
func (sm *StateMachine) Size() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.states)
}

// cleanup periodically removes expired states
func (sm *StateMachine) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for key, state := range sm.states {
			if now.Sub(state.LastUpdate) > sm.ttl {
				delete(sm.states, key)
			}
		}
		sm.mu.Unlock()
	}
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
