//go:build cli || hunter || tap || all

package keylog

import (
	"encoding/hex"
	"sync"
	"time"
)

// StoreConfig configures the key store behavior.
type StoreConfig struct {
	// MaxSessions limits the number of sessions stored.
	// When exceeded, oldest sessions are evicted (LRU).
	// Default: 10000
	MaxSessions int

	// SessionTTL is how long to keep session keys after last access.
	// Default: 1 hour
	SessionTTL time.Duration

	// CleanupInterval is how often to run the cleanup routine.
	// Default: 5 minutes
	CleanupInterval time.Duration

	// OnKeyAdded is called when a new key entry is added.
	// This can be used to trigger decryption attempts.
	OnKeyAdded func(clientRandom [32]byte, entry *KeyEntry)
}

// DefaultStoreConfig returns the default store configuration.
func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		MaxSessions:     10000,
		SessionTTL:      1 * time.Hour,
		CleanupInterval: 5 * time.Minute,
	}
}

// sessionEntry wraps SessionKeys with metadata for LRU.
type sessionEntry struct {
	keys       *SessionKeys
	lastAccess time.Time
	createdAt  time.Time
}

// Store provides thread-safe storage and lookup of TLS session keys.
type Store struct {
	config   StoreConfig
	sessions map[[32]byte]*sessionEntry
	mu       sync.RWMutex
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Stats
	totalAdded   uint64
	totalLookups uint64
	totalHits    uint64
	totalEvicted uint64
}

// NewStore creates a new key store.
func NewStore(config StoreConfig) *Store {
	if config.MaxSessions <= 0 {
		config.MaxSessions = DefaultStoreConfig().MaxSessions
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = DefaultStoreConfig().SessionTTL
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = DefaultStoreConfig().CleanupInterval
	}

	s := &Store{
		config:   config,
		sessions: make(map[[32]byte]*sessionEntry),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	return s
}

// Add adds a key entry to the store.
// If the session doesn't exist, it is created.
// Returns true if this is a new key (not a duplicate).
func (s *Store) Add(entry *KeyEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	isNew := false

	session, exists := s.sessions[entry.ClientRandom]
	if !exists {
		// Check if we need to evict
		if len(s.sessions) >= s.config.MaxSessions {
			s.evictOldestLocked()
		}

		session = &sessionEntry{
			keys: &SessionKeys{
				ClientRandom: entry.ClientRandom,
			},
			createdAt:  now,
			lastAccess: now,
		}
		s.sessions[entry.ClientRandom] = session
		isNew = true
	}

	// Check if this specific key already exists
	existingKey := s.hasKeyLocked(session.keys, entry.Label)

	// Add the entry to the session
	session.keys.AddEntry(entry)
	session.lastAccess = now
	s.totalAdded++

	// Call callback if set and this is new data
	if !existingKey && s.config.OnKeyAdded != nil {
		// Call outside lock to prevent deadlock
		go s.config.OnKeyAdded(entry.ClientRandom, entry)
	}

	return isNew || !existingKey
}

// hasKeyLocked checks if a session already has a key for the given label.
func (s *Store) hasKeyLocked(keys *SessionKeys, label LabelType) bool {
	switch label {
	case LabelClientRandom:
		return len(keys.PreMasterSecret) > 0
	case LabelClientHandshakeTrafficSecret:
		return len(keys.ClientHandshakeTrafficSecret) > 0
	case LabelServerHandshakeTrafficSecret:
		return len(keys.ServerHandshakeTrafficSecret) > 0
	case LabelClientTrafficSecret0:
		return len(keys.ClientTrafficSecret0) > 0
	case LabelServerTrafficSecret0:
		return len(keys.ServerTrafficSecret0) > 0
	case LabelExporterSecret:
		return len(keys.ExporterSecret) > 0
	case LabelEarlyExporterSecret:
		return len(keys.EarlyExporterSecret) > 0
	case LabelClientEarlyTrafficSecret:
		return len(keys.ClientEarlyTrafficSecret) > 0
	default:
		return false
	}
}

// AddMultiple adds multiple entries efficiently.
func (s *Store) AddMultiple(entries []*KeyEntry) int {
	added := 0
	for _, entry := range entries {
		if s.Add(entry) {
			added++
		}
	}
	return added
}

// Get retrieves session keys by client random.
// Returns nil if not found.
func (s *Store) Get(clientRandom [32]byte) *SessionKeys {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalLookups++

	session, exists := s.sessions[clientRandom]
	if !exists {
		return nil
	}

	session.lastAccess = time.Now()
	s.totalHits++
	return session.keys
}

// GetByHex retrieves session keys by hex-encoded client random.
// Returns nil if not found or invalid hex.
func (s *Store) GetByHex(clientRandomHex string) *SessionKeys {
	bytes, err := hex.DecodeString(clientRandomHex)
	if err != nil || len(bytes) != 32 {
		return nil
	}

	var clientRandom [32]byte
	copy(clientRandom[:], bytes)
	return s.Get(clientRandom)
}

// Has checks if a session exists.
func (s *Store) Has(clientRandom [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.sessions[clientRandom]
	return exists
}

// HasByHex checks if a session exists by hex-encoded client random.
func (s *Store) HasByHex(clientRandomHex string) bool {
	bytes, err := hex.DecodeString(clientRandomHex)
	if err != nil || len(bytes) != 32 {
		return false
	}

	var clientRandom [32]byte
	copy(clientRandom[:], bytes)
	return s.Has(clientRandom)
}

// Delete removes a session from the store.
func (s *Store) Delete(clientRandom [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[clientRandom]; exists {
		delete(s.sessions, clientRandom)
		return true
	}
	return false
}

// Clear removes all sessions from the store.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions = make(map[[32]byte]*sessionEntry)
}

// Size returns the number of sessions in the store.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Stats returns store statistics.
func (s *Store) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tls12Count := 0
	tls13Count := 0
	completeCount := 0

	for _, session := range s.sessions {
		if session.keys.IsTLS12() {
			tls12Count++
		}
		if session.keys.IsTLS13() {
			tls13Count++
		}
		if session.keys.HasDecryptionKeys() {
			completeCount++
		}
	}

	return StoreStats{
		TotalSessions:    len(s.sessions),
		TLS12Sessions:    tls12Count,
		TLS13Sessions:    tls13Count,
		CompleteSessions: completeCount,
		TotalAdded:       s.totalAdded,
		TotalLookups:     s.totalLookups,
		TotalHits:        s.totalHits,
		TotalEvicted:     s.totalEvicted,
	}
}

// StoreStats contains store statistics.
type StoreStats struct {
	TotalSessions    int
	TLS12Sessions    int
	TLS13Sessions    int
	CompleteSessions int // Sessions with all keys needed for decryption
	TotalAdded       uint64
	TotalLookups     uint64
	TotalHits        uint64
	TotalEvicted     uint64
}

// HitRate returns the cache hit rate (0.0 - 1.0).
func (s StoreStats) HitRate() float64 {
	if s.TotalLookups == 0 {
		return 0
	}
	return float64(s.TotalHits) / float64(s.TotalLookups)
}

// AllSessions returns all session keys.
// Use with caution - this copies all keys.
func (s *Store) AllSessions() []*SessionKeys {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*SessionKeys, 0, len(s.sessions))
	for _, session := range s.sessions {
		result = append(result, session.keys)
	}
	return result
}

// Stop stops the cleanup goroutine.
func (s *Store) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}

// cleanupLoop periodically removes expired sessions.
func (s *Store) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopChan:
			return
		}
	}
}

// cleanup removes expired sessions.
func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for clientRandom, session := range s.sessions {
		if now.Sub(session.lastAccess) > s.config.SessionTTL {
			delete(s.sessions, clientRandom)
			s.totalEvicted++
		}
	}
}

// evictOldestLocked removes the oldest session (by last access).
// Must be called with lock held.
func (s *Store) evictOldestLocked() {
	var oldestKey [32]byte
	var oldestTime time.Time
	first := true

	for clientRandom, session := range s.sessions {
		if first || session.lastAccess.Before(oldestTime) {
			oldestKey = clientRandom
			oldestTime = session.lastAccess
			first = false
		}
	}

	if !first {
		delete(s.sessions, oldestKey)
		s.totalEvicted++
	}
}

// ForEach iterates over all sessions.
// The callback receives a copy of each SessionKeys.
// Return false from callback to stop iteration.
func (s *Store) ForEach(fn func(keys *SessionKeys) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, session := range s.sessions {
		if !fn(session.keys) {
			return
		}
	}
}
