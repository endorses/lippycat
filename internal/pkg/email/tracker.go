package email

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// SessionTracker tracks SMTP sessions for command/response correlation.
type SessionTracker struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	config   TrackerConfig
}

// TrackerConfig holds configuration for the session tracker.
type TrackerConfig struct {
	// SessionTimeout is how long to keep idle sessions
	SessionTimeout time.Duration

	// MaxSessions is the maximum number of concurrent sessions to track
	MaxSessions int

	// CleanupInterval is how often to clean up expired sessions
	CleanupInterval time.Duration
}

// DefaultTrackerConfig returns default tracker configuration.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		SessionTimeout:  5 * time.Minute,
		MaxSessions:     10000,
		CleanupInterval: 30 * time.Second,
	}
}

// Session represents an SMTP session.
type Session struct {
	ID           string    // Session identifier (src:port-dst:port)
	StartTime    time.Time // When session started
	LastActivity time.Time // Last activity time

	// Envelope information (accumulated during session)
	MailFrom string
	RcptTo   []string

	// Current transaction state
	InData       bool      // Currently in DATA mode
	LastCommand  string    // Last command sent
	LastCmdTime  time.Time // When last command was sent
	MessageCount int       // Number of messages in this session

	// STARTTLS state
	STARTTLSOffered   bool
	STARTTLSRequested bool
	Encrypted         bool

	// Server info
	ServerBanner string
	ClientHelo   string
}

// NewSessionTracker creates a new session tracker.
func NewSessionTracker(config TrackerConfig) *SessionTracker {
	tracker := &SessionTracker{
		sessions: make(map[string]*Session),
		config:   config,
	}

	// Start cleanup goroutine
	go tracker.cleanupLoop()

	return tracker
}

// GetOrCreateSession gets or creates a session for the given connection.
func (t *SessionTracker) GetOrCreateSession(sessionID string) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		// Check if we're at capacity
		if len(t.sessions) >= t.config.MaxSessions {
			// Evict oldest session
			t.evictOldest()
		}

		session = &Session{
			ID:           sessionID,
			StartTime:    time.Now(),
			LastActivity: time.Now(),
		}
		t.sessions[sessionID] = session
	}

	return session
}

// UpdateSession updates a session with new packet data.
func (t *SessionTracker) UpdateSession(sessionID string, metadata *types.EmailMetadata) {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		return
	}

	session.LastActivity = time.Now()

	// Update session state from metadata
	if metadata.MailFrom != "" {
		session.MailFrom = metadata.MailFrom
	}
	if len(metadata.RcptTo) > 0 {
		session.RcptTo = append(session.RcptTo, metadata.RcptTo...)
	}
	if metadata.ServerBanner != "" {
		session.ServerBanner = metadata.ServerBanner
	}
	if metadata.ClientHelo != "" {
		session.ClientHelo = metadata.ClientHelo
	}
	if metadata.STARTTLSOffered {
		session.STARTTLSOffered = true
	}
	if metadata.STARTTLSRequested {
		session.STARTTLSRequested = true
	}
	if metadata.Encrypted {
		session.Encrypted = true
	}

	// Track commands for correlation
	if !metadata.IsServer && metadata.Command != "" {
		session.LastCommand = metadata.Command
		session.LastCmdTime = time.Now()

		if metadata.Command == "DATA" {
			session.InData = true
		}
	}

	// Track responses
	if metadata.IsServer {
		// Calculate response time if we have a pending command
		if !session.LastCmdTime.IsZero() {
			metadata.TransactionTimeMs = time.Since(session.LastCmdTime).Milliseconds()
			metadata.Correlated = true
		}

		// Check for end of DATA (250 after DATA)
		if session.InData && metadata.ResponseCode == 250 {
			session.InData = false
			session.MessageCount++
			// Reset envelope for next message
			session.MailFrom = ""
			session.RcptTo = nil
		}
	}

	// Populate session info into metadata
	metadata.SessionID = sessionID
}

// GetSession returns a session by ID.
func (t *SessionTracker) GetSession(sessionID string) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[sessionID]
}

// RemoveSession removes a session.
func (t *SessionTracker) RemoveSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
}

// Stats returns tracker statistics.
func (t *SessionTracker) Stats() TrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := TrackerStats{
		ActiveSessions: len(t.sessions),
	}

	for _, s := range t.sessions {
		stats.TotalMessages += s.MessageCount
		if s.Encrypted {
			stats.EncryptedSessions++
		}
	}

	return stats
}

// TrackerStats holds tracker statistics.
type TrackerStats struct {
	ActiveSessions    int
	TotalMessages     int
	EncryptedSessions int
}

// cleanupLoop periodically cleans up expired sessions.
func (t *SessionTracker) cleanupLoop() {
	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes expired sessions.
func (t *SessionTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for id, session := range t.sessions {
		if now.Sub(session.LastActivity) > t.config.SessionTimeout {
			delete(t.sessions, id)
		}
	}
}

// evictOldest removes the oldest session (called when at capacity).
func (t *SessionTracker) evictOldest() {
	var oldestID string
	var oldestTime time.Time

	for id, session := range t.sessions {
		if oldestID == "" || session.LastActivity.Before(oldestTime) {
			oldestID = id
			oldestTime = session.LastActivity
		}
	}

	if oldestID != "" {
		delete(t.sessions, oldestID)
	}
}

// Stop stops the tracker and releases resources.
func (t *SessionTracker) Stop() {
	// Cleanup goroutine will be garbage collected
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[string]*Session)
}
