package email

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// POP3Tracker tracks POP3 sessions for command/response correlation.
type POP3Tracker struct {
	sessions map[string]*POP3Session
	mu       sync.RWMutex
	config   TrackerConfig
}

// POP3Session represents a POP3 session.
type POP3Session struct {
	ID           string    // Session identifier (src:port-dst:port)
	StartTime    time.Time // When session started
	LastActivity time.Time // Last activity time

	// Authentication state
	State      POP3State // Current session state
	AuthMethod string
	AuthUser   string

	// Mailbox state (from STAT)
	MessageCount uint32 // Number of messages
	MailboxSize  uint64 // Total size in bytes

	// Current command (POP3 is single-threaded, no pipelining)
	LastCommand string
	LastCmdTime time.Time
	LastMsgNum  uint32 // Last message number referenced
	InMultiline bool   // Currently receiving multi-line response

	// STARTTLS state
	STARTTLSOffered   bool
	STARTTLSRequested bool
	Encrypted         bool

	// Server info
	ServerBanner string
	Capabilities []string

	// Statistics
	MessagesRetrieved int
	MessagesDeleted   int
	BytesTransferred  uint64
}

// POP3State represents the POP3 session state.
type POP3State int

const (
	POP3StateAuthorization POP3State = iota // Before authentication
	POP3StateTransaction                    // After authentication, before QUIT
	POP3StateUpdate                         // After QUIT (committing changes)
)

// NewPOP3Tracker creates a new POP3 session tracker.
func NewPOP3Tracker(config TrackerConfig) *POP3Tracker {
	tracker := &POP3Tracker{
		sessions: make(map[string]*POP3Session),
		config:   config,
	}

	// Start cleanup goroutine
	go tracker.cleanupLoop()

	return tracker
}

// GetOrCreateSession gets or creates a session for the given connection.
func (t *POP3Tracker) GetOrCreateSession(sessionID string) *POP3Session {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		// Check if we're at capacity
		if len(t.sessions) >= t.config.MaxSessions {
			t.evictOldest()
		}

		session = &POP3Session{
			ID:           sessionID,
			StartTime:    time.Now(),
			LastActivity: time.Now(),
			State:        POP3StateAuthorization,
		}
		t.sessions[sessionID] = session
	}

	return session
}

// UpdateSession updates a session with new packet data.
func (t *POP3Tracker) UpdateSession(sessionID string, metadata *types.EmailMetadata) {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		return
	}

	session.LastActivity = time.Now()

	if !metadata.IsServer {
		// Client command
		t.handleClientCommand(session, metadata)
	} else {
		// Server response
		t.handleServerResponse(session, metadata)
	}

	// Populate session info into metadata
	metadata.SessionID = sessionID
	if session.AuthUser != "" && metadata.AuthUser == "" {
		metadata.AuthUser = session.AuthUser
	}
}

// handleClientCommand processes client commands.
func (t *POP3Tracker) handleClientCommand(session *POP3Session, metadata *types.EmailMetadata) {
	session.LastCommand = metadata.POP3Command
	session.LastCmdTime = time.Now()
	session.LastMsgNum = metadata.POP3MsgNum

	// Track authentication
	if metadata.AuthUser != "" {
		session.AuthUser = metadata.AuthUser
	}
	if metadata.AuthMethod != "" {
		session.AuthMethod = metadata.AuthMethod
	}

	// Track STARTTLS
	if metadata.STARTTLSRequested {
		session.STARTTLSRequested = true
	}

	// Track commands that start multi-line responses
	switch metadata.POP3Command {
	case "LIST", "UIDL", "RETR", "TOP", "CAPA":
		// These commands can return multi-line responses
		session.InMultiline = false // Will be set true on +OK
	case "QUIT":
		session.State = POP3StateUpdate
	}
}

// handleServerResponse processes server responses.
func (t *POP3Tracker) handleServerResponse(session *POP3Session, metadata *types.EmailMetadata) {
	// Calculate response time
	if !session.LastCmdTime.IsZero() {
		metadata.TransactionTimeMs = time.Since(session.LastCmdTime).Milliseconds()
		metadata.Correlated = true
	}

	// Handle +OK response
	if metadata.POP3Status == "+OK" {
		switch session.LastCommand {
		case "USER":
			// User accepted, waiting for PASS
		case "PASS", "APOP":
			// Authentication successful
			session.State = POP3StateTransaction
		case "STAT":
			// Update mailbox stats from metadata
			if metadata.POP3MsgCount > 0 {
				session.MessageCount = metadata.POP3MsgCount
			}
			if metadata.POP3TotalSize > 0 {
				session.MailboxSize = metadata.POP3TotalSize
			}
		case "LIST", "UIDL", "CAPA":
			// Multi-line response follows
			session.InMultiline = true
		case "RETR":
			// Message retrieval
			session.MessagesRetrieved++
			session.InMultiline = true
		case "TOP":
			// Header retrieval
			session.InMultiline = true
		case "DELE":
			// Message marked for deletion
			session.MessagesDeleted++
		case "RSET":
			// Reset deletion marks
			session.MessagesDeleted = 0
		case "STLS":
			// TLS negotiation starting
			session.Encrypted = true
		}
	}

	// Track STARTTLS capability
	if metadata.STARTTLSOffered {
		session.STARTTLSOffered = true
	}

	// Track server banner
	if session.ServerBanner == "" && metadata.ResponseText != "" && session.LastCommand == "" {
		session.ServerBanner = metadata.ResponseText
	}

	// Check for end of multi-line response
	if session.InMultiline && metadata.ResponseText == "" && metadata.POP3Status == "" {
		// Might be a "." terminator
	}

	// Track message size for RETR
	if session.LastCommand == "RETR" && metadata.POP3MsgSize > 0 {
		session.BytesTransferred += uint64(metadata.POP3MsgSize)
	}

	// Populate session state into metadata
	if session.MessageCount > 0 && metadata.POP3MsgCount == 0 {
		metadata.POP3MsgCount = session.MessageCount
	}
	if session.MailboxSize > 0 && metadata.POP3TotalSize == 0 {
		metadata.POP3TotalSize = session.MailboxSize
	}
}

// GetSession returns a session by ID.
func (t *POP3Tracker) GetSession(sessionID string) *POP3Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[sessionID]
}

// RemoveSession removes a session.
func (t *POP3Tracker) RemoveSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
}

// Stats returns tracker statistics.
func (t *POP3Tracker) Stats() POP3TrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := POP3TrackerStats{
		ActiveSessions: len(t.sessions),
	}

	for _, s := range t.sessions {
		stats.TotalMessagesRetrieved += s.MessagesRetrieved
		stats.TotalMessagesDeleted += s.MessagesDeleted
		stats.TotalBytesTransferred += s.BytesTransferred
		if s.State == POP3StateTransaction {
			stats.AuthenticatedSessions++
		}
		if s.Encrypted {
			stats.EncryptedSessions++
		}
	}

	return stats
}

// POP3TrackerStats holds tracker statistics.
type POP3TrackerStats struct {
	ActiveSessions         int
	AuthenticatedSessions  int
	EncryptedSessions      int
	TotalMessagesRetrieved int
	TotalMessagesDeleted   int
	TotalBytesTransferred  uint64
}

// cleanupLoop periodically cleans up expired sessions.
func (t *POP3Tracker) cleanupLoop() {
	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes expired sessions.
func (t *POP3Tracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for id, session := range t.sessions {
		if now.Sub(session.LastActivity) > t.config.SessionTimeout {
			delete(t.sessions, id)
		}
	}
}

// evictOldest removes the oldest session.
func (t *POP3Tracker) evictOldest() {
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
func (t *POP3Tracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[string]*POP3Session)
}
