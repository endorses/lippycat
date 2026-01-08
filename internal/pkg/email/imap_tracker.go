package email

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// IMAPTracker tracks IMAP sessions for command/response correlation.
type IMAPTracker struct {
	sessions map[string]*IMAPSession
	mu       sync.RWMutex
	config   TrackerConfig
}

// IMAPSession represents an IMAP session.
type IMAPSession struct {
	ID           string    // Session identifier (src:port-dst:port)
	StartTime    time.Time // When session started
	LastActivity time.Time // Last activity time

	// Authentication state
	Authenticated bool
	AuthMethod    string
	AuthUser      string

	// Current mailbox state
	SelectedMailbox string // Currently selected mailbox
	MailboxExists   uint32 // Message count in mailbox
	MailboxRecent   uint32 // Recent message count
	UIDNext         uint32 // Next UID to be assigned
	UIDValidity     uint32 // UID validity for mailbox

	// Pending commands (IMAP supports pipelining - multiple in-flight commands)
	PendingCommands map[string]*IMAPPendingCommand

	// STARTTLS state
	STARTTLSOffered   bool
	STARTTLSRequested bool
	Encrypted         bool

	// Server capabilities
	Capabilities []string
	ServerBanner string

	// Statistics
	CommandCount int
	FetchCount   int
	MessageCount int // Messages retrieved
	SearchCount  int
	IdleSessions int
}

// IMAPPendingCommand represents a command waiting for response.
type IMAPPendingCommand struct {
	Tag       string
	Command   string
	Mailbox   string // For SELECT/EXAMINE
	Timestamp time.Time
}

// NewIMAPTracker creates a new IMAP session tracker.
func NewIMAPTracker(config TrackerConfig) *IMAPTracker {
	tracker := &IMAPTracker{
		sessions: make(map[string]*IMAPSession),
		config:   config,
	}

	// Start cleanup goroutine
	go tracker.cleanupLoop()

	return tracker
}

// GetOrCreateSession gets or creates a session for the given connection.
func (t *IMAPTracker) GetOrCreateSession(sessionID string) *IMAPSession {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		// Check if we're at capacity
		if len(t.sessions) >= t.config.MaxSessions {
			t.evictOldest()
		}

		session = &IMAPSession{
			ID:              sessionID,
			StartTime:       time.Now(),
			LastActivity:    time.Now(),
			PendingCommands: make(map[string]*IMAPPendingCommand),
		}
		t.sessions[sessionID] = session
	}

	return session
}

// UpdateSession updates a session with new packet data.
func (t *IMAPTracker) UpdateSession(sessionID string, metadata *types.EmailMetadata) {
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
	if session.SelectedMailbox != "" && metadata.IMAPMailbox == "" {
		metadata.IMAPMailbox = session.SelectedMailbox
	}
}

// handleClientCommand processes client commands.
func (t *IMAPTracker) handleClientCommand(session *IMAPSession, metadata *types.EmailMetadata) {
	session.CommandCount++

	// Track pending command
	if metadata.IMAPTag != "" {
		session.PendingCommands[metadata.IMAPTag] = &IMAPPendingCommand{
			Tag:       metadata.IMAPTag,
			Command:   metadata.IMAPCommand,
			Mailbox:   metadata.IMAPMailbox,
			Timestamp: time.Now(),
		}
	}

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

	// Track specific commands
	switch metadata.IMAPCommand {
	case "SELECT", "EXAMINE":
		// Will be confirmed when we get OK response
	case "FETCH", "UID FETCH":
		session.FetchCount++
	case "SEARCH", "UID SEARCH":
		session.SearchCount++
	case "IDLE":
		session.IdleSessions++
	case "LOGOUT":
		// Session ending
	}
}

// handleServerResponse processes server responses.
func (t *IMAPTracker) handleServerResponse(session *IMAPSession, metadata *types.EmailMetadata) {
	// Handle tagged response (command completion)
	if metadata.IMAPTag != "" && metadata.IMAPStatus != "" {
		pending, exists := session.PendingCommands[metadata.IMAPTag]
		if exists {
			// Calculate response time
			metadata.TransactionTimeMs = time.Since(pending.Timestamp).Milliseconds()
			metadata.Correlated = true

			// Handle command-specific state updates on OK
			if metadata.IMAPStatus == "OK" {
				switch pending.Command {
				case "SELECT", "EXAMINE":
					session.SelectedMailbox = pending.Mailbox
					// Copy mailbox info from metadata to session
					if metadata.IMAPExists > 0 {
						session.MailboxExists = metadata.IMAPExists
					}
					if metadata.IMAPRecent > 0 {
						session.MailboxRecent = metadata.IMAPRecent
					}
					if metadata.IMAPUIDNext > 0 {
						session.UIDNext = metadata.IMAPUIDNext
					}
					if metadata.IMAPUIDValidity > 0 {
						session.UIDValidity = metadata.IMAPUIDValidity
					}
				case "LOGIN", "AUTHENTICATE":
					session.Authenticated = true
				case "CLOSE":
					session.SelectedMailbox = ""
				case "LOGOUT":
					// Clear session state
					session.SelectedMailbox = ""
					session.Authenticated = false
				}
			}

			// Remove from pending
			delete(session.PendingCommands, metadata.IMAPTag)
		}
	}

	// Handle untagged responses (status updates)
	if metadata.IMAPExists > 0 {
		session.MailboxExists = metadata.IMAPExists
	}
	if metadata.IMAPRecent > 0 {
		session.MailboxRecent = metadata.IMAPRecent
	}
	if metadata.IMAPUIDNext > 0 {
		session.UIDNext = metadata.IMAPUIDNext
	}
	if metadata.IMAPUIDValidity > 0 {
		session.UIDValidity = metadata.IMAPUIDValidity
	}

	// Track STARTTLS capability
	if metadata.STARTTLSOffered {
		session.STARTTLSOffered = true
	}

	// Track server banner
	if metadata.ServerBanner != "" {
		session.ServerBanner = metadata.ServerBanner
	}

	// Populate session state into metadata
	if session.MailboxExists > 0 && metadata.IMAPExists == 0 {
		metadata.IMAPExists = session.MailboxExists
	}
	if session.MailboxRecent > 0 && metadata.IMAPRecent == 0 {
		metadata.IMAPRecent = session.MailboxRecent
	}
}

// GetSession returns a session by ID.
func (t *IMAPTracker) GetSession(sessionID string) *IMAPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[sessionID]
}

// RemoveSession removes a session.
func (t *IMAPTracker) RemoveSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
}

// Stats returns tracker statistics.
func (t *IMAPTracker) Stats() IMAPTrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := IMAPTrackerStats{
		ActiveSessions: len(t.sessions),
	}

	for _, s := range t.sessions {
		stats.TotalCommands += s.CommandCount
		stats.TotalFetches += s.FetchCount
		stats.TotalSearches += s.SearchCount
		if s.Authenticated {
			stats.AuthenticatedSessions++
		}
		if s.Encrypted {
			stats.EncryptedSessions++
		}
		if s.SelectedMailbox != "" {
			stats.SelectedMailboxes++
		}
	}

	return stats
}

// IMAPTrackerStats holds tracker statistics.
type IMAPTrackerStats struct {
	ActiveSessions        int
	AuthenticatedSessions int
	EncryptedSessions     int
	SelectedMailboxes     int
	TotalCommands         int
	TotalFetches          int
	TotalSearches         int
}

// cleanupLoop periodically cleans up expired sessions.
func (t *IMAPTracker) cleanupLoop() {
	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes expired sessions.
func (t *IMAPTracker) cleanup() {
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
func (t *IMAPTracker) evictOldest() {
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
func (t *IMAPTracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[string]*IMAPSession)
}
