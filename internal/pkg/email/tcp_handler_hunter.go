//go:build hunter || all

package email

import (
	"sync"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EmailPacketForwarder is an interface for forwarding packets (implemented by Hunter).
type EmailPacketForwarder interface {
	// ForwardPacketWithMetadata forwards a packet with embedded metadata, interface name, and link type
	ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType) error
}

// EmailHunterHandler handles SMTP messages for hunter mode.
// It accumulates email metadata, applies content filtering including body keywords,
// and forwards matched email sessions to the processor.
type EmailHunterHandler struct {
	forwarder     EmailPacketForwarder
	contentFilter *ContentFilter

	// Session state tracking (accumulates envelope data across SMTP commands)
	sessions   map[string]*emailSession
	sessionsMu sync.RWMutex
}

// emailSession tracks the state of an SMTP session for filtering decisions.
type emailSession struct {
	sessionID string
	flow      gopacket.Flow

	// Accumulated envelope data
	mailFrom  string
	rcptTo    []string
	subject   string
	messageID string

	// Body data (from DATA_COMPLETE)
	bodyPreview   string
	bodySize      int
	bodyTruncated bool

	// State
	matched  bool // Already matched and forwarded
	complete bool // DATA_COMPLETE received
}

// NewEmailHunterHandler creates a handler for hunter packet forwarding with content filtering.
func NewEmailHunterHandler(forwarder EmailPacketForwarder, contentFilter *ContentFilter) *EmailHunterHandler {
	return &EmailHunterHandler{
		forwarder:     forwarder,
		contentFilter: contentFilter,
		sessions:      make(map[string]*emailSession),
	}
}

// HandleSMTPLine processes SMTP lines and applies content filtering.
// Called by TCP reassembly for each SMTP command/response.
func (h *EmailHunterHandler) HandleSMTPLine(line string, metadata *types.EmailMetadata, sessionID string, flow gopacket.Flow) {
	if metadata == nil {
		return
	}

	h.sessionsMu.Lock()
	session, exists := h.sessions[sessionID]
	if !exists {
		session = &emailSession{
			sessionID: sessionID,
			flow:      flow,
		}
		h.sessions[sessionID] = session
	}
	h.sessionsMu.Unlock()

	// Skip if already matched and forwarded
	if session.matched {
		return
	}

	// Accumulate envelope data based on command type
	switch metadata.Command {
	case "MAIL":
		if metadata.MailFrom != "" {
			session.mailFrom = metadata.MailFrom
		}

	case "RCPT":
		// RcptTo accumulates across multiple RCPT commands
		if len(metadata.RcptTo) > 0 {
			session.rcptTo = append(session.rcptTo, metadata.RcptTo...)
		}

	case "DATA_COMPLETE":
		// Complete message with headers and body
		session.subject = metadata.Subject
		session.messageID = metadata.MessageID
		session.bodyPreview = metadata.BodyPreview
		session.bodySize = metadata.BodySize
		session.bodyTruncated = metadata.BodyTruncated
		session.complete = true

		// Now apply content filter
		h.checkAndForward(session)

	case "RSET", "QUIT":
		// Transaction reset or session end
		h.cleanupSession(sessionID)
	}
}

// checkAndForward applies content filter and forwards matched sessions.
func (h *EmailHunterHandler) checkAndForward(session *emailSession) {
	// Build metadata for content filter
	filterMetadata := &types.EmailMetadata{
		MailFrom:      session.mailFrom,
		RcptTo:        session.rcptTo,
		Subject:       session.subject,
		MessageID:     session.messageID,
		BodyPreview:   session.bodyPreview,
		BodySize:      session.bodySize,
		BodyTruncated: session.bodyTruncated,
	}

	// Apply content filter (includes body keyword matching via Aho-Corasick)
	if h.contentFilter != nil && h.contentFilter.HasFilters() {
		if !h.contentFilter.Match(filterMetadata) {
			// No match - discard buffered packets
			logger.Debug("Email session filtered out",
				"session_id", session.sessionID,
				"mail_from", session.mailFrom,
				"subject", truncateSubject(session.subject, 50))
			DiscardEmailBufferedPackets(session.sessionID)
			h.cleanupSession(session.sessionID)
			return
		}
	}

	// Session matched! Get buffered packets and forward
	session.matched = true

	bufferedPackets := GetEmailBufferedPackets(session.sessionID)
	if len(bufferedPackets) == 0 {
		logger.Warn("Email session matched but no buffered packets",
			"session_id", session.sessionID)
		h.cleanupSession(session.sessionID)
		return
	}

	logger.Info("Email session matched filter, forwarding to processor",
		"session_id", session.sessionID,
		"mail_from", session.mailFrom,
		"rcpt_to", session.rcptTo,
		"subject", truncateSubject(session.subject, 50),
		"buffered_packets", len(bufferedPackets))

	// Create protobuf metadata for email
	pbMetadata := &data.PacketMetadata{
		Email: &data.EmailMetadata{
			MailFrom:      session.mailFrom,
			RcptTo:        session.rcptTo,
			Subject:       session.subject,
			MessageId:     session.messageID,
			BodyPreview:   session.bodyPreview,
			BodySize:      int32(session.bodySize),
			BodyTruncated: session.bodyTruncated,
		},
	}

	// Forward all buffered TCP packets with metadata
	for _, pkt := range bufferedPackets {
		if err := h.forwarder.ForwardPacketWithMetadata(pkt.Packet, pbMetadata, pkt.Interface, pkt.LinkType); err != nil {
			logger.Error("Failed to forward email TCP packet",
				"session_id", session.sessionID,
				"error", err)
		}
	}

	// Cleanup after forwarding
	h.cleanupSession(session.sessionID)
}

// cleanupSession removes session tracking state.
func (h *EmailHunterHandler) cleanupSession(sessionID string) {
	h.sessionsMu.Lock()
	delete(h.sessions, sessionID)
	h.sessionsMu.Unlock()
}

// UpdateContentFilter updates the content filter configuration.
// Thread-safe for runtime filter updates from processor.
func (h *EmailHunterHandler) UpdateContentFilter(filter *ContentFilter) {
	h.sessionsMu.Lock()
	h.contentFilter = filter
	h.sessionsMu.Unlock()

	if filter != nil && filter.HasFilters() {
		logger.Info("Email hunter content filter updated",
			"has_sender_patterns", len(filter.senderPatterns) > 0,
			"has_recipient_patterns", len(filter.recipientPatterns) > 0,
			"has_subject_patterns", len(filter.subjectPatterns) > 0,
			"has_keywords", filter.keywordsMatcher != nil)
	}
}

// GetSessionCount returns the number of active sessions being tracked.
func (h *EmailHunterHandler) GetSessionCount() int {
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()
	return len(h.sessions)
}

// CleanupStaleSessions removes sessions that have been inactive.
// Call periodically to prevent memory leaks from abandoned sessions.
func (h *EmailHunterHandler) CleanupStaleSessions() {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()

	// Note: Sessions are cleaned up when:
	// 1. Filter match/no-match decision is made
	// 2. RSET or QUIT commands are received
	// TCP buffer cleanup handles packet memory via CleanupOldEmailBuffers()

	// For incomplete sessions without recent activity, the TCP buffer
	// cleanup will handle the packet memory, and these sessions will
	// be cleaned up when the buffer is cleaned.
}

// truncateSubject truncates subject for logging.
func truncateSubject(subject string, maxLen int) string {
	if len(subject) <= maxLen {
		return subject
	}
	return subject[:maxLen] + "..."
}
