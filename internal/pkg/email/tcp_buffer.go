//go:build hunter || all

package email

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// TCP buffer constants
const (
	defaultEmailTCPBufferSize = 1000 // Max packets per session
	defaultEmailBufferMaxAge  = 60   // Seconds before buffer expires
	emailBufferPoolSize       = 100  // Pool size for buffer reuse
)

// EmailTCPBuffer holds buffered packets for an email session.
type EmailTCPBuffer struct {
	packets    []capture.PacketInfo
	createdAt  time.Time
	lastAccess time.Time
	sessionID  string
	maxSize    int
}

// emailBufferPool provides buffer reuse to reduce allocations.
type emailBufferPool struct {
	buffers []*EmailTCPBuffer
	maxSize int
	mu      sync.Mutex
}

var (
	emailTCPBuffers         = make(map[string]*EmailTCPBuffer) // keyed by sessionID
	emailTCPBuffersMu       sync.RWMutex
	emailBufferPoolInstance = &emailBufferPool{
		buffers: make([]*EmailTCPBuffer, 0, emailBufferPoolSize),
		maxSize: emailBufferPoolSize,
	}
)

// getOrCreateEmailBuffer returns an existing buffer or creates a new one.
func getOrCreateEmailBuffer(sessionID string, maxSize int) *EmailTCPBuffer {
	emailTCPBuffersMu.Lock()
	defer emailTCPBuffersMu.Unlock()

	if buffer, exists := emailTCPBuffers[sessionID]; exists {
		buffer.lastAccess = time.Now()
		return buffer
	}

	// Try to get from pool
	buffer := emailBufferPoolInstance.get(maxSize)
	buffer.sessionID = sessionID
	emailTCPBuffers[sessionID] = buffer

	return buffer
}

// BufferEmailTCPPacket buffers a TCP packet for an email session.
func BufferEmailTCPPacket(sessionID string, pkt capture.PacketInfo) {
	buffer := getOrCreateEmailBuffer(sessionID, defaultEmailTCPBufferSize)

	emailTCPBuffersMu.Lock()
	defer emailTCPBuffersMu.Unlock()

	buffer.lastAccess = time.Now()

	// Drop oldest packets if buffer is full
	if len(buffer.packets) >= buffer.maxSize {
		// Remove oldest 10%
		removeCount := buffer.maxSize / 10
		if removeCount < 1 {
			removeCount = 1
		}
		copy(buffer.packets, buffer.packets[removeCount:])
		buffer.packets = buffer.packets[:len(buffer.packets)-removeCount]
	}

	buffer.packets = append(buffer.packets, pkt)
}

// BufferEmailTCPPacketByFlow buffers a TCP packet using flow as key.
// This is used when we don't have a sessionID yet (early packets).
func BufferEmailTCPPacketByFlow(flow gopacket.Flow, pkt capture.PacketInfo) {
	sessionID := flow.String()
	BufferEmailTCPPacket(sessionID, pkt)
}

// GetEmailBufferedPackets returns and clears buffered packets for a session.
func GetEmailBufferedPackets(sessionID string) []capture.PacketInfo {
	emailTCPBuffersMu.Lock()
	defer emailTCPBuffersMu.Unlock()

	buffer, exists := emailTCPBuffers[sessionID]
	if !exists || len(buffer.packets) == 0 {
		return nil
	}

	// Copy packets
	packets := make([]capture.PacketInfo, len(buffer.packets))
	copy(packets, buffer.packets)

	// Clear and release buffer
	buffer.packets = buffer.packets[:0]
	delete(emailTCPBuffers, sessionID)
	emailBufferPoolInstance.put(buffer)

	return packets
}

// GetEmailBufferedPacketsByFlow returns buffered packets using flow as key.
func GetEmailBufferedPacketsByFlow(flow gopacket.Flow) []capture.PacketInfo {
	return GetEmailBufferedPackets(flow.String())
}

// DiscardEmailBufferedPackets removes buffered packets without returning them.
func DiscardEmailBufferedPackets(sessionID string) {
	emailTCPBuffersMu.Lock()
	defer emailTCPBuffersMu.Unlock()

	buffer, exists := emailTCPBuffers[sessionID]
	if !exists {
		return
	}

	buffer.packets = buffer.packets[:0]
	delete(emailTCPBuffers, sessionID)
	emailBufferPoolInstance.put(buffer)
}

// DiscardEmailBufferedPacketsByFlow discards buffered packets using flow as key.
func DiscardEmailBufferedPacketsByFlow(flow gopacket.Flow) {
	DiscardEmailBufferedPackets(flow.String())
}

// CleanupOldEmailBuffers removes buffers older than maxAge.
func CleanupOldEmailBuffers(maxAge time.Duration) {
	emailTCPBuffersMu.Lock()
	defer emailTCPBuffersMu.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	for sessionID, buffer := range emailTCPBuffers {
		if now.Sub(buffer.lastAccess) > maxAge {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		buffer := emailTCPBuffers[sessionID]
		delete(emailTCPBuffers, sessionID)
		emailBufferPoolInstance.put(buffer)
	}

	if len(expiredSessions) > 0 {
		logger.Debug("Cleaned up expired email TCP buffers", "count", len(expiredSessions))
	}
}

// EmailTCPBufferStats holds buffer statistics.
type EmailTCPBufferStats struct {
	ActiveBuffers int `json:"active_buffers"`
	TotalPackets  int `json:"total_packets"`
	PoolSize      int `json:"pool_size"`
	PoolAvailable int `json:"pool_available"`
}

// GetEmailTCPBufferStats returns current buffer statistics.
func GetEmailTCPBufferStats() EmailTCPBufferStats {
	emailTCPBuffersMu.RLock()
	defer emailTCPBuffersMu.RUnlock()

	totalPackets := 0
	for _, buffer := range emailTCPBuffers {
		totalPackets += len(buffer.packets)
	}

	emailBufferPoolInstance.mu.Lock()
	poolAvailable := len(emailBufferPoolInstance.buffers)
	emailBufferPoolInstance.mu.Unlock()

	return EmailTCPBufferStats{
		ActiveBuffers: len(emailTCPBuffers),
		TotalPackets:  totalPackets,
		PoolSize:      emailBufferPoolSize,
		PoolAvailable: poolAvailable,
	}
}

// get returns a buffer from the pool or creates a new one.
func (p *emailBufferPool) get(maxSize int) *EmailTCPBuffer {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.buffers) > 0 {
		buffer := p.buffers[len(p.buffers)-1]
		p.buffers = p.buffers[:len(p.buffers)-1]
		buffer.packets = buffer.packets[:0]
		buffer.createdAt = time.Now()
		buffer.lastAccess = time.Now()
		buffer.maxSize = maxSize
		buffer.sessionID = ""
		return buffer
	}

	return &EmailTCPBuffer{
		packets:    make([]capture.PacketInfo, 0, maxSize),
		createdAt:  time.Now(),
		lastAccess: time.Now(),
		maxSize:    maxSize,
	}
}

// put returns a buffer to the pool.
func (p *emailBufferPool) put(buffer *EmailTCPBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.buffers) < p.maxSize {
		p.buffers = append(p.buffers, buffer)
	}
}
