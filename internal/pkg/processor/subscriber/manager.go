package subscriber

import (
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/protobuf/proto"
)

// Manager manages TUI/monitoring client subscriptions
type Manager struct {
	subscribers sync.Map // map[string]chan *data.PacketBatch
	filters     sync.Map // map[string][]string (clientID -> hunterIDs subscription list)

	nextSubID atomic.Uint64

	// Backpressure tracking
	broadcasts atomic.Uint64 // total broadcast attempts
	drops      atomic.Uint64 // drops due to full channels

	maxSubscribers int
}

// NewManager creates a new subscriber manager
func NewManager(maxSubscribers int) *Manager {
	return &Manager{
		maxSubscribers: maxSubscribers,
	}
}

// Add adds a new subscriber
// Returns the channel for receiving packets
func (m *Manager) Add(clientID string) chan *data.PacketBatch {
	ch := make(chan *data.PacketBatch, constants.SubscriberChannelBuffer)
	m.subscribers.Store(clientID, ch)
	return ch
}

// Remove removes a subscriber
func (m *Manager) Remove(clientID string) {
	m.subscribers.Delete(clientID)
	m.filters.Delete(clientID)
}

// SetFilter sets the hunter filter for a subscriber
func (m *Manager) SetFilter(clientID string, hunterIDs []string) {
	m.filters.Store(clientID, hunterIDs)
}

// DeleteFilter deletes the hunter filter for a subscriber
func (m *Manager) DeleteFilter(clientID string) {
	m.filters.Delete(clientID)
}

// Count returns the number of active subscribers
func (m *Manager) Count() int {
	count := 0
	m.subscribers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// NextID generates the next subscriber ID
func (m *Manager) NextID() uint64 {
	return m.nextSubID.Add(1)
}

// Broadcast broadcasts a packet batch to all monitoring subscribers
// Uses sync.Map for lock-free concurrent iteration
// Tracks broadcast attempts and drops for backpressure calculation
func (m *Manager) Broadcast(batch *data.PacketBatch) {
	// IMPORTANT: Make a copy of the batch before broadcasting to avoid race conditions
	// The same batch structure will be serialized by multiple goroutines concurrently
	// (one per TUI client), which can corrupt the protobuf wire format
	batchCopy := proto.Clone(batch).(*data.PacketBatch)

	// Lock-free iteration over subscribers
	m.subscribers.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		ch := value.(chan *data.PacketBatch)

		m.broadcasts.Add(1)

		select {
		case ch <- batchCopy:
			logger.Debug("Broadcasted batch to subscriber", "client_id", clientID, "packets", len(batchCopy.Packets))
		default:
			m.drops.Add(1)
			logger.Warn("Subscriber channel full, dropping batch", "client_id", clientID)
		}
		return true // Continue iteration
	})
}

// GetBackpressureStats returns broadcast and drop counts
func (m *Manager) GetBackpressureStats() (broadcasts, drops uint64) {
	return m.broadcasts.Load(), m.drops.Load()
}

// CheckLimit checks if adding a new subscriber would exceed the limit
// Returns true if limit would be exceeded
func (m *Manager) CheckLimit() bool {
	if m.maxSubscribers <= 0 {
		return false // No limit
	}

	count := m.Count()
	return count >= m.maxSubscribers
}
