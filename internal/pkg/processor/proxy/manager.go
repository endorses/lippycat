package proxy

import (
	"context"
	"log/slog"
	"sync"
)

// Manager coordinates topology subscription and operation proxying for hierarchical
// processor deployments. It maintains the topology cache, manages authorization
// tokens, and handles event broadcasting to upstream subscribers.
//
// Manager is thread-safe and designed for concurrent access from multiple goroutines:
//   - gRPC server handlers calling ProxyFilterOperation()
//   - Topology update receivers calling ApplyTopologyUpdate()
//   - Event publishers calling PublishHunterConnected()
//   - Subscriber management from SubscribeTopology() RPC handler
type Manager struct {
	// logger is the structured logger for audit and debug logging
	logger *slog.Logger

	// cache maintains the current topology state (hunters, processors, filters)
	cache *TopologyCache

	// subscribers is the list of active topology update subscribers
	// Each subscriber has a buffered channel receiving TopologyUpdate messages
	subscribersMu sync.RWMutex
	subscribers   map[string]chan interface{} // interface{} will be TopologyUpdate from protobuf

	// processorID is this processor's unique identifier
	processorID string

	// tlsCert is the TLS certificate used for signing authorization tokens
	// Set during initialization if TLS is enabled
	tlsCert []byte

	// tlsPrivateKey is the private key for signing tokens
	tlsPrivateKey []byte

	// shutdown context for graceful cleanup
	ctx    context.Context
	cancel context.CancelFunc

	// wg tracks active goroutines for graceful shutdown
	wg sync.WaitGroup
}

// NewManager creates a new proxy manager with the given logger and processor ID.
// The manager starts with an empty topology cache and no subscribers.
//
// If TLS is enabled, call SetTLSCredentials() to configure token signing.
func NewManager(log *slog.Logger, processorID string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		logger:      log,
		cache:       NewTopologyCache(),
		subscribers: make(map[string]chan interface{}),
		processorID: processorID,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// SetTLSCredentials configures the TLS certificate and private key used for
// signing authorization tokens. This must be called before IssueAuthToken()
// if TLS is enabled.
//
// cert and key should be PEM-encoded certificate and private key bytes.
func (m *Manager) SetTLSCredentials(cert, key []byte) {
	m.tlsCert = cert
	m.tlsPrivateKey = key
}

// GetCache returns the topology cache for direct access.
// This is primarily used by the processor's gRPC server handlers
// to query current topology state.
//
// The returned cache is thread-safe and can be accessed concurrently.
func (m *Manager) GetCache() *TopologyCache {
	return m.cache
}

// Shutdown gracefully shuts down the manager, closing all subscriber channels
// and waiting for active goroutines to complete.
//
// This should be called during processor shutdown to ensure clean cleanup.
func (m *Manager) Shutdown() {
	m.cancel()

	// Close all subscriber channels
	m.subscribersMu.Lock()
	for subscriberID, ch := range m.subscribers {
		close(ch)
		delete(m.subscribers, subscriberID)
	}
	m.subscribersMu.Unlock()

	// Wait for active goroutines
	m.wg.Wait()

	m.logger.Info("proxy manager shutdown complete")
}

// RegisterSubscriber adds a new topology update subscriber with the given ID.
// Returns a buffered channel that will receive topology updates.
//
// The channel has a buffer size of 100. If the subscriber cannot keep up,
// updates will be dropped (non-blocking send).
//
// Call UnregisterSubscriber() when the subscriber disconnects to clean up.
func (m *Manager) RegisterSubscriber(subscriberID string) chan interface{} {
	m.subscribersMu.Lock()
	defer m.subscribersMu.Unlock()

	ch := make(chan interface{}, 100)
	m.subscribers[subscriberID] = ch

	m.logger.Info("registered topology subscriber",
		"subscriber_id", subscriberID,
		"total_subscribers", len(m.subscribers))

	return ch
}

// UnregisterSubscriber removes a topology update subscriber and closes its channel.
// This should be called when a subscriber disconnects or the subscription ends.
func (m *Manager) UnregisterSubscriber(subscriberID string) {
	m.subscribersMu.Lock()
	defer m.subscribersMu.Unlock()

	if ch, exists := m.subscribers[subscriberID]; exists {
		close(ch)
		delete(m.subscribers, subscriberID)

		m.logger.Info("unregistered topology subscriber",
			"subscriber_id", subscriberID,
			"remaining_subscribers", len(m.subscribers))
	}
}

// broadcastTopologyUpdate sends a topology update to all active subscribers.
// Uses non-blocking sends to prevent slow subscribers from blocking the broadcaster.
//
// Dropped updates are logged as warnings, including the subscriber ID.
func (m *Manager) broadcastTopologyUpdate(update interface{}) {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()

	for subscriberID, ch := range m.subscribers {
		select {
		case ch <- update:
			// Successfully sent
		default:
			// Channel full, drop update
			m.logger.Warn("dropped topology update for slow subscriber",
				"subscriber_id", subscriberID)
		}
	}
}
