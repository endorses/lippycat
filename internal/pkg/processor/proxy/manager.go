package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	subscribers   map[string]chan *management.TopologyUpdate

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
		subscribers: make(map[string]chan *management.TopologyUpdate),
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
func (m *Manager) RegisterSubscriber(subscriberID string) chan *management.TopologyUpdate {
	m.subscribersMu.Lock()
	defer m.subscribersMu.Unlock()

	ch := make(chan *management.TopologyUpdate, 100)
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

// PublishTopologyUpdate implements TopologyPublisher interface.
// This method:
// 1. Applies the update to the local topology cache
// 2. Broadcasts the update to all active subscribers
//
// This is called by hunter manager and downstream manager when topology events occur.
func (m *Manager) PublishTopologyUpdate(update *management.TopologyUpdate) {
	if update == nil {
		m.logger.Warn("received nil topology update, ignoring")
		return
	}

	// Apply update to topology cache
	m.cache.Apply(update)

	// Broadcast to all subscribers
	m.broadcastTopologyUpdate(update)

	m.logger.Debug("published topology update",
		"update_type", update.UpdateType,
		"timestamp_ns", update.TimestampNs)
}

// broadcastTopologyUpdate sends a topology update to all active subscribers.
// Uses non-blocking sends to prevent slow subscribers from blocking the broadcaster.
//
// Dropped updates are logged as warnings, including the subscriber ID.
func (m *Manager) broadcastTopologyUpdate(update *management.TopologyUpdate) {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()

	for subscriberID, ch := range m.subscribers {
		select {
		case ch <- update:
			// Successfully sent
		default:
			// Channel full, drop update
			m.logger.Warn("dropped topology update for slow subscriber",
				"subscriber_id", subscriberID,
				"update_type", update.UpdateType)
		}
	}
}

// FindDownstreamForTarget searches the topology cache to find which downstream
// processor is on the path to the target processor.
// Returns the downstream processor ID, or empty string if not found.
func (m *Manager) FindDownstreamForTarget(targetProcessorID string) string {
	// First, check if target is a direct downstream
	if proc := m.cache.GetProcessor(targetProcessorID); proc != nil {
		// Found in cache - it's either this processor or a downstream
		return targetProcessorID
	}

	// TODO: For phase 3, we need to search the full hierarchy tree
	// For now, we only support direct downstream routing (one level)
	// Full recursive routing will be implemented when topology cache
	// stores the full hierarchy structure

	return ""
}

// RoutingDecision contains information about how to route a request to a target processor
type RoutingDecision struct {
	// IsLocal indicates whether the target processor is this processor
	IsLocal bool

	// DownstreamProcessorID is the ID of the downstream processor to route through
	// Only set if IsLocal is false
	DownstreamProcessorID string

	// RecommendedTimeout is the recommended timeout for this operation
	// Calculated as: 5 seconds base + (depth * 500ms per hop)
	RecommendedTimeout time.Duration

	// Depth is the hierarchy depth of the target processor
	// 0 for local processor, >0 for downstream processors
	Depth int32

	// TargetReachable indicates whether the target processor is reachable
	// False if the processor is marked as unreachable in the topology cache
	TargetReachable bool

	// UnreachableReason provides context if TargetReachable is false
	UnreachableReason string
}

// RouteToProcessor determines how to route a request to a target processor.
// This method performs routing decision logic for multi-level processor hierarchies.
//
// It checks if the target is the local processor, finds the downstream processor
// on the path to the target, validates reachability, and calculates recommended
// timeouts based on hierarchy depth.
//
// Returns:
//   - RoutingDecision with routing information
//   - error if the processor is not found or if there's a routing issue
//
// Errors:
//   - codes.NotFound: target processor not found in topology
//   - codes.Unavailable: target processor is marked as unreachable
func (m *Manager) RouteToProcessor(ctx context.Context, targetProcessorID string) (*RoutingDecision, error) {
	m.logger.Debug("routing request to processor",
		"target_processor_id", targetProcessorID,
		"local_processor_id", m.processorID)

	// Check if target is local processor (empty string means local)
	if targetProcessorID == "" || targetProcessorID == m.processorID {
		m.logger.Debug("target is local processor")
		return &RoutingDecision{
			IsLocal:            true,
			RecommendedTimeout: 5 * time.Second, // Base timeout for local operation
			Depth:              0,
			TargetReachable:    true,
		}, nil
	}

	// Look up target processor in topology cache
	targetProc := m.cache.GetProcessor(targetProcessorID)
	if targetProc == nil {
		m.logger.Warn("target processor not found in topology cache",
			"target_processor_id", targetProcessorID)
		return nil, status.Errorf(codes.NotFound,
			"processor not found: %s", targetProcessorID)
	}

	// Check if target is reachable
	if !targetProc.Reachable {
		m.logger.Warn("target processor is unreachable",
			"target_processor_id", targetProcessorID,
			"reason", targetProc.UnreachableReason)
		return nil, status.Errorf(codes.Unavailable,
			"processor unreachable: %s (reason: %s)",
			targetProcessorID, targetProc.UnreachableReason)
	}

	// Find downstream processor on path to target
	downstreamID := m.FindDownstreamForTarget(targetProcessorID)
	if downstreamID == "" {
		m.logger.Error("could not find downstream route to target processor",
			"target_processor_id", targetProcessorID)
		return nil, status.Errorf(codes.Internal,
			"no route found to processor: %s", targetProcessorID)
	}

	// Calculate timeout based on hierarchy depth
	// Base timeout: 5 seconds
	// Additional time per hop: 500ms
	depth := targetProc.HierarchyDepth
	baseTimeout := 5 * time.Second
	perHopTimeout := 500 * time.Millisecond
	recommendedTimeout := baseTimeout + time.Duration(depth)*perHopTimeout

	m.logger.Debug("routing decision calculated",
		"target_processor_id", targetProcessorID,
		"downstream_processor_id", downstreamID,
		"depth", depth,
		"recommended_timeout", recommendedTimeout)

	return &RoutingDecision{
		IsLocal:               false,
		DownstreamProcessorID: downstreamID,
		RecommendedTimeout:    recommendedTimeout,
		Depth:                 depth,
		TargetReachable:       true,
	}, nil
}

// ValidateRoutingConnection checks if a downstream processor is available for routing.
// This is called before forwarding a request to validate the connection is ready.
//
// Returns error if:
//   - Downstream processor not found in cache
//   - Downstream processor marked as unreachable
func (m *Manager) ValidateRoutingConnection(downstreamProcessorID string) error {
	proc := m.cache.GetProcessor(downstreamProcessorID)
	if proc == nil {
		m.logger.Warn("downstream processor not found for routing validation",
			"downstream_processor_id", downstreamProcessorID)
		return status.Errorf(codes.NotFound,
			"downstream processor not found: %s", downstreamProcessorID)
	}

	if !proc.Reachable {
		m.logger.Warn("downstream processor is unreachable",
			"downstream_processor_id", downstreamProcessorID,
			"reason", proc.UnreachableReason)
		return status.Errorf(codes.Unavailable,
			"downstream processor unreachable: %s (reason: %s)",
			downstreamProcessorID, proc.UnreachableReason)
	}

	return nil
}

// CalculateChainTimeout calculates the recommended timeout for a multi-hop operation
// based on the number of hops in the chain.
//
// Formula: 5s base + (hops * 500ms per hop)
//
// Examples:
//   - 1 hop (direct downstream): 5.5s
//   - 2 hops: 6.0s
//   - 3 hops: 6.5s
//
// This is exported for use by callers who need to set context timeouts.
func CalculateChainTimeout(hops int32) time.Duration {
	const (
		baseTimeout   = 5 * time.Second
		perHopTimeout = 500 * time.Millisecond
	)
	return baseTimeout + time.Duration(hops)*perHopTimeout
}

// FormatRoutingError formats a routing error with context about the processor chain.
// This helps with debugging multi-level routing issues by showing which processor
// in the chain encountered the error.
//
// Example: "processor-b -> processor-c: connection refused"
func FormatRoutingError(processorChain []string, err error) error {
	if len(processorChain) == 0 {
		return err
	}

	chainStr := ""
	for i, procID := range processorChain {
		if i > 0 {
			chainStr += " -> "
		}
		chainStr += procID
	}

	return fmt.Errorf("%s: %w", chainStr, err)
}
