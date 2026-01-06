//go:build cli || hunter || tap || all

package tls

import (
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// TrackerConfig configures the connection tracker.
type TrackerConfig struct {
	// MaxConnections limits the number of tracked connections.
	MaxConnections int
	// ConnectionTimeout is how long to keep a connection without ServerHello.
	ConnectionTimeout time.Duration
	// CleanupInterval is how often to clean expired connections.
	CleanupInterval time.Duration
}

// DefaultTrackerConfig returns default tracker configuration.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		MaxConnections:    10000,
		ConnectionTimeout: 30 * time.Second,
		CleanupInterval:   10 * time.Second,
	}
}

// ConnectionRecord tracks a TLS connection from ClientHello to ServerHello.
type ConnectionRecord struct {
	FlowKey         string
	ClientHello     *types.TLSMetadata
	ServerHello     *types.TLSMetadata
	ClientTimestamp time.Time
	ServerTimestamp time.Time
	Complete        bool
}

// Tracker tracks TLS connections for correlation.
type Tracker struct {
	config      TrackerConfig
	connections map[string]*ConnectionRecord // FlowKey -> Record
	mu          sync.RWMutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewTracker creates a new TLS connection tracker.
func NewTracker(config TrackerConfig) *Tracker {
	t := &Tracker{
		config:      config,
		connections: make(map[string]*ConnectionRecord),
		stopChan:    make(chan struct{}),
	}
	t.wg.Add(1)
	go t.cleanupLoop()
	return t
}

// TrackClientHello records a ClientHello for correlation.
func (t *Tracker) TrackClientHello(pkt *types.PacketDisplay, metadata *types.TLSMetadata) {
	if metadata == nil || metadata.IsServer {
		return
	}

	flowKey := t.flowKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	metadata.FlowKey = flowKey

	t.mu.Lock()
	defer t.mu.Unlock()

	// Enforce max connections limit
	if len(t.connections) >= t.config.MaxConnections {
		// Evict oldest entry
		t.evictOldest()
	}

	t.connections[flowKey] = &ConnectionRecord{
		FlowKey:         flowKey,
		ClientHello:     metadata,
		ClientTimestamp: pkt.Timestamp,
	}
}

// CorrelateServerHello correlates a ServerHello with its ClientHello.
func (t *Tracker) CorrelateServerHello(pkt *types.PacketDisplay, metadata *types.TLSMetadata) bool {
	if metadata == nil || !metadata.IsServer {
		return false
	}

	// For ServerHello, the flow is reversed (server -> client)
	flowKey := t.flowKey(pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
	metadata.FlowKey = flowKey

	t.mu.Lock()
	defer t.mu.Unlock()

	record, exists := t.connections[flowKey]
	if !exists || record.Complete {
		return false
	}

	record.ServerHello = metadata
	record.ServerTimestamp = pkt.Timestamp
	record.Complete = true

	// Calculate handshake time
	if !record.ClientTimestamp.IsZero() {
		metadata.HandshakeTimeMs = pkt.Timestamp.Sub(record.ClientTimestamp).Milliseconds()
		metadata.CorrelatedPeer = true
	}

	return true
}

// GetConnection retrieves a connection record by flow key.
func (t *Tracker) GetConnection(flowKey string) *ConnectionRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connections[flowKey]
}

// Stats returns tracker statistics.
func (t *Tracker) Stats() TrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := TrackerStats{
		TotalConnections: len(t.connections),
	}

	for _, c := range t.connections {
		if c.Complete {
			stats.CompletedHandshakes++
		} else {
			stats.PendingHandshakes++
		}
	}

	return stats
}

// TrackerStats holds tracker statistics.
type TrackerStats struct {
	TotalConnections    int
	CompletedHandshakes int
	PendingHandshakes   int
}

// Stop stops the tracker's cleanup goroutine.
func (t *Tracker) Stop() {
	close(t.stopChan)
	t.wg.Wait()
}

// flowKey generates a unique key for a connection.
func (t *Tracker) flowKey(srcIP, srcPort, dstIP, dstPort string) string {
	return fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
}

// cleanupLoop periodically removes expired connections.
func (t *Tracker) cleanupLoop() {
	defer t.wg.Done()
	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.cleanup()
		case <-t.stopChan:
			return
		}
	}
}

// cleanup removes expired connections.
func (t *Tracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for key, record := range t.connections {
		age := now.Sub(record.ClientTimestamp)
		if record.Complete || age > t.config.ConnectionTimeout {
			delete(t.connections, key)
		}
	}
}

// evictOldest removes the oldest connection to make room.
func (t *Tracker) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, record := range t.connections {
		if oldestKey == "" || record.ClientTimestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = record.ClientTimestamp
		}
	}

	if oldestKey != "" {
		delete(t.connections, oldestKey)
	}
}
