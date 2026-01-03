package dns

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// QueryTracker correlates DNS queries with their responses using transaction IDs.
type QueryTracker struct {
	mu      sync.RWMutex
	queries map[queryKey]*pendingQuery
	maxAge  time.Duration
}

// queryKey uniquely identifies a DNS query.
type queryKey struct {
	TransactionID uint16
	SrcIP         string
	DstIP         string
}

// pendingQuery stores information about a query awaiting response.
type pendingQuery struct {
	Timestamp time.Time
	QueryName string
	QueryType string
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Interface string
	NodeID    string
}

// TrackerConfig holds configuration for the query tracker.
type TrackerConfig struct {
	MaxAge          time.Duration // Maximum age for pending queries
	CleanupInterval time.Duration // How often to clean up old queries
}

// DefaultTrackerConfig returns the default tracker configuration.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		MaxAge:          30 * time.Second,
		CleanupInterval: 10 * time.Second,
	}
}

// NewQueryTracker creates a new query tracker.
func NewQueryTracker(config TrackerConfig) *QueryTracker {
	if config.MaxAge == 0 {
		config.MaxAge = 30 * time.Second
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 10 * time.Second
	}

	qt := &QueryTracker{
		queries: make(map[queryKey]*pendingQuery),
		maxAge:  config.MaxAge,
	}

	// Start cleanup goroutine
	go qt.cleanupLoop(config.CleanupInterval)

	return qt
}

// TrackQuery records a DNS query for later correlation.
func (qt *QueryTracker) TrackQuery(pkt *types.PacketDisplay, metadata *types.DNSMetadata) {
	if metadata == nil || metadata.IsResponse {
		return
	}

	key := queryKey{
		TransactionID: metadata.TransactionID,
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
	}

	pending := &pendingQuery{
		Timestamp: pkt.Timestamp,
		QueryName: metadata.QueryName,
		QueryType: metadata.QueryType,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Interface: pkt.Interface,
		NodeID:    pkt.NodeID,
	}

	qt.mu.Lock()
	qt.queries[key] = pending
	qt.mu.Unlock()
}

// CorrelateResponse attempts to correlate a DNS response with its query.
// If successful, updates the metadata with correlation information and returns true.
func (qt *QueryTracker) CorrelateResponse(pkt *types.PacketDisplay, metadata *types.DNSMetadata) bool {
	if metadata == nil || !metadata.IsResponse {
		return false
	}

	// Response comes from DNS server to client, so swap src/dst from query perspective
	key := queryKey{
		TransactionID: metadata.TransactionID,
		SrcIP:         pkt.DstIP, // Client was the source of the query
		DstIP:         pkt.SrcIP, // Server was the destination of the query
	}

	qt.mu.Lock()
	pending, found := qt.queries[key]
	if found {
		delete(qt.queries, key)
	}
	qt.mu.Unlock()

	if !found {
		return false
	}

	// Calculate response time
	responseTime := pkt.Timestamp.Sub(pending.Timestamp)
	metadata.QueryResponseTimeMs = responseTime.Milliseconds()
	metadata.CorrelatedQuery = true

	return true
}

// cleanupLoop periodically removes old pending queries.
func (qt *QueryTracker) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		qt.cleanup()
	}
}

// cleanup removes queries older than maxAge.
func (qt *QueryTracker) cleanup() {
	now := time.Now()
	cutoff := now.Add(-qt.maxAge)

	qt.mu.Lock()
	defer qt.mu.Unlock()

	for key, pending := range qt.queries {
		if pending.Timestamp.Before(cutoff) {
			delete(qt.queries, key)
		}
	}
}

// Stats returns current tracker statistics.
func (qt *QueryTracker) Stats() TrackerStats {
	qt.mu.RLock()
	defer qt.mu.RUnlock()

	return TrackerStats{
		PendingQueries: len(qt.queries),
	}
}

// TrackerStats holds query tracker statistics.
type TrackerStats struct {
	PendingQueries int
}

// QueryInfo represents information about a pending or completed DNS query.
type QueryInfo struct {
	TransactionID     uint16
	QueryName         string
	QueryType         string
	QueryTimestamp    time.Time
	ResponseTimestamp time.Time
	ResponseTimeMs    int64
	ResponseCode      string
	AnswerCount       int
	Correlated        bool
	SrcIP             string
	DstIP             string
	ServerIP          string
}

// QueryAggregator tracks DNS queries and their statistics.
type QueryAggregator struct {
	mu      sync.RWMutex
	queries map[string]*QueryStats // Key: domain name
	maxSize int
}

// QueryStats holds statistics for a domain.
type QueryStats struct {
	Domain            string
	QueryCount        int64
	ResponseCount     int64
	NXDomainCount     int64
	ServerFailCount   int64
	TotalResponseTime time.Duration
	LastSeen          time.Time
	UniqueClients     map[string]struct{}
	RecordTypes       map[string]int64
}

// NewQueryAggregator creates a new query aggregator.
func NewQueryAggregator(maxSize int) *QueryAggregator {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &QueryAggregator{
		queries: make(map[string]*QueryStats),
		maxSize: maxSize,
	}
}

// RecordQuery records a DNS query for aggregation.
func (qa *QueryAggregator) RecordQuery(metadata *types.DNSMetadata, clientIP string) {
	if metadata == nil || metadata.QueryName == "" {
		return
	}

	qa.mu.Lock()
	defer qa.mu.Unlock()

	stats, exists := qa.queries[metadata.QueryName]
	if !exists {
		if len(qa.queries) >= qa.maxSize {
			// Simple eviction: remove oldest entry
			var oldestKey string
			var oldestTime time.Time
			for k, v := range qa.queries {
				if oldestKey == "" || v.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.LastSeen
				}
			}
			delete(qa.queries, oldestKey)
		}
		stats = &QueryStats{
			Domain:        metadata.QueryName,
			UniqueClients: make(map[string]struct{}),
			RecordTypes:   make(map[string]int64),
		}
		qa.queries[metadata.QueryName] = stats
	}

	if metadata.IsResponse {
		stats.ResponseCount++
		if metadata.CorrelatedQuery {
			stats.TotalResponseTime += time.Duration(metadata.QueryResponseTimeMs) * time.Millisecond
		}
		switch metadata.ResponseCode {
		case "NXDOMAIN":
			stats.NXDomainCount++
		case "SERVFAIL":
			stats.ServerFailCount++
		}
	} else {
		stats.QueryCount++
		if clientIP != "" {
			stats.UniqueClients[clientIP] = struct{}{}
		}
	}

	if metadata.QueryType != "" {
		stats.RecordTypes[metadata.QueryType]++
	}
	stats.LastSeen = time.Now()
}

// GetTopDomains returns the top N queried domains.
func (qa *QueryAggregator) GetTopDomains(n int) []QueryStats {
	qa.mu.RLock()
	defer qa.mu.RUnlock()

	// Collect all stats
	allStats := make([]QueryStats, 0, len(qa.queries))
	for _, stats := range qa.queries {
		allStats = append(allStats, *stats)
	}

	// Sort by query count (simple selection for top N)
	for i := 0; i < n && i < len(allStats); i++ {
		maxIdx := i
		for j := i + 1; j < len(allStats); j++ {
			if allStats[j].QueryCount > allStats[maxIdx].QueryCount {
				maxIdx = j
			}
		}
		allStats[i], allStats[maxIdx] = allStats[maxIdx], allStats[i]
	}

	if n > len(allStats) {
		n = len(allStats)
	}
	return allStats[:n]
}
