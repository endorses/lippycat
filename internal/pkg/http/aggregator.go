package http

import (
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// RequestAggregator tracks statistics for HTTP requests/responses.
type RequestAggregator struct {
	mu      sync.RWMutex
	paths   map[string]*PathStats
	hosts   map[string]*HostStats
	maxSize int
}

// PathStats holds statistics for a specific path.
type PathStats struct {
	Path              string
	RequestCount      int64
	ResponseCount     int64
	Status2xx         int64
	Status3xx         int64
	Status4xx         int64
	Status5xx         int64
	TotalResponseTime int64 // Sum of response times in ms
	AvgResponseTimeMs int64 // Calculated average
	Methods           map[string]int64
	UniqueHosts       map[string]struct{}
	LastSeen          time.Time
}

// HostStats holds statistics for a specific host.
type HostStats struct {
	Host         string
	RequestCount int64
	StatusCodes  map[int]int64
	TopPaths     map[string]int64
	LastSeen     time.Time
}

// NewRequestAggregator creates a new request aggregator.
func NewRequestAggregator(maxSize int) *RequestAggregator {
	if maxSize <= 0 {
		maxSize = 10000
	}

	return &RequestAggregator{
		paths:   make(map[string]*PathStats),
		hosts:   make(map[string]*HostStats),
		maxSize: maxSize,
	}
}

// RecordRequest records an HTTP request for aggregation.
func (a *RequestAggregator) RecordRequest(metadata *types.HTTPMetadata) {
	if metadata.Type != "request" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Update path stats
	path := normalizePath(metadata.Path)
	pathStats := a.getOrCreatePath(path)
	pathStats.RequestCount++
	pathStats.LastSeen = time.Now()

	// Track method
	if pathStats.Methods == nil {
		pathStats.Methods = make(map[string]int64)
	}
	pathStats.Methods[metadata.Method]++

	// Track host
	if metadata.Host != "" {
		if pathStats.UniqueHosts == nil {
			pathStats.UniqueHosts = make(map[string]struct{})
		}
		pathStats.UniqueHosts[metadata.Host] = struct{}{}
	}

	// Update host stats
	if metadata.Host != "" {
		hostStats := a.getOrCreateHost(metadata.Host)
		hostStats.RequestCount++
		hostStats.LastSeen = time.Now()

		if hostStats.TopPaths == nil {
			hostStats.TopPaths = make(map[string]int64)
		}
		hostStats.TopPaths[path]++
	}
}

// RecordResponse records an HTTP response for aggregation.
func (a *RequestAggregator) RecordResponse(metadata *types.HTTPMetadata) {
	if metadata.Type != "response" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// We need a path to aggregate - use Host if available
	host := metadata.Host
	if host == "" {
		return
	}

	hostStats := a.getOrCreateHost(host)

	// Track status code
	if hostStats.StatusCodes == nil {
		hostStats.StatusCodes = make(map[int]int64)
	}
	hostStats.StatusCodes[metadata.StatusCode]++
}

// RecordCorrelatedResponse records a response correlated with a request.
func (a *RequestAggregator) RecordCorrelatedResponse(path string, metadata *types.HTTPMetadata) {
	if metadata.Type != "response" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	normalPath := normalizePath(path)
	pathStats := a.getOrCreatePath(normalPath)
	pathStats.ResponseCount++
	pathStats.LastSeen = time.Now()

	// Track status code category
	switch {
	case metadata.StatusCode >= 200 && metadata.StatusCode < 300:
		pathStats.Status2xx++
	case metadata.StatusCode >= 300 && metadata.StatusCode < 400:
		pathStats.Status3xx++
	case metadata.StatusCode >= 400 && metadata.StatusCode < 500:
		pathStats.Status4xx++
	case metadata.StatusCode >= 500:
		pathStats.Status5xx++
	}

	// Track response time
	if metadata.RequestResponseTimeMs > 0 {
		pathStats.TotalResponseTime += metadata.RequestResponseTimeMs
		if pathStats.ResponseCount > 0 {
			pathStats.AvgResponseTimeMs = pathStats.TotalResponseTime / pathStats.ResponseCount
		}
	}
}

// getOrCreatePath gets or creates path stats.
func (a *RequestAggregator) getOrCreatePath(path string) *PathStats {
	if stats, ok := a.paths[path]; ok {
		return stats
	}

	// Enforce max size
	if len(a.paths) >= a.maxSize {
		a.evictOldestPath()
	}

	stats := &PathStats{
		Path:     path,
		Methods:  make(map[string]int64),
		LastSeen: time.Now(),
	}
	a.paths[path] = stats
	return stats
}

// getOrCreateHost gets or creates host stats.
func (a *RequestAggregator) getOrCreateHost(host string) *HostStats {
	if stats, ok := a.hosts[host]; ok {
		return stats
	}

	// Enforce max size
	if len(a.hosts) >= a.maxSize {
		a.evictOldestHost()
	}

	stats := &HostStats{
		Host:        host,
		StatusCodes: make(map[int]int64),
		TopPaths:    make(map[string]int64),
		LastSeen:    time.Now(),
	}
	a.hosts[host] = stats
	return stats
}

// evictOldestPath removes the oldest path entry.
func (a *RequestAggregator) evictOldestPath() {
	var oldestPath string
	var oldestTime time.Time

	for path, stats := range a.paths {
		if oldestPath == "" || stats.LastSeen.Before(oldestTime) {
			oldestPath = path
			oldestTime = stats.LastSeen
		}
	}

	if oldestPath != "" {
		delete(a.paths, oldestPath)
	}
}

// evictOldestHost removes the oldest host entry.
func (a *RequestAggregator) evictOldestHost() {
	var oldestHost string
	var oldestTime time.Time

	for host, stats := range a.hosts {
		if oldestHost == "" || stats.LastSeen.Before(oldestTime) {
			oldestHost = host
			oldestTime = stats.LastSeen
		}
	}

	if oldestHost != "" {
		delete(a.hosts, oldestHost)
	}
}

// GetTopPaths returns the top N paths by request count.
func (a *RequestAggregator) GetTopPaths(n int) []PathStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make([]PathStats, 0, len(a.paths))
	for _, s := range a.paths {
		stats = append(stats, *s)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].RequestCount > stats[j].RequestCount
	})

	if n > len(stats) {
		n = len(stats)
	}
	return stats[:n]
}

// GetTopHosts returns the top N hosts by request count.
func (a *RequestAggregator) GetTopHosts(n int) []HostStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make([]HostStats, 0, len(a.hosts))
	for _, s := range a.hosts {
		stats = append(stats, *s)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].RequestCount > stats[j].RequestCount
	})

	if n > len(stats) {
		n = len(stats)
	}
	return stats[:n]
}

// Stats returns aggregator statistics.
func (a *RequestAggregator) Stats() AggregatorStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var totalRequests, totalResponses int64
	for _, p := range a.paths {
		totalRequests += p.RequestCount
		totalResponses += p.ResponseCount
	}

	return AggregatorStats{
		UniquePaths:    int64(len(a.paths)),
		UniqueHosts:    int64(len(a.hosts)),
		TotalRequests:  totalRequests,
		TotalResponses: totalResponses,
	}
}

// AggregatorStats holds aggregator statistics.
type AggregatorStats struct {
	UniquePaths    int64
	UniqueHosts    int64
	TotalRequests  int64
	TotalResponses int64
}

// normalizePath normalizes a URL path for aggregation.
// Removes query strings and normalizes some common patterns.
func normalizePath(path string) string {
	// Limit path length
	if len(path) > 200 {
		path = path[:200]
	}

	// Already stripped query string in parser
	return path
}
