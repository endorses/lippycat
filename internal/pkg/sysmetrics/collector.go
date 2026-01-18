// Package sysmetrics provides system metrics collection for CPU and memory usage.
// Used by hunter and TAP nodes to report resource utilization to processors.
package sysmetrics

import (
	"context"
	"sync"
	"time"
)

// Metrics contains the current system metrics snapshot.
type Metrics struct {
	// CPUPercent is the CPU usage as a percentage (0-100).
	// Returns -1 if unavailable (e.g., on non-Linux platforms).
	CPUPercent float64

	// MemoryRSSBytes is the process resident set size in bytes.
	MemoryRSSBytes uint64

	// MemoryLimitBytes is the memory limit from cgroup.
	// Returns 0 if no limit is set or unavailable.
	MemoryLimitBytes uint64
}

// Collector collects system metrics in the background.
type Collector interface {
	// Start begins background metrics collection.
	Start(ctx context.Context)

	// Stop halts metrics collection.
	Stop()

	// Get returns the most recent metrics snapshot.
	Get() Metrics
}

// collector is the shared implementation structure.
type collector struct {
	mu      sync.RWMutex
	metrics Metrics

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Platform-specific fields are in collector_*.go files
	platformData platformCollector
}

// New creates a new Collector.
func New() Collector {
	return &collector{
		metrics: Metrics{
			CPUPercent: -1, // Unavailable until first sample
		},
	}
}

// Start begins background metrics collection.
func (c *collector) Start(ctx context.Context) {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Initialize platform-specific state
	c.initPlatform()

	c.wg.Add(1)
	go c.collectLoop()
}

// Stop halts metrics collection.
func (c *collector) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

// Get returns the most recent metrics snapshot.
func (c *collector) Get() Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// collectLoop runs in the background collecting metrics.
func (c *collector) collectLoop() {
	defer c.wg.Done()

	// Collect immediately on start
	c.collect()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

// collect gathers current metrics from the platform.
func (c *collector) collect() {
	m := c.collectPlatform()

	c.mu.Lock()
	c.metrics = m
	c.mu.Unlock()
}
