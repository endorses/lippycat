package hunter

import (
	"context"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Monitor monitors hunter health and performs cleanup
type Monitor struct {
	manager *Manager

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewMonitor creates a new hunter monitor
func NewMonitor(manager *Manager) *Monitor {
	return &Monitor{
		manager: manager,
	}
}

// Start begins monitoring hunter health
func (m *Monitor) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Start heartbeat monitor
	m.wg.Add(1)
	go m.monitorHeartbeats()

	// Start cleanup janitor
	m.wg.Add(1)
	go m.cleanupStaleHunters()

	logger.Info("Hunter monitor started")
}

// Stop stops the monitor
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	logger.Info("Hunter monitor stopped")
}

// monitorHeartbeats monitors hunter heartbeats and marks stale hunters
func (m *Monitor) monitorHeartbeats() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	logger.Info("Heartbeat monitor started")

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Heartbeat monitor stopped")
			return

		case <-ticker.C:
			staleThreshold := 30 * time.Second // 30 seconds without heartbeat
			m.manager.MarkStale(staleThreshold)
		}
	}
}

// cleanupStaleHunters periodically removes hunters that have been in ERROR state for too long
func (m *Monitor) cleanupStaleHunters() {
	defer m.wg.Done()

	// Cleanup interval: check every 2 minutes (more frequent for faster recovery)
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	// Grace period: remove hunters that have been in ERROR state for 5 minutes
	// This allows hunters to reconnect quickly without being stuck in registry
	// Hunters will re-register when they reconnect, so aggressive cleanup is safe
	const gracePeriod = 5 * time.Minute

	logger.Info("Stale hunter cleanup janitor started",
		"cleanup_interval", "2m",
		"grace_period", gracePeriod)

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Stale hunter cleanup janitor stopped")
			return
		case <-ticker.C:
			removed := m.manager.RemoveStale(gracePeriod)

			if len(removed) > 0 {
				logger.Info("Cleaned up stale hunters",
					"count", len(removed),
					"hunter_ids", removed,
					"grace_period", gracePeriod)
			}
		}
	}
}
