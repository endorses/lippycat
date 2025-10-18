//go:build hunter || all

package filtering

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
)

// CaptureRestarter is an interface for restarting capture with new filters
type CaptureRestarter interface {
	Restart(filters []*management.Filter) error
}

// DisconnectMarker is an interface for marking connection as disconnected
type DisconnectMarker interface {
	MarkDisconnected()
}

// ApplicationFilterUpdater is an interface for hot-reloading application-level filters
type ApplicationFilterUpdater interface {
	UpdateFilters(filters []*management.Filter)
}

// Manager handles filter subscription and updates from processor
type Manager struct {
	hunterID string
	mu       sync.RWMutex
	filters  []*management.Filter

	// Dependencies
	captureRestarter CaptureRestarter
	disconnectMarker DisconnectMarker
	appFilterUpdater ApplicationFilterUpdater // Optional: for hot-reload of app-level filters
}

// New creates a new filter manager
func New(hunterID string, captureRestarter CaptureRestarter, disconnectMarker DisconnectMarker) *Manager {
	return &Manager{
		hunterID:         hunterID,
		filters:          make([]*management.Filter, 0),
		captureRestarter: captureRestarter,
		disconnectMarker: disconnectMarker,
	}
}

// SetApplicationFilterUpdater sets the application filter updater for hot-reload support
// This is optional - if not set, all filter updates will trigger capture restart
func (m *Manager) SetApplicationFilterUpdater(updater ApplicationFilterUpdater) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appFilterUpdater = updater
}

// GetFilters returns a copy of current filters (thread-safe)
func (m *Manager) GetFilters() []*management.Filter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	filtersCopy := make([]*management.Filter, len(m.filters))
	copy(filtersCopy, m.filters)
	return filtersCopy
}

// GetFilterCount returns the number of active filters (thread-safe)
func (m *Manager) GetFilterCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.filters)
}

// SetInitialFilters sets the initial filters from registration response
func (m *Manager) SetInitialFilters(filters []*management.Filter) {
	m.mu.Lock()
	m.filters = filters
	m.mu.Unlock()

	// Sync SIP user filters to sipusers package
	m.syncSIPUserFilters(filters)
}

// Subscribe subscribes to filter updates from processor
func (m *Manager) Subscribe(ctx, connCtx context.Context, mgmtClient management.ManagementServiceClient) {
	logger.Debug("Subscribe() called", "hunter_id", m.hunterID)
	logger.Info("Subscribing to filter updates")

	req := &management.FilterRequest{
		HunterId: m.hunterID,
	}

	stream, err := mgmtClient.SubscribeFilters(ctx, req)
	if err != nil {
		logger.Error("Failed to subscribe to filters", "error", err)
		m.disconnectMarker.MarkDisconnected()
		return
	}

	logger.Info("Filter subscription established")

	// Use a channel with timeout to prevent goroutine leak
	updateCh := make(chan *management.FilterUpdate, constants.ErrorChannelBuffer)
	errCh := make(chan error, constants.ErrorChannelBuffer)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Recovered from panic in filter subscription receiver", "panic", r)
			}
		}()
		for {
			// Check context before Recv
			select {
			case <-ctx.Done():
				return
			case <-connCtx.Done():
				return
			default:
			}

			update, err := stream.Recv()
			if err != nil {
				// Only send error if not shutting down
				if ctx.Err() == nil && connCtx.Err() == nil {
					errCh <- err
				}
				return
			}
			select {
			case updateCh <- update:
			case <-ctx.Done():
				return
			case <-connCtx.Done():
				return
			}
		}
	}()

	// Read with periodic timeout check
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-connCtx.Done():
			logger.Debug("Filter subscription: connCtx cancelled", "hunter_id", m.hunterID, "error", connCtx.Err())
			logger.Info("Filter subscription closed (context)")
			return

		case err := <-errCh:
			if err == io.EOF {
				logger.Info("Filter subscription closed by processor (EOF)", "hunter_id", m.hunterID)
			} else {
				logger.Error("Filter subscription error", "hunter_id", m.hunterID, "error", err)
			}
			logger.Debug("Filter subscription: calling MarkDisconnected()", "hunter_id", m.hunterID)
			m.disconnectMarker.MarkDisconnected()
			return

		case update := <-updateCh:
			logger.Debug("Filter subscription: received update", "hunter_id", m.hunterID, "update_type", update.UpdateType)
			m.handleUpdate(update)

		case <-ticker.C:
			// Periodic keepalive check
			logger.Debug("Filter subscription: periodic check", "hunter_id", m.hunterID)
			if ctx.Err() != nil {
				logger.Debug("Filter subscription: main ctx cancelled", "hunter_id", m.hunterID, "error", ctx.Err())
				return
			}
		}
	}
}

// handleUpdate applies filter updates from processor
// Routes updates by filter type: BPF filters require restart, app-level filters hot-reload
func (m *Manager) handleUpdate(update *management.FilterUpdate) {
	logger.Info("Received filter update",
		"type", update.UpdateType,
		"filter_id", update.Filter.Id,
		"filter_type", update.Filter.Type)

	m.mu.Lock()
	filtersChanged := false

	switch update.UpdateType {
	case management.FilterUpdateType_UPDATE_ADD:
		// Check if filter already exists (prevent duplicates)
		exists := false
		for _, f := range m.filters {
			if f.Id == update.Filter.Id {
				exists = true
				logger.Debug("Filter already exists, skipping duplicate add",
					"filter_id", update.Filter.Id)
				break
			}
		}

		if !exists {
			// Add new filter
			m.filters = append(m.filters, update.Filter)
			filtersChanged = true
			logger.Info("Filter added",
				"filter_id", update.Filter.Id,
				"pattern", update.Filter.Pattern)
		}

	case management.FilterUpdateType_UPDATE_MODIFY:
		// Modify existing filter
		for i, f := range m.filters {
			if f.Id == update.Filter.Id {
				m.filters[i] = update.Filter
				filtersChanged = true
				logger.Info("Filter modified",
					"filter_id", update.Filter.Id,
					"pattern", update.Filter.Pattern)
				break
			}
		}
		if !filtersChanged {
			logger.Warn("Filter to modify not found", "filter_id", update.Filter.Id)
		}

	case management.FilterUpdateType_UPDATE_DELETE:
		// Delete filter
		for i, f := range m.filters {
			if f.Id == update.Filter.Id {
				m.filters = append(m.filters[:i], m.filters[i+1:]...)
				filtersChanged = true
				logger.Info("Filter deleted", "filter_id", update.Filter.Id)
				break
			}
		}
		if !filtersChanged {
			logger.Warn("Filter to delete not found", "filter_id", update.Filter.Id)
		}
	}

	// Get current filters and appFilterUpdater before unlocking
	currentFilters := m.filters
	appFilterUpdater := m.appFilterUpdater
	m.mu.Unlock()

	// Apply filters based on type
	if filtersChanged {
		// Check if this is a BPF filter change (requires capture restart)
		needsRestart := m.containsBPFFilter(update.Filter)

		if needsRestart {
			// BPF filter changed - must restart capture
			logger.Info("BPF filter changed, restarting capture", "active_filters", len(currentFilters))

			// Sync SIP user filters to sipusers package for application-level filtering
			m.syncSIPUserFilters(currentFilters)

			if err := m.captureRestarter.Restart(currentFilters); err != nil {
				logger.Error("Failed to restart capture with new filters", "error", err)
			}
		} else if appFilterUpdater != nil {
			// Application-level filter changed - hot-reload without restart
			logger.Info("Application-level filter changed, hot-reloading (no restart)",
				"active_filters", len(currentFilters))

			// Sync SIP user filters to sipusers package for application-level filtering
			m.syncSIPUserFilters(currentFilters)

			// Update application filter without restarting capture
			appFilterUpdater.UpdateFilters(currentFilters)
		} else {
			// No app filter updater - fall back to restart (backward compatibility)
			logger.Info("Application-level filter changed but no updater set, restarting capture",
				"active_filters", len(currentFilters))

			// Sync SIP user filters to sipusers package for application-level filtering
			m.syncSIPUserFilters(currentFilters)

			if err := m.captureRestarter.Restart(currentFilters); err != nil {
				logger.Error("Failed to restart capture with new filters", "error", err)
			}
		}
	}
}

// containsBPFFilter checks if a filter is a BPF filter (requires capture restart)
func (m *Manager) containsBPFFilter(filter *management.Filter) bool {
	return filter.Type == management.FilterType_FILTER_BPF
}

// syncSIPUserFilters synchronizes FILTER_SIP_USER filters to the sipusers package
// This allows application-level filtering to work correctly in hunter mode
func (m *Manager) syncSIPUserFilters(filters []*management.Filter) {
	// Build map of SIP users from filters
	sipUsers := make(map[string]*sipusers.SipUser)
	for _, filter := range filters {
		if filter.Type == management.FilterType_FILTER_SIP_USER {
			// Use a far-future expiration date since processor manages filter lifetime
			sipUsers[filter.Pattern] = &sipusers.SipUser{
				ExpirationDate: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
			}
		}
	}

	// Clear existing SIP users and add new ones
	// Note: This is safe because in hunter mode, sipusers are ONLY managed by filter updates
	sipusers.ClearAll()
	sipusers.AddMultipleSipUsers(sipUsers)

	logger.Debug("Synchronized SIP user filters", "sip_user_count", len(sipUsers))
}
