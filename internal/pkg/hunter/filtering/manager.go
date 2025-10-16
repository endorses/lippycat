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

// Manager handles filter subscription and updates from processor
type Manager struct {
	hunterID string
	mu       sync.RWMutex
	filters  []*management.Filter

	// Dependencies
	captureRestarter CaptureRestarter
	disconnectMarker DisconnectMarker
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
	logger.Info("Subscribing to filter updates")

	req := &management.FilterRequest{
		HunterId: m.hunterID,
	}

	stream, err := mgmtClient.SubscribeFilters(ctx, req)
	if err != nil {
		logger.Error("Failed to subscribe to filters", "error", err)
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
			logger.Info("Filter subscription closed (context)")
			return

		case err := <-errCh:
			if err == io.EOF {
				logger.Info("Filter subscription closed by processor")
			} else {
				logger.Error("Filter subscription error", "error", err)
			}
			m.disconnectMarker.MarkDisconnected()
			return

		case update := <-updateCh:
			m.handleUpdate(update)

		case <-ticker.C:
			// Periodic keepalive check
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// handleUpdate applies filter updates from processor
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

	// Get current filters before unlocking
	currentFilters := m.filters
	m.mu.Unlock()

	// Apply filters by restarting capture with new BPF filter
	if filtersChanged {
		logger.Info("Filters changed, restarting capture", "active_filters", len(currentFilters))

		// Sync SIP user filters to sipusers package for application-level filtering
		m.syncSIPUserFilters(currentFilters)

		if err := m.captureRestarter.Restart(currentFilters); err != nil {
			logger.Error("Failed to restart capture with new filters", "error", err)
		}
	}
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
