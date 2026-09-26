package filtering

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

// Manager manages filters and their distribution to hunters
type Manager struct {
	// Serialize mutations through distribution and persistence so hunters cannot
	// receive an older revision (or deletion) after a newer committed update.
	// Keep mu separate: distribution callbacks may read the current filters.
	mutationMu      sync.Mutex
	mu              sync.RWMutex
	filters         map[string]*management.Filter
	radiusRevisions map[string]uint64
	initialized     bool
	fault           error
	closed          bool

	channelsMu sync.RWMutex
	channels   map[string]chan *management.FilterUpdate // hunterID -> channel

	// Capabilities
	capabilityProvider CapabilityProvider

	// Callbacks
	onFilterFailure func(hunterID string, failed bool)
	onFilterChange  func() // Called when filter count changes

	// Persistence
	persistenceFile string
	persistence     PersistenceHandler
}

// PersistenceHandler handles filter persistence
type PersistenceHandler interface {
	Load(file string) (map[string]*management.Filter, error)
	Save(file string, filters map[string]*management.Filter) error
}

// CapabilityProvider provides hunter capabilities for filtering
type CapabilityProvider interface {
	GetCapabilities(hunterID string) *management.HunterCapabilities
}

// NewManager creates a new filter manager
func NewManager(persistenceFile string, persistence PersistenceHandler, capabilityProvider CapabilityProvider, onFilterFailure func(string, bool), onFilterChange func()) *Manager {
	return &Manager{
		filters:            make(map[string]*management.Filter),
		radiusRevisions:    make(map[string]uint64),
		channels:           make(map[string]chan *management.FilterUpdate),
		capabilityProvider: capabilityProvider,
		onFilterFailure:    onFilterFailure,
		onFilterChange:     onFilterChange,
		persistenceFile:    persistenceFile,
		persistence:        persistence,
	}
}

var (
	ErrFilterNotFound      = errors.New("filter not found")
	ErrFilterInvalid       = errors.New("invalid managed filter")
	ErrFilterStoreFault    = errors.New("filter storage is faulted; restart and reconcile persistence")
	ErrFilterManagerClosed = errors.New("filter manager is closed")
	ErrFilterDistribution  = errors.New("filter policy committed but hunter distribution is incomplete")
)

// Load restores startup state exactly once, before any filter mutation.
// Runtime reconciliation must use Update/Delete to preserve revision history.
func (m *Manager) Load() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	return m.load()
}

// Initialize loads a not-yet-owned store; repeated calls never reload policy.
func (m *Manager) Initialize() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	return m.ensureInitialized()
}

// load requires mutationMu.
func (m *Manager) load() error {
	if err := m.available(); err != nil {
		return err
	}
	m.mu.RLock()
	initialized := m.initialized
	m.mu.RUnlock()
	if initialized {
		return fmt.Errorf("filter Load is startup-only; use Update/Delete after initialization")
	}
	var filters map[string]*management.Filter
	if m.persistence != nil {
		var err error
		filters, err = m.persistence.Load(m.persistenceFile)
		if err != nil {
			return err
		}
	}
	revisions := make(map[string]uint64)
	restored := make(map[string]*management.Filter, len(filters))
	for id, f := range filters {
		if f == nil || id != f.Id {
			return ErrFilterInvalid
		}
		if err := filtering.ValidateManagedFilter(f); err != nil {
			return ErrFilterInvalid
		}
		if filtering.IsRADIUSFilter(f.Type) {
			if len(revisions) >= 65536 {
				return fmt.Errorf("RADIUS revision history capacity reached")
			}
			revisions[strings.Clone(id)] = f.Revision
		}
		restored[id] = proto.Clone(f).(*management.Filter)
	}
	m.mu.Lock()
	m.radiusRevisions = revisions
	m.filters = restored
	m.initialized = true
	m.mu.Unlock()
	logger.Info("Loaded filters from file", "count", len(filters), "file", m.persistenceFile)
	return nil
}

// ensureInitialized prevents an embedded caller's first mutation from replacing
// an existing store with an empty startup map. It requires mutationMu.
func (m *Manager) ensureInitialized() error {
	if err := m.available(); err != nil {
		return err
	}
	m.mu.RLock()
	initialized := m.initialized
	m.mu.RUnlock()
	if initialized {
		return nil
	}
	return m.load()
}

// available requires mutationMu; Fault remains safe for concurrent readers.
func (m *Manager) available() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ErrFilterManagerClosed
	}
	if m.fault != nil {
		return errors.Join(ErrFilterStoreFault, m.fault)
	}
	return nil
}

func (m *Manager) Fault() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fault
}

// persistCandidate returns a committed flag independently of cleanup errors.
// Once uncertain, no mutation can assume the old policy is authoritative.
func (m *Manager) persistCandidate(candidate map[string]*management.Filter) (bool, error) {
	if m.persistence == nil {
		return true, nil
	}
	err := m.persistence.Save(m.persistenceFile, candidate)
	outcome := securestore.OutcomeOf(err)
	if outcome == securestore.Uncertain {
		m.mu.Lock()
		m.fault = err
		m.mu.Unlock()
		m.closeSubscriptions()
	}
	return outcome == securestore.Committed, err
}

// Save persists the currently committed desired policy without republishing it.
func (m *Manager) Save() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := m.ensureInitialized(); err != nil {
		return err
	}
	m.mu.RLock()
	candidate := cloneFilterMap(m.filters)
	m.mu.RUnlock()
	_, err := m.persistCandidate(candidate)
	return err
}

// Close releases store ownership only after mutations have finished. It does not
// save again: every accepted mutation has already crossed its durable boundary.
func (m *Manager) Close() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()
	m.closeSubscriptions()
	if closer, ok := m.persistence.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (m *Manager) closeSubscriptions() {
	m.channelsMu.Lock()
	defer m.channelsMu.Unlock()
	for id, ch := range m.channels {
		close(ch)
		delete(m.channels, id)
	}
}

// hunterSupportsFilterType checks if a hunter supports a given filter type
func hunterSupportsFilterType(capabilities *management.HunterCapabilities, filterType management.FilterType) bool {
	if filtering.IsRADIUSFilter(filterType) && (capabilities == nil || capabilities.RadiusFilterVersion != 1) {
		return false
	}
	if capabilities == nil {
		// No capabilities info - this is a legacy hunter from before v0.2.8
		// Assume it's a generic hunter (only supports BPF and IP filters)
		logger.Debug("Hunter capabilities missing - treating as generic hunter (BPF/IP only)",
			"filter_type", filterType)
		// Only BPF and IP filters supported by legacy/generic hunters
		return filterType == management.FilterType_FILTER_BPF ||
			filterType == management.FilterType_FILTER_IP_ADDRESS
	}

	if len(capabilities.FilterTypes) == 0 {
		// Empty capabilities - this shouldn't happen with current hunters
		// Treat as generic hunter for safety
		logger.Warn("Hunter has empty FilterTypes capability list - treating as generic hunter (BPF/IP only)",
			"filter_type", filterType)
		return filterType == management.FilterType_FILTER_BPF ||
			filterType == management.FilterType_FILTER_IP_ADDRESS
	}

	// Map protobuf enum to string
	filterTypeStr := filtering.FilterTypeToString(filterType)

	// Check if hunter supports this filter type
	for _, supportedType := range capabilities.FilterTypes {
		if supportedType == filterTypeStr {
			return true
		}
	}

	return false
}

// GetForHunter returns filters applicable to a hunter
func (m *Manager) GetForHunter(hunterID string) []*management.Filter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get hunter capabilities from hunter manager
	var hunterCaps *management.HunterCapabilities
	if m.capabilityProvider != nil {
		hunterCaps = m.capabilityProvider.GetCapabilities(hunterID)
	}

	filters := make([]*management.Filter, 0)

	for _, filter := range m.filters {
		// Check if hunter supports this filter type
		if !hunterSupportsFilterType(hunterCaps, filter.Type) {
			logger.Debug("Skipping filter incompatible with hunter capabilities",
				"hunter_id", hunterID,
				"filter_type", filter.Type)
			continue
		}

		// If no target hunters specified, apply to all
		if len(filter.TargetHunters) == 0 {
			filters = append(filters, proto.Clone(filter).(*management.Filter))
			continue
		}

		// Check if this hunter is targeted
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				filters = append(filters, proto.Clone(filter).(*management.Filter))
				break
			}
		}
	}

	return filters
}

// Update adds or modifies a filter without mutating the caller's protobuf.
func (m *Manager) Update(filter *management.Filter) (uint32, error) {
	_, count, err := m.UpdateCommitted(filter)
	return count, err
}

// UpdateCommitted returns the detached accepted filter (including a generated ID)
// only after persistence commits. A nonnil filter with an error means committed
// desired policy with cleanup/distribution failure, never an ordinary rollback.
func (m *Manager) UpdateCommitted(input *management.Filter) (*management.Filter, uint32, error) {
	return m.UpdateValidated(input, nil)
}

// UpdateValidated performs owner validation on a detached normalized candidate
// under mutation ordering, before any persistence or subscriber publication.
func (m *Manager) UpdateValidated(input *management.Filter, validate func(*management.Filter) error) (*management.Filter, uint32, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := m.ensureInitialized(); err != nil {
		return nil, 0, err
	}
	if input == nil {
		return nil, 0, ErrFilterInvalid
	}
	filter := proto.Clone(input).(*management.Filter)
	if filter.Id == "" {
		filter.Id = fmt.Sprintf("filter-%d", time.Now().UnixNano())
	}
	if filter.Type == management.FilterType_FILTER_PHONE_NUMBER {
		filter.Pattern = filtering.NormalizePhonePattern(filter.Pattern)
	}
	if err := filtering.ValidateManagedFilter(filter); err != nil {
		return nil, 0, ErrFilterInvalid
	}
	if filtering.IsRADIUSFilter(filter.Type) {
		for _, hunterID := range filter.TargetHunters {
			var caps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				caps = m.capabilityProvider.GetCapabilities(hunterID)
			}
			if !hunterSupportsFilterType(caps, filter.Type) {
				return nil, 0, fmt.Errorf("%w: target hunter lacks RADIUS criteria/provenance capability v1", ErrFilterInvalid)
			}
		}
	}
	m.mu.RLock()
	oldFilter, exists := m.filters[filter.Id]
	if filtering.IsRADIUSFilter(filter.Type) {
		previous, known := m.radiusRevisions[filter.Id]
		if (!known && len(m.radiusRevisions) >= 65536) || ((!exists || !filtering.IsRADIUSFilter(oldFilter.Type)) && known && filter.Revision <= previous) {
			m.mu.RUnlock()
			return nil, 0, fmt.Errorf("%w: RADIUS revision history requires newer revision or has reached capacity", ErrFilterInvalid)
		}
	}

	if exists && (filtering.IsRADIUSFilter(filter.Type) || filtering.IsRADIUSFilter(oldFilter.Type)) && !proto.Equal(oldFilter, filter) && filter.Revision <= oldFilter.Revision {
		m.mu.RUnlock()
		return nil, 0, fmt.Errorf("%w: RADIUS filter modification requires a newer revision", ErrFilterInvalid)
	}
	if exists && filtering.IsRADIUSFilter(filter.Type) && oldFilter.Radius != nil && filter.Radius != nil && !proto.Equal(oldFilter.Radius, filter.Radius) {
		oldR, newR := oldFilter.Radius, filter.Radius
		if oldR.TaskId != "" && oldR.TaskId == newR.TaskId && newR.TaskGeneration <= oldR.TaskGeneration {
			m.mu.RUnlock()
			return nil, 0, fmt.Errorf("%w: RADIUS task criteria modification requires a newer task generation", ErrFilterInvalid)
		}
		for _, oldC := range oldR.Criteria {
			for _, newC := range newR.Criteria {
				if oldC != nil && newC != nil && oldC.FilterId == newC.FilterId && !proto.Equal(oldC, newC) && newC.FilterRevision <= oldC.FilterRevision {
					m.mu.RUnlock()
					return nil, 0, fmt.Errorf("%w: RADIUS criterion modification requires a newer criterion revision", ErrFilterInvalid)
				}
			}
		}
	}

	candidate := cloneFilterMap(m.filters)
	m.mu.RUnlock()
	candidate[filter.Id] = filter
	if validate != nil {
		if err := validate(proto.Clone(filter).(*management.Filter)); err != nil {
			return nil, 0, err
		}
	}
	committed, saveErr := m.persistCandidate(candidate)
	if !committed {
		return nil, 0, saveErr
	}
	m.mu.Lock()
	m.initialized = true
	m.filters = candidate
	if filtering.IsRADIUSFilter(filter.Type) {
		m.radiusRevisions[strings.Clone(filter.Id)] = filter.Revision
	}
	m.mu.Unlock()
	var distributionErr error
	if exists {
		removals := m.getHuntersToRemove(oldFilter, filter)
		if len(removals) > 0 {
			_, distributionErr = m.pushFilterUpdateToSpecificHunters(removals, &management.FilterUpdate{
				UpdateType: management.FilterUpdateType_UPDATE_DELETE, Filter: proto.Clone(oldFilter).(*management.Filter),
			})
		}
	}
	updateType := management.FilterUpdateType_UPDATE_ADD
	if exists {
		updateType = management.FilterUpdateType_UPDATE_MODIFY
	}
	count, err := m.pushFilterUpdate(filter, &management.FilterUpdate{UpdateType: updateType, Filter: proto.Clone(filter).(*management.Filter)})
	if !exists && m.onFilterChange != nil {
		m.onFilterChange()
	}
	resultErr := errors.Join(saveErr, distributionErr, err)
	if resultErr != nil {
		resultErr = &securestore.CommitError{Outcome: securestore.Committed, Op: "publish filter policy", Err: resultErr}
	}
	return proto.Clone(filter).(*management.Filter), count, resultErr
}

// Delete persists the complete detached candidate before publishing deletion.
// Deleted RADIUS revision watermarks remain process-local, as before.
func (m *Manager) Delete(filterID string) (uint32, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := m.ensureInitialized(); err != nil {
		return 0, err
	}
	m.mu.RLock()
	filter, exists := m.filters[filterID]
	if !exists {
		m.mu.RUnlock()
		return 0, ErrFilterNotFound
	}
	candidate := cloneFilterMap(m.filters)
	m.mu.RUnlock()
	delete(candidate, filterID)
	committed, saveErr := m.persistCandidate(candidate)
	if !committed {
		return 0, saveErr
	}
	m.mu.Lock()
	m.filters = candidate
	m.initialized = true
	m.mu.Unlock()
	count, err := m.pushFilterUpdate(filter, &management.FilterUpdate{UpdateType: management.FilterUpdateType_UPDATE_DELETE, Filter: proto.Clone(filter).(*management.Filter)})
	if m.onFilterChange != nil {
		m.onFilterChange()
	}
	resultErr := errors.Join(saveErr, err)
	if resultErr != nil {
		resultErr = &securestore.CommitError{Outcome: securestore.Committed, Op: "publish filter deletion", Err: resultErr}
	}
	return count, resultErr
}

// SubscribeSnapshot atomically captures policy and attaches the live stream.
// mutationMu ensures no committed mutation can be queued before its snapshot.
func (m *Manager) SubscribeSnapshot(hunterID string) (chan *management.FilterUpdate, []*management.Filter) {
	ch, snapshot, _ := m.SubscribeSnapshotE(hunterID)
	return ch, snapshot
}

// SubscribeSnapshotE additionally exposes failed startup/fault state to network
// handlers so no empty authoritative snapshot is sent after a storage failure.
func (m *Manager) SubscribeSnapshotE(hunterID string) (chan *management.FilterUpdate, []*management.Filter, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := m.ensureInitialized(); err != nil {
		ch := make(chan *management.FilterUpdate)
		close(ch)
		return ch, nil, err
	}
	filters := m.GetForHunter(hunterID)
	ch := m.AddChannel(hunterID)
	return ch, filters, nil
}

// AddChannel creates and adds a filter update channel for a hunter
func (m *Manager) AddChannel(hunterID string) chan *management.FilterUpdate {
	ch := make(chan *management.FilterUpdate, constants.FilterUpdateChannelBuffer)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || m.fault != nil {
		close(ch)
		return ch
	}
	m.channelsMu.Lock()
	if oldCh, exists := m.channels[hunterID]; exists {
		close(oldCh)
	}
	m.channels[hunterID] = ch
	m.channelsMu.Unlock()

	return ch
}

// RemoveChannel removes and closes a filter update channel for a hunter
func (m *Manager) RemoveChannel(hunterID string, ch chan *management.FilterUpdate) {
	m.channelsMu.Lock()
	if storedCh, exists := m.channels[hunterID]; exists && storedCh == ch {
		delete(m.channels, hunterID)
		close(storedCh)
	}
	m.channelsMu.Unlock()
}

// getHuntersToRemove finds connected hunters that could receive the old filter
// but cannot receive its replacement because of target scope or capability.
func (m *Manager) getHuntersToRemove(oldFilter, newFilter *management.Filter) []string {
	m.channelsMu.RLock()
	defer m.channelsMu.RUnlock()

	targetsHunter := func(filter *management.Filter, hunterID string) bool {
		if len(filter.TargetHunters) == 0 {
			return true
		}
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				return true
			}
		}
		return false
	}

	var huntersToRemove []string
	for hunterID := range m.channels {
		if !targetsHunter(oldFilter, hunterID) {
			continue
		}
		var caps *management.HunterCapabilities
		if m.capabilityProvider != nil {
			caps = m.capabilityProvider.GetCapabilities(hunterID)
		}
		if !hunterSupportsFilterType(caps, oldFilter.Type) {
			continue
		}
		if !targetsHunter(newFilter, hunterID) || !hunterSupportsFilterType(caps, newFilter.Type) {
			huntersToRemove = append(huntersToRemove, hunterID)
		}
	}
	return huntersToRemove
}

// pushFilterUpdateToSpecificHunters sends filter update to a specific list of hunters
func (m *Manager) pushFilterUpdateToSpecificHunters(hunterIDs []string, update *management.FilterUpdate) (uint32, error) {
	m.channelsMu.RLock()
	// A missed policy update invalidates the stream. Remove it after releasing
	// the read lock, using channel identity so reconnect replacements survive.
	failedChannels := make(map[string]chan *management.FilterUpdate)
	defer func() {
		m.channelsMu.RUnlock()
		for id, ch := range failedChannels {
			m.RemoveChannel(id, ch)
		}
	}()

	var huntersUpdated uint32
	const sendTimeout = 2 * time.Second

	// Helper to send with timeout and track failures
	sendUpdate := func(hunterID string, ch chan *management.FilterUpdate) bool {
		timer := time.NewTimer(sendTimeout)
		defer timer.Stop()

		select {
		case ch <- update:
			// Success - reset failure counter
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, false)
			}
			logger.Debug("Sent filter update", "hunter_id", hunterID, "update_type", update.UpdateType)
			return true

		case <-timer.C:
			failedChannels[hunterID] = ch
			// Timeout - track failure
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, true)
			}

			logger.Warn("Filter update send timeout",
				"hunter_id", hunterID,
				"update_type", update.UpdateType)
			return false
		}
	}

	// Send to specific hunters
	for _, hunterID := range hunterIDs {
		if ch, exists := m.channels[hunterID]; exists {
			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
	}

	return huntersUpdated, distributionFailure(len(failedChannels))
}

// pushFilterUpdate sends filter update to affected hunters
func (m *Manager) pushFilterUpdate(filter *management.Filter, update *management.FilterUpdate) (uint32, error) {
	m.channelsMu.RLock()
	// A missed policy update invalidates the stream. Remove it after releasing
	// the read lock, using channel identity so reconnect replacements survive.
	failedChannels := make(map[string]chan *management.FilterUpdate)
	defer func() {
		m.channelsMu.RUnlock()
		for id, ch := range failedChannels {
			m.RemoveChannel(id, ch)
		}
	}()

	var huntersUpdated uint32
	const sendTimeout = 2 * time.Second
	const maxConsecutiveFailures = 5
	const circuitBreakerThreshold = 10 // Disconnect after this many failures

	// Helper to send with timeout and track failures
	sendUpdate := func(hunterID string, ch chan *management.FilterUpdate) bool {
		timer := time.NewTimer(sendTimeout)
		defer timer.Stop()

		select {
		case ch <- update:
			// Success - reset failure counter
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, false)
			}
			logger.Debug("Sent filter update", "hunter_id", hunterID)
			return true

		case <-timer.C:
			failedChannels[hunterID] = ch
			// Timeout - track failure
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, true)
			}

			// Get failure count to determine logging level
			// Note: This is a bit circular since we're calling back to hunter manager
			// but it's acceptable for logging purposes
			logger.Warn("Filter update send timeout",
				"hunter_id", hunterID)
			return false
		}
	}

	// If no target hunters specified, send to all COMPATIBLE hunters
	if len(filter.TargetHunters) == 0 {
		for hunterID, ch := range m.channels {
			// Check if hunter supports this filter type
			var hunterCaps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				hunterCaps = m.capabilityProvider.GetCapabilities(hunterID)
			}

			if !hunterSupportsFilterType(hunterCaps, filter.Type) {
				logger.Debug("Skipping filter update for incompatible hunter",
					"hunter_id", hunterID,
					"filter_type", filter.Type)
				continue
			}

			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
		return huntersUpdated, distributionFailure(len(failedChannels))
	}

	// Send to specific hunters (still check capabilities)
	for _, targetID := range filter.TargetHunters {
		if ch, exists := m.channels[targetID]; exists {
			// Check if hunter supports this filter type
			var hunterCaps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				hunterCaps = m.capabilityProvider.GetCapabilities(targetID)
			}

			if !hunterSupportsFilterType(hunterCaps, filter.Type) {
				logger.Warn("Skipping filter update for targeted but incompatible hunter",
					"hunter_id", targetID,
					"filter_type", filter.Type)
				continue
			}

			if sendUpdate(targetID, ch) {
				huntersUpdated++
			}
		}
	}

	return huntersUpdated, distributionFailure(len(failedChannels))
}

// Count returns the total number of filters
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.filters)
}

// GetAll returns all filters
func (m *Manager) GetAll() []*management.Filter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filters := make([]*management.Filter, 0, len(m.filters))
	for _, filter := range m.filters {
		filters = append(filters, proto.Clone(filter).(*management.Filter))
	}
	return filters
}

func distributionFailure(failed int) error {
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d subscriber streams disconnected", ErrFilterDistribution, failed)
}
