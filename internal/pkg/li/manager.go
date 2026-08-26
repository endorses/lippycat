//go:build li

// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// X1ClientConfig holds configuration for the X1 client (ADMF notifications).
// These are separate from X1ServerConfig used for the X1 server.
type X1ClientConfig struct {
	// TLSCertFile is the path to the client TLS certificate for mutual TLS with ADMF.
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate for ADMF server verification.
	TLSCAFile string

	// KeepaliveInterval is the interval for sending keepalive messages to ADMF.
	// Set to 0 to disable keepalive.
	KeepaliveInterval time.Duration
}

// ManagerConfig holds configuration for the LI Manager.
type ManagerConfig struct {
	// Enabled controls whether LI processing is active.
	Enabled bool

	// X1ListenAddr is the address for the X1 administration interface.
	// Format: "host:port" (e.g., "0.0.0.0:8443")
	X1ListenAddr string

	// X1TLSCertFile is the path to the X1 server TLS certificate.
	X1TLSCertFile string

	// X1TLSKeyFile is the path to the X1 server TLS key.
	X1TLSKeyFile string

	// X1TLSCAFile is the path to the CA certificate for X1 client verification (mutual TLS).
	X1TLSCAFile string

	// ADMFEndpoint is the address of the ADMF for X1 notifications.
	// Format: "https://host:port"
	ADMFEndpoint string

	// NEIdentifier is the network element identifier for X1 responses.
	// Defaults to hostname if empty.
	NEIdentifier string

	// X1Client contains configuration for the X1 client (ADMF notifications).
	X1Client X1ClientConfig

	// FilterPusher integrates with the processor's filter management system.
	FilterPusher FilterPusher

	// SyncOnStartup enables querying the ADMF for task/destination state on startup.
	// When true, the manager will call GetAllDetails to restore state after restart.
	SyncOnStartup bool

	// SyncTimeout is the timeout for the startup state sync operation.
	// Defaults to 30s if zero.
	SyncTimeout time.Duration

	// ReconcileInterval is the interval for periodic state reconciliation with ADMF.
	// Set to 0 to disable periodic reconciliation.
	ReconcileInterval time.Duration

	// ReconcileOrphanPolls is how many consecutive reconciliation polls must
	// agree a task is gone from the ADMF before it is torn down. Defaults to
	// defaultReconcileOrphanPolls.
	ReconcileOrphanPolls int

	// TombstoneRetention controls operational retention of deactivated tasks.
	// Zero uses 24 hours. Audit logging remains independent of this registry data.
	TombstoneRetention time.Duration
	// LifecycleInterval controls pending promotion and tombstone maintenance.
	// Zero uses 100 milliseconds.
	LifecycleInterval time.Duration

	// StateFile enables atomic local lifecycle persistence. Empty disables it.
	StateFile string
}

// defaultReconcileOrphanPolls trades one reconcile interval of over-collection
// for immunity to single-poll flukes.
const defaultReconcileOrphanPolls = 2

// PacketProcessor is the callback for processing matched packets.
// Called when a packet matches an active intercept task.
type PacketProcessor func(task *InterceptTask, pkt *types.PacketDisplay)

// Manager coordinates all LI components.
//
// It aggregates:
//   - Registry: task and destination storage
//   - FilterManager: XID-to-filter mapping
//   - X1Server: administration interface for ADMF communication
//   - X1Client: ADMF notification sender (keepalive, error reports)
//   - (Future) DestinationManager: X2/X3 delivery connections
//
// The Manager is the main entry point for LI operations in the processor.
type Manager struct {
	mu          sync.RWMutex
	lifecycleMu sync.Mutex

	config   ManagerConfig
	registry *Registry
	filters  *FilterManager

	// x1Client sends notifications to ADMF.
	x1Client *x1.Client

	// x1Server is the X1 administration interface server.
	x1Server *x1.Server

	// x1ServerCtx controls the X1 server lifecycle.
	x1ServerCtx    context.Context
	x1ServerCancel context.CancelFunc

	// onPacketMatch is called when a packet matches an intercept task.
	// This allows the processor to handle X2/X3 delivery.
	onPacketMatch atomic.Pointer[packetProcessorHolder]

	// onDestinationCreated is called when a new destination is created via X1.
	// This allows the processor to bridge destinations to the delivery manager.
	onDestinationCreated  func(dest *Destination)
	onDestinationModified func(dest *Destination)
	onDestinationRemoved  func(did uuid.UUID)

	// stats tracks LI processing statistics.
	stats managerAtomicStats

	// orphanStreak counts consecutive polls in which a local task was absent
	// from the ADMF response.
	orphanMu        sync.Mutex
	orphanStreak    map[uuid.UUID]int
	persistedActive map[uuid.UUID]*InterceptTask

	// stopChan signals shutdown.
	stopChan chan struct{}
	wg       sync.WaitGroup
}

type packetProcessorHolder struct{ fn PacketProcessor }
type managerAtomicStats struct {
	packetsProcessed     atomic.Uint64
	packetsMatched       atomic.Uint64
	x2EventsSent         atomic.Uint64
	x3EventsSent         atomic.Uint64
	matchErrors          atomic.Uint64
	rejectedCombinations atomic.Uint64
}

// ManagerStats contains LI processing statistics.
type ManagerStats struct {
	PacketsProcessed     uint64
	PacketsMatched       uint64
	X2EventsSent         uint64
	X3EventsSent         uint64
	MatchErrors          uint64
	RejectedCombinations uint64
}

// NewManager creates a new LI Manager.
//
// The deactivationCallback is called when a task is implicitly deactivated
// (e.g., EndTime expiration). This is used to notify ADMF via X1.
func NewManager(config ManagerConfig, deactivationCallback DeactivationCallback) *Manager {
	m := &Manager{
		config:          config,
		filters:         NewFilterManager(config.FilterPusher),
		stopChan:        make(chan struct{}),
		orphanStreak:    make(map[uuid.UUID]int),
		persistedActive: make(map[uuid.UUID]*InterceptTask),
	}

	// Create X1 client if ADMF endpoint is configured.
	// This is used to send notifications (keepalive, errors, etc.) to the ADMF.
	if config.ADMFEndpoint != "" {
		x1ClientConfig := x1.ClientConfig{
			ADMFEndpoint:      config.ADMFEndpoint,
			NEIdentifier:      config.NEIdentifier,
			TLSCertFile:       config.X1Client.TLSCertFile,
			TLSKeyFile:        config.X1Client.TLSKeyFile,
			TLSCAFile:         config.X1Client.TLSCAFile,
			KeepaliveInterval: config.X1Client.KeepaliveInterval,
		}

		client, err := x1.NewClient(x1ClientConfig)
		if err != nil {
			logger.Warn("X1 client creation failed, ADMF notifications disabled",
				"error", err,
				"admf_endpoint", config.ADMFEndpoint,
			)
		} else {
			m.x1Client = client
		}
	}

	// Create deactivation callback that reports to ADMF and then calls user callback.
	internalCallback := func(task *InterceptTask, reason DeactivationReason) {
		if reason == DeactivationReasonExpired {
			m.lifecycleMu.Lock()
			if err := m.completeExpiration(task); err != nil {
				logger.Error("LI task expiry enforcement failed", "xid", task.XID, "end_time", task.EndTime, "error", err)
				m.lifecycleMu.Unlock()
				return
			}
			m.lifecycleMu.Unlock()
		}
		// Report implicit deactivation to ADMF via X1 client.
		if m.x1Client != nil && reason != DeactivationReasonADMF {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				reasonStr := reason.String()
				if reason == DeactivationReasonExpired {
					reasonStr = "Task EndTime reached"
				} else if reason == DeactivationReasonFault {
					reasonStr = task.LastError
					if reasonStr == "" {
						reasonStr = "Task terminated due to fault"
					}
				}

				if err := m.x1Client.ReportTaskImplicitDeactivation(ctx, task.XID, reasonStr); err != nil {
					logger.Error("Failed to report implicit deactivation to ADMF",
						"xid", task.XID,
						"reason", reason,
						"error", err,
					)
				}
			}()
		}

		// Call user's callback if provided.
		if deactivationCallback != nil {
			deactivationCallback(task, reason)
		}
	}

	m.registry = NewRegistry(internalCallback)

	// Create X1 server if TLS is configured.
	if config.X1ListenAddr != "" && config.X1TLSCertFile != "" && config.X1TLSKeyFile != "" {
		x1Config := x1.ServerConfig{
			ListenAddr:   config.X1ListenAddr,
			TLSCertFile:  config.X1TLSCertFile,
			TLSKeyFile:   config.X1TLSKeyFile,
			TLSCAFile:    config.X1TLSCAFile,
			NEIdentifier: config.NEIdentifier,
		}
		// Wire ADMF identifier learning: when the server receives a request
		// from the ADMF, pass the identifier to the client for outbound messages.
		if m.x1Client != nil {
			x1Config.OnADMFIdentified = m.x1Client.SetADMFIdentifier
		}
		// Create adapters that implement x1.DestinationManager and x1.TaskManager.
		destAdapter := &managerDestinationAdapter{m: m}
		taskAdapter := &managerTaskAdapter{m: m}
		m.x1Server = x1.NewServer(x1Config, destAdapter, taskAdapter)
	}

	return m
}

// Start begins LI Manager operation.
//
// This starts the registry's expiration checker and any other
// background goroutines needed for LI processing.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		logger.Info("LI Manager disabled")
		return nil
	}
	if err := m.restorePersistedState(); err != nil {
		return fmt.Errorf("restore LI state (interception remains disarmed): %w", err)
	}
	// Verify the configured store is writable before starting any listener or
	// lifecycle goroutine. A persistence fault must fail closed.
	if err := m.persistState(); err != nil {
		return fmt.Errorf("initialize LI state persistence (interception remains disarmed): %w", err)
	}

	// Start the registry's background task management
	m.registry.Start()
	m.wg.Add(1)
	go m.runLifecycleMaintenance()

	// Start X1 server if configured.
	if m.x1Server != nil {
		m.x1ServerCtx, m.x1ServerCancel = context.WithCancel(context.Background())
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := m.x1Server.Start(m.x1ServerCtx); err != nil {
				logger.Error("X1 server error", "error", err)
			}
		}()
		logger.Info("X1 server started", "addr", m.config.X1ListenAddr)
	} else if m.config.X1ListenAddr != "" {
		logger.Warn("X1 server not started: TLS certificate not configured",
			"addr", m.config.X1ListenAddr,
			"hint", "provide --li-x1-tls-cert and --li-x1-tls-key",
		)
	}

	// Start X1 client if configured (for ADMF notifications).
	if m.x1Client != nil {
		m.x1Client.Start()

		// Send startup notification to ADMF.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.x1Client.ReportStartup(ctx); err != nil {
				logger.Warn("Failed to send startup notification to ADMF",
					"error", err,
					"admf", m.config.ADMFEndpoint,
				)
			}
		}()

		logger.Info("X1 client started", "admf_endpoint", m.config.ADMFEndpoint)
	}

	// Sync state from ADMF on startup if configured.
	if m.config.SyncOnStartup && m.x1Client != nil {
		syncTimeout := m.config.SyncTimeout
		if syncTimeout == 0 {
			syncTimeout = 30 * time.Second
		}
		syncCtx, syncCancel := context.WithTimeout(context.Background(), syncTimeout)
		if err := m.syncStateFromADMF(syncCtx); err != nil {
			logger.Warn("ADMF state sync failed, continuing without pre-loaded state",
				"error", err,
				"admf", m.config.ADMFEndpoint,
			)
		}
		syncCancel()
	}

	// Start periodic reconciliation if configured.
	if m.config.ReconcileInterval > 0 && m.x1Client != nil {
		m.wg.Add(1)
		go m.startReconciliation()
	}

	logger.Info("LI Manager started",
		"x1_listen", m.config.X1ListenAddr,
		"admf_endpoint", m.config.ADMFEndpoint,
	)
	return nil
}

// Stop halts LI Manager operation.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Send shutdown notification to ADMF before stopping X1 client.
	if m.x1Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := m.x1Client.ReportShutdown(ctx); err != nil {
			logger.Warn("Failed to send shutdown notification to ADMF",
				"error", err,
				"admf", m.config.ADMFEndpoint,
			)
		}
		cancel()
	}

	// Stop X1 server.
	if m.x1ServerCancel != nil {
		m.x1ServerCancel()
	}
	if m.x1Server != nil {
		if err := m.x1Server.Shutdown(); err != nil {
			logger.Error("X1 server shutdown error", "error", err)
		}
	}

	// Stop X1 client.
	if m.x1Client != nil {
		m.x1Client.Stop()
	}

	close(m.stopChan)
	m.registry.Stop()
	m.wg.Wait()

	logger.Info("LI Manager stopped",
		"packets_processed", m.stats.packetsProcessed.Load(),
		"packets_matched", m.stats.packetsMatched.Load(),
	)
}

// syncStateFromADMF queries the ADMF for all tasks and destinations,
// and restores them into the local registry. This is used on startup
// to recover state after a restart without waiting for ADMF to re-push.
func (m *Manager) syncStateFromADMF(ctx context.Context) error {
	resp, err := m.x1Client.GetAllDetails(ctx)
	if err != nil {
		// If ADMF does not support this operation, log and return nil.
		var admfErr *x1.ADMFError
		if errors.As(err, &admfErr) && admfErr.IsUnsupportedOperation() {
			logger.Warn("ADMF does not support GetAllDetails, skipping state sync",
				"admf", m.config.ADMFEndpoint,
			)
			return nil
		}
		return fmt.Errorf("get all details from ADMF: %w", err)
	}

	var destCount, taskCount int
	var destErrors, taskErrors int
	snapshot := newADMFSnapshot()

	// Register destinations first (tasks reference destinations by DID).
	if resp.ListOfDestinationResponseDetails != nil {
		for _, dd := range resp.ListOfDestinationResponseDetails.DestinationResponseDetails {
			dest, convErr := DestinationResponseDetailsToDestination(dd)
			if convErr != nil {
				logger.Warn("Failed to convert ADMF destination, skipping",
					"error", convErr,
				)
				destErrors++
				snapshot.destinationConvErrors++
				continue
			}
			snapshot.destinations[dest.DID] = true
			if createErr := m.registry.CreateDestination(dest); createErr != nil {
				// Destination may already exist if sync is called multiple times.
				if errors.Is(createErr, ErrDestinationAlreadyExists) {
					current, getErr := m.registry.GetDestination(dest.DID)
					if getErr == nil {
						dest.CreatedAt = current.CreatedAt
						if modifyErr := m.registry.ModifyDestination(dest.DID, dest); modifyErr != nil {
							destErrors++
						}
					}
				} else {
					logger.Warn("Failed to register ADMF destination, skipping",
						"did", dest.DID,
						"error", createErr,
					)
					destErrors++
				}
				continue
			}
			destCount++
		}
	}

	// Activate tasks.
	if resp.ListOfTaskResponseDetails != nil {
		for _, td := range resp.ListOfTaskResponseDetails.TaskResponseDetails {
			task, convErr := TaskResponseDetailsToInterceptTask(td)
			if convErr != nil {
				logger.Warn("Failed to convert ADMF task, skipping",
					"error", convErr,
				)
				taskErrors++
				snapshot.convErrors++
				continue
			}
			snapshot.tasks[task.XID] = true
			if restored := m.persistedActive[task.XID]; restored != nil {
				generation := restored.ActivationGeneration
				if generation > 0 {
					generation-- // ActivateTask increments to the confirmed generation.
				}
				m.registry.seedGeneration(task.XID, generation)
			}
			if activateErr := m.ActivateTask(task); activateErr != nil {
				// Task may already exist if sync is called multiple times.
				if !errors.Is(activateErr, ErrTaskAlreadyExists) {
					logger.Warn("Failed to activate ADMF task, skipping",
						"xid", task.XID,
						"error", activateErr,
					)
					taskErrors++
				}
				continue
			}
			taskCount++
		}
	}

	// The ADMF defines what may be armed. Merging additively lets state that no
	// ADMF ever authorised survive on disk and be re-armed every restart, so
	// drop whatever the ADMF did not return.
	removedTasks := m.removeOrphanedTasks(snapshot, false)
	removedDestinations := m.removeOrphanedDestinations(snapshot)
	removedFilters := m.removeOrphanedLIFilters(snapshot)

	logger.Info("ADMF state sync complete",
		"tasks", taskCount,
		"destinations", destCount,
		"task_errors", taskErrors,
		"destination_errors", destErrors,
		"orphan_tasks_removed", removedTasks,
		"orphan_destinations_removed", removedDestinations,
		"orphan_filters_removed", removedFilters,
	)

	return nil
}

func (m *Manager) removeOrphanedDestinations(snapshot admfSnapshot) int {
	if !snapshot.destinationsComplete() {
		logger.Warn("Reconciliation: incomplete ADMF destination response, skipping removal",
			"conversion_errors", snapshot.destinationConvErrors)
		return 0
	}
	local := m.ListDestinations()
	if len(local) > 0 && len(snapshot.destinations) == 0 {
		logger.Warn("Reconciliation: ADMF returned no destinations while destinations exist locally, keeping them",
			"local_destinations", len(local))
		return 0
	}
	removed := 0
	for _, dest := range local {
		if snapshot.destinations[dest.DID] {
			continue
		}
		if err := m.registry.RemoveDestination(dest.DID); err != nil {
			logger.Error("Reconciliation: failed to remove orphan destination", "did", dest.DID, "error", err)
			continue
		}
		m.mu.RLock()
		cb := m.onDestinationRemoved
		m.mu.RUnlock()
		if cb != nil {
			cb(dest.DID)
		}
		removed++
	}
	return removed
}

// admfSnapshot is one GetAllDetails response: the task XIDs it returned, plus
// how many entries failed conversion.
type admfSnapshot struct {
	tasks                 map[uuid.UUID]bool
	destinations          map[uuid.UUID]bool
	convErrors            int
	destinationConvErrors int
}

func newADMFSnapshot() admfSnapshot {
	return admfSnapshot{tasks: make(map[uuid.UUID]bool), destinations: make(map[uuid.UUID]bool)}
}

// complete reports whether the snapshot can be trusted to say what the ADMF
// does NOT have. A conversion error drops an XID for reasons unrelated to the
// ADMF's intent, so a parsing bug must never deactivate a live warrant.
func (s admfSnapshot) complete() bool { return s.convErrors == 0 }

func (s admfSnapshot) destinationsComplete() bool { return s.destinationConvErrors == 0 }

// removeOrphanedTasks deactivates local tasks the ADMF no longer has, so a lost
// DeactivateTask cannot leave an intercept running without authorisation.
//
// requireStreak makes N consecutive polls agree before acting; startup passes
// false because its local state came off disk and was never ADMF-checked.
// A GetAllDetails failure never reaches here — callers return first.
func (m *Manager) removeOrphanedTasks(snapshot admfSnapshot, requireStreak bool) int {
	if !snapshot.complete() {
		logger.Warn("Reconciliation: incomplete ADMF response, skipping orphan removal",
			"conversion_errors", snapshot.convErrors,
			"admf_tasks", len(snapshot.tasks),
		)
		return 0
	}

	// Collect before deactivating: ListTasks holds the registry read lock for
	// the callback, and DeactivateTask takes the write lock.
	var orphans []uuid.UUID
	var localActive int
	m.registry.ListTasks(func(task *InterceptTask) bool {
		if task.Status != TaskStatusActive && task.Status != TaskStatusPending {
			return true
		}
		localActive++
		if !snapshot.tasks[task.XID] {
			orphans = append(orphans, task.XID)
		}
		return true
	})

	if len(orphans) == 0 {
		m.clearOrphanStreaks()
		return 0
	}

	// The ADMF recovery procedure truncates its tables and re-syncs, answering
	// successfully with zero tasks meanwhile. Never disarm everything on that.
	if len(snapshot.tasks) == 0 {
		logger.Warn("Reconciliation: ADMF returned no tasks while tasks are active locally, "+
			"keeping them (explicit DeactivateTask required to clear the last task)",
			"local_active", localActive,
		)
		return 0
	}

	threshold := 1
	if requireStreak {
		threshold = m.orphanPollThreshold()
	}

	removed := 0
	for _, xid := range m.recordOrphanStreaks(orphans, threshold) {
		// Removing an intercept is auditable; never silent.
		logger.Warn("Reconciliation: deactivating task absent from ADMF",
			"xid", xid,
			"admf_tasks", len(snapshot.tasks),
		)
		if err := m.DeactivateTask(xid); err != nil {
			logger.Error("Reconciliation: failed to deactivate orphaned task",
				"xid", xid,
				"error", err,
			)
			continue
		}
		m.clearOrphanStreak(xid)
		removed++
	}
	return removed
}

// removeOrphanedLIFilters deletes LI filters belonging to no task in the
// snapshot. Startup-only: filters are reloaded from disk before the registry
// exists, so an orphaned filter is armed with no task pointing at it — which is
// what re-armed the stale filter across restarts.
func (m *Manager) removeOrphanedLIFilters(snapshot admfSnapshot) int {
	lister, ok := m.config.FilterPusher.(FilterLister)
	if !ok || !snapshot.complete() {
		return 0
	}

	live := make(map[string]bool, len(snapshot.tasks))
	legacyOwners := make(map[string][]uuid.UUID)
	for xid := range snapshot.tasks {
		live[xid.String()] = true
		prefix := xid.String()[:8]
		legacyOwners[prefix] = append(legacyOwners[prefix], xid)
	}

	var orphans []string
	var migrations []string
	for _, id := range lister.ListFilterIDs() {
		owner, isLI := liFilterXIDPrefix(id)
		if !isLI {
			continue
		}
		if len(owner) == 8 {
			matches := legacyOwners[owner]
			switch len(matches) {
			case 0:
				orphans = append(orphans, id)
			case 1:
				// ActivateTask has installed the canonical replacement already.
				migrations = append(migrations, id)
			default:
				logger.Error("Startup reconciliation: ambiguous legacy LI filter retained; ownership cannot be proven",
					"filter_id", id, "xid_prefix", owner, "candidate_xids", matches)
			}
			continue
		}
		if !live[owner] {
			orphans = append(orphans, id)
		}
	}
	orchans := append(orphans, migrations...)
	if len(orchans) == 0 {
		return 0
	}

	if len(snapshot.tasks) == 0 {
		logger.Warn("Startup reconciliation: ADMF returned no tasks while LI filters are installed, "+
			"keeping them (explicit DeactivateTask required)",
			"li_filters", len(orphans),
		)
		return 0
	}

	removed := 0
	for _, id := range orchans {
		reason := "orphan"
		if slices.Contains(migrations, id) {
			reason = "legacy_migration"
		}
		logger.Warn("Startup reconciliation: removing legacy or orphaned LI filter", "filter_id", id, "reason", reason)
		if err := m.config.FilterPusher.DeleteFilter(id); err != nil {
			logger.Error("Startup reconciliation: failed to remove orphaned LI filter",
				"filter_id", id,
				"error", err,
			)
			continue
		}
		removed++
	}
	return removed
}

func (m *Manager) orphanPollThreshold() int {
	if m.config.ReconcileOrphanPolls > 0 {
		return m.config.ReconcileOrphanPolls
	}
	return defaultReconcileOrphanPolls
}

// recordOrphanStreaks bumps each orphan's consecutive-absence count, resets
// tasks that reappeared, and returns those that have reached threshold.
func (m *Manager) recordOrphanStreaks(orphans []uuid.UUID, threshold int) []uuid.UUID {
	m.orphanMu.Lock()
	defer m.orphanMu.Unlock()

	current := make(map[uuid.UUID]bool, len(orphans))
	for _, xid := range orphans {
		current[xid] = true
	}
	for xid := range m.orphanStreak {
		if !current[xid] {
			delete(m.orphanStreak, xid)
		}
	}

	var due []uuid.UUID
	for _, xid := range orphans {
		m.orphanStreak[xid]++
		if m.orphanStreak[xid] >= threshold {
			due = append(due, xid)
			continue
		}
		logger.Info("Reconciliation: task absent from ADMF, awaiting confirmation",
			"xid", xid,
			"polls", m.orphanStreak[xid],
			"required", threshold,
		)
	}
	return due
}

func (m *Manager) clearOrphanStreaks() {
	m.orphanMu.Lock()
	defer m.orphanMu.Unlock()
	clear(m.orphanStreak)
}

func (m *Manager) clearOrphanStreak(xid uuid.UUID) {
	m.orphanMu.Lock()
	defer m.orphanMu.Unlock()
	delete(m.orphanStreak, xid)
}

// startReconciliation runs periodic state reconciliation with the ADMF.
// It compares local registry state with ADMF state and logs discrepancies.
func (m *Manager) startReconciliation() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.ReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.reconcileWithADMF()
		}
	}
}

// reconcileWithADMF queries the ADMF for current state and compares it
// with the local registry, activating any tasks found in ADMF but missing
// locally. Tasks present locally but not in ADMF are logged as warnings
// but not automatically deactivated (could be a transient ADMF issue).
func (m *Manager) reconcileWithADMF() {
	syncTimeout := m.config.SyncTimeout
	if syncTimeout == 0 {
		syncTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()

	resp, err := m.x1Client.GetAllDetails(ctx)
	if err != nil {
		var admfErr *x1.ADMFError
		if errors.As(err, &admfErr) && admfErr.IsUnsupportedOperation() {
			logger.Debug("ADMF does not support GetAllDetails, skipping reconciliation")
			return
		}
		logger.Warn("ADMF reconciliation failed",
			"error", err,
			"admf", m.config.ADMFEndpoint,
		)
		return
	}

	// Build set of ADMF task XIDs.
	snapshot := newADMFSnapshot()
	if resp.ListOfDestinationResponseDetails != nil {
		for _, dd := range resp.ListOfDestinationResponseDetails.DestinationResponseDetails {
			dest, convErr := DestinationResponseDetailsToDestination(dd)
			if convErr != nil {
				snapshot.destinationConvErrors++
				continue
			}
			snapshot.destinations[dest.DID] = true
			if current, getErr := m.registry.GetDestination(dest.DID); getErr != nil {
				if err := m.registry.CreateDestination(dest); err == nil {
					m.mu.RLock()
					cb := m.onDestinationCreated
					m.mu.RUnlock()
					if cb != nil {
						cb(dest)
					}
				}
			} else if current.Address != dest.Address || current.Port != dest.Port || current.X2Enabled != dest.X2Enabled || current.X3Enabled != dest.X3Enabled || current.ProtocolType != dest.ProtocolType || current.Description != dest.Description {
				dest.CreatedAt = current.CreatedAt
				if err := m.registry.ModifyDestination(dest.DID, dest); err == nil {
					m.mu.RLock()
					cb := m.onDestinationModified
					m.mu.RUnlock()
					if cb != nil {
						cb(dest)
					}
				}
			}
		}
	}
	var activated int
	if resp.ListOfTaskResponseDetails != nil {
		for _, td := range resp.ListOfTaskResponseDetails.TaskResponseDetails {
			task, convErr := TaskResponseDetailsToInterceptTask(td)
			if convErr != nil {
				logger.Warn("Reconciliation: failed to convert ADMF task, skipping",
					"error", convErr,
				)
				snapshot.convErrors++
				continue
			}
			snapshot.tasks[task.XID] = true

			// If task is in ADMF but not in local registry, activate it.
			if _, getErr := m.registry.GetTaskDetails(task.XID); getErr != nil {
				// Register any missing destinations first.
				if resp.ListOfDestinationResponseDetails != nil {
					for _, dd := range resp.ListOfDestinationResponseDetails.DestinationResponseDetails {
						dest, destErr := DestinationResponseDetailsToDestination(dd)
						if destErr != nil {
							continue
						}
						_ = m.registry.CreateDestination(dest) // Ignore already-exists
					}
				}

				if activateErr := m.ActivateTask(task); activateErr != nil {
					logger.Warn("Reconciliation: failed to activate missing task",
						"xid", task.XID,
						"error", activateErr,
					)
				} else {
					activated++
					logger.Info("Reconciliation: activated missing task from ADMF",
						"xid", task.XID,
					)
				}
			}
		}
	}

	// Tear down tasks the ADMF no longer has, rather than only warning: an
	// intercept the ADMF has dropped is running without authorisation.
	deactivated := m.removeOrphanedTasks(snapshot, true)
	removedDestinations := m.removeOrphanedDestinations(snapshot)
	if err := m.persistState(); err != nil {
		logger.Error("Reconciliation: persist LI state failed", "error", err)
	}

	if activated > 0 || deactivated > 0 || removedDestinations > 0 {
		logger.Info("ADMF reconciliation complete",
			"activated", activated,
			"deactivated", deactivated,
			"destinations_removed", removedDestinations,
			"admf_tasks", len(snapshot.tasks),
		)
	} else {
		logger.Debug("ADMF reconciliation complete, no discrepancies",
			"admf_tasks", len(snapshot.tasks),
		)
	}
}

// SetPacketProcessor sets the callback for matched packets.
//
// This is called by the processor to handle X2/X3 delivery.
func (m *Manager) SetPacketProcessor(processor PacketProcessor) {
	if processor == nil {
		m.onPacketMatch.Store(nil)
		return
	}
	m.onPacketMatch.Store(&packetProcessorHolder{fn: processor})
}

// SetDestinationCreatedCallback sets a callback invoked when destinations are created via X1.
func (m *Manager) SetDestinationCreatedCallback(cb func(dest *Destination)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDestinationCreated = cb
}

// SetDestinationModifiedCallback sets a callback invoked when destinations are modified via X1.
func (m *Manager) SetDestinationModifiedCallback(cb func(dest *Destination)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDestinationModified = cb
}

// SetDestinationRemovedCallback sets a callback invoked when destinations are removed via X1.
func (m *Manager) SetDestinationRemovedCallback(cb func(did uuid.UUID)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDestinationRemoved = cb
}

// ProcessPacket processes a packet that has already been matched by the
// filter infrastructure.
//
// This is called by the processor when a packet matches one or more filters.
// The matchedFilterIDs come from lippycat's existing optimized filter system
// (IP hash map, PhoneNumberMatcher, SIP URI Aho-Corasick) - the LI Manager
// does NOT do its own matching.
//
// Flow:
//  1. Hunter matches packet using optimized filters (Phase 0 infrastructure)
//  2. Processor receives packet with matched filter IDs
//  3. ProcessPacket looks up which XIDs those filter IDs belong to
//  4. PacketProcessor callback is invoked for X2/X3 delivery
func (m *Manager) ProcessPacket(pkt *types.PacketDisplay, matchedFilterIDs []string) {
	if pkt == nil || len(matchedFilterIDs) == 0 {
		return
	}

	if !m.config.Enabled {
		return
	}

	// Update stats
	m.stats.packetsProcessed.Add(1)

	// Look up which LI tasks these filter IDs belong to
	matches := m.filters.LookupMatches(matchedFilterIDs)
	if len(matches) == 0 {
		return
	}

	// Update match stats and get processor
	m.stats.packetsMatched.Add(1)
	holder := m.onPacketMatch.Load()

	if holder == nil {
		return
	}
	processor := holder.fn

	// For each matching task, invoke the packet processor
	for _, match := range matches {
		task, err := m.registry.GetTaskDetails(match.XID)
		if err != nil {
			// Task may have been deactivated between match and lookup
			m.stats.matchErrors.Add(1)
			continue
		}

		if !task.IsActive() {
			continue
		}

		processor(task, pkt)
	}
}

// ActivateTask adds and activates a new intercept task.
//
// This creates filters for the task's targets and pushes them
// to the filter management system.
func (m *Manager) ActivateTask(task *InterceptTask) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.activateTask(task)
}

func (m *Manager) activateTask(task *InterceptTask) error {
	if task == nil {
		return fmt.Errorf("%w: task is nil", ErrInvalidTask)
	}
	isReactivation := false
	var previousGeneration uint64
	if existing, err := m.registry.GetTaskDetails(task.XID); err == nil {
		switch existing.Status {
		case TaskStatusActive, TaskStatusPending:
			if equivalentTaskDefinition(existing, task) {
				// A retry is deliberately a pure read: do not bump the generation,
				// reinstall filters, move a pending boundary, or persist state.
				return nil
			}
			return fmt.Errorf("%w: XID %s is %s", ErrTaskDefinitionConflict, task.XID, existing.Status)
		case TaskStatusSuspended, TaskStatusFailed:
			return fmt.Errorf("%w: XID %s is %s", ErrTaskDefinitionConflict, task.XID, existing.Status)
		case TaskStatusDeactivated:
			if !equivalentReactivationIdentity(existing, task) {
				return fmt.Errorf("%w: XID %s", ErrReactivationIdentityConflict, task.XID)
			}
			isReactivation = true
			previousGeneration = existing.ActivationGeneration
		default:
			return fmt.Errorf("%w: XID %s has unknown status %d", ErrTaskDefinitionConflict, task.XID, existing.Status)
		}
	} else if !errors.Is(err, ErrTaskNotFound) {
		return fmt.Errorf("check activation retry for XID %s: %w", task.XID, err)
	}

	// First activate in registry (validates task)
	if err := m.registry.ActivateTask(task); err != nil {
		if errors.Is(err, ErrUnsupportedDeliveryCombination) {
			m.stats.rejectedCombinations.Add(1)
		}
		return err
	}

	// Create filters for the task
	registered, getErr := m.registry.GetTaskDetails(task.XID)
	if getErr != nil {
		return fmt.Errorf("read activation identity for XID %s: %w", task.XID, getErr)
	}
	if registered.Status == TaskStatusPending {
		if err := m.registry.commitActivation(task.XID, registered.ActivatedAt); err != nil {
			return err
		}
		logTaskActivation(isReactivation, registered, previousGeneration, 0)
		return m.persistState()
	}
	filterIDs, err := m.filters.CreateFiltersForTask(registered)
	if err != nil {
		rollbackErr := m.registry.rollbackActivation(task.XID, registered.ActivatedAt)
		return errors.Join(fmt.Errorf("activate XID %s: %w", task.XID, err), rollbackErr)
	}
	if err := m.registry.commitActivation(task.XID, registered.ActivatedAt); err != nil {
		return errors.Join(fmt.Errorf("commit activation XID %s: %w", task.XID, err),
			m.filters.RemoveFiltersForTask(task.XID), m.registry.rollbackActivation(task.XID, registered.ActivatedAt))
	}

	logTaskActivation(isReactivation, registered, previousGeneration, len(filterIDs))
	return m.persistState()
}

func logTaskActivation(reactivation bool, task *InterceptTask, previousGeneration uint64, filterCount int) {
	operation := "activation"
	message := "LI task activated"
	if reactivation {
		operation = "reactivation"
		message = "LI task reactivated"
	} else if task.Status == TaskStatusPending {
		message = "LI task registered pending"
	}
	logger.Info(message,
		"operation", operation,
		"xid", task.XID,
		"previous_generation", previousGeneration,
		"new_generation", task.ActivationGeneration,
		"state", task.Status.String(),
		"destinations", len(task.DestinationIDs),
		"filters", filterCount,
	)
}

func (m *Manager) completeExpiration(task *InterceptTask) error {
	filterIDs := m.filters.GetFiltersForXID(task.XID)
	if err := m.filters.RemoveFiltersForTask(task.XID); err != nil {
		return fmt.Errorf("withdraw %d filters: %w", len(filterIDs), err)
	}
	if err := m.registry.finishExpiration(task.XID); err != nil {
		return err
	}
	logger.Info("LI task expired", "xid", task.XID, "end_time", task.EndTime, "filters", len(filterIDs), "cleanup", "complete")
	return m.persistState()
}

// ModifyTask updates an existing task's parameters atomically.
func (m *Manager) ModifyTask(xid uuid.UUID, mod *TaskModification) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	previous, err := m.registry.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	// First modify in registry
	if err := m.registry.ModifyTask(xid, mod); err != nil {
		return err
	}

	// If targets changed, update filters
	if mod.Targets != nil && previous.Status == TaskStatusActive {
		task, err := m.registry.GetTaskDetails(xid)
		if err != nil {
			return err
		}
		if err := m.filters.UpdateFiltersForTask(task); err != nil {
			var cleanupErr *FilterCleanupError
			if errors.As(err, &cleanupErr) {
				markErr := m.registry.MarkTaskFailed(xid, err.Error())
				return errors.Join(fmt.Errorf("modify XID %s filter enforcement degraded: %w", xid, err), markErr)
			}
			return errors.Join(fmt.Errorf("modify XID %s filter enforcement: %w", xid, err), m.registry.restoreTask(previous))
		}
	}

	logger.Info("LI task modified", "xid", xid)
	return m.persistState()
}

// DeactivateTask removes a task from active interception.
func (m *Manager) DeactivateTask(xid uuid.UUID) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.deactivateTask(xid)
}

func (m *Manager) deactivateTask(xid uuid.UUID) error {
	// Remove filters first
	if err := m.filters.RemoveFiltersForTask(xid); err != nil {
		logger.Error("Failed to remove filters for task",
			"xid", xid,
			"error", err,
		)
		return err
	}

	// Then deactivate in registry
	if err := m.registry.DeactivateTask(xid); err != nil {
		return err
	}

	logger.Info("LI task deactivated", "xid", xid)
	return m.persistState()
}

func (m *Manager) runLifecycleMaintenance() {
	defer m.wg.Done()
	interval := m.config.LifecycleInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	retention := m.config.TombstoneRetention
	if retention <= 0 {
		retention = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.promotePendingTasks()
			m.registry.PurgeDeactivatedTasks(retention)
		}
	}
}

func (m *Manager) promotePendingTasks() {
	var pending []*InterceptTask
	m.registry.ListTasks(func(task *InterceptTask) bool {
		if task.Status == TaskStatusPending && task.ShouldStart() {
			pending = append(pending, task)
		}
		return true
	})
	for _, task := range pending {
		m.lifecycleMu.Lock()
		current, err := m.registry.GetTaskDetails(task.XID)
		if err == nil && current.Status == TaskStatusPending && current.ActivatedAt.Equal(task.ActivatedAt) {
			var filterIDs []string
			filterIDs, err = m.filters.CreateFiltersForTask(current)
			if err == nil {
				err = m.registry.promotePending(current.XID, current.ActivatedAt)
			}
			if err != nil {
				if cleanupErr := m.filters.RemoveFiltersForTask(current.XID); cleanupErr != nil {
					err = errors.Join(err, cleanupErr)
				}
				if markErr := m.registry.MarkTaskFailed(current.XID, err.Error()); markErr != nil {
					err = errors.Join(err, markErr)
				}
				logger.Error("LI pending task promotion failed", "xid", current.XID, "error", err)
			} else {
				logger.Info("LI pending task promoted", "xid", current.XID, "filters", len(filterIDs), "start_time", current.StartTime)
			}
		}
		m.lifecycleMu.Unlock()
	}
	if err := m.persistState(); err != nil {
		logger.Error("Persist LI lifecycle state failed", "error", err)
	}
}

// GetTaskDetails retrieves a task by its XID.
func (m *Manager) GetTaskDetails(xid uuid.UUID) (*InterceptTask, error) {
	return m.registry.GetTaskDetails(xid)
}

// GetActiveTasks returns all active intercept tasks.
func (m *Manager) GetActiveTasks() []*InterceptTask {
	return m.registry.GetActiveTasks()
}

// CreateDestination adds a new X2/X3 delivery destination.
func (m *Manager) CreateDestination(dest *Destination) error {
	if err := m.registry.CreateDestination(dest); err != nil {
		return err
	}
	return m.persistState()
}

// GetDestination retrieves a destination by its DID.
func (m *Manager) GetDestination(did uuid.UUID) (*Destination, error) {
	return m.registry.GetDestination(did)
}

// RemoveDestination removes a delivery destination.
func (m *Manager) RemoveDestination(did uuid.UUID) error {
	if err := m.registry.RemoveDestination(did); err != nil {
		return err
	}
	return m.persistState()
}

// ModifyDestination updates an existing delivery destination.
func (m *Manager) ModifyDestination(did uuid.UUID, dest *Destination) error {
	if err := m.registry.ModifyDestination(did, dest); err != nil {
		return err
	}
	return m.persistState()
}

// ListDestinations returns all registered destinations.
func (m *Manager) ListDestinations() []*Destination {
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()
	dests := make([]*Destination, 0, len(m.registry.destinations))
	for _, d := range m.registry.destinations {
		dests = append(dests, d)
	}
	return dests
}

// managerDestinationAdapter adapts the Manager to the x1.DestinationManager interface.
type managerDestinationAdapter struct {
	m *Manager
}

// Ensure managerDestinationAdapter implements x1.DestinationManager.
var _ x1.DestinationManager = (*managerDestinationAdapter)(nil)

// CreateDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) CreateDestination(dest *x1.Destination) error {
	return a.m.CreateDestinationX1(dest)
}

// GetDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) GetDestination(did uuid.UUID) (*x1.Destination, error) {
	return a.m.GetDestinationX1(did)
}

// RemoveDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) RemoveDestination(did uuid.UUID) error {
	return a.m.RemoveDestinationX1(did)
}

// ModifyDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) ModifyDestination(did uuid.UUID, dest *x1.Destination) error {
	return a.m.ModifyDestinationX1(did, dest)
}

// The following methods are the actual implementation,
// adapting between x1.Destination and li.Destination types.

// CreateDestinationX1 creates a destination from X1 request data.
func (m *Manager) CreateDestinationX1(dest *x1.Destination) error {
	liDest := &Destination{
		DID:          dest.DID,
		Address:      dest.Address,
		Port:         dest.Port,
		X2Enabled:    dest.X2Enabled,
		X3Enabled:    dest.X3Enabled,
		ProtocolType: dest.ProtocolType,
		Description:  dest.Description,
	}
	err := m.registry.CreateDestination(liDest)
	if err != nil {
		// Convert to x1 error type
		if errors.Is(err, ErrDestinationAlreadyExists) {
			return x1.ErrDestinationAlreadyExists
		}
		return err
	}

	// Notify delivery manager about new destination
	m.mu.RLock()
	cb := m.onDestinationCreated
	m.mu.RUnlock()
	if cb != nil {
		cb(liDest)
	}
	return m.persistState()
}

// GetDestinationX1 retrieves a destination for X1 response.
func (m *Manager) GetDestinationX1(did uuid.UUID) (*x1.Destination, error) {
	liDest, err := m.registry.GetDestination(did)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return nil, x1.ErrDestinationNotFound
		}
		return nil, err
	}
	return &x1.Destination{
		DID:          liDest.DID,
		Address:      liDest.Address,
		Port:         liDest.Port,
		X2Enabled:    liDest.X2Enabled,
		X3Enabled:    liDest.X3Enabled,
		ProtocolType: liDest.ProtocolType,
		Description:  liDest.Description,
	}, nil
}

// RemoveDestinationX1 removes a destination via X1 request.
func (m *Manager) RemoveDestinationX1(did uuid.UUID) error {
	err := m.registry.RemoveDestination(did)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
		return err
	}
	m.mu.RLock()
	cb := m.onDestinationRemoved
	m.mu.RUnlock()
	if cb != nil {
		cb(did)
	}
	return m.persistState()
}

// ModifyDestinationX1 modifies a destination via X1 request.
func (m *Manager) ModifyDestinationX1(did uuid.UUID, dest *x1.Destination) error {
	liDest := &Destination{
		DID:          dest.DID,
		Address:      dest.Address,
		Port:         dest.Port,
		X2Enabled:    dest.X2Enabled,
		X3Enabled:    dest.X3Enabled,
		ProtocolType: dest.ProtocolType,
		Description:  dest.Description,
	}
	err := m.registry.ModifyDestination(did, liDest)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
		return err
	}
	m.mu.RLock()
	cb := m.onDestinationModified
	m.mu.RUnlock()
	if cb != nil {
		cb(liDest)
	}
	return m.persistState()
}

// managerTaskAdapter adapts the Manager to the x1.TaskManager interface.
type managerTaskAdapter struct {
	m *Manager
}

// Ensure managerTaskAdapter implements x1.TaskManager.
var _ x1.TaskManager = (*managerTaskAdapter)(nil)

// ActivateTask implements x1.TaskManager.
func (a *managerTaskAdapter) ActivateTask(task *x1.Task) error {
	return a.m.ActivateTaskX1(task)
}

// DeactivateTask implements x1.TaskManager.
func (a *managerTaskAdapter) DeactivateTask(xid uuid.UUID) error {
	return a.m.DeactivateTaskX1(xid)
}

// ModifyTask implements x1.TaskManager.
func (a *managerTaskAdapter) ModifyTask(xid uuid.UUID, mod *x1.TaskModification) error {
	return a.m.ModifyTaskX1(xid, mod)
}

// GetTaskDetails implements x1.TaskManager.
func (a *managerTaskAdapter) GetTaskDetails(xid uuid.UUID) (*x1.Task, error) {
	return a.m.GetTaskDetailsX1(xid)
}

// The following methods are the actual implementation,
// adapting between x1.Task and li.InterceptTask types.

// ActivateTaskX1 activates a task from X1 request data.
func (m *Manager) ActivateTaskX1(task *x1.Task) error {
	// Convert x1.Task to li.InterceptTask
	liTask := &InterceptTask{
		XID:                         task.XID,
		DestinationIDs:              task.DestinationIDs,
		StartTime:                   task.StartTime,
		EndTime:                     task.EndTime,
		ImplicitDeactivationAllowed: task.ImplicitDeactivationAllowed,
	}

	// Convert targets
	for _, t := range task.Targets {
		liTask.Targets = append(liTask.Targets, TargetIdentity{
			Type:  convertTargetType(t.Type),
			Value: t.Value,
		})
	}

	// Convert delivery type
	liTask.DeliveryType = convertDeliveryType(task.DeliveryType)

	err := m.ActivateTask(liTask)
	if err != nil {
		// Convert to x1 error types
		if errors.Is(err, ErrReactivationIdentityConflict) {
			return fmt.Errorf("%w: %v", x1.ErrReactivationIdentityConflict, err)
		}
		if errors.Is(err, ErrTaskDefinitionConflict) {
			return fmt.Errorf("%w: %v", x1.ErrTaskDefinitionConflict, err)
		}
		if errors.Is(err, ErrTaskAlreadyExists) {
			return x1.ErrTaskAlreadyExists
		}
		if errors.Is(err, ErrInvalidTask) {
			return x1.ErrInvalidTask
		}
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
		if errors.Is(err, ErrUnsupportedDeliveryCombination) {
			return fmt.Errorf("%w: %v", x1.ErrUnsupportedDeliveryCombination, err)
		}
	}
	return err
}

// DeactivateTaskX1 deactivates a task via X1 request.
func (m *Manager) DeactivateTaskX1(xid uuid.UUID) error {
	err := m.DeactivateTask(xid)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return x1.ErrTaskNotFound
		}
	}
	return err
}

// ModifyTaskX1 modifies a task via X1 request.
func (m *Manager) ModifyTaskX1(xid uuid.UUID, mod *x1.TaskModification) error {
	// Convert x1.TaskModification to li.TaskModification
	liMod := &TaskModification{
		DestinationIDs:              mod.DestinationIDs,
		EndTime:                     mod.EndTime,
		ImplicitDeactivationAllowed: mod.ImplicitDeactivationAllowed,
	}

	// Convert targets if provided
	if mod.Targets != nil {
		targets := make([]TargetIdentity, len(*mod.Targets))
		for i, t := range *mod.Targets {
			targets[i] = TargetIdentity{
				Type:  convertTargetType(t.Type),
				Value: t.Value,
			}
		}
		liMod.Targets = &targets
	}

	// Convert delivery type if provided
	if mod.DeliveryType != nil {
		dt := convertDeliveryType(*mod.DeliveryType)
		liMod.DeliveryType = &dt
	}

	err := m.ModifyTask(xid, liMod)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return x1.ErrTaskNotFound
		}
		if errors.Is(err, ErrModifyNotAllowed) {
			return x1.ErrModifyNotAllowed
		}
		if errors.Is(err, ErrInvalidTask) {
			return x1.ErrInvalidTask
		}
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
		if errors.Is(err, ErrUnsupportedDeliveryCombination) {
			return fmt.Errorf("%w: %v", x1.ErrUnsupportedDeliveryCombination, err)
		}
	}
	return err
}

// GetTaskDetailsX1 retrieves a task for X1 response.
func (m *Manager) GetTaskDetailsX1(xid uuid.UUID) (*x1.Task, error) {
	liTask, err := m.GetTaskDetails(xid)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return nil, x1.ErrTaskNotFound
		}
		return nil, err
	}

	// Convert li.InterceptTask to x1.Task
	task := &x1.Task{
		XID:                         liTask.XID,
		DestinationIDs:              liTask.DestinationIDs,
		StartTime:                   liTask.StartTime,
		EndTime:                     liTask.EndTime,
		ImplicitDeactivationAllowed: liTask.ImplicitDeactivationAllowed,
		Status:                      convertTaskStatusToX1(liTask.Status),
		ActivatedAt:                 liTask.ActivatedAt,
		LastError:                   liTask.LastError,
	}

	// Convert targets
	for _, t := range liTask.Targets {
		task.Targets = append(task.Targets, x1.TargetIdentity{
			Type:  convertTargetTypeToX1(t.Type),
			Value: t.Value,
		})
	}

	// Convert delivery type
	task.DeliveryType = convertDeliveryTypeToX1(liTask.DeliveryType)

	return task, nil
}

// convertTargetType converts x1.TargetType to li.TargetType.
func convertTargetType(t x1.TargetType) TargetType {
	switch t {
	case x1.TargetTypeSIPURI:
		return TargetTypeSIPURI
	case x1.TargetTypeTELURI:
		return TargetTypeTELURI
	case x1.TargetTypeIPv4Address:
		return TargetTypeIPv4Address
	case x1.TargetTypeIPv4CIDR:
		return TargetTypeIPv4CIDR
	case x1.TargetTypeIPv6Address:
		return TargetTypeIPv6Address
	case x1.TargetTypeIPv6CIDR:
		return TargetTypeIPv6CIDR
	case x1.TargetTypeNAI:
		return TargetTypeNAI
	case x1.TargetTypeE164:
		return TargetTypeTELURI // E.164 is essentially TEL URI without prefix
	default:
		return TargetTypeSIPURI // Default to SIPURI
	}
}

// convertTargetTypeToX1 converts li.TargetType to x1.TargetType.
func convertTargetTypeToX1(t TargetType) x1.TargetType {
	switch t {
	case TargetTypeSIPURI:
		return x1.TargetTypeSIPURI
	case TargetTypeTELURI:
		return x1.TargetTypeTELURI
	case TargetTypeIPv4Address:
		return x1.TargetTypeIPv4Address
	case TargetTypeIPv4CIDR:
		return x1.TargetTypeIPv4CIDR
	case TargetTypeIPv6Address:
		return x1.TargetTypeIPv6Address
	case TargetTypeIPv6CIDR:
		return x1.TargetTypeIPv6CIDR
	case TargetTypeNAI:
		return x1.TargetTypeNAI
	default:
		return x1.TargetTypeSIPURI
	}
}

// convertDeliveryType converts x1.DeliveryType to li.DeliveryType.
func convertDeliveryType(dt x1.DeliveryType) DeliveryType {
	switch dt {
	case x1.DeliveryX2Only:
		return DeliveryX2Only
	case x1.DeliveryX3Only:
		return DeliveryX3Only
	case x1.DeliveryX2andX3:
		return DeliveryX2andX3
	default:
		return DeliveryX2andX3
	}
}

// convertDeliveryTypeToX1 converts li.DeliveryType to x1.DeliveryType.
func convertDeliveryTypeToX1(dt DeliveryType) x1.DeliveryType {
	switch dt {
	case DeliveryX2Only:
		return x1.DeliveryX2Only
	case DeliveryX3Only:
		return x1.DeliveryX3Only
	case DeliveryX2andX3:
		return x1.DeliveryX2andX3
	default:
		return x1.DeliveryX2andX3
	}
}

// convertTaskStatusToX1 converts li.TaskStatus to x1.TaskStatus.
func convertTaskStatusToX1(s TaskStatus) x1.TaskStatus {
	switch s {
	case TaskStatusPending:
		return x1.TaskStatusPending
	case TaskStatusActive:
		return x1.TaskStatusActive
	case TaskStatusSuspended:
		return x1.TaskStatusSuspended
	case TaskStatusDeactivated:
		return x1.TaskStatusDeactivated
	case TaskStatusFailed:
		return x1.TaskStatusFailed
	default:
		return x1.TaskStatusPending
	}
}

// Stats returns current LI processing statistics.
func (m *Manager) Stats() ManagerStats {
	return ManagerStats{
		PacketsProcessed:     m.stats.packetsProcessed.Load(),
		PacketsMatched:       m.stats.packetsMatched.Load(),
		X2EventsSent:         m.stats.x2EventsSent.Load(),
		X3EventsSent:         m.stats.x3EventsSent.Load(),
		MatchErrors:          m.stats.matchErrors.Load(),
		RejectedCombinations: m.stats.rejectedCombinations.Load(),
	}
}

// TaskCount returns the total number of tasks.
func (m *Manager) TaskCount() int {
	return m.registry.TaskCount()
}

// ActiveTaskCount returns the number of active tasks.
func (m *Manager) ActiveTaskCount() int {
	return m.registry.ActiveTaskCount()
}

// FilterCount returns the total number of LI filters.
func (m *Manager) FilterCount() int {
	return m.filters.FilterCount()
}

// IsEnabled returns whether LI processing is enabled.
func (m *Manager) IsEnabled() bool {
	return m.config.Enabled
}

// Config returns the manager configuration.
func (m *Manager) Config() ManagerConfig {
	return m.config
}

// MarkTaskFailed marks a task as failed with an error message.
func (m *Manager) MarkTaskFailed(xid uuid.UUID, errMsg string) error {
	// Remove filters
	if err := m.filters.RemoveFiltersForTask(xid); err != nil {
		logger.Error("Failed to remove filters for failed task",
			"xid", xid,
			"error", err,
		)
	}

	if err := m.registry.MarkTaskFailed(xid, errMsg); err != nil {
		return err
	}
	return m.persistState()
}

// PurgeDeactivatedTasks removes old deactivated tasks.
func (m *Manager) PurgeDeactivatedTasks(olderThan time.Duration) int {
	return m.registry.PurgeDeactivatedTasks(olderThan)
}

// ReportTaskError reports a task execution error to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportTaskError(xid uuid.UUID, errorCode int, details string) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportTaskError(ctx, xid, errorCode, details); err != nil {
			logger.Error("Failed to report task error to ADMF",
				"xid", xid,
				"error_code", errorCode,
				"error", err,
			)
		}
	}()
}

// ReportDeliveryError reports an X2/X3 delivery error to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportDeliveryError(did uuid.UUID, errorCode int, details string) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportDeliveryError(ctx, did, errorCode, details); err != nil {
			logger.Error("Failed to report delivery error to ADMF",
				"did", did,
				"error_code", errorCode,
				"error", err,
			)
		}
	}()
}

// ReportDeliveryRecovered reports that X2/X3 delivery has recovered to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportDeliveryRecovered(did uuid.UUID) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportDeliveryRecovered(ctx, did); err != nil {
			logger.Error("Failed to report delivery recovered to ADMF",
				"did", did,
				"error", err,
			)
		}
	}()
}

// X1ClientStats returns the X1 client statistics.
// Returns zero values if X1 client is not configured.
func (m *Manager) X1ClientStats() x1.ClientStats {
	if m.x1Client == nil {
		return x1.ClientStats{}
	}
	return m.x1Client.Stats()
}

// IsADMFConnected returns whether the X1 client is connected to ADMF.
// Returns false if X1 client is not configured.
func (m *Manager) IsADMFConnected() bool {
	if m.x1Client == nil {
		return false
	}
	return m.x1Client.IsConnected()
}
