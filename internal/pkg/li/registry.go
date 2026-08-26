// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Registry errors matching ETSI X1 error semantics.
var (
	// ErrTaskNotFound indicates the requested task XID does not exist.
	ErrTaskNotFound = errors.New("task not found")
	// ErrTaskAlreadyExists indicates a task with the given XID already exists.
	ErrTaskAlreadyExists = errors.New("task already exists")
	// ErrTaskNotActive indicates the operation requires an active task.
	ErrTaskNotActive = errors.New("task is not active")
	// ErrInvalidTask indicates the task parameters are invalid.
	ErrInvalidTask = errors.New("invalid task parameters")
	// ErrModifyNotAllowed indicates the requested modification is not permitted.
	ErrModifyNotAllowed = errors.New("modification not allowed")
	// ErrDestinationNotFound indicates the requested destination DID does not exist.
	ErrDestinationNotFound = errors.New("destination not found")
	// ErrDestinationAlreadyExists indicates a destination with the given DID already exists.
	ErrDestinationAlreadyExists = errors.New("destination already exists")
)

// DeactivationReason indicates why a task was deactivated.
type DeactivationReason int

const (
	// DeactivationReasonADMF indicates deactivation by explicit ADMF request.
	DeactivationReasonADMF DeactivationReason = iota
	// DeactivationReasonExpired indicates implicit deactivation due to EndTime.
	DeactivationReasonExpired
	// DeactivationReasonFault indicates deactivation due to a terminating fault.
	DeactivationReasonFault
)

// String returns the string representation of DeactivationReason.
func (r DeactivationReason) String() string {
	switch r {
	case DeactivationReasonADMF:
		return "ADMF"
	case DeactivationReasonExpired:
		return "Expired"
	case DeactivationReasonFault:
		return "Fault"
	default:
		return "Unknown"
	}
}

// DeactivationCallback is called when a task is implicitly deactivated.
// This allows the registry to notify the X1 client to send status to ADMF.
type DeactivationCallback func(task *InterceptTask, reason DeactivationReason)

// TaskModification specifies which fields to modify in a task.
// nil values indicate no change; non-nil values indicate the new value.
type TaskModification struct {
	// Targets replaces the target list if non-nil.
	Targets *[]TargetIdentity
	// DestinationIDs replaces the destination list if non-nil.
	DestinationIDs *[]uuid.UUID
	// DeliveryType changes the delivery type if non-nil.
	DeliveryType *DeliveryType
	// EndTime changes the end time if non-nil.
	EndTime *time.Time
	// ImplicitDeactivationAllowed changes the implicit deactivation flag if non-nil.
	ImplicitDeactivationAllowed *bool
}

// Registry provides thread-safe storage and management of intercept tasks.
//
// The registry implements task lifecycle management per ETSI TS 103 221-1:
//   - Tasks can be activated, modified, and deactivated via ADMF requests
//   - Implicit deactivation (EndTime expiration) is handled if allowed
//   - All state changes are thread-safe
type Registry struct {
	mu           sync.RWMutex
	tasks        map[uuid.UUID]*InterceptTask
	destinations map[uuid.UUID]*Destination
	auditHistory map[uuid.UUID][]InterceptTask
	rollbackTask map[uuid.UUID]*InterceptTask
	generations  map[uuid.UUID]uint64

	// onDeactivation is called when a task is implicitly deactivated.
	onDeactivation DeactivationCallback

	// expirationTicker controls the implicit deactivation check interval.
	expirationTicker *time.Ticker
	stopChan         chan struct{}
	wg               sync.WaitGroup
}

// NewRegistry creates a new task registry.
//
// The deactivationCallback is called when a task is implicitly deactivated
// (e.g., EndTime expiration). Pass nil if no callback is needed.
func NewRegistry(deactivationCallback DeactivationCallback) *Registry {
	r := &Registry{
		tasks:          make(map[uuid.UUID]*InterceptTask),
		destinations:   make(map[uuid.UUID]*Destination),
		auditHistory:   make(map[uuid.UUID][]InterceptTask),
		rollbackTask:   make(map[uuid.UUID]*InterceptTask),
		generations:    make(map[uuid.UUID]uint64),
		onDeactivation: deactivationCallback,
		stopChan:       make(chan struct{}),
	}
	return r
}

// Start begins background task lifecycle management.
// This includes checking for tasks that should be implicitly deactivated.
func (r *Registry) Start() {
	r.expirationTicker = time.NewTicker(time.Second)
	r.wg.Add(1)
	go r.runExpirationChecker()
}

// Stop halts background task lifecycle management.
func (r *Registry) Stop() {
	if r.expirationTicker != nil {
		r.expirationTicker.Stop()
	}
	close(r.stopChan)
	r.wg.Wait()
}

// runExpirationChecker periodically checks for expired tasks.
func (r *Registry) runExpirationChecker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.stopChan:
			return
		case <-r.expirationTicker.C:
			r.checkExpiredTasks()
		}
	}
}

// checkExpiredTasks deactivates tasks that have reached their EndTime.
func (r *Registry) checkExpiredTasks() {
	r.mu.Lock()
	now := time.Now()
	var expired []*InterceptTask
	for _, task := range r.tasks {
		if task.Status != TaskStatusActive && task.Status != TaskStatusSuspended {
			continue
		}
		if !task.ImplicitDeactivationAllowed {
			continue
		}
		if task.EndTime.IsZero() {
			continue
		}
		if !now.Before(task.EndTime) {
			task.Status = TaskStatusSuspended // enforcement gate while filters withdraw
			taskCopy := *task
			expired = append(expired, &taskCopy)
		}
	}
	r.mu.Unlock()
	for _, task := range expired {
		if r.onDeactivation != nil {
			r.onDeactivation(task, DeactivationReasonExpired)
		}
		// Manager callbacks normally complete this after enforcement withdrawal;
		// a plain registry callback has no enforcement layer, so finalize here.
		_ = r.finishExpiration(task.XID)
	}
}

func (r *Registry) finishExpiration(xid uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, ok := r.tasks[xid]
	if !ok {
		return fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}
	if task.Status == TaskStatusDeactivated {
		return nil
	}
	if task.Status != TaskStatusSuspended {
		return fmt.Errorf("%w: task status is %s", ErrTaskNotActive, task.Status)
	}
	task.Status = TaskStatusDeactivated
	task.DeactivatedAt = time.Now()
	return nil
}

func (r *Registry) promotePending(xid uuid.UUID, activatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, ok := r.tasks[xid]
	if !ok {
		return fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}
	if !task.ActivatedAt.Equal(activatedAt) || task.Status != TaskStatusPending {
		return fmt.Errorf("%w: pending task changed", ErrTaskNotActive)
	}
	task.Status = TaskStatusActive
	return nil
}

// ActivateTask adds and activates a new intercept task.
//
// Per ETSI TS 103 221-1, task activation:
//   - Validates the task parameters
//   - Registers the task in the registry
//   - Marks the task as active (or pending if StartTime is in the future)
//
// Returns ErrTaskAlreadyExists if a task with the same XID exists.
// Returns ErrInvalidTask if the task parameters are invalid.
func (r *Registry) ActivateTask(task *InterceptTask) error {
	if err := r.validateTask(task); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, exists := r.tasks[task.XID]; exists {
		if existing.Status != TaskStatusDeactivated {
			return fmt.Errorf("%w: XID %s is %s", ErrTaskAlreadyExists, task.XID, existing.Status)
		}
		previous := *existing
		previous.Targets = append([]TargetIdentity(nil), existing.Targets...)
		previous.DestinationIDs = append([]uuid.UUID(nil), existing.DestinationIDs...)
		r.rollbackTask[task.XID] = &previous
		r.auditHistory[task.XID] = append(r.auditHistory[task.XID], previous)
	}

	// Validate destination IDs exist
	for _, did := range task.DestinationIDs {
		destination, exists := r.destinations[did]
		if !exists {
			return fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
		}
		if err := validateDestinationDelivery(task.DeliveryType, destination); err != nil {
			return err
		}
	}

	// Create a copy to store
	taskCopy := *task
	taskCopy.ActivatedAt = time.Now()
	r.generations[task.XID]++
	taskCopy.ActivationGeneration = r.generations[task.XID]

	// Determine initial status
	if taskCopy.ShouldStart() {
		taskCopy.Status = TaskStatusActive
	} else {
		taskCopy.Status = TaskStatusPending
	}

	r.tasks[task.XID] = &taskCopy
	return nil
}

// restorePendingTask restores durable state without installing enforcement.
func (r *Registry) restorePendingTask(task *InterceptTask) error {
	if err := r.validateTask(task); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if task.Status != TaskStatusPending {
		return fmt.Errorf("restore pending task %s: status is %s", task.XID, task.Status)
	}
	if _, exists := r.tasks[task.XID]; exists {
		return fmt.Errorf("%w: XID %s", ErrTaskAlreadyExists, task.XID)
	}
	for _, did := range task.DestinationIDs {
		if _, ok := r.destinations[did]; !ok {
			return fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
		}
	}
	copyTask := *task
	copyTask.Targets = append([]TargetIdentity(nil), task.Targets...)
	copyTask.DestinationIDs = append([]uuid.UUID(nil), task.DestinationIDs...)
	r.tasks[task.XID] = &copyTask
	if r.generations[task.XID] < task.ActivationGeneration {
		r.generations[task.XID] = task.ActivationGeneration
	}
	return nil
}

func (r *Registry) restoreDestination(dest *Destination) error {
	if dest == nil {
		return fmt.Errorf("restore destination: nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	copyDest := *dest
	r.destinations[dest.DID] = &copyDest
	return nil
}

func (r *Registry) seedGeneration(xid uuid.UUID, generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation > r.generations[xid] {
		r.generations[xid] = generation
	}
}

// rollbackActivation removes precisely the registry entry created by an
// activation that has not committed its enforcement. activatedAt is the
// activation identity, preventing a stale rollback from removing another task.
func (r *Registry) rollbackActivation(xid uuid.UUID, activatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, exists := r.tasks[xid]
	if !exists {
		return fmt.Errorf("rollback activation: %w: XID %s", ErrTaskNotFound, xid)
	}
	if !task.ActivatedAt.Equal(activatedAt) || (task.Status != TaskStatusActive && task.Status != TaskStatusPending) {
		return fmt.Errorf("rollback activation for XID %s: registry entry no longer belongs to this activation", xid)
	}
	if previous := r.rollbackTask[xid]; previous != nil {
		r.tasks[xid] = previous
		delete(r.rollbackTask, xid)
		history := r.auditHistory[xid]
		if len(history) > 0 {
			r.auditHistory[xid] = history[:len(history)-1]
		}
	} else {
		delete(r.tasks, xid)
	}
	return nil
}

func (r *Registry) commitActivation(xid uuid.UUID, activatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, ok := r.tasks[xid]
	if !ok || !task.ActivatedAt.Equal(activatedAt) {
		return fmt.Errorf("commit activation for XID %s: registry entry changed", xid)
	}
	delete(r.rollbackTask, xid)
	return nil
}

func (r *Registry) restoreTask(task *InterceptTask) error {
	if task == nil {
		return fmt.Errorf("restore task: task is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.tasks[task.XID]
	if !exists || !current.ActivatedAt.Equal(task.ActivatedAt) {
		return fmt.Errorf("restore task XID %s: registry entry changed concurrently", task.XID)
	}
	copyTask := *task
	copyTask.Targets = append([]TargetIdentity(nil), task.Targets...)
	copyTask.DestinationIDs = append([]uuid.UUID(nil), task.DestinationIDs...)
	r.tasks[task.XID] = &copyTask
	return nil
}

// ModifyTask updates an existing task's parameters atomically.
//
// Per ETSI TS 103 221-1, task modification:
//   - Must be atomic: all changes succeed or none do
//   - Certain fields may not be modifiable depending on task state
//   - Returns error if any requested modification is not allowed
//
// Modifiable fields (when task is active):
//   - Targets: Always modifiable
//   - DestinationIDs: Always modifiable
//   - DeliveryType: Always modifiable
//   - EndTime: Always modifiable
//   - ImplicitDeactivationAllowed: Always modifiable
//
// Non-modifiable fields:
//   - XID: Never modifiable (identity)
//   - StartTime: Not modifiable after activation
func (r *Registry) ModifyTask(xid uuid.UUID, mod *TaskModification) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[xid]
	if !exists {
		return fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}

	// Validate the modification is allowed
	if err := r.validateModification(task, mod); err != nil {
		return err
	}

	// Validate the complete prospective definition before changing the live
	// task. This prevents a later invalid field from leaving earlier fields
	// partially applied.
	candidate := *task
	candidate.Targets = append([]TargetIdentity(nil), task.Targets...)
	candidate.DestinationIDs = append([]uuid.UUID(nil), task.DestinationIDs...)
	if mod.Targets != nil {
		candidate.Targets = append([]TargetIdentity(nil), (*mod.Targets)...)
	}
	if mod.DestinationIDs != nil {
		candidate.DestinationIDs = append([]uuid.UUID(nil), (*mod.DestinationIDs)...)
	}
	if mod.DeliveryType != nil {
		candidate.DeliveryType = *mod.DeliveryType
	}
	if mod.EndTime != nil {
		candidate.EndTime = *mod.EndTime
	}
	if mod.ImplicitDeactivationAllowed != nil {
		candidate.ImplicitDeactivationAllowed = *mod.ImplicitDeactivationAllowed
	}
	if err := r.validateTask(&candidate); err != nil {
		return err
	}
	for _, did := range candidate.DestinationIDs {
		destination, exists := r.destinations[did]
		if !exists {
			return fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
		}
		if err := validateDestinationDelivery(candidate.DeliveryType, destination); err != nil {
			return err
		}
	}

	// Apply modifications atomically
	if mod.Targets != nil {
		task.Targets = candidate.Targets
	}

	if mod.DestinationIDs != nil {
		task.DestinationIDs = candidate.DestinationIDs
	}

	if mod.DeliveryType != nil {
		task.DeliveryType = *mod.DeliveryType
	}

	if mod.EndTime != nil {
		task.EndTime = *mod.EndTime
	}

	if mod.ImplicitDeactivationAllowed != nil {
		task.ImplicitDeactivationAllowed = *mod.ImplicitDeactivationAllowed
	}

	return nil
}

func validateDestinationDelivery(deliveryType DeliveryType, destination *Destination) error {
	if destination == nil {
		return fmt.Errorf("%w: destination is nil", ErrUnsupportedDeliveryCombination)
	}
	// Destinations created by older internal APIs did not carry capability
	// metadata. X1-created destinations always set ProtocolType, so enforce the
	// declared interface capabilities without breaking restored legacy state.
	if destination.ProtocolType == "" {
		return nil
	}
	requiresX2 := deliveryType == DeliveryX2Only || deliveryType == DeliveryX2andX3
	requiresX3 := deliveryType == DeliveryX3Only || deliveryType == DeliveryX2andX3
	if (requiresX2 && !destination.X2Enabled) || (requiresX3 && !destination.X3Enabled) {
		return fmt.Errorf("%w: DID %s cannot provide %s", ErrUnsupportedDeliveryCombination, destination.DID, deliveryType)
	}
	return nil
}

// validateModification checks if the requested modification is allowed.
func (r *Registry) validateModification(task *InterceptTask, mod *TaskModification) error {
	if mod == nil {
		return fmt.Errorf("%w: modification is nil", ErrInvalidTask)
	}
	// Task must be active or pending to be modified
	if task.Status != TaskStatusActive && task.Status != TaskStatusPending {
		return fmt.Errorf("%w: task status is %s", ErrModifyNotAllowed, task.Status)
	}

	// Validate delivery type if specified
	if mod.DeliveryType != nil {
		dt := *mod.DeliveryType
		if dt != DeliveryX2Only && dt != DeliveryX3Only && dt != DeliveryX2andX3 {
			return fmt.Errorf("%w: invalid delivery type %d", ErrInvalidTask, dt)
		}
	}
	if mod.EndTime != nil && !mod.EndTime.IsZero() {
		start := task.StartTime
		if start.IsZero() {
			start = time.Now()
		}
		if !mod.EndTime.After(start) {
			return fmt.Errorf("%w: EndTime must be after StartTime and in the future", ErrInvalidTask)
		}
	}

	return nil
}

// DeactivateTask removes a task from active interception.
//
// Per ETSI TS 103 221-1:
//   - The task transitions to Deactivated status
//   - The task remains in the registry for audit purposes
//   - Returns ErrTaskNotFound if the task doesn't exist
func (r *Registry) DeactivateTask(xid uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[xid]
	if !exists {
		return fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}

	if task.Status == TaskStatusDeactivated {
		// Already deactivated, idempotent success
		return nil
	}

	task.Status = TaskStatusDeactivated
	task.DeactivatedAt = time.Now()

	// Notify callback for explicit ADMF deactivation
	if r.onDeactivation != nil {
		taskCopy := *task
		r.mu.Unlock()
		r.onDeactivation(&taskCopy, DeactivationReasonADMF)
		r.mu.Lock()
	}

	return nil
}

// GetTaskDetails retrieves a task by its XID.
//
// Returns a copy of the task to prevent external modification.
// Returns ErrTaskNotFound if the task doesn't exist.
func (r *Registry) GetTaskDetails(xid uuid.UUID) (*InterceptTask, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	task, exists := r.tasks[xid]
	if !exists {
		return nil, fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}

	// Return a copy to prevent external modification
	taskCopy := *task
	// Deep copy slices
	if task.Targets != nil {
		taskCopy.Targets = make([]TargetIdentity, len(task.Targets))
		copy(taskCopy.Targets, task.Targets)
	}
	if task.DestinationIDs != nil {
		taskCopy.DestinationIDs = make([]uuid.UUID, len(task.DestinationIDs))
		copy(taskCopy.DestinationIDs, task.DestinationIDs)
	}

	return &taskCopy, nil
}

// ListTasks iterates over all tasks in the registry.
//
// The callback receives a copy of each task. Return false to stop iteration.
// This is an internal operation with no ETSI X1 equivalent.
func (r *Registry) ListTasks(fn func(task *InterceptTask) bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, task := range r.tasks {
		taskCopy := *task
		if !fn(&taskCopy) {
			return
		}
	}
}

// GetActiveTasks returns a slice of all active tasks.
//
// Returns copies of tasks to prevent external modification.
func (r *Registry) GetActiveTasks() []*InterceptTask {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var active []*InterceptTask
	for _, task := range r.tasks {
		if task.Status == TaskStatusActive {
			taskCopy := *task
			active = append(active, &taskCopy)
		}
	}
	return active
}

// TaskCount returns the total number of tasks in the registry.
func (r *Registry) TaskCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tasks)
}

// ActiveTaskCount returns the number of active tasks.
func (r *Registry) ActiveTaskCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, task := range r.tasks {
		if task.Status == TaskStatusActive {
			count++
		}
	}
	return count
}

// validateTask validates task parameters before activation.
func (r *Registry) validateTask(task *InterceptTask) error {
	if task == nil {
		return fmt.Errorf("%w: task is nil", ErrInvalidTask)
	}

	if task.XID == uuid.Nil {
		return fmt.Errorf("%w: XID is nil", ErrInvalidTask)
	}

	if len(task.Targets) == 0 {
		return fmt.Errorf("%w: no targets specified", ErrInvalidTask)
	}

	for i, target := range task.Targets {
		if target.Value == "" {
			return fmt.Errorf("%w: target %d has empty value", ErrInvalidTask, i)
		}
		if target.Type == 0 {
			return fmt.Errorf("%w: target %d has invalid type", ErrInvalidTask, i)
		}
	}

	if len(task.DestinationIDs) == 0 {
		return fmt.Errorf("%w: no destinations specified", ErrInvalidTask)
	}

	if task.DeliveryType != DeliveryX2Only &&
		task.DeliveryType != DeliveryX3Only &&
		task.DeliveryType != DeliveryX2andX3 {
		return fmt.Errorf("%w: invalid delivery type %d", ErrInvalidTask, task.DeliveryType)
	}
	for _, target := range task.Targets {
		switch target.Type {
		case TargetTypeIPv4Address, TargetTypeIPv4CIDR, TargetTypeIPv6Address, TargetTypeIPv6CIDR:
			if task.DeliveryType == DeliveryX2Only {
				return fmt.Errorf("%w: %s targets require X3 raw-packet delivery", ErrUnsupportedDeliveryCombination, target.Type)
			}
		case TargetTypeSIPURI, TargetTypeTELURI, TargetTypeNAI, TargetTypeUsername, TargetTypeIMSI, TargetTypeIMEI:
		default:
			return fmt.Errorf("%w: target type %d has no encoder", ErrUnsupportedDeliveryCombination, target.Type)
		}
	}
	if !task.EndTime.IsZero() {
		start := task.StartTime
		if start.IsZero() {
			start = time.Now()
		}
		if !task.EndTime.After(start) {
			return fmt.Errorf("%w: EndTime must be after StartTime and in the future", ErrInvalidTask)
		}
	}

	return nil
}

// CreateDestination adds a new delivery destination.
//
// Returns ErrDestinationAlreadyExists if a destination with the same DID exists.
func (r *Registry) CreateDestination(dest *Destination) error {
	if dest == nil {
		return fmt.Errorf("%w: destination is nil", ErrInvalidTask)
	}
	if dest.DID == uuid.Nil {
		return fmt.Errorf("%w: DID is nil", ErrInvalidTask)
	}
	if dest.Address == "" {
		return fmt.Errorf("%w: address is empty", ErrInvalidTask)
	}
	if dest.Port <= 0 || dest.Port > 65535 {
		return fmt.Errorf("%w: invalid port %d", ErrInvalidTask, dest.Port)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.destinations[dest.DID]; exists {
		return fmt.Errorf("%w: DID %s", ErrDestinationAlreadyExists, dest.DID)
	}

	// Create a copy to store
	destCopy := *dest
	destCopy.CreatedAt = time.Now()
	r.destinations[dest.DID] = &destCopy

	return nil
}

// GetDestination retrieves a destination by its DID.
//
// Returns a copy of the destination to prevent external modification.
// Returns ErrDestinationNotFound if the destination doesn't exist.
func (r *Registry) GetDestination(did uuid.UUID) (*Destination, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dest, exists := r.destinations[did]
	if !exists {
		return nil, fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
	}

	// Return a copy (note: TLSConfig is a pointer, not deep copied)
	destCopy := *dest
	return &destCopy, nil
}

// RemoveDestination removes a delivery destination.
//
// Returns ErrDestinationNotFound if the destination doesn't exist.
// Note: This does not check if the destination is in use by tasks.
func (r *Registry) RemoveDestination(did uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.destinations[did]; !exists {
		return fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
	}

	delete(r.destinations, did)
	return nil
}

// ModifyDestination updates an existing delivery destination.
//
// Returns ErrDestinationNotFound if the destination doesn't exist.
func (r *Registry) ModifyDestination(did uuid.UUID, dest *Destination) error {
	if dest == nil {
		return fmt.Errorf("%w: destination is nil", ErrInvalidTask)
	}
	if dest.DID != did {
		return fmt.Errorf("%w: DID mismatch", ErrInvalidTask)
	}
	if dest.Address == "" {
		return fmt.Errorf("%w: address is empty", ErrInvalidTask)
	}
	if dest.Port <= 0 || dest.Port > 65535 {
		return fmt.Errorf("%w: invalid port %d", ErrInvalidTask, dest.Port)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.destinations[did]; !exists {
		return fmt.Errorf("%w: DID %s", ErrDestinationNotFound, did)
	}

	// Update the destination (preserving CreatedAt)
	existing := r.destinations[did]
	dest.CreatedAt = existing.CreatedAt
	r.destinations[did] = dest

	return nil
}

// DestinationCount returns the total number of destinations.
func (r *Registry) DestinationCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.destinations)
}

// MarkTaskFailed marks a task as failed with an error message.
//
// This is used when a terminating fault prevents continued interception.
func (r *Registry) MarkTaskFailed(xid uuid.UUID, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[xid]
	if !exists {
		return fmt.Errorf("%w: XID %s", ErrTaskNotFound, xid)
	}

	task.Status = TaskStatusFailed
	task.DeactivatedAt = time.Now()
	task.LastError = errMsg

	// Notify callback for fault deactivation
	if r.onDeactivation != nil {
		taskCopy := *task
		r.mu.Unlock()
		r.onDeactivation(&taskCopy, DeactivationReasonFault)
		r.mu.Lock()
	}

	return nil
}

// PurgeDeactivatedTasks removes tasks that have been deactivated for the
// specified duration. This is for housekeeping, not ETSI mandated.
func (r *Registry) PurgeDeactivatedTasks(olderThan time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	count := 0

	for xid, task := range r.tasks {
		if task.Status == TaskStatusDeactivated || task.Status == TaskStatusFailed {
			if !task.DeactivatedAt.IsZero() && task.DeactivatedAt.Before(cutoff) {
				delete(r.tasks, xid)
				count++
			}
		}
	}

	return count
}
