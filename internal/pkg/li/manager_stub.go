//go:build !li

// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
//
// This file provides stub implementations when built without the "li" tag.
// All methods are no-ops that indicate LI is not available.
package li

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// ErrLINotAvailable is returned when LI operations are attempted
// but lippycat was built without LI support.
var ErrLINotAvailable = errors.New("LI support not available: rebuild with -tags li")

// ManagerConfig holds configuration for the LI Manager.
type ManagerConfig struct {
	Enabled      bool
	X1ListenAddr string
	ADMFEndpoint string
	FilterPusher FilterPusher
}

// PacketProcessor is the callback for processing matched packets.
type PacketProcessor func(task *InterceptTask, pkt *types.PacketDisplay)

// Manager is a stub that does nothing when LI is not compiled in.
type Manager struct{}

// ManagerStats contains LI processing statistics.
type ManagerStats struct {
	PacketsProcessed uint64
	PacketsMatched   uint64
	X2EventsSent     uint64
	X3EventsSent     uint64
	MatchErrors      uint64
}

// NewManager returns a stub manager when LI is not available.
func NewManager(_ ManagerConfig, _ DeactivationCallback) *Manager {
	return &Manager{}
}

// Start is a no-op in stub mode.
func (m *Manager) Start() error {
	return nil
}

// Stop is a no-op in stub mode.
func (m *Manager) Stop() {}

// SetPacketProcessor is a no-op in stub mode.
func (m *Manager) SetPacketProcessor(_ PacketProcessor) {}

// ProcessPacket is a no-op in stub mode.
func (m *Manager) ProcessPacket(_ *types.PacketDisplay, _ []string) {}

// ActivateTask returns an error indicating LI is not available.
func (m *Manager) ActivateTask(_ *InterceptTask) error {
	return ErrLINotAvailable
}

// ModifyTask returns an error indicating LI is not available.
func (m *Manager) ModifyTask(_ uuid.UUID, _ *TaskModification) error {
	return ErrLINotAvailable
}

// DeactivateTask returns an error indicating LI is not available.
func (m *Manager) DeactivateTask(_ uuid.UUID) error {
	return ErrLINotAvailable
}

// GetTaskDetails returns an error indicating LI is not available.
func (m *Manager) GetTaskDetails(_ uuid.UUID) (*InterceptTask, error) {
	return nil, ErrLINotAvailable
}

// GetActiveTasks returns nil when LI is not available.
func (m *Manager) GetActiveTasks() []*InterceptTask {
	return nil
}

// CreateDestination returns an error indicating LI is not available.
func (m *Manager) CreateDestination(_ *Destination) error {
	return ErrLINotAvailable
}

// GetDestination returns an error indicating LI is not available.
func (m *Manager) GetDestination(_ uuid.UUID) (*Destination, error) {
	return nil, ErrLINotAvailable
}

// RemoveDestination returns an error indicating LI is not available.
func (m *Manager) RemoveDestination(_ uuid.UUID) error {
	return ErrLINotAvailable
}

// Stats returns zero stats when LI is not available.
func (m *Manager) Stats() ManagerStats {
	return ManagerStats{}
}

// TaskCount returns 0 when LI is not available.
func (m *Manager) TaskCount() int {
	return 0
}

// ActiveTaskCount returns 0 when LI is not available.
func (m *Manager) ActiveTaskCount() int {
	return 0
}

// FilterCount returns 0 when LI is not available.
func (m *Manager) FilterCount() int {
	return 0
}

// IsEnabled returns false when LI is not available.
func (m *Manager) IsEnabled() bool {
	return false
}

// Config returns the manager configuration.
func (m *Manager) Config() ManagerConfig {
	return ManagerConfig{}
}

// MarkTaskFailed returns an error indicating LI is not available.
func (m *Manager) MarkTaskFailed(_ uuid.UUID, _ string) error {
	return ErrLINotAvailable
}

// PurgeDeactivatedTasks returns 0 when LI is not available.
func (m *Manager) PurgeDeactivatedTasks(_ time.Duration) int {
	return 0
}
