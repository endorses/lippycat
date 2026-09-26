//go:build li

package li

import "github.com/endorses/lippycat/internal/pkg/securestore"

// AdministrativeStorageStatus reads only immutable/atomic diagnostic views;
// administrative transactions and store fsync cannot block collection.
func (m *Manager) AdministrativeStorageStatus() securestore.StorageStatus {
	status := securestore.StorageStatus{Mode: "disabled", State: "ready"}
	if owner := m.stateTelemetry.Load(); owner != nil {
		status = owner.StorageStatus()
	} else if m.config.StateFile != "" {
		status.Mode, status.State = "encrypted", "unopened"
	}
	status.AdmissionBlocked = !m.administrativeAdmissionReady()
	if m.stateFault.Load() != nil {
		status.PolicyFaultCode = "reconciliation_required"
	}
	return status
}
