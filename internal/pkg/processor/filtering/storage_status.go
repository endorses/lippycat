package filtering

import "github.com/endorses/lippycat/internal/pkg/securestore"

// StorageStatus never takes mutationMu or a persistence owner's I/O lock.
func (m *Manager) StorageStatus() securestore.StorageStatus {
	status := securestore.StorageStatus{Mode: "disabled", State: "ready"}
	if provider, ok := m.persistence.(interface {
		StorageStatus() securestore.StorageStatus
	}); ok {
		status = provider.StorageStatus()
	} else if m.persistence != nil {
		status.Mode, status.State = "unknown", "unopened"
	}
	m.mu.RLock()
	status.AdmissionBlocked = m.closed || m.fault != nil || !m.initialized || status.State == "faulted"
	if m.fault != nil {
		status.PolicyFaultCode = "reconciliation_required"
	}
	m.mu.RUnlock()
	return status
}
