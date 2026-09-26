//go:build li

package li

import (
	"errors"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// Keyring returns the immutable ring retained by this authenticated state owner.
// It has no raw-key export or mutators and must never be logged.
func (s *EncryptedStateStore) Keyring() *securestore.Keyring { return s.ring }

// AdministrativeKeyring returns the actual keys held after administrative
// preflight, before reconciliation has published tasks or changed filters.
func (m *Manager) AdministrativeKeyring() (*securestore.Keyring, error) {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.administrativeError(); err != nil {
		return nil, err
	}
	if !m.config.Enabled || m.config.StateFile == "" {
		return nil, nil
	}
	provider, ok := m.stateStore.(interface{ Keyring() *securestore.Keyring })
	if !ok || provider.Keyring() == nil {
		return nil, errors.New("LI administrative storage has not been authenticated")
	}
	return provider.Keyring(), nil
}

// ReleasePreparedAdministrativeStorage releases a coordinator that has not
// entered Start. It performs no ADMF notification, listener, or reconciliation
// effects. Direct pre-Start mutations may already have made the snapshot ready.
func (m *Manager) ReleasePreparedAdministrativeStorage() error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if m.startedLifecycle.Load() {
		return errors.New("LI administrative lifecycle already entered startup")
	}
	return m.closeAdministrativeStateLocked()
}
