package filtering

import "github.com/endorses/lippycat/internal/pkg/securestore"

// Keyring returns the immutable keys loaded by the persistence owner, or nil
// for plaintext storage. It exposes neither raw material nor mutation methods.
func (m *Manager) Keyring() *securestore.Keyring {
	if provider, ok := m.persistence.(interface{ Keyring() *securestore.Keyring }); ok {
		return provider.Keyring()
	}
	return nil
}
