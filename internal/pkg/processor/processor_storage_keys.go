//go:build processor || tap || all

package processor

import (
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// validateIndependentStorageKeys runs before filter ownership, LI construction,
// or journal initialization. It compares the filter backend's actual immutable
// keys and every active/prior key for each configured, enabled LI store.
// Owners authenticate their snapshots/ledgers at startup. storageKeyValidator
// repeats independence with their actual loaded rings before recovery effects.
func validateIndependentStorageKeys(config Config, persistence filtering.PersistenceHandler) error {
	if !config.LIEnabled {
		return nil
	}
	provider, ok := persistence.(interface{ Keyring() *securestore.Keyring })
	if !ok || provider.Keyring() == nil {
		return errors.New("LI requires encrypted managed filter storage")
	}
	rings := []*securestore.Keyring{provider.Keyring()}
	if config.LIStateFile != "" {
		ring, err := securestore.LoadKeyring(config.LIStateKeys)
		if err != nil {
			return fmt.Errorf("validate LI state encryption keys: %w", err)
		}
		rings = append(rings, ring)
	}
	if config.LIDeliveryX2SpoolDir != "" {
		ring, err := securestore.LoadKeyring(x2StorageKeyConfig(config))
		if err != nil {
			return fmt.Errorf("validate X2 journal encryption keys: %w", err)
		}
		rings = append(rings, ring)
	}
	return securestore.CheckIndependent(rings...)
}

// storageKeyValidator checks the authenticated administrative owner against the
// filter owner's immutable ring, then retains both for the journal's key-load
// boundary. The journal must call the returned validator before recovery and
// reuse that exact ring for all subsequent operations. X3 storage must join this
// boundary when its owner is introduced; it is not covered by the X2 callback.
func (p *Processor) storageKeyValidator(state *securestore.Keyring) (func(*securestore.Keyring) error, error) {
	if !p.config.LIEnabled {
		return nil, nil
	}
	if p.filterManager == nil || p.filterManager.Keyring() == nil {
		return nil, errors.New("LI requires encrypted managed filter storage")
	}
	if (p.config.LIStateFile != "") != (state != nil) {
		return nil, errors.New("LI administrative storage ownership is incomplete")
	}
	rings := []*securestore.Keyring{p.filterManager.Keyring()}
	if state != nil {
		rings = append(rings, state)
	}
	if err := securestore.CheckIndependent(rings...); err != nil {
		return nil, err
	}
	if p.config.LIDeliveryX2SpoolDir == "" {
		return nil, nil
	}
	return func(journal *securestore.Keyring) error {
		if journal == nil {
			return errors.New("X2 journal encryption ownership is incomplete")
		}
		return securestore.CheckIndependent(append(rings, journal)...)
	}, nil
}

// Keep the original key-file-only X2 meaning identical to openJournal. Explicit
// active IDs never implicitly select a key for legacy records.
func x2StorageKeyConfig(config Config) securestore.KeyConfig {
	id, legacy := config.LIDeliveryX2SpoolKeyID, config.LIDeliveryX2SpoolLegacyKeyID
	if id == "" {
		id = "default"
		if legacy == "" {
			legacy = id
		}
	}
	return securestore.KeyConfig{
		Active:   securestore.KeyRef{ID: id, File: config.LIDeliveryX2SpoolKeyFile},
		Prior:    config.LIDeliveryX2SpoolReadKeys,
		LegacyID: legacy,
	}
}
