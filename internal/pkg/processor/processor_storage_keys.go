//go:build processor || tap || all

package processor

import (
	"errors"
	"fmt"
	"sync"

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
		if config.LIDeliveryX3SpoolDir != "" || config.LIDeliveryX3SpoolReplayPolicy != "" && config.LIDeliveryX3SpoolReplayPolicy != "hold" {
			return errors.New("persistent X3 requires LI to be enabled")
		}
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
	if config.LIDeliveryX3SpoolDir != "" {
		ring, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: config.LIDeliveryX3SpoolKeyID, File: config.LIDeliveryX3SpoolKeyFile}, Prior: config.LIDeliveryX3SpoolReadKeys})
		if err != nil {
			return fmt.Errorf("validate X3 journal encryption keys: %w", err)
		}
		rings = append(rings, ring)
	}
	return securestore.CheckIndependent(rings...)
}

// storageKeyValidator checks the authenticated administrative owner against the
// filter owner's immutable ring, then retains both for the journal's key-load
// boundary. The journal must call the returned validator before recovery and
// reuse that exact ring for all subsequent operations. The shared validator
// accumulates both actual journal rings before either journal has effects.
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
	if p.config.LIDeliveryX2SpoolDir == "" && p.config.LIDeliveryX3SpoolDir == "" {
		return nil, nil
	}
	var mu sync.Mutex
	return func(journal *securestore.Keyring) error {
		mu.Lock()
		defer mu.Unlock()
		if journal == nil {
			return errors.New("LI journal encryption ownership is incomplete")
		}
		if err := securestore.CheckIndependent(append(rings, journal)...); err != nil {
			return err
		}
		rings = append(rings, journal)
		return nil
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
