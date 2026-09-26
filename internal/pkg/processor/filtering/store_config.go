package filtering

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

type StoreMode string

const (
	StoreAuto      StoreMode = "auto"
	StoreYAML      StoreMode = "yaml"
	StoreEncrypted StoreMode = "encrypted"
)

// StoreConfig contains configuration references, never key bytes. File must be
// empty unless a path was explicitly configured; defaults depend on runtime LI.
type StoreConfig struct {
	Mode StoreMode
	File string
	Keys securestore.KeyConfig
}

type ResolvedStoreConfig struct {
	Mode StoreMode
	File string
	Keys securestore.KeyConfig
}

// ResolveStoreConfig selects the format from runtime policy, never file contents,
// filename extensions, or build tags. Explicit custom paths remain authoritative.
func ResolveStoreConfig(cfg StoreConfig, liEnabled bool) (ResolvedStoreConfig, error) {
	return resolveStoreConfig(cfg, liEnabled, os.UserHomeDir)
}

func resolveStoreConfig(cfg StoreConfig, liEnabled bool, homeDirectory func() (string, error)) (ResolvedStoreConfig, error) {
	mode := cfg.Mode
	if mode == "" || mode == StoreAuto {
		mode = StoreYAML
		if liEnabled {
			mode = StoreEncrypted
		}
	}
	if mode != StoreYAML && mode != StoreEncrypted {
		return ResolvedStoreConfig{}, errors.New("filter-store-mode must be auto, yaml, or encrypted")
	}
	if liEnabled && mode != StoreEncrypted {
		return ResolvedStoreConfig{}, errors.New("LI requires encrypted managed filter storage; migrate the store and select encrypted mode")
	}
	hasKeys := cfg.Keys.Active.ID != "" || cfg.Keys.Active.File != "" || len(cfg.Keys.Prior) != 0 || cfg.Keys.LegacyID != ""
	if mode == StoreYAML && hasKeys {
		return ResolvedStoreConfig{}, errors.New("filter store key options require filter-store-mode=encrypted")
	}
	if mode == StoreEncrypted && (cfg.Keys.Active.ID == "" || cfg.Keys.Active.File == "") {
		return ResolvedStoreConfig{}, errors.New("encrypted filter storage requires an active key ID and key file")
	}
	path := cfg.File
	if path == "" {
		home, err := homeDirectory()
		if err != nil {
			return ResolvedStoreConfig{}, fmt.Errorf("resolve default filter storage directory: %w", err)
		}
		yamlPath := filepath.Join(home, ".config", "lippycat", "filters.yaml")
		encryptedPath := filepath.Join(home, ".config", "lippycat", "filters.enc")
		yamlExists, err := pathExists(yamlPath)
		if err != nil {
			return ResolvedStoreConfig{}, err
		}
		encryptedExists, err := pathExists(encryptedPath)
		if err != nil {
			return ResolvedStoreConfig{}, err
		}
		if yamlExists && encryptedExists {
			return ResolvedStoreConfig{}, errors.New("both default filter stores exist; select an explicit --filter-file and mode")
		}
		if mode == StoreEncrypted {
			if yamlExists && !encryptedExists {
				return ResolvedStoreConfig{}, errors.New("only the default YAML filter store exists; migrate it explicitly before enabling encrypted storage")
			}
			path = encryptedPath
		} else {
			if encryptedExists && !yamlExists {
				return ResolvedStoreConfig{}, errors.New("only the default encrypted filter store exists; select its mode and path explicitly")
			}
			path = yamlPath
		}
	}
	return ResolvedStoreConfig{Mode: mode, File: path, Keys: cfg.Keys}, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect configured filter store: %w", err)
	}
	return true, nil
}

// NewStorePersistence constructs the selected backend. Opening/validation still
// occurs at Load, before a processor may apply any policy or start listeners.
func NewStorePersistence(cfg ResolvedStoreConfig) (PersistenceHandler, error) {
	switch cfg.Mode {
	case StoreYAML:
		return NewYAMLPersistence(), nil
	case StoreEncrypted:
		return NewEncryptedPersistence(cfg.Keys)
	default:
		return nil, errors.New("filter store configuration must be resolved before construction")
	}
}
