//go:build processor || tap || all

package processor

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// newTestProcessor keeps each test's managed filter store private and releases
// its lifetime ownership lock even when an assertion stops the test early.
func newTestProcessor(t testing.TB, cfg Config) (*Processor, error) {
	t.Helper()
	if cfg.FilterFile == "" {
		cfg.FilterFile = newTestFilterFile(t)
	}
	if cfg.LIEnabled && cfg.FilterStoreMode != filtering.StoreYAML && cfg.FilterStoreKeys.Active.File == "" {
		cfg.FilterStoreKeys = newTestFilterKeys(t)
		if _, err := filtering.InitializeEncryptedFilterStore(cfg.FilterFile, cfg.FilterStoreKeys, filtering.OfflineOptions{}); err != nil {
			t.Fatalf("initialize encrypted test policy: %v", err)
		}
	}
	p, err := New(cfg)
	if p != nil {
		t.Cleanup(func() {
			if err := p.Shutdown(); err != nil {
				t.Errorf("shutdown test processor: %v", err)
			}
		})
	}
	return p, err
}

func newTestFilterKeys(t testing.TB) securestore.KeyConfig {
	t.Helper()
	keyFile := newTestFilterFile(t)
	key := make([]byte, securestore.KeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test storage key: %v", err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatalf("write test storage key: %v", err)
	}
	return securestore.KeyConfig{Active: securestore.KeyRef{ID: "filter-test", File: keyFile}}
}

func newTestFilterFile(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "filter-store")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create private test filter directory: %v", err)
	}
	return filepath.Join(dir, "filters.yaml")
}
