//go:build processor || tap || all

package processor

import (
	"os"
	"path/filepath"
	"testing"
)

// newTestProcessor keeps each test's managed filter store private and releases
// its lifetime ownership lock even when an assertion stops the test early.
func newTestProcessor(t testing.TB, cfg Config) (*Processor, error) {
	t.Helper()
	if cfg.FilterFile == "" {
		cfg.FilterFile = newTestFilterFile(t)
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

func newTestFilterFile(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "filter-store")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create private test filter directory: %v", err)
	}
	return filepath.Join(dir, "filters.yaml")
}
