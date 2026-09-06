//go:build tui || all

package tui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineProductionCompactBacking(t *testing.T) {
	for _, policy := range []offline.BackingPolicy{offline.BackingSource, offline.BackingSnapshot} {
		t.Run(string(policy), func(t *testing.T) {
			path := writeCompactProtocolFixture(t)
			limits := FreezeOfflineOpen([]string{path}, "", 32).Limits
			limits.Directory = t.TempDir()
			storage, err := offline.NewStorage(limits)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, storage.Close()) })
			cfg := FreezeOfflineOpen([]string{path}, "", 32).Config
			cfg.BackingPolicy = policy
			session, err := indexOfflineDataset(context.Background(), storage, 91, cfg, nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, session.Close()) })
			var manifests int
			require.NoError(t, filepath.WalkDir(limits.Directory, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.Name() != "manifest" {
					return nil
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				var manifest struct {
					Version  int
					Complete bool
					Compact  struct{ BaseComplete, AnalysisComplete bool }
				}
				if err := json.Unmarshal(raw, &manifest); err != nil {
					return err
				}
				require.Equal(t, 2, manifest.Version)
				require.True(t, manifest.Complete)
				require.True(t, manifest.Compact.BaseComplete)
				require.True(t, manifest.Compact.AnalysisComplete)
				manifests++
				return nil
			}))
			require.Equal(t, 1, manifests)
			require.NoError(t, os.Truncate(path, 24))
			detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 91}, 0)
			if policy == offline.BackingSource {
				require.ErrorIs(t, err, offline.ErrSourceChanged)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, detail.Packet.RawData)
			}
		})
	}
}
