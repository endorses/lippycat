//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineIndexerRetainsFailedBuilderCleanup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires directory permissions to prevent removal")
	}
	directory := t.TempDir()
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: directory, DiskBytes: 64 << 20, CacheBytes: 16 << 20, MaxRecordBytes: 1 << 20, MaxSources: 64})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sessionDirectory string
	session, err := indexOfflineDataset(ctx, storage, 41, OfflineAnalysisConfig{Inputs: writeOrderedBridgeFixtures(t), EventCapacity: 8}, func(offline.Progress) {
		if sessionDirectory != "" {
			return
		}
		entries, readErr := os.ReadDir(directory)
		require.NoError(t, readErr)
		require.Len(t, entries, 1)
		sessionDirectory = filepath.Join(directory, entries[0].Name())
		require.NoError(t, os.Chmod(sessionDirectory, 0500))
		cancel()
	})
	// Restore permissions before assertions so a failed regression still cleans up.
	require.NotEmpty(t, sessionDirectory)
	require.NoError(t, os.Chmod(sessionDirectory, 0700))
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "remove private offline session")
	require.NotNil(t, session, "failed cleanup must retain ownership for retry")
	require.Nil(t, session.Dataset, "unfinished storage must never be published")
	require.Positive(t, storage.Resources().DiskBytes)
	require.NoError(t, session.Close())
	require.NoError(t, session.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Empty(t, entries)
}
