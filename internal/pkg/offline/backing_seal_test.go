package offline

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackingSealReopensDerivedReadOnly(t *testing.T) {
	storage := newTestStorage(t)
	registry := storage.NewBackingRegistry()
	loc, err := registry.AppendDerived(context.Background(), 0, []byte("derived payload"))
	require.NoError(t, err)
	lease, err := registry.Read(context.Background(), loc)
	require.NoError(t, err)
	require.ErrorContains(t, registry.Seal(), "leases active")
	require.NoError(t, lease.Close())
	require.NoError(t, registry.Seal())
	require.NoError(t, registry.Seal())
	lease, err = registry.Read(context.Background(), loc)
	require.NoError(t, err)
	require.Equal(t, []byte("derived payload"), lease.Bytes)
	require.NoError(t, lease.Close())
	_, err = registry.AppendDerived(context.Background(), 0, []byte("more"))
	require.Error(t, err)
	_, err = registry.entries[0].file.WriteAt([]byte("x"), 0)
	require.Error(t, err)
	require.NoError(t, registry.Close())
	require.NoError(t, storage.Close())
}

func TestBackingSealFailurePoisonsAndCleans(t *testing.T) {
	storage := newTestStorage(t)
	registry := storage.NewBackingRegistry()
	loc, err := registry.AppendDerived(context.Background(), 0, []byte("derived payload"))
	require.NoError(t, err)
	require.NoError(t, registry.entries[0].file.Close())
	require.Error(t, registry.Seal())
	_, err = registry.Read(context.Background(), loc)
	require.Error(t, err)
	// The injected close is itself surfaced once; cleanup still removes storage.
	require.Error(t, registry.Close())
	require.NoError(t, registry.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.NoError(t, storage.Close())
}

func TestBackingSealSourceSnapshotDecompressed(t *testing.T) {
	for _, policy := range []BackingPolicy{BackingSource, BackingSnapshot} {
		for _, compressed := range []bool{false, true} {
			t.Run(string(policy)+map[bool]string{true: "-gzip", false: "-plain"}[compressed], func(t *testing.T) {
				_, registry, path := backingFixture(t)
				data := []byte("original packet content")
				if compressed {
					var encoded bytes.Buffer
					gz := gzip.NewWriter(&encoded)
					_, err := gz.Write(data)
					require.NoError(t, err)
					require.NoError(t, gz.Close())
					require.NoError(t, os.WriteFile(path, encoded.Bytes(), 0600))
				}
				input, err := registry.Open(context.Background(), path, 0, policy, false)
				require.NoError(t, err)
				require.NoError(t, input.Close())
				loc, err := registry.Locator(input.ID, 0, data)
				require.NoError(t, err)
				require.NoError(t, registry.Seal())
				lease, err := registry.Read(context.Background(), loc)
				require.NoError(t, err)
				require.Equal(t, data, lease.Bytes)
				require.NoError(t, lease.Close())
				_, err = registry.entries[input.ID-1].file.WriteAt([]byte("x"), 0)
				require.Error(t, err)
			})
		}
	}
}
