package events

import (
	"context"
	"crypto/sha256"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineInputIdentityFromDigests(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(a, []byte("first"), 0600))
	require.NoError(t, os.WriteFile(b, []byte("second"), 0600))
	for _, paths := range [][]string{nil, {a}, {a, b}, {b, a}, {a, b, a}} {
		digests := make([][32]byte, len(paths))
		for i, path := range paths {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			digests[i] = sha256.Sum256(data)
		}
		want, err := OfflineInputIdentityContext(context.Background(), paths)
		require.NoError(t, err)
		require.Equal(t, want, OfflineInputIdentityFromDigests(digests))
	}
}
