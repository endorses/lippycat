package events

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOfflineInputIdentityTracksOrderedContents(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.pcap")
	second := filepath.Join(dir, "second.pcap")
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o600))

	identity, err := OfflineInputIdentity([]string{first, second})
	require.NoError(t, err)
	repeated, err := OfflineInputIdentity([]string{first, second})
	require.NoError(t, err)
	require.Equal(t, identity, repeated)

	reversed, err := OfflineInputIdentity([]string{second, first})
	require.NoError(t, err)
	require.NotEqual(t, identity, reversed)

	require.NoError(t, os.WriteFile(first, []byte("changed"), 0o600))
	changed, err := OfflineInputIdentity([]string{first, second})
	require.NoError(t, err)
	require.NotEqual(t, identity, changed)
}
