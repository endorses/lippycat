package securestore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadedKeyIdentitySurvivesDirectoryRename(t *testing.T) {
	parent := t.TempDir()
	oldDir, newDir := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	require.NoError(t, os.Mkdir(oldDir, 0700))
	keyPath := filepath.Join(oldDir, "key")
	require.NoError(t, os.WriteFile(keyPath, make([]byte, KeyBytes), 0600))
	ring, err := LoadKeyring(KeyConfig{Active: KeyRef{ID: "active", File: keyPath}})
	require.NoError(t, err)
	require.NoError(t, os.Rename(oldDir, newDir))
	dir, err := OpenDir(newDir)
	require.NoError(t, err)
	defer func() { require.NoError(t, dir.Close()) }()
	identity, err := dir.FileIdentity("key")
	require.NoError(t, err)
	require.True(t, ring.UsesFile(identity), "key bytes and inode identity must come from the same descriptor")
	_, _, err = ReadFileWithIdentity(filepath.Join(newDir, "key"), KeyBytes-1)
	require.Error(t, err)
}
