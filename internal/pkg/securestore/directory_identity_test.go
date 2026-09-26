package securestore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectoryIdentitySurvivesPathRename(t *testing.T) {
	parent := t.TempDir()
	old, moved := filepath.Join(parent, "original"), filepath.Join(parent, "moved")
	require.NoError(t, os.Mkdir(old, 0700))
	dir, err := OpenDir(old)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dir.Close()) })
	same, err := dir.SameDirectory(dir)
	require.NoError(t, err)
	require.True(t, same)
	require.NoError(t, os.Rename(old, moved))
	require.NoError(t, os.Mkdir(old, 0700))
	alias, err := OpenDir(moved)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, alias.Close()) })
	replacement, err := OpenDir(old)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, replacement.Close()) })
	same, err = dir.SameDirectory(alias)
	require.NoError(t, err)
	require.True(t, same)
	key, err := dir.LockOrderKey("snapshot")
	require.NoError(t, err)
	aliasKey, err := alias.LockOrderKey("snapshot")
	require.NoError(t, err)
	require.Equal(t, key, aliasKey)
	differentName, err := dir.LockOrderKey("snapshot2")
	require.NoError(t, err)
	require.Less(t, key, differentName)
	_, err = dir.LockOrderKey("../snapshot")
	require.Error(t, err)
	same, err = dir.SameDirectory(replacement)
	require.NoError(t, err)
	require.False(t, same)
	replacementKey, err := replacement.LockOrderKey("snapshot")
	require.NoError(t, err)
	require.NotEqual(t, key, replacementKey)
	require.NoError(t, dir.Close())
	_, err = dir.SameDirectory(alias)
	require.ErrorIs(t, err, os.ErrClosed)
}
