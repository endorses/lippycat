package securestore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureDirProvisionsPrivateComponents(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "first", "second")
	require.NoError(t, EnsureDir(path))
	require.NoError(t, EnsureDir(path))
	for _, directory := range []string{filepath.Dir(path), path} {
		stat, err := os.Stat(directory)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0700), stat.Mode().Perm())
	}
	dir, err := OpenDir(path)
	require.NoError(t, err)
	require.NoError(t, dir.Close())
}

func TestEnsureDirRejectsUntrustedAncestorsBeforeCreation(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	alias := filepath.Join(parent, "alias")
	require.NoError(t, os.Mkdir(real, 0700))
	require.NoError(t, os.Symlink(real, alias))
	require.Error(t, EnsureDir(alias+"/new"))
	_, err := os.Stat(filepath.Join(real, "new"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Error(t, EnsureDir(alias+"/../new"))
	require.NoError(t, os.Chmod(real, 0777))
	require.Error(t, EnsureDir(filepath.Join(real, "new")))
	_, err = os.Stat(filepath.Join(real, "new"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestOfflinePrivateSourceAllowsTrustedPublicParent(t *testing.T) {
	parent := t.TempDir()
	require.NoError(t, os.Chmod(parent, 0755))
	path := filepath.Join(parent, "filters.yaml")
	require.NoError(t, os.WriteFile(path, []byte("filters: []\n"), 0600))
	source, err := OpenPrivateSource(path)
	require.NoError(t, err)
	data, err := source.Read(100)
	require.NoError(t, err)
	require.Equal(t, "filters: []\n", string(data))
	_, err = OpenPrivateSource(path)
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, source.Close())
	require.NoError(t, source.Close())
	_, err = source.Read(100)
	require.ErrorIs(t, err, os.ErrClosed)
	_, err = OpenPrivateSource(filepath.Join(parent, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
