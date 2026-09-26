package securestore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectoryPathIdentityTrustedPublicParent(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	private, public := filepath.Join(root, "private"), filepath.Join(root, "public")
	require.NoError(t, os.Mkdir(private, 0700))
	require.NoError(t, os.Mkdir(public, 0755))
	d, err := OpenDir(private)
	require.NoError(t, err)
	defer func() { require.NoError(t, d.Close()) }()
	same, err := d.SameDirectoryPath(public)
	require.NoError(t, err)
	require.False(t, same)
	same, err = d.SameDirectoryPath(private)
	require.NoError(t, err)
	require.True(t, same)
	alias := filepath.Join(root, "alias")
	require.NoError(t, os.Symlink(private, alias))
	_, err = d.SameDirectoryPath(alias + "/../public")
	require.Error(t, err, "symlink must be rejected before parent traversal")
	require.NoError(t, os.Chmod(public, 0777))
	_, err = d.SameDirectoryPath(public)
	require.Error(t, err)
}
