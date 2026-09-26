//go:build linux

package securestore

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationTemporaryAllocationUsesActualWorkspaceNames(t *testing.T) {
	path, d := privateTestDir(t)
	name := rotationWorkspacePrefix + strings.Repeat("a", 64) + "-" + rotationStageNames[0] + "-" + strings.Repeat("b", 32)
	require.NoError(t, os.WriteFile(filepath.Join(path, name), []byte("ciphertext"), 0600))
	n, err := d.RotationTemporaryAllocatedSize(name)
	require.NoError(t, err)
	require.Positive(t, n)
	_, err = d.RotationTemporaryAllocatedSize(strings.Replace(name, strings.Repeat("a", 64), strings.Repeat("a", 32), 1))
	require.Error(t, err)
	_, err = d.RotationTemporaryAllocatedSize(rotationWorkspacePrefix + strings.Repeat("a", 64) + "-invalid-" + strings.Repeat("b", 32))
	require.Error(t, err)
}
