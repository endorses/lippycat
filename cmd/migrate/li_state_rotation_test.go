//go:build (all || cli || processor || tap) && li

package migrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestLIStateCommandEncryptedRotationPreservesAllocator(t *testing.T) {
	oldKey, newKey := rotationCommandKey(t, 71), rotationCommandKey(t, 72)
	dir := privateDir(t)
	source, destination, pin := filepath.Join(dir, "source.enc"), filepath.Join(dir, "dest.enc"), filepath.Join(dir, "allocator")
	allocator := []byte("unchanged synthetic allocator watermark")
	require.NoError(t, os.WriteFile(pin, allocator, 0600))
	before, err := os.Stat(pin)
	require.NoError(t, err)
	_, err = executeState(t, "--init", "--destination", source, "--key-id=old", "--key-file", oldKey, "--radius-state-file", pin)
	require.NoError(t, err)
	args := []string{"--source-format=encrypted", "--source", source, "--destination", destination,
		"--source-key-id=old", "--source-key-file", oldKey, "--key-id=new", "--key-file", newKey}
	output, err := executeState(t, args...)
	require.NoError(t, err)
	require.Contains(t, output, "Encrypted LI state store rotation committed.")
	_, err = executeState(t, append(args, "--resume")...)
	require.NoError(t, err)
	store, err := li.OpenStateStore(destination, securestore.KeyConfig{Active: securestore.KeyRef{ID: "new", File: newKey}})
	require.NoError(t, err)
	state, err := store.Load()
	require.NoError(t, err)
	require.NoError(t, store.Close())
	require.Equal(t, pin, state.RADIUSCorrelationStateFile)
	after, err := os.Stat(pin)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after))
	data, err := os.ReadFile(pin)
	require.NoError(t, err)
	require.Equal(t, allocator, data)
}

func TestLIStateRotationRejectsPinOverrideAndPlaintextKeyOptions(t *testing.T) {
	base := []string{"--source-format=encrypted", "--source=absent", "--destination=unused",
		"--source-key-id=old", "--source-key-file=absent", "--key-id=new", "--key-file=absent"}
	for _, pin := range []string{"", "sensitive-allocator-path"} {
		_, err := executeState(t, append(append([]string{}, base...), "--radius-state-file="+pin)...)
		require.ErrorContains(t, err, "not accepted for encrypted rotation")
		require.NotContains(t, err.Error(), "sensitive-allocator-path")
	}
	_, err := executeState(t, "--source-format=json", "--source=absent", "--destination=unused", "--key-id=new", "--key-file=absent", "--source-key-id=old")
	require.ErrorContains(t, err, "require --source-format=encrypted")
	_, err = executeState(t, "--init", "--destination=unused", "--key-id=new", "--key-file=absent", "--max-working-bytes=100")
	require.ErrorContains(t, err, "require --source-format=encrypted")
}
