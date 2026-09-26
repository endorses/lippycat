//go:build linux

package securestore

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalSourceCatalogWorkspaceIsFiniteAndJournalOnly(t *testing.T) {
	cfg := workspaceConfig()
	cfg.Purpose = JournalState
	cfg.EnvelopeBytes = 1 << 20
	cfg.Stages = []RotationStage{RotationSourceCatalogStage}
	_, dir, w := workspaceFixture(t, cfg)
	name, err := w.Name(RotationSourceCatalogStage)
	require.NoError(t, err)
	require.Equal(t, ".rotation-source-catalog-"+cfg.Token, name)
	require.NoError(t, w.Reserve())
	data := bytes.Repeat([]byte{7}, 1<<20)
	out, err := w.Create(RotationSourceCatalogStage, data)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	got, err := dir.Read(name, 1<<20)
	require.NoError(t, err)
	require.Equal(t, data, got)
	_, err = w.Create(RotationSourceCatalogStage, data)
	require.Error(t, err, "one allocated inode cannot be refilled")
	require.NoError(t, w.Close())
	cfg.Purpose = FilterSnapshot
	_, err = OpenRotationWorkspace(dir, cfg)
	require.Error(t, err, "journal-only role must not expand snapshot protocol")
}
