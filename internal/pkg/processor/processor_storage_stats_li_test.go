//go:build (processor || tap || all) && li

package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/stretchr/testify/require"
)

func TestStorageTelemetryLIEnabledWithDisabledPersistence(t *testing.T) {
	p := &Processor{liManager: li.NewManager(li.ManagerConfig{Enabled: true}, nil)}
	t.Cleanup(p.liManager.Stop)
	dst := &management.ProcessorStats{}
	p.populateStorageStats(dst)
	require.NotNil(t, dst.Storage.LiState)
	require.Equal(t, "disabled", dst.Storage.LiState.Mode)
	require.Nil(t, dst.Storage.LiState.KeyUsage)
}
