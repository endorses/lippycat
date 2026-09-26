//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestStorageTelemetryCommonBuildMapping(t *testing.T) {
	fm := filtering.NewManager("", nil, nil, nil, nil)
	require.NoError(t, fm.Initialize())
	p := &Processor{filterManager: fm}
	dst := &management.ProcessorStats{}
	p.populateStorageStats(dst)
	require.Equal(t, "disabled", dst.Storage.Filters.Mode)
	require.Nil(t, dst.Storage.LiState)
	status := storageStatusProto(securestore.StorageStatus{Mode: "encrypted", State: "ready", ActiveKeyID: "active", Usage: &securestore.UsageStats{Invocations: 4096, Blocks: 1 << 20, ReservationOutcome: "committed"}})
	require.Equal(t, securestore.MaxKeyInvocations, status.KeyUsage.InvocationLimit)
	require.Equal(t, securestore.MaxKeyBlocks, status.KeyUsage.BlockLimit)
	require.Equal(t, "active", status.ActiveKeyId)
}
