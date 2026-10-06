package mediaadmission

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplayBudgetIsSeparateAndShared(t *testing.T) {
	for _, bound := range []string{"contexts", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			cfg := DefaultConfig()
			if bound == "contexts" {
				cfg.ReplayGuardCapacity = 1
			} else {
				cfg.ReplayGuardBytes = 128
			}
			store, err := NewMetadataStore(cfg)
			require.NoError(t, err)
			guard := SelectedDerivationUsage{Contexts: 1, Bytes: 128}
			// Separate callers represent bridges sharing this process store.
			require.NoError(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, guard))
			require.ErrorIs(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, guard), ErrCapacity)
			require.Equal(t, 1, store.Stats().ReplayContexts)
			require.Equal(t, 128, store.Stats().ReplayBytes)
			live := SelectedDerivationUsage{Contexts: cfg.PendingDialogCapacity, Bytes: cfg.PendingBytes}
			require.NoError(t, store.ReserveSelectedDerivation(SelectedDerivationUsage{}, live))
			require.NoError(t, store.ReserveReplayGuards(guard, SelectedDerivationUsage{}))
			require.NoError(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, guard))
			require.Equal(t, cfg.PendingDialogCapacity, store.Stats().SelectedContexts)
			require.Error(t, store.ReserveReplayGuards(SelectedDerivationUsage{Contexts: 2, Bytes: 256}, SelectedDerivationUsage{}))
			require.Equal(t, 1, store.Stats().ReplayContexts)
		})
	}
}
