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

func TestReplayOverflowReservationPartitionsAggregateBudget(t *testing.T) {
	for _, bound := range []string{"count", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			cfg := DefaultConfig()
			if bound == "count" {
				cfg.ReplayGuardCapacity = 4
			} else {
				cfg.ReplayGuardBytes = 512
			}
			store, err := NewMetadataStore(cfg)
			require.NoError(t, err)
			entry := SelectedDerivationUsage{Contexts: 1, Bytes: 128}
			for range 3 {
				require.NoError(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, entry))
			}
			require.ErrorIs(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, entry), ErrCapacity)
			// Another domain's overflow identity uses the shared reserved final entry.
			require.NoError(t, store.ReserveReplayOverflow(SelectedDerivationUsage{}, entry))
			require.ErrorIs(t, store.ReserveReplayOverflow(SelectedDerivationUsage{}, entry), ErrCapacity)
			require.Equal(t, 4, store.Stats().ReplayContexts)
			require.Equal(t, 512, store.Stats().ReplayBytes)
			require.NoError(t, store.ReserveReplayOverflow(entry, SelectedDerivationUsage{}))
			require.Error(t, store.ReserveReplayOverflow(entry, SelectedDerivationUsage{}))
			require.NoError(t, store.ReserveReplayGuards(SelectedDerivationUsage{Contexts: 3, Bytes: 384}, SelectedDerivationUsage{}))
			require.Zero(t, store.Stats().ReplayContexts)
			require.Zero(t, store.Stats().ReplayBytes)
		})
	}
}

func TestReplayBudgetCannotFitOneEntry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReplayGuardBytes = 127
	store, err := NewMetadataStore(cfg)
	require.NoError(t, err)
	entry := SelectedDerivationUsage{Contexts: 1, Bytes: 128}
	require.ErrorIs(t, store.ReserveReplayGuards(SelectedDerivationUsage{}, entry), ErrCapacity)
	require.ErrorIs(t, store.ReserveReplayOverflow(SelectedDerivationUsage{}, entry), ErrCapacity)
	require.Zero(t, store.Stats().ReplayContexts)
	require.Zero(t, store.Stats().ReplayBytes)
}
