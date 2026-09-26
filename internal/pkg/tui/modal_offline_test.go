//go:build tui || all

package tui

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestModalOutsideClickCancelsOfflineOpening(t *testing.T) {
	m := footerMouseModel(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m.offlineOpening = true
	m.offlineController.cancel = cancel
	m.offlineProgress.State = offline.Reading

	m = updateEventRenderModel(t, m, selectionPress(0, 0))
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.Equal(t, offline.Cancelling, m.offlineProgress.State)
	require.True(t, m.offlineOpening, "cleanup must finish before the progress modal disappears")
}

func TestModalOutsideClickCancelsOfflineFilter(t *testing.T) {
	m := footerMouseModel(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m.offlineFilter = &offlineFilterState{owner: &offlineFilterOwner{cancel: cancel}}

	m = updateEventRenderModel(t, m, selectionPress(0, 0))
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.NotNil(t, m.offlineFilter, "the worker still owns pending cleanup")
	require.True(t, m.offlineFilter.cancelled)
	require.Contains(t, m.View(), "Waiting for cleanup")
}
