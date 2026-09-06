//go:build tui || all

package tui

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOfflineFilterAcceptedDeepBooleanFallback(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	// This is accepted by the existing parser but exceeds the storage
	// expression depth limit. The opaque predicate must remain usable.
	input := strings.Repeat("NOT ", 65) + "impossible"
	f, err := filters.ParseBooleanExpression(input, m.parseSimpleFilter)
	require.NoError(t, err)
	require.True(t, f.Match(types.PacketDisplay{}))
	total := m.offlinePacketCount()
	cmd := m.parseAndApplyFilter(input)
	require.NotNil(t, m.offlineFilter, "accepted filter must start an offline query")
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, total, m.offlinePacketCount())
	require.Equal(t, total, m.offlineBrowse.owner.query.Statistics().Packets)
	require.True(t, m.packetStore.HasFilter())
}
