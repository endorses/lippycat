//go:build tui || all

package store

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/stretchr/testify/require"
)

func TestPacketArrivalIdentitySurvivesEvictionFiltersAndCounterReset(t *testing.T) {
	s := NewPacketStore(3)
	identical := components.PacketDisplay{Protocol: "TCP"}
	input := []components.PacketDisplay{identical, identical, identical}
	s.AddPacketBatch(input)
	require.Zero(t, input[0].CaptureID, "ingestion must not mutate caller-owned packets")
	packets := s.GetPacketsInOrder()
	require.Equal(t, uint64(1), packets[0].CaptureID)
	require.Equal(t, uint64(2), packets[1].CaptureID)
	require.Equal(t, uint64(3), packets[2].CaptureID)
	s.AddPacket(identical)
	s.AddFilter(filters.NewTextFilter("TCP", []string{"protocol"}))
	packets = s.GetFilteredPackets()
	require.Equal(t, uint64(2), packets[0].CaptureID)
	require.Equal(t, uint64(4), packets[2].CaptureID)
	s.ResizeBuffer(2)
	require.Equal(t, uint64(3), s.GetPacketsInOrder()[0].CaptureID)
	s.ResetCounts()
	s.Clear()
	s.AddPacket(identical)
	require.Equal(t, uint64(5), s.GetPacketsInOrder()[0].CaptureID)
}
