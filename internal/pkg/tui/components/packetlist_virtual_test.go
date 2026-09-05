//go:build tui || all

package components

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketListVirtualNavigationBeyondMachineInt(t *testing.T) {
	p := NewPacketList()
	p.SetSize(120, 20)
	p.SetVirtualPackets(math.MaxUint64, 0, nil)
	p.GotoBottom()
	require.Equal(t, uint64(math.MaxUint64-1), p.LogicalCursor())
	require.Equal(t, uint64(math.MaxUint64-15), p.LogicalOffset())
	p.PageDown()
	p.CursorDown()
	require.Equal(t, uint64(math.MaxUint64-1), p.LogicalCursor())
	p.PageUp()
	require.Equal(t, uint64(math.MaxUint64-16), p.LogicalCursor())
	p.CursorUp()
	require.Equal(t, uint64(math.MaxUint64-17), p.LogicalCursor())
	p.GotoTop()
	p.PageUp()
	p.CursorUp()
	require.Zero(t, p.LogicalCursor())
	require.Zero(t, p.LogicalOffset())
	p.SetLogicalCursor(math.MaxUint64)
	require.Equal(t, uint64(math.MaxUint64-1), p.LogicalCursor())
	p.SetSize(120, 40)
	require.Equal(t, uint64(math.MaxUint64-35), p.LogicalOffset())
}

func TestPacketListVirtualPageEvictionAndSelection(t *testing.T) {
	p := NewPacketList()
	p.SetVirtualPackets(1000000, 0, []PacketDisplay{{Info: "first"}})
	require.Equal(t, "first", p.GetSelectedPacket().Info)
	p.SetLogicalCursor(999999)
	require.Nil(t, p.GetSelectedPacket())
	require.Contains(t, p.View(true, true), "Loading packet...")
	p.SetVirtualPackets(1000000, 999999, []PacketDisplay{{Info: "last"}})
	require.Equal(t, uint64(999999), p.LogicalCursor())
	require.Equal(t, "last", p.GetSelectedPacket().Info)
	p.SetVirtualPackets(1000000, 0, []PacketDisplay{{Info: "first"}})
	require.Nil(t, p.GetSelectedPacket())
	require.Equal(t, uint64(999999), p.LogicalCursor())
	require.Len(t, p.GetPackets(), 1)
	p.SetVirtualPackets(2, 0, []PacketDisplay{{}, {}, {}})
	require.Len(t, p.GetPackets(), 2)
	require.Equal(t, uint64(1), p.LogicalCursor())
	p.SetVirtualPackets(0, 0, nil)
	p.GotoBottom()
	p.PageDown()
	require.Zero(t, p.LogicalCursor())
	require.Nil(t, p.GetSelectedPacket())
	require.NotContains(t, p.View(false, false), "Loading packet...")
}

func TestPacketListVirtualReturnsToLive(t *testing.T) {
	p := NewPacketList()
	p.SetVirtualPackets(math.MaxUint64, 0, nil)
	p.GotoBottom()
	p.SetPackets([]PacketDisplay{{Info: "live"}, {Info: "new"}})
	require.False(t, p.IsVirtual())
	require.Equal(t, uint64(2), p.LogicalCount())
	require.Equal(t, "new", p.GetSelectedPacket().Info)
	p.GotoTop()
	require.Equal(t, "live", p.GetSelectedPacket().Info)
	p.SetLogicalCursor(math.MaxUint64)
	require.Equal(t, "new", p.GetSelectedPacket().Info)
}

func TestPacketListVirtualRenderIsPure(t *testing.T) {
	p := NewPacketList()
	p.SetSize(140, 30)
	p.SetVirtualPackets(1<<40, 0, []PacketDisplay{{Protocol: "TCP", Info: "loaded"}})
	before := p
	first := p.View(true, true)
	require.Equal(t, before, p)
	require.Equal(t, first, p.View(true, true))
	p.PrepareLayout(true)
	prepared := p
	require.Equal(t, first, p.View(true, true))
	require.Equal(t, prepared, p)
	p.GotoBottom()
	before = p
	require.Contains(t, p.View(false, false), "Loading packet...")
	require.Equal(t, before, p)
}
