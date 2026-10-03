//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func inspectionPackets(count int) []PacketDisplay {
	packets := make([]PacketDisplay, count)
	for i := range packets {
		packets[i] = PacketDisplay{
			Timestamp: time.Unix(int64(i+1), 0), NodeID: "hunter",
			SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Protocol: "TCP",
		}
	}
	return packets
}

func TestPacketListInspectionStopsFollowingUntilEnd(t *testing.T) {
	packets := inspectionPackets(8)
	p := NewPacketList()
	p.SetPackets(packets[:3])
	p.SetInspecting(true)
	p.AppendPackets(packets[3:4])
	require.Equal(t, packets[2], *p.GetSelectedPacket())
	require.False(t, p.IsAutoScrolling())

	// A full snapshot and front eviction preserve the same retained packet.
	p.SetPackets(packets[1:5])
	require.Equal(t, packets[2], *p.GetSelectedPacket())
	p.TrimOldPackets(1)
	p.AppendPackets(packets[5:6])
	require.Equal(t, packets[2], *p.GetSelectedPacket())

	p.SetInspecting(false)
	p.SetPackets(packets[2:7])
	require.Equal(t, packets[2], *p.GetSelectedPacket())
	require.False(t, p.IsAutoScrolling())
	p.GotoBottom()
	p.AppendPackets(packets[7:])
	require.Equal(t, packets[7], *p.GetSelectedPacket())
	require.True(t, p.IsAutoScrolling())
}

func TestPacketListInspectionMatchesCaptureSourceAndBytes(t *testing.T) {
	selected := inspectionPackets(1)[0]
	selected.RawData = []byte{1}
	p := NewPacketList()
	p.SetPackets([]PacketDisplay{selected})
	p.SetInspecting(true)
	otherSource, otherBytes := selected, selected
	otherSource.NodeID = "other hunter"
	otherBytes.RawData = []byte{2}
	p.SetPackets([]PacketDisplay{otherSource, otherBytes, selected})
	require.Equal(t, 2, p.GetCursor())
	p.SetInspecting(false)
	// Refreshing while the inspected item is last must not re-enable follow.
	p.SetPackets([]PacketDisplay{selected})
	p.SetPackets([]PacketDisplay{selected})
	p.AppendPackets([]PacketDisplay{otherBytes})
	require.Equal(t, selected, *p.GetSelectedPacket())
	require.False(t, p.IsAutoScrolling())
}

func TestPacketListInspectionSurvivesCompleteRetentionEviction(t *testing.T) {
	packets := inspectionPackets(3)
	p := NewPacketList()
	p.SetPackets(packets[:1])
	p.SetInspecting(true)
	p.TrimOldPackets(1)
	p.AppendPackets(packets[1:])
	require.Equal(t, packets[1], *p.GetSelectedPacket())
	require.False(t, p.IsAutoScrolling())
	require.Equal(t, packets[0].Timestamp, p.captureStartTime)
	p.Reset()
	p.SetPackets(packets)
	require.True(t, p.IsAutoScrolling())
}

func TestPacketListInspectionPreservesViewportDuringTrim(t *testing.T) {
	packets := inspectionPackets(30)
	p := NewPacketList()
	p.SetSize(80, 10)
	p.SetPackets(packets[:20])
	p.SetInspecting(true)
	row := p.GetCursor() - p.GetOffset()
	p.TrimOldPackets(3)
	require.Equal(t, row, p.GetCursor()-p.GetOffset())
	require.Equal(t, packets[19], *p.GetSelectedPacket())
	p.SetPackets(packets[5:25])
	require.Equal(t, row, p.GetCursor()-p.GetOffset())
	require.Equal(t, packets[19], *p.GetSelectedPacket())
}
