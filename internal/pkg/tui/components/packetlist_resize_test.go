//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketListGrowthFillsAvailableRows(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		count, cursor, wantOffset int
	}{
		{"following", 100, 99, 65},
		{"manual near end", 100, 97, 65},
		{"manual history", 100, 40, 40},
		{"short list", 12, 11, 0},
		{"empty list", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPacketList()
			p.SetSize(80, 15)
			p.SetPackets(inspectionPackets(tc.count))
			p.SetCursor(tc.cursor)
			selected, following := p.GetSelectedPacket(), p.IsAutoScrolling()
			p.SetSize(110, 40)
			require.Equal(t, tc.wantOffset, p.GetOffset())
			require.Equal(t, selected, p.GetSelectedPacket())
			require.Equal(t, following, p.IsAutoScrolling())
		})
	}
}
