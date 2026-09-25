//go:build tui || all

package components

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/selection"
	"github.com/stretchr/testify/require"
)

func TestDetailsTextSelectionSeparatesScrolledDumpColumns(t *testing.T) {
	d := NewDetailsPanel()
	d.SetSize(77, 12)
	d.SetPacket(&PacketDisplay{Timestamp: time.Now(), RawData: []byte(strings.Repeat("INVITE sip:test  ", 8) + "LAST")})
	d.SetScrollOffset(d.viewport.TotalLineCount())
	lines := strings.Split(ansi.Strip(d.viewport.View()), "\n")
	first, last := -1, -1
	for row, line := range lines {
		if _, ok := selectionHexRow(line); ok {
			if first < 0 {
				first = row
			}
			last = row
		}
	}
	require.GreaterOrEqual(t, first, 0)
	require.Greater(t, last, first)
	for _, tc := range []struct {
		name string
		x    int
		want selection.Rect
	}{
		{"offset", 3, selection.Rect{X: 3, Y: first + 2, Width: 4, Height: last - first + 1}},
		{"hex", 9, selection.Rect{X: 9, Y: first + 2, Width: 49, Height: last - first + 1}},
		{"ascii", 59, selection.Rect{X: 59, Y: first + 2, Width: 16, Height: last - first + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			region, ok := d.TextSelectionAt(tc.x, last+2)
			require.True(t, ok)
			require.Equal(t, tc.want, region)
		})
	}
	_, ok := d.TextSelectionAt(58, last+2)
	require.False(t, ok, "hex/ASCII separator is not selectable")
	_, ok = d.TextSelectionAt(77, 3)
	require.False(t, ok, "scrollbar is not selectable")
	_, ok = d.TextSelectionAt(3, 1)
	require.False(t, ok, "pane padding is not selectable")
}

func TestDetailsTextSelectionRecognizesBinaryDecryptedBlocksAndWideOffsets(t *testing.T) {
	d := NewDetailsPanel()
	d.SetSize(77, 16)
	d.viewport.SetContent("Metadata\n\n" + d.renderHexDump([]byte(strings.Repeat("B", 33))) + "\nOther metadata")
	region, ok := d.TextSelectionAt(60, 4)
	require.True(t, ok)
	require.Equal(t, selection.Rect{X: 59, Y: 4, Width: 16, Height: 3}, region)
	region, ok = d.TextSelectionAt(5, 2)
	require.True(t, ok)
	require.Equal(t, selection.Rect{X: 3, Y: 2, Width: 72, Height: 12}, region)
	wide := ansi.Strip(d.renderHexDump(make([]byte, 65537)))
	rows := strings.Split(strings.TrimSuffix(wide, "\n"), "\n")
	width, valid := selectionHexRow(rows[len(rows)-1])
	require.True(t, valid)
	require.Equal(t, 5, width)
	_, valid = selectionHexRow("abcd  normal metadata that happens to start with a four character hex-looking prefix")
	require.False(t, valid)
}

func TestNodesTextSelectionContainsGraphBoxAndTable(t *testing.T) {
	n := NewNodesView()
	n.SetSize(100, 10)
	region, ok := n.TextSelectionAt(30, 5)
	require.True(t, ok)
	require.Equal(t, selection.Rect{Width: 99, Height: 10}, region)
	_, ok = n.TextSelectionAt(99, 5)
	require.False(t, ok)
	n.viewMode = "graph"
	n.viewport.SetContent(strings.Repeat("row\n", 30))
	n.viewport.SetYOffset(5)
	n.processorBoxRegions = append(n.processorBoxRegions, struct {
		startLine     int
		endLine       int
		startCol      int
		endCol        int
		processorAddr string
	}{startLine: 3, endLine: 12, startCol: 10, endCol: 40})
	region, ok = n.TextSelectionAt(20, 2)
	require.True(t, ok)
	require.Equal(t, selection.Rect{X: 11, Y: 0, Width: 28, Height: 7}, region)
	n.ShowAddNodeModal()
	_, ok = n.TextSelectionAt(20, 2)
	require.False(t, ok)
}

func TestStatisticsTextSelectionContainsCardsAtEveryLayoutWidth(t *testing.T) {
	for _, width := range []int{65, 100, 180} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			s := NewStatisticsView()
			s.SetSize(width, 12)
			s.SetStatistics(&Statistics{TotalPackets: 10, ProtocolCounts: NewBoundedCounter(100), SourceCounts: NewBoundedCounter(100), DestCounts: NewBoundedCounter(100)})
			_ = s.View()
			_, ok := s.TextSelectionAt(0, 0)
			require.False(t, ok, "subview controls must remain clickable")
			_, ok = s.TextSelectionAt(width-1, 4)
			require.False(t, ok, "scrollbar must remain draggable")
			region, ok := s.TextSelectionAt(3, 4)
			require.True(t, ok)
			if width < 80 {
				require.Equal(t, selection.Rect{Y: 1, Width: width - 1, Height: 11}, region)
			} else {
				require.Equal(t, 1, region.X)
				require.Equal(t, 3, region.Y)
				require.Less(t, region.Width, width-1)
			}
			before := s.viewport.YOffset
			_, _ = s.TextSelectionAt(3, 4)
			require.Equal(t, before, s.viewport.YOffset, "selection geometry must not scroll the view")
			s.viewport.SetYOffset(4)
			region, ok = s.TextSelectionAt(3, 0)
			require.True(t, ok)
			require.Zero(t, region.Y)
			if width >= 80 {
				require.Less(t, region.Width, width-1, "scrolled card must preserve its columns")
			}
		})
	}
}

func TestHelpTextSelectionExcludesControlsAndScrollbar(t *testing.T) {
	h := NewHelpView()
	h.SetSize(100, 20)
	region, ok := h.TextSelectionAt(3, 2)
	require.True(t, ok)
	require.Equal(t, selection.Rect{Y: 1, Width: 99, Height: 19}, region)
	for _, point := range [][2]int{{3, 0}, {99, 3}, {3, 20}} {
		_, ok := h.TextSelectionAt(point[0], point[1])
		require.False(t, ok)
	}
}
