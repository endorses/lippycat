//go:build tui || all

package components

import (
	"math"
	"strings"
	"testing"
	"unsafe"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestEventsViewVirtualNavigationRetainsUint64Rows(t *testing.T) {
	v := NewEventsView()
	v.SetSize(120, 10)
	v.EnableVirtualEvents(math.MaxUint64)
	require.True(t, v.IsVirtual())
	require.Equal(t, 5, v.VisibleRows())
	v.SetLogicalCursor(math.MaxUint64)
	require.EqualValues(t, uint64(math.MaxUint64-1), v.LogicalCursor())
	require.EqualValues(t, uint64(math.MaxUint64-5), v.LogicalOffset())
	v.SelectNext()
	require.EqualValues(t, uint64(math.MaxUint64-1), v.LogicalCursor())
	v.SelectPrevious()
	require.EqualValues(t, uint64(math.MaxUint64-2), v.LogicalCursor())
	v.SetLogicalCursor(0)
	v.SelectPrevious()
	require.Zero(t, v.LogicalCursor())
	require.Zero(t, v.LogicalOffset())
	v.SetLogicalOffset(math.MaxUint64)
	total, visible, offset := v.LogicalTimelineScrollState(10)
	require.EqualValues(t, uint64(math.MaxUint64), total)
	require.EqualValues(t, 5, visible)
	require.EqualValues(t, uint64(math.MaxUint64-5), offset)
	row, ok := v.LogicalIndexAtVisibleRow(4)
	require.True(t, ok)
	require.EqualValues(t, uint64(math.MaxUint64-1), row)
	_, ok = v.LogicalIndexAtVisibleRow(5)
	require.False(t, ok)
	_, ok = v.LogicalIndexAtVisibleRow(-1)
	require.False(t, ok)
	legacyTotal, _, legacyOffset := v.TimelineScrollState(10)
	require.Equal(t, int(^uint(0)>>1), legacyTotal, "legacy scrollbar adapters saturate instead of wrapping")
	require.Equal(t, int(^uint(0)>>1), legacyOffset)
	v.SetVirtualWindow(2, 0, nil)
	v.SetLogicalCursor(math.MaxUint64)
	require.EqualValues(t, 1, v.LogicalCursor())
	require.Zero(t, v.LogicalOffset())
	v.SetVirtualWindow(0, 0, nil)
	require.Zero(t, v.LogicalCursor())
	_, ok = v.LogicalIndexAtVisibleRow(0)
	require.False(t, ok)
}

func TestEventsViewVirtualRepeatedIDsUseArrivalSelectionAndDetailLease(t *testing.T) {
	first, second := dnsEvent("same-delivery-id", "first.example"), dnsEvent("same-delivery-id", "amended.example")
	items := []EventItem{{Event: &first, ArrivalSequence: 501}, {Event: &second, ArrivalSequence: 502}}
	v := NewEventsView()
	v.EnableVirtualEvents(100)
	v.SetVirtualWindow(100, 80, items)
	v.SetLogicalCursor(80)
	selected, ok := v.Selected()
	require.True(t, ok)
	require.Same(t, &first, selected.Event)
	_, ok = v.DetailSelection()
	require.False(t, ok, "a page borrow is not a separately leased detail")
	v.SetVirtualDetail(&items[0])
	v.PrepareLayout(120, 10, 80, 14)
	v.ScrollDetailsToBottom()
	require.Positive(t, v.detailsViewport.YOffset)
	oldOffset := v.detailsViewport.YOffset
	v.SetVirtualDetail(&items[0])
	v.PrepareLayout(120, 10, 80, 14)
	require.Equal(t, oldOffset, v.detailsViewport.YOffset, "renewing the same arrival lease preserves reading position")
	v.SetInspecting(true)
	require.Nil(t, v.inspectedEvent, "virtual inspection must not allocate an uncharged event copy")
	require.Same(t, &items[0], v.virtualDetail)
	v.SetInspecting(false)
	v.SelectNext()
	require.EqualValues(t, 81, v.LogicalCursor())
	selected, ok = v.Selected()
	require.True(t, ok)
	require.EqualValues(t, 502, selected.ArrivalSequence)
	require.Equal(t, "same-delivery-id", v.SelectedID())
	_, ok = v.DetailSelection()
	require.False(t, ok, "old details are released as soon as logical selection changes")
	v.SetVirtualDetail(&items[1])
	v.PrepareLayout(120, 10, 80, 14)
	require.Zero(t, v.detailsViewport.YOffset, "an amended row has its own detail scroll even when EventID repeats")
	require.Equal(t, "arrival:502", v.detailsSelectedID)
	selected, ok = v.DetailSelection()
	require.True(t, ok)
	require.Same(t, &second, selected.Event)
	v.SetSelectedID("same-delivery-id")
	require.EqualValues(t, 81, v.LogicalCursor(), "stable delivery identity must not select the first repeated arrival")
	replacement := []EventItem{{Event: &first, ArrivalSequence: 900}}
	v.SetVirtualWindow(100, 81, replacement)
	_, ok = v.DetailSelection()
	require.False(t, ok, "a changed query row cannot retain details for an earlier arrival")
}

func TestEventsViewVirtualWindowAndCacheRemainBoundedWhileLoading(t *testing.T) {
	require.LessOrEqual(t, uint64(unsafe.Sizeof(EventItem{})), offline.EventPresentationBytesPerRow, "the disk page/detail reservation must cover each borrowed presentation struct")
	v := NewEventsView()
	v.SetEvents([]EventItem{{Event: dnsEvent("live", "previous.example")}})
	v.SetInspecting(true)
	const total, start uint64 = 1 << 48, 1 << 42
	v.EnableVirtualEvents(total)
	require.Nil(t, v.items)
	require.Nil(t, v.itemStorage)
	require.Nil(t, v.positions)
	require.Nil(t, v.nextDuplicate)
	require.Nil(t, v.inspectedEvent)
	items := make([]EventItem, 128)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent("repeated", "loaded.example"), ArrivalSequence: uint64(i + 1)}
	}
	v.SetVirtualWindow(total, start, items)
	require.Same(t, &items[0], &v.virtualItems[0], "the owner-charged page backing is borrowed, never copied")
	v.SetLogicalCursor(start + 60)
	v.PrepareLayout(140, 12, 0, 0)
	require.Len(t, v.timelineCache.rows, 7)
	require.Contains(t, v.RenderTimeline(140, 12, true), "loaded.example")
	v.SetLogicalCursor(total - 1)
	v.PrepareLayout(140, 12, 0, 0)
	rendered := v.RenderTimeline(140, 12, true)
	require.Contains(t, rendered, "Loading")
	require.NotContains(t, rendered, "No protocol events")
	require.NotContains(t, rendered, "loaded.example")
	require.Len(t, v.virtualItems, 128, "a distant cursor never materializes intervening rows")
	require.Len(t, v.timelineCache.rows, 7)
	_, ok := v.Selected()
	require.False(t, ok)
	_, ok = v.EventIDAtVisibleRow(6)
	require.False(t, ok, "mouse targeting can use logical indexes without a loaded event identity")
	row, ok := v.LogicalIndexAtVisibleRow(6)
	require.True(t, ok)
	require.Equal(t, total-1, row)
	v.PrepareLayout(140, 6, 0, 0)
	require.Len(t, v.timelineCache.rows, 1)
	require.Equal(t, 1, cap(v.timelineCache.rows))
	v.SetVirtualWindow(total, total-1, items[:0])
	require.Nil(t, v.virtualItems)
	v.SetEvents([]EventItem{{Event: dnsEvent("live-again", "live.example"), ArrivalSequence: 1}})
	require.False(t, v.IsVirtual())
	require.Nil(t, v.virtualItems)
	require.Nil(t, v.virtualDetail)
	require.Equal(t, "live-again", v.SelectedID())
	require.Contains(t, v.RenderTimeline(140, 12, true), "live.example")
}

func TestEventsViewVirtualLayoutAndRenderingKeepLogicalTargetsReadOnly(t *testing.T) {
	v := NewEventsView()
	const start uint64 = 1 << 40
	item := EventItem{Event: dnsEvent("detail", "detail.example"), ArrivalSequence: 21}
	v.EnableVirtualEvents(start + 100)
	v.SetSize(130, 11)
	v.SetLogicalCursor(start)
	v.SetVirtualWindow(start+100, start, []EventItem{item})
	v.SetVirtualDetail(&item)
	v.PrepareLayout(130, 11, 75, 14)
	v.ScrollDetailsToBottom()
	before := *v
	for range 3 {
		text := v.RenderTimeline(130, 11, true)
		require.Equal(t, 130, lipgloss.Width(text))
		require.Equal(t, 11, lipgloss.Height(text))
		_ = v.RenderTimeline(80, 8, false)
		_ = v.RenderDetails(60, 9, true)
		require.Equal(t, before, *v, "render-only cache misses must not mutate logical positions, details, geometry, or leases")
	}
	v.SetSize(130, 20)
	row, ok := v.LogicalIndexAtVisibleRow(14)
	require.True(t, ok)
	require.Equal(t, v.LogicalOffset()+14, row, "resized hit geometry is ready before any render")
	v.SetVirtualDetail(nil)
	v.PrepareDetails(75, 14)
	require.Contains(t, v.RenderDetails(75, 14, false), "No event selected")
	require.NotContains(t, v.RenderDetails(75, 14, false), "detail.example")
	require.Zero(t, v.detailsViewport.YOffset)
	for _, line := range strings.Split(v.RenderTimeline(60, 7, false), "\n") {
		require.LessOrEqual(t, lipgloss.Width(line), 60)
	}
}
