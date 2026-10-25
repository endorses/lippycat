//go:build tui || all

package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

type eventTimelineRowCache struct{ plain, normal, selected string }

// Only the visible viewport is retained, with no event or projection references.
// Absolute positions distinguish duplicate stable IDs and survive front trims.
type eventTimelineCache struct {
	ready            bool
	width, height    int
	theme            themes.Theme
	generation       uint64
	start            uint64
	selectedID       string
	selectedPosition uint64
	virtual          bool
	rows             []eventTimelineRowCache
	columns          eventTimelineWidths
	header           string
	styles           map[events.Kind]lipgloss.Style
	selectedStyle    lipgloss.Style
	pane             paneStyleCache
}

func (v *EventsView) timelineRenderOffset(height int) int {
	if height == v.height {
		return v.offset
	}
	return v.timelineOffset(height, v.indexByID(v.selectedID))
}

func (v *EventsView) virtualRenderOffset(height int) uint64 {
	if height == v.height {
		return v.virtualOffset
	}
	return v.virtualTimelineOffset(height, true)
}

func (v *EventsView) timelineRange(height int) (start uint64, count int, selected uint64) {
	visible := max(0, height-5)
	if v.virtual {
		start = v.virtualRenderOffset(height)
		if start < v.virtualTotal {
			count = int(min(uint64(visible), v.virtualTotal-start))
		}
		return start, count, v.virtualCursor
	}
	offset := v.timelineRenderOffset(height)
	return v.itemBase + uint64(offset), min(visible, max(0, len(v.items)-offset)), v.itemBase + uint64(max(0, v.indexByID(v.selectedID)))
}

func (c *eventTimelineCache) matches(v *EventsView, width, height int) bool {
	start, count, selected := v.timelineRange(height)
	return c.ready && c.width == width && c.height == height && c.theme == v.theme &&
		c.generation == v.timelineGeneration && c.start == start && c.virtual == v.virtual &&
		len(c.rows) == count && c.selectedID == v.selectedID && c.selectedPosition == selected
}

// Called only from Update's PrepareLayout. A render cache miss uses a local
// result instead, preserving rendering purity and mouse hit-testing state.
func (v *EventsView) prepareTimeline() {
	if v.timelineCache.matches(v, v.width, v.height) {
		return
	}
	v.timelineCache = v.buildTimelineCache(v.width, v.height, &v.timelineCache)
}

func (v *EventsView) buildTimelineCache(width, height int, previous *eventTimelineCache) eventTimelineCache {
	contentWidth := max(1, width-6)
	start, count, selected := v.timelineRange(height)
	c := eventTimelineCache{ready: true, width: width, height: height, theme: v.theme, generation: v.timelineGeneration,
		start: start, selectedID: v.selectedID, selectedPosition: selected, virtual: v.virtual}
	reusable := previous != nil && previous.ready && previous.width == width && previous.theme == v.theme && previous.virtual == v.virtual
	if reusable {
		c.columns, c.header, c.styles, c.selectedStyle = previous.columns, previous.header, previous.styles, previous.selectedStyle
		c.pane = previous.pane
	} else {
		c.columns = eventTimelineColumnWidths(contentWidth)
		c.header = lipgloss.NewStyle().Bold(true).Foreground(v.theme.HeaderBg).Reverse(true).Width(contentWidth).Render(eventTimelineHeader(contentWidth))
		c.styles = make(map[events.Kind]lipgloss.Style)
		for _, kind := range []events.Kind{events.KindTLS, events.KindHTTP, events.KindDNS, events.KindConn, events.KindNotice} {
			c.styles[kind] = lipgloss.NewStyle().Foreground(v.eventColor(kind)).Width(contentWidth)
		}
		c.styles[""] = lipgloss.NewStyle().Foreground(v.theme.Foreground).Width(contentWidth)
		c.selectedStyle = lipgloss.NewStyle().Foreground(v.theme.SelectionFg).Background(v.theme.SelectionBg).Bold(true).Width(contentWidth)
	}
	c.pane.prepare(v.theme, width-2, height-2)
	c.rows = make([]eventTimelineRowCache, count)
	for j := range c.rows {
		pos := c.start + uint64(j)
		if reusable && previous.generation == c.generation && pos >= previous.start && pos-previous.start < uint64(len(previous.rows)) {
			c.rows[j] = previous.rows[pos-previous.start]
		} else {
			var item *EventItem
			if v.virtual {
				item, _ = v.virtualItemAt(pos)
			} else {
				item = &v.items[int(pos-v.itemBase)]
			}
			kind, plain := events.Kind(""), "Loading…"
			if item != nil && item.Event != nil {
				env := item.Event.Envelope()
				kind = item.Event.Kind()
				endpoints := fmt.Sprintf("%s:%d -> %s:%d", env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort)
				plain = eventTimelineRowWithColumns(v.displayEventTimestamp(env.Timestamp).Format("15:04:05.000"), string(kind), compactNode(env.NodeID), endpoints, eventSummary(item.Event), contentWidth, c.columns)
			}
			plain = fitEventCells(sanitizeEventText(plain), contentWidth)
			style, ok := c.styles[kind]
			if !ok {
				style = c.styles[""]
			}
			c.rows[j] = eventTimelineRowCache{plain: plain, normal: style.Render(plain)}
		}
		if pos == selected && c.rows[j].selected == "" {
			c.rows[j].selected = c.selectedStyle.Render(c.rows[j].plain)
		}
	}
	return c
}
