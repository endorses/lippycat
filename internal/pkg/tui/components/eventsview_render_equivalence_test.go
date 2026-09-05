//go:build tui || all

package components

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"
)

// legacyEventTimeline preserves the Phase 6 renderer and formatting helpers as
// an independent byte-for-byte control for Phase 7 styles and row caching.
func legacyEventTimeline(v *EventsView, width, height int, focused bool) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	contentWidth := max(1, width-6)        // border (2) and horizontal padding (4)
	contentHeight := max(1, height-4)      // border (2) and vertical padding (2)
	visibleRows := max(0, contentHeight-1) // table header

	borderColor := v.theme.BorderColor
	borderType := lipgloss.RoundedBorder()
	if focused {
		borderColor = v.theme.SelectionBg
		borderType = lipgloss.ThickBorder()
	}
	borderStyle := lipgloss.NewStyle().
		Border(borderType).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(width - 2).
		Height(height - 2)

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(v.theme.HeaderBg).
		Reverse(true).
		Width(contentWidth)

	var content strings.Builder
	content.WriteString(headerStyle.Render(legacyEventTimelineHeader(contentWidth)))
	if visibleRows > 0 {
		content.WriteByte('\n')
	}
	if len(v.items) == 0 {
		content.WriteString("No protocol events")
		for i := 1; i < visibleRows; i++ {
			content.WriteByte('\n')
		}
		return borderStyle.Render(content.String())
	}
	selected := v.indexByID(v.selectedID)
	if selected < 0 {
		selected = 0
	}
	offset := v.offset
	if height != v.height {
		offset = v.timelineOffset(height, selected)
	}
	end := min(offset+visibleRows, len(v.items))
	for i := offset; i < end; i++ {
		item := v.items[i]
		env := item.Event.Envelope()
		style := lipgloss.NewStyle().Foreground(v.eventColor(item.Event.Kind()))
		if i == selected {
			style = style.Foreground(v.theme.SelectionFg).Background(v.theme.SelectionBg).Bold(true)
		}
		endpoints := fmt.Sprintf("%s:%d -> %s:%d", env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort)
		line := legacyEventTimelineRow(
			env.Timestamp.Format("15:04:05.000"),
			string(item.Event.Kind()),
			legacyCompactNode(env.NodeID),
			endpoints,
			eventSummary(item.Event),
			contentWidth,
		)
		line = legacyPadRunes(legacyTruncateRunes(legacySanitizeEventText(line), contentWidth), contentWidth)
		content.WriteString(style.Width(contentWidth).Render(line))
		if i < end-1 {
			content.WriteByte('\n')
		}
	}
	for i := end - offset; i < visibleRows; i++ {
		content.WriteByte('\n')
	}
	return borderStyle.Render(content.String())
}

func legacyEventTimelineHeader(width int) string {
	return legacyEventTimelineRow("Time", "Event", "Origin", "Src IP:Port -> Dst IP:Port", "Info", width)
}

func legacyEventTimelineRow(timestamp, kind, origin, flow, info string, width int) string {
	info = strings.TrimSpace(legacySanitizeEventText(info))
	columns := legacyEventTimelineColumnWidths(width)
	row := strings.Join([]string{
		legacyFitRunes(timestamp, columns.time),
		legacyFitRunes(kind, columns.kind),
		legacyFitRunes(origin, columns.origin),
		legacyFitRunes(flow, columns.flow),
		info,
	}, " ")
	return legacyPadRunes(legacyTruncateRunes(row, width), width)
}

func legacyEventTimelineColumnWidths(width int) eventTimelineWidths {
	columns := eventTimelineWidths{
		time: eventTimeWidth, kind: eventKindMinWidth,
		origin: eventOriginMinWidth, flow: eventFlowMinWidth,
	}
	const separators = 4
	remaining := width - columns.time - columns.kind - columns.origin - columns.flow - eventInfoMinWidth - separators
	if remaining <= 0 {
		return columns
	}
	grow := func(current *int, preferred int) {
		extra := min(remaining, preferred-*current)
		*current += extra
		remaining -= extra
	}
	// Preserve endpoint readability first. Event kind and origin can safely
	// contract to their short forms in narrower split layouts.
	grow(&columns.flow, eventFlowWidth)
	grow(&columns.origin, eventOriginWidth)
	grow(&columns.kind, eventKindWidth)
	return columns
}

func legacyFitRunes(value string, width int) string {
	return legacyPadRunes(legacyTruncateRunes(legacySanitizeEventText(value), width), width)
}

func legacyPadRunes(value string, width int) string {
	count := utf8.RuneCountInString(value)
	if count >= width {
		return value
	}
	return value + strings.Repeat(" ", width-count)
}

func legacySanitizeEventText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return legacyTruncateRunes(value, maxEventFieldRunes)
}

func legacyTruncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func legacyCompactNode(node string) string {
	if node == "" {
		return "-"
	}
	parts := strings.Fields(legacySanitizeEventText(node))
	sort.Strings(parts)
	return legacyTruncateRunes(strings.Join(parts, " "), 16)
}

func renderEquivalenceItems(count int) []EventItem {
	items := benchmarkEventItems(count)
	for i := range items {
		env := items[i].Event.Envelope()
		env.NodeID = "zéro\tnœud\nα"
		switch i % 6 {
		case 0:
			e := events.NewDNSEvent(env)
			e.Query, e.QType = "éxample\n.test\t\x1b[31m", 28
			items[i].Event = e
		case 1:
			e := events.NewTLSEvent(env)
			e.ServerName, e.Version = "münchen.example", "TLS 1.3"
			items[i].Event = e
		case 2:
			e := events.NewHTTPEvent(env)
			e.Method, e.Host, e.URI, e.StatusCode = "GET", "example.test", "/café\r\x00path", 200
			items[i].Event = e
		case 3:
			e := events.NewConnEvent(env)
			e.Service, e.State = "ssh", "S0"
			items[i].Event = e
		case 4:
			e := events.NewSMTPEvent(env)
			e.MailFrom, e.Subject = "test@example.org", strings.Repeat("Ü", 700)
			items[i].Event = e
		case 5:
			e := events.NewFileMetadataEvent(env)
			e.Filename, e.MIMEType = "naïve.txt", "text/plain"
			items[i].Event = e
		}
	}
	return items
}

func TestEventsViewTimelineLegacyEquivalence(t *testing.T) {
	// Force ANSI output so equality covers protocol colors and selected styles,
	// even when tests run without a terminal. No test using this global is parallel.
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	alternate := themes.Solarized()
	alternate.Name = "alternate"
	alternate.BorderColor, alternate.HeaderBg = "#102030", "#405060"
	alternate.SelectionBg, alternate.SelectionFg = "#abcdef", "#123456"
	alternate.DNSColor, alternate.HTTPColor = "#ddaa11", "#bb3388"
	alternate.TLSColor, alternate.TCPColor, alternate.Foreground = "#11aabb", "#44dd66", "#ccbb99"
	items := renderEquivalenceItems(60)
	for _, theme := range []themes.Theme{themes.Solarized(), alternate} {
		for _, width := range []int{0, 1, 6, 24, 65, 80, 100, 140, 160, 240, 600, 1000} {
			for _, height := range []int{0, 2, 6, 12, 40} {
				t.Run(fmt.Sprintf("%s/%dx%d", theme.Name, width, height), func(t *testing.T) {
					v := NewEventsView()
					v.SetTheme(theme)
					v.PrepareLayout(width, height, 0, 0)
					check := func() {
						t.Helper()
						for _, focused := range []bool{false, true} {
							require.Equal(t, legacyEventTimeline(v, width, height, focused), v.RenderTimeline(width, height, focused))
							// Unprepared alternate dimensions must remain correct and read-only.
							require.Equal(t, legacyEventTimeline(v, width+3, height+1, focused), v.RenderTimeline(width+3, height+1, focused))
							v.PrepareLayout(width, height, 0, 0)
							require.Equal(t, legacyEventTimeline(v, width, height, focused), v.RenderTimeline(width, height, focused))
						}
					}
					check()
					v.SetEvents(items[:40])
					check()
					v.SetSelectedID(items[39].Event.Envelope().EventID)
					check()
					v.SelectPrevious()
					check()
					v.SetSelectedID(items[4].Event.Envelope().EventID)
					check()
					v.AppendEvents(items[40:])
					v.TrimOldEvents(12)
					check()
					v.SetSelectedID(items[59].Event.Envelope().EventID)
					check()
					v.SetTheme(alternate)
					check()
					// Full replacement with a reused ID must invalidate cached row fields.
					changed := dnsEvent(items[59].Event.Envelope().EventID, "replacement")
					v.SetEvents([]EventItem{{Event: changed}})
					check()
					v.SetEvents(nil)
					check()
				})
			}
		}
	}
}

// The legacy renderer counted code points rather than terminal cells. Wide
// characters and combining sequences intentionally receive corrected alignment,
// so their contract is cell positions instead of equality with that bug.
func TestEventTimelineUnicodeCellAlignment(t *testing.T) {
	const width = 140
	columns := eventTimelineColumnWidths(width)
	flowStart := columns.time + 1 + columns.kind + 1 + columns.origin + 1
	infoStart := flowStart + columns.flow + 1
	for _, origin := range []string{"节点", "cafe\u0301", "🛰️📡", strings.Repeat("界", 40)} {
		row := eventTimelineRow("12:34:56.789", "dns", origin, "FLOW", "INFO", width)
		require.Equal(t, width, lipgloss.Width(row), "origin %q", origin)
		require.Equal(t, flowStart, lipgloss.Width(row[:strings.Index(row, "FLOW")]), "origin %q", origin)
		require.Equal(t, infoStart, lipgloss.Width(row[:strings.Index(row, "INFO")]), "origin %q", origin)
	}
	for _, width := range []int{24, 65, 100, 160} {
		v := NewEventsView()
		v.SetEvents([]EventItem{{Event: dnsEvent("wide", strings.Repeat("界e\u0301📡", 100))}})
		v.PrepareLayout(width, 10, 0, 0)
		rendered := v.RenderTimeline(width, 10, true)
		require.Equal(t, width, lipgloss.Width(rendered))
		require.Equal(t, 10, lipgloss.Height(rendered))
	}
}

var eventTimelineBenchmarkOutput string

func BenchmarkEventsViewTimelineControl(b *testing.B) {
	for _, retained := range []int{1_000, 10_000} {
		for _, legacy := range []bool{false, true} {
			b.Run(fmt.Sprintf("retained_%d/legacy_%t", retained, legacy), func(b *testing.B) {
				items := renderEquivalenceItems(retained)
				v := NewEventsView()
				v.SetEvents(items)
				v.SetSelectedID(items[retained-1].Event.Envelope().EventID)
				v.PrepareLayout(160, 40, 0, 0)
				render := v.RenderTimeline
				if legacy {
					render = func(w, h int, focus bool) string { return legacyEventTimeline(v, w, h, focus) }
				}
				eventTimelineBenchmarkOutput = render(160, 40, true)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					eventTimelineBenchmarkOutput = render(160, 40, true)
				}
			})
		}
	}
}

func BenchmarkEventsViewTimelineAppendRender(b *testing.B) {
	for _, retained := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("retained_%d", retained), func(b *testing.B) {
			items := renderEquivalenceItems(retained + 1)
			v := NewEventsView()
			v.SetEvents(items[:retained])
			v.SetSelectedID(items[retained-1].Event.Envelope().EventID)
			v.PrepareLayout(160, 40, 0, 0)
			next := retained
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				v.AppendEvents(items[next : next+1])
				v.TrimOldEvents(1)
				v.SetSelectedID(items[next].Event.Envelope().EventID)
				v.PrepareLayout(160, 40, 0, 0)
				eventTimelineBenchmarkOutput = v.RenderTimeline(160, 40, true)
				next = (next + 1) % len(items)
			}
		})
	}
}

func TestEventsViewPreparedTimelineReducesAllocations(t *testing.T) {
	items := renderEquivalenceItems(1_000)
	v := NewEventsView()
	v.SetEvents(items)
	v.SetSelectedID(items[len(items)-1].Event.Envelope().EventID)
	v.PrepareLayout(160, 40, 0, 0)
	cached := testing.AllocsPerRun(20, func() { eventTimelineBenchmarkOutput = v.RenderTimeline(160, 40, true) })
	legacy := testing.AllocsPerRun(20, func() { eventTimelineBenchmarkOutput = legacyEventTimeline(v, 160, 40, true) })
	require.Less(t, cached, legacy, "prepared visible rows must allocate less than the same-binary legacy control")
}
