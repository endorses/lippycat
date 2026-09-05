//go:build tui || all

package components

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

const (
	maxEventFieldRunes = 512
	maxEventListItems  = 64
	eventTimeWidth     = 12
	eventKindWidth     = 13
	eventOriginWidth   = 16
	// 46 fits two maximum-length IPv4 address:port endpoints plus the arrow.
	eventFlowWidth      = 46
	eventKindMinWidth   = 4
	eventOriginMinWidth = 5
	eventFlowMinWidth   = 24
	eventInfoMinWidth   = 10
)

// EventItem is the immutable presentation record retained by EventStore.
type EventItem struct {
	Event           events.Event
	ArrivalSequence uint64
	ArrivedAt       time.Time
}

// eventIDPositions tracks the first and last retained occurrence of a stable ID.
// Absolute positions survive front trims and backing-slice compaction.
type eventIDPositions struct{ first, last uint64 }

// EventsView renders a protocol-neutral event timeline and detail panel.
type EventsView struct {
	items                   []EventItem
	itemStorage             []EventItem
	itemBase                uint64
	positions               map[string]eventIDPositions
	nextDuplicate           map[uint64]uint64
	selectedID              string
	offset                  int
	width, height           int
	theme                   themes.Theme
	offlinePacketNavigation bool
	relatedPacketsKnown     bool
	relatedPacketsAvailable bool
	detailsViewport         viewport.Model
	detailsViewportReady    bool
	detailsSelectedID       string
	timelineCache           eventTimelineCache
	timelineGeneration      uint64
}

func NewEventsView() *EventsView { return &EventsView{theme: themes.Solarized()} }

func (v *EventsView) SetTheme(theme themes.Theme) {
	v.theme = theme
	v.detailsSelectedID = ""
}
func (v *EventsView) SetSize(width, height int) {
	if v.width == width && v.height == height {
		return
	}
	v.width, v.height = width, height
	v.offset = v.timelineOffset(height, v.indexByID(v.selectedID))
}

// PrepareLayout prepares presentation state during Update, after event selection,
// availability, and pane dimensions have been applied. Rendering never rebuilds
// the detail projection or changes the timeline's hit-testing offset.
// Zero detail dimensions leave the hidden detail pane and its scroll cache alone.
func (v *EventsView) PrepareLayout(timelineWidth, timelineHeight, detailsWidth, detailsHeight int) {
	v.SetSize(timelineWidth, timelineHeight)
	v.prepareTimeline()
	if detailsWidth <= 0 || detailsHeight <= 0 {
		return
	}
	contentWidth := max(1, detailsWidth-6)
	contentHeight := max(5, detailsHeight-4)
	if !v.detailsViewportReady {
		v.detailsViewport = viewport.New(contentWidth, contentHeight)
		v.detailsViewportReady = true
	} else {
		if v.detailsViewport.Width != contentWidth {
			v.detailsSelectedID = ""
		}
		v.detailsViewport.Width = contentWidth
		v.detailsViewport.Height = contentHeight
	}
	if v.detailsSelectedID == v.selectedID && v.selectedID != "" {
		// A taller viewport can reduce the maximum valid scroll offset.
		v.detailsViewport.SetYOffset(v.detailsViewport.YOffset)
		return
	}
	i := v.indexByID(v.selectedID)
	if i < 0 {
		v.detailsSelectedID = ""
		v.detailsViewport.SetContent("")
		v.detailsViewport.GotoTop()
		return
	}
	if v.detailsSelectedID != v.selectedID {
		v.detailsSelectedID = v.selectedID
		v.detailsViewport.SetContent(v.renderEventDetailsContent(v.items[i], contentWidth))
		v.detailsViewport.GotoTop()
	}
}

func (v *EventsView) timelineOffset(height, selected int) int {
	visibleRows := max(0, max(1, height-4)-1)
	if visibleRows == 0 || len(v.items) == 0 {
		return 0
	}
	selected = max(0, selected)
	offset := min(max(0, v.offset), max(0, len(v.items)-visibleRows))
	if selected < offset {
		offset = selected
	} else if selected >= offset+visibleRows {
		offset = selected - visibleRows + 1
	}
	return offset
}

func (v *EventsView) SetEvents(items []EventItem) {
	v.timelineGeneration++
	oldSelected := v.indexByID(v.selectedID)
	oldStorage := v.itemStorage
	v.itemStorage = append(v.itemStorage[:0], items...)
	if len(oldStorage) > len(items) {
		clear(oldStorage[len(items):])
	}
	v.items = v.itemStorage
	v.itemBase = 0
	clear(v.positions)
	clear(v.nextDuplicate)
	v.indexAppended(0)
	newSelected := v.indexByID(v.selectedID)
	if oldSelected >= 0 && newSelected >= 0 {
		v.offset += newSelected - oldSelected
	}
	if newSelected >= 0 {
		v.offset = v.timelineOffset(v.height, newSelected)
		return
	}
	v.detailsSelectedID = ""
	if len(v.items) == 0 {
		v.selectedID = ""
		v.offset = 0
		return
	}
	v.selectedID = v.items[0].Event.Envelope().EventID
	v.offset = v.timelineOffset(v.height, 0)
}

// AppendEvents copies new rows without rebuilding the retained projection.
// Selection remains pinned until the owner applies its selected stable ID.
func (v *EventsView) AppendEvents(items []EventItem) {
	if len(items) == 0 {
		return
	}
	oldCount := len(v.items)
	start := len(v.itemStorage) - oldCount
	if len(v.itemStorage)+len(items) > cap(v.itemStorage) {
		// Compact only after at least as many rows have been trimmed as remain.
		// Otherwise grow geometrically, keeping append/trim amortized O(delta).
		if start >= oldCount && oldCount+len(items) <= cap(v.itemStorage) {
			copy(v.itemStorage, v.items)
			clear(v.itemStorage[oldCount:])
			v.itemStorage = v.itemStorage[:oldCount]
		} else {
			storage := make([]EventItem, oldCount, max(2*cap(v.itemStorage), oldCount+len(items)))
			copy(storage, v.items)
			v.itemStorage = storage
		}
		start = 0
	}
	v.itemStorage = append(v.itemStorage, items...)
	v.items = v.itemStorage[start:]
	v.indexAppended(oldCount)
	if oldCount == 0 {
		v.selectedID = v.items[0].Event.Envelope().EventID
	}
	v.offset = v.timelineOffset(v.height, v.indexByID(v.selectedID))
}

// TrimOldEvents removes a visible prefix, releasing event references immediately.
// Logical positions are derived from a moving base; surviving IDs are not reindexed.
// For a combined delta, append before trimming to retain the original selection
// as the viewport anchor if the same stable ID is evicted and reintroduced.
func (v *EventsView) TrimOldEvents(count int) {
	count = min(max(count, 0), len(v.items))
	if count == 0 {
		return
	}
	oldSelected := v.indexByID(v.selectedID)
	for i, item := range v.items[:count] {
		if item.Event == nil {
			continue
		}
		id := item.Event.Envelope().EventID
		position := v.itemBase + uint64(i)
		entry := v.positions[id]
		if entry.first == entry.last {
			delete(v.positions, id)
		} else {
			entry.first = v.nextDuplicate[position]
			delete(v.nextDuplicate, position)
			v.positions[id] = entry
		}
	}
	clear(v.items[:count])
	v.items = v.items[count:]
	v.itemBase += uint64(count)
	newSelected := v.indexByID(v.selectedID)
	if oldSelected >= 0 && newSelected >= 0 {
		v.offset += newSelected - oldSelected
	} else {
		// PrepareLayout invalidates details using the final selected ID after
		// trim, append, and owner selection have all been applied. The same
		// immutable ID can be evicted and reintroduced in one delta.
		if len(v.items) == 0 {
			v.selectedID = ""
			v.offset = 0
			return
		}
		v.selectedID = v.items[0].Event.Envelope().EventID
		newSelected = 0
	}
	v.offset = v.timelineOffset(v.height, newSelected)
}

func (v *EventsView) indexAppended(start int) {
	if v.positions == nil {
		v.positions = make(map[string]eventIDPositions, len(v.items))
	}
	for i := start; i < len(v.items); i++ {
		if v.items[i].Event == nil {
			continue
		}
		id := v.items[i].Event.Envelope().EventID
		position := v.itemBase + uint64(i)
		entry, exists := v.positions[id]
		if !exists {
			v.positions[id] = eventIDPositions{first: position, last: position}
			continue
		}
		if v.nextDuplicate == nil {
			v.nextDuplicate = make(map[uint64]uint64)
		}
		v.nextDuplicate[entry.last] = position
		entry.last = position
		v.positions[id] = entry
	}
}

// Selected returns the first retained row with the selected stable ID.
func (v *EventsView) Selected() (EventItem, bool) {
	if i := v.indexByID(v.selectedID); i >= 0 {
		return v.items[i], true
	}
	return EventItem{}, false
}

func (v *EventsView) SetSelectedID(id string) {
	if selected := v.indexByID(id); selected >= 0 {
		v.selectedID = id
		v.offset = v.timelineOffset(v.height, selected)
	}
}

func (v *EventsView) SelectedID() string { return v.selectedID }

// EventIDAtVisibleRow returns the event at a zero-based data row in the
// currently rendered viewport.
func (v *EventsView) EventIDAtVisibleRow(row int) (string, bool) {
	index := v.offset + row
	if row < 0 || index < 0 || index >= len(v.items) || v.items[index].Event == nil {
		return "", false
	}
	return v.items[index].Event.Envelope().EventID, true
}

func (v *EventsView) SelectNext() {
	i := v.indexByID(v.selectedID)
	if i >= 0 && i+1 < len(v.items) {
		v.selectedID = v.items[i+1].Event.Envelope().EventID
		v.offset = v.timelineOffset(v.height, i+1)
	}
}

func (v *EventsView) SelectPrevious() {
	i := v.indexByID(v.selectedID)
	if i > 0 {
		v.selectedID = v.items[i-1].Event.Envelope().EventID
		v.offset = v.timelineOffset(v.height, i-1)
	}
}

// SetOfflinePacketNavigation enables the dataset navigation hint and absence label.
func (v *EventsView) SetOfflinePacketNavigation(enabled bool) {
	if v.offlinePacketNavigation != enabled {
		v.offlinePacketNavigation = enabled
		v.detailsSelectedID = ""
	}
}

// SetRelatedPacketsPending hides the eviction notice until an asynchronous
// dataset lookup has completed. Cache misses do not imply packet loss.
func (v *EventsView) SetRelatedPacketsPending() {
	if v.relatedPacketsKnown {
		v.relatedPacketsKnown = false
		v.invalidateRelatedDetails()
	}
}

// SetRelatedPacketsAvailable controls the explicit packet-availability notice.
func (v *EventsView) SetRelatedPacketsAvailable(available bool) {
	changed := !v.relatedPacketsKnown || v.relatedPacketsAvailable != available
	v.relatedPacketsKnown = true
	v.relatedPacketsAvailable = available
	if changed {
		v.invalidateRelatedDetails()
	}
}

// An asynchronous availability update belongs to the same selected event;
// preserve the user's reading position while replacing only its notice.
func (v *EventsView) invalidateRelatedDetails() {
	if v.offlinePacketNavigation && v.detailsViewportReady && v.selectedID != "" && v.detailsSelectedID == v.selectedID {
		if i := v.indexByID(v.selectedID); i >= 0 {
			offset := v.detailsViewport.YOffset
			v.detailsViewport.SetContent(v.renderEventDetailsContent(v.items[i], v.detailsViewport.Width))
			v.detailsViewport.SetYOffset(offset)
			return
		}
	}
	v.detailsSelectedID = ""
}

func (v *EventsView) RenderTimeline(width, height int, focused bool) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	contentHeight := max(1, height-4)      // border (2) and vertical padding (2)
	visibleRows := max(0, contentHeight-1) // table header

	cache := &v.timelineCache
	if !cache.matches(v, width, height) {
		local := v.buildTimelineCache(width, height, nil)
		cache = &local
	}
	borderStyle := cache.pane.border(focused)

	var content strings.Builder
	content.WriteString(cache.header)
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
		row := cache.rows[i-offset]
		if i == selected {
			content.WriteString(row.selected)
		} else {
			content.WriteString(row.normal)
		}

		if i < end-1 {
			content.WriteByte('\n')
		}
	}
	for i := end - offset; i < visibleRows; i++ {
		content.WriteByte('\n')
	}
	return borderStyle.Render(content.String())
}

func (v *EventsView) RenderDetails(width, height int, focused bool) string {
	if width <= 0 || height <= 0 {
		return ""
	}
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
		Width(width).
		Height(height - 2)
	i := v.indexByID(v.selectedID)
	if i < 0 {
		return borderStyle.Render("No event selected")
	}
	return borderStyle.Render(v.detailsViewport.View())
}

func (v *EventsView) ScrollDetailsUp() {
	if v.detailsViewportReady {
		v.detailsViewport.LineUp(1)
	}
}
func (v *EventsView) ScrollDetailsDown() {
	if v.detailsViewportReady {
		v.detailsViewport.LineDown(1)
	}
}
func (v *EventsView) ScrollDetailsPageUp() {
	if v.detailsViewportReady {
		v.detailsViewport.ViewUp()
	}
}
func (v *EventsView) ScrollDetailsPageDown() {
	if v.detailsViewportReady {
		v.detailsViewport.ViewDown()
	}
}
func (v *EventsView) ScrollDetailsToTop() {
	if v.detailsViewportReady {
		v.detailsViewport.GotoTop()
	}
}
func (v *EventsView) ScrollDetailsToBottom() {
	if v.detailsViewportReady {
		v.detailsViewport.GotoBottom()
	}
}

func (v *EventsView) renderEventDetailsContent(item EventItem, width int) string {
	env := item.Event.Envelope()
	sectionStyle := lipgloss.NewStyle().Bold(true).Foreground(v.theme.InfoColor)
	labelStyle := lipgloss.NewStyle().Bold(true).Foreground(v.theme.StatusBarFg)
	valueStyle := lipgloss.NewStyle().Foreground(v.theme.StatusBarFg)
	mutedStyle := lipgloss.NewStyle().Foreground(v.theme.Foreground)
	kindStyle := lipgloss.NewStyle().Bold(true).Foreground(v.eventColor(item.Event.Kind()))
	warningStyle := lipgloss.NewStyle().Bold(true).Foreground(v.theme.WarningColor)

	var content strings.Builder
	content.WriteString(kindStyle.Render(eventKindIcon(item.Event.Kind()) + " " + strings.ToUpper(string(item.Event.Kind())) + " Event"))
	if v.offlinePacketNavigation {
		content.WriteString("\n" + mutedStyle.Render("Enter: jump to first related packet"))
	}
	if v.relatedPacketsKnown && !v.relatedPacketsAvailable {
		content.WriteString("\n\n")
		notice := "⚠ Related packets are no longer buffered."
		if v.offlinePacketNavigation {
			notice = "No related packets in this dataset."
		}
		content.WriteString(warningStyle.Render(notice))
	}

	writeSection := func(title string, rows []eventDetailRow) {
		visible := rows[:0]
		for _, row := range rows {
			if strings.TrimSpace(row.value) != "" {
				visible = append(visible, row)
			}
		}
		if len(visible) == 0 {
			return
		}
		content.WriteString("\n\n")
		content.WriteString(sectionStyle.Render(title))
		content.WriteString("\n\n")
		for _, row := range visible {
			content.WriteString(renderEventDetailRow(row.label, row.value, width, labelStyle, valueStyle, mutedStyle, v.theme))
			content.WriteByte('\n')
		}
	}

	writeSection("Overview", []eventDetailRow{
		{"Time", env.Timestamp.Format("2006-01-02 15:04:05.000000")},
		{"Origin", env.NodeID},
		{"Summary", eventSummary(item.Event)},
	})
	writeSection("Flow", []eventDetailRow{
		{"Source", fmt.Sprintf("%s:%d", env.Flow.SourceAddress, env.Flow.SourcePort)},
		{"Destination", fmt.Sprintf("%s:%d", env.Flow.DestinationAddress, env.Flow.DestinationPort)},
		{"Transport", fmt.Sprint(env.Flow.Protocol)},
		{"Scope", string(env.CaptureScope)},
		{"Partial", fmt.Sprint(env.Partial)},
	})

	commonFields := map[string]bool{"ts": true, "uid": true, "id.orig_h": true, "id.orig_p": true, "id.resp_h": true, "id.resp_p": true, "proto": true, "community_id": true, "node_id": true, "capture_scope": true, "partial": true}
	protocolRows := make([]eventDetailRow, 0)
	for _, field := range eventFields(item.Event) {
		if !commonFields[field.Name] && strings.TrimSpace(field.Value) != "" {
			protocolRows = append(protocolRows, eventDetailRow{humanizeEventField(field.Name), field.Value})
		}
	}
	writeSection(eventKindSectionTitle(item.Event.Kind()), protocolRows)

	interfaceValue := env.Provenance.InterfaceName
	if interfaceValue != "" || env.Provenance.InterfaceIndex != 0 {
		interfaceValue = fmt.Sprintf("%s (index %d)", valueOrDash(interfaceValue), env.Provenance.InterfaceIndex)
	}
	writeSection("Provenance", []eventDetailRow{
		{"Capture", env.Provenance.CaptureSource},
		{"Interface", interfaceValue},
		{"Input File", env.Provenance.InputFile},
		{"Processors", boundedValue(env.Provenance.ProcessorNodeIDs)},
	})
	writeSection("Flow Identity", []eventDetailRow{{"UID", env.UID}, {"Community ID", env.CommunityID}})
	writeSection("Event Identity", []eventDetailRow{
		{"Event ID", env.EventID},
		{"Session", env.ProducerSessionID},
		{"Sequence", fmt.Sprint(env.EventSequence)},
		{"Arrival", fmt.Sprint(item.ArrivalSequence)},
	})
	return strings.TrimRight(content.String(), "\n")
}

type eventDetailRow struct{ label, value string }

func renderEventDetailRow(label, value string, width int, labelStyle, valueStyle, mutedStyle lipgloss.Style, theme themes.Theme) string {
	const labelWidth = 15
	valueWidth := max(10, width-labelWidth)
	var content strings.Builder
	content.WriteString(labelStyle.Render(fitRunes(label, labelWidth)))
	style := valueStyle
	displayValue := sanitizeEventText(value)
	if value == "false" {
		displayValue = "no"
		style = mutedStyle
	} else if value == "true" {
		displayValue = "yes"
		style = valueStyle.Foreground(theme.SuccessColor)
	}
	wrapped := wrapEventValue(displayValue, valueWidth)
	for i, line := range wrapped {
		if i > 0 {
			content.WriteByte('\n')
			content.WriteString(strings.Repeat(" ", labelWidth))
		}
		content.WriteString(style.Render(line))
	}
	return content.String()
}

func wrapEventValue(value string, width int) []string {
	if value == "" {
		return []string{"-"}
	}
	runes := []rune(value)
	lines := make([]string, 0, (len(runes)/width)+1)
	for len(runes) > width {
		lines = append(lines, string(runes[:width]))
		runes = runes[width:]
	}
	return append(lines, string(runes))
}

func humanizeEventField(name string) string {
	replacer := strings.NewReplacer("id.orig_h", "Source Address", "id.orig_p", "Source Port", "id.resp_h", "Destination Address", "id.resp_p", "Destination Port", "ja3s", "JA3S", "ja3", "JA3", "ja4", "JA4", "rtt", "RTT", "uid", "UID", "fuid", "FUID", "ttls", "TTLs", "qclass", "Query Class", "qtype", "Query Type", "rcode", "Response Code", "_", " ")
	words := strings.Fields(replacer.Replace(name))
	for i := range words {
		words[i] = strings.ToUpper(words[i][:1]) + words[i][1:]
	}
	return strings.Join(words, " ")
}

func eventKindIcon(kind events.Kind) string {
	switch kind {
	case events.KindTLS:
		return "🔐"
	case events.KindHTTP:
		return "🌐"
	case events.KindDNS:
		return "🔍"
	case events.KindConn:
		return "🔗"
	case events.KindSMTP:
		return "✉"
	case events.KindFileMetadata:
		return "📄"
	default:
		return "📋"
	}
}

func eventKindSectionTitle(kind events.Kind) string {
	name := strings.ToUpper(string(kind))
	if kind == events.KindFileMetadata {
		name = "File"
	}
	return name + " Details"
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// View renders the full-width timeline using the configured dimensions.
func (v *EventsView) View() string { return v.RenderTimeline(v.width, v.height, true) }

func (v *EventsView) eventColor(kind events.Kind) lipgloss.Color {
	switch kind {
	case events.KindTLS:
		return v.theme.TLSColor
	case events.KindHTTP:
		return v.theme.HTTPColor
	case events.KindDNS:
		return v.theme.DNSColor
	case events.KindConn:
		return v.theme.TCPColor
	default:
		return v.theme.Foreground
	}
}

func eventTimelineHeader(width int) string {
	return eventTimelineRow("Time", "Event", "Origin", "Src IP:Port -> Dst IP:Port", "Info", width)
}

func eventTimelineRow(timestamp, kind, origin, flow, info string, width int) string {
	return eventTimelineRowWithColumns(timestamp, kind, origin, flow, info, width, eventTimelineColumnWidths(width))
}

func eventTimelineRowWithColumns(timestamp, kind, origin, flow, info string, width int, columns eventTimelineWidths) string {
	info = strings.TrimSpace(sanitizeEventText(info))
	row := strings.Join([]string{
		fitEventCells(sanitizeEventText(timestamp), columns.time),
		fitEventCells(sanitizeEventText(kind), columns.kind),
		fitEventCells(sanitizeEventText(origin), columns.origin),
		fitEventCells(sanitizeEventText(flow), columns.flow), info,
	}, " ")
	return fitEventCells(row, width)
}

// Input is already sanitized: ANSI sequences can never enter cached rows.
func fitEventCells(value string, width int) string {
	if width <= 0 {
		return ""
	}
	// Most timeline cells are ASCII. Avoid the grapheme scanner on this path.
	ascii := true
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		if len(value) > width {
			return value[:width-1] + "…"
		}
		return value + strings.Repeat(" ", width-len(value))
	}
	value = ansi.Truncate(value, width, "…")
	return value + strings.Repeat(" ", max(0, width-ansi.StringWidth(value)))
}

type eventTimelineWidths struct {
	time, kind, origin, flow int
}

func eventTimelineColumnWidths(width int) eventTimelineWidths {
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

func fitRunes(value string, width int) string {
	return padRunes(truncateRunes(sanitizeEventText(value), width), width)
}

func padRunes(value string, width int) string {
	count := utf8.RuneCountInString(value)
	if count >= width {
		return value
	}
	return value + strings.Repeat(" ", width-count)
}

func (v *EventsView) indexByID(id string) int {
	if entry, ok := v.positions[id]; ok {
		return int(entry.first - v.itemBase)
	}
	return -1
}

type eventField struct{ Name, Type, Value string }

func eventFields(event events.Event) []eventField {
	if event == nil || event.Kind() == events.KindFileContent {
		return nil
	}
	streamName := string(event.Kind())
	if event.Kind() == events.KindTLS {
		streamName = "ssl"
	} else if event.Kind() == events.KindFileMetadata {
		streamName = "files"
	}
	schema, ok := logschema.ByName(streamName)
	if !ok {
		return nil
	}
	fields := make([]eventField, 0, len(schema.Fields))
	projection := eventquery.Project(event)
	for _, canonical := range schema.Fields {
		projected, present := projection.Fields[canonical.Name]
		if !present {
			continue
		}
		fields = append(fields, eventField{Name: canonical.Name, Type: canonical.Type, Value: sanitizeEventText(projectedValue(projected))})
	}
	return fields
}

func projectedValue(value eventquery.Value) string {
	parts := make([]string, len(value.Values))
	for i, member := range value.Values {
		parts[i] = fmt.Sprint(member)
	}
	return strings.Join(parts, ", ")
}

func canonicalEventValue(event events.Event, name string) (string, bool) {
	value, ok := eventquery.Project(event).Fields[name]
	return projectedValue(value), ok
}

func eventSpecificValues(event events.Event) map[string]string {
	values := make(map[string]string)
	put := func(name string, value any) { values[name] = boundedValue(value) }
	switch e := event.(type) {
	case events.ConnEvent:
		put("service", e.Service)
		put("duration", e.Duration)
		put("orig_bytes", e.OriginBytes)
		put("resp_bytes", e.ResponseBytes)
		put("conn_state", e.State)
		put("local_orig", e.LocalOrigin)
		put("local_resp", e.LocalResponse)
		put("missed_bytes", e.MissedBytes)
		put("history", e.History)
		put("orig_pkts", e.OriginPackets)
		put("orig_ip_bytes", e.OriginIPBytes)
		put("resp_pkts", e.ResponsePackets)
		put("resp_ip_bytes", e.ResponseIPBytes)
	case events.DNSEvent:
		put("trans_id", e.TransactionID)
		put("rtt", e.RTT)
		put("query", e.Query)
		put("qclass", e.QClass)
		put("qtype", e.QType)
		put("rcode", e.RCode)
		put("AA", e.Authoritative)
		put("TC", e.Truncated)
		put("RD", e.RecursionDesired)
		put("RA", e.RecursionAvailable)
		put("Z", e.Z)
		put("answers", e.Answers)
		put("TTLs", e.TTLs)
		put("rejected", e.Rejected)
	case events.TLSEvent:
		put("version", e.Version)
		put("cipher", e.Cipher)
		put("curve", e.Curve)
		put("server_name", e.ServerName)
		put("resumed", e.Resumed)
		put("last_alert", e.LastAlert)
		put("next_protocol", e.NextProtocol)
		put("established", e.Established)
		put("cert_chain_fuids", e.CertificateFileIDs)
		put("client_cert_chain_fuids", e.ClientCertificateFileIDs)
		put("subject", e.Subject)
		put("issuer", e.Issuer)
		put("client_subject", e.ClientSubject)
		put("client_issuer", e.ClientIssuer)
		put("validation_status", e.ValidationStatus)
		put("ja3", e.JA3)
		put("ja3s", e.JA3S)
		put("ja4", e.JA4)
	case events.HTTPEvent:
		put("trans_depth", e.TransactionDepth)
		put("method", e.Method)
		put("host", e.Host)
		put("uri", e.URI)
		put("referrer", e.Referrer)
		put("version", e.Version)
		put("user_agent", e.UserAgent)
		put("origin", e.Origin)
		put("request_body_len", e.RequestBodyLength)
		put("response_body_len", e.ResponseBodyLength)
		put("status_code", e.StatusCode)
		put("status_msg", e.StatusMessage)
		put("info_code", e.InformationalCode)
		put("info_msg", e.InformationalMessage)
		put("tags", e.Tags)
		put("username", e.Username)
		put("proxied", e.Proxies)
		put("orig_fuids", e.RequestFileIDs)
		put("orig_filenames", e.RequestFilenames)
		put("orig_mime_types", e.RequestMIMETypes)
		put("resp_fuids", e.ResponseFileIDs)
		put("resp_filenames", e.ResponseFilenames)
		put("resp_mime_types", e.ResponseMIMETypes)
	case events.SMTPEvent:
		put("trans_depth", e.TransactionDepth)
		put("helo", e.HELO)
		put("mailfrom", e.MailFrom)
		put("rcptto", e.Recipients)
		put("date", e.Date)
		put("from", e.From)
		put("to", e.To)
		put("cc", e.CC)
		put("reply_to", e.ReplyTo)
		put("msg_id", e.MessageID)
		put("in_reply_to", e.InReplyTo)
		put("subject", e.Subject)
		put("x_originating_ip", e.OriginatingIP)
		if len(e.Received) > 0 {
			put("first_received", e.Received[0])
		}
		if len(e.Received) > 1 {
			put("second_received", e.Received[1])
		}
		put("last_reply", e.LastReply)
		put("path", e.Path)
		put("user_agent", e.UserAgent)
		put("tls", e.TLS)
		put("fuids", e.FileIDs)
		put("is_webmail", e.IsWebmail)
	case events.FileMetadataEvent:
		put("fuid", e.FileID)
		put("source", e.Source)
		put("depth", e.Depth)
		put("analyzers", e.Analyzers)
		put("mime_type", e.MIMEType)
		put("filename", e.Filename)
		put("duration", e.Duration)
		put("local_orig", e.LocalOrigin)
		put("is_orig", e.IsOrigin)
		put("seen_bytes", e.SeenBytes)
		put("total_bytes", e.TotalBytes)
		put("missing_bytes", e.MissingBytes)
		put("overflow_bytes", e.OverflowBytes)
		put("timedout", e.TimedOut)
		put("parent_fuid", e.ParentFileID)
		put("md5", e.MD5)
		put("sha1", e.SHA1)
		put("sha256", e.SHA256)
		put("hash_complete", e.HashComplete)
		put("extracted", e.ExtractedPath)
	}
	return values
}

func eventSummary(event events.Event) string {
	return eventquery.Summary(event)
}

func boundedValue(value any) string {
	switch values := value.(type) {
	case []string:
		copyValues := append([]string(nil), values...)
		if len(copyValues) > maxEventListItems {
			copyValues = copyValues[:maxEventListItems]
		}
		for i := range copyValues {
			copyValues[i] = sanitizeEventText(copyValues[i])
		}
		return strings.Join(copyValues, ", ")
	case []time.Duration:
		parts := make([]string, min(len(values), maxEventListItems))
		for i := range parts {
			parts[i] = values[i].String()
		}
		return strings.Join(parts, ", ")
	default:
		return sanitizeEventText(fmt.Sprint(value))
	}
}

func sanitizeEventText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return truncateRunes(value, maxEventFieldRunes)
}

func truncateRunes(value string, limit int) string {
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

func compactNode(node string) string {
	if node == "" {
		return "-"
	}
	parts := strings.Fields(sanitizeEventText(node))
	sort.Strings(parts)
	return truncateRunes(strings.Join(parts, " "), 16)
}
