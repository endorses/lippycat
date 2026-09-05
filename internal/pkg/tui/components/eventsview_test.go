//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dnsEvent(id, query string) events.DNSEvent {
	event := events.NewDNSEvent(events.Envelope{Timestamp: time.Unix(1, 0), EventID: id, UID: "uid", NodeID: "node\nspoof"})
	event.Query = query
	event.QType = 1
	return event
}

func TestEventsViewTimelineUsesPacketListChrome(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: dnsEvent("one", "example.org"), ArrivalSequence: 1}})

	rendered := view.RenderTimeline(100, 20, false)
	assert.Equal(t, 100, lipgloss.Width(rendered))
	assert.Equal(t, 20, lipgloss.Height(rendered))
	assert.Contains(t, rendered, "Time")
	assert.Contains(t, rendered, "Event")
	assert.Contains(t, rendered, "Origin")
	assert.Contains(t, rendered, "Src IP:Port -> Dst IP:Port")
	assert.NotContains(t, rendered, "> 00:00:01.000")
	assert.Contains(t, rendered, "╭")
	assert.Contains(t, rendered, "╯")
}

func TestEventsViewSplitPanesExposeFocusAndFixedSize(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: dnsEvent("one", "example.org"), ArrivalSequence: 1}})

	timeline := view.RenderTimeline(100, 20, true)
	view.PrepareLayout(100, 20, 60, 20)
	details := view.RenderDetails(60, 20, false)
	assert.Equal(t, 100, lipgloss.Width(timeline))
	assert.Equal(t, 20, lipgloss.Height(timeline))
	assert.Equal(t, 62, lipgloss.Width(details))
	assert.Equal(t, 20, lipgloss.Height(details))
	assert.Contains(t, timeline, "┏")
	assert.Contains(t, details, "╭")

	view.PrepareLayout(100, 20, 60, 20)
	focusedDetails := view.RenderDetails(60, 20, true)
	assert.Equal(t, 62, lipgloss.Width(focusedDetails))
	assert.Contains(t, focusedDetails, "┏")
}

func TestEventTimelineRowsKeepColumnsAlignedWithLongValues(t *testing.T) {
	header := eventTimelineHeader(120)
	row := eventTimelineRow(
		"12:34:56.789",
		"unexpectedly-long-event-kind",
		"unexpectedly-long-processor-node-name",
		"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff:65535 -> 2001:db8::1:65535",
		"summary",
		120,
	)

	kindStart := eventTimeWidth + 1
	columns := eventTimelineColumnWidths(120)
	originStart := kindStart + columns.kind + 1
	flowStart := originStart + columns.origin + 1
	infoStart := flowStart + columns.flow + 1
	headerRunes := []rune(header)
	rowRunes := []rune(row)
	assert.Equal(t, "Event", strings.TrimSpace(string(headerRunes[kindStart:originStart-1])))
	assert.Equal(t, "Origin", strings.TrimSpace(string(headerRunes[originStart:flowStart-1])))
	assert.Equal(t, "Src IP:Port -> Dst IP:Port", strings.TrimSpace(string(headerRunes[flowStart:infoStart-1])))
	assert.Equal(t, "Info", strings.TrimSpace(string(headerRunes[infoStart:])))
	assert.Equal(t, "summary", strings.TrimSpace(string(rowRunes[infoStart:])))
	assert.Equal(t, 120, len(rowRunes))
}

func TestEventTimelineFlowColumnFitsFullIPv4Endpoints(t *testing.T) {
	flow := "255.255.255.255:65535 -> 255.255.255.255:65535"
	row := []rune(eventTimelineRow("12:34:56.789", "tls", "processor", flow, "TLS 1.3", 140))
	columns := eventTimelineColumnWidths(140)
	flowStart := columns.time + 1 + columns.kind + 1 + columns.origin + 1
	infoStart := flowStart + columns.flow + 1

	assert.Equal(t, flow, strings.TrimSpace(string(row[flowStart:infoStart-1])))
	assert.Equal(t, "TLS 1.3", strings.TrimSpace(string(row[infoStart:])))
}

func TestEventTimelineInfoStartsAtFixedColumn(t *testing.T) {
	columns := eventTimelineColumnWidths(140)
	infoStart := columns.time + 1 + columns.kind + 1 + columns.origin + 1 + columns.flow + 1
	for _, info := range []string{
		"query qtype=1 rcode=0",
		"  TLS 1.3 ",
		" GET example.org status=200",
		"  S0 0s",
	} {
		row := []rune(eventTimelineRow("12:34:56.789", "event", "processor", "192.0.2.1:1 -> 192.0.2.2:2", info, 140))
		assert.Equal(t, strings.TrimSpace(info), strings.TrimSpace(string(row[infoStart:])))
		assert.NotEqual(t, ' ', row[infoStart])
	}
}

func TestEventTimelineColumnsContractResponsively(t *testing.T) {
	wide := eventTimelineColumnWidths(140)
	narrow := eventTimelineColumnWidths(80)

	assert.Equal(t, eventKindWidth, wide.kind)
	assert.Equal(t, eventOriginWidth, wide.origin)
	assert.Equal(t, eventFlowWidth, wide.flow)
	assert.Equal(t, eventKindMinWidth, narrow.kind)
	assert.Equal(t, eventOriginMinWidth, narrow.origin)
	assert.GreaterOrEqual(t, narrow.flow, eventFlowMinWidth)
	assert.Equal(t, 80, len([]rune(eventTimelineRow("12:34:56.789", "file_metadata", "processor-long", "192.0.2.1:12345 -> 198.51.100.2:443", "summary", 80))))
}

func TestEventsViewUsesPacketProtocolColors(t *testing.T) {
	view := NewEventsView()
	assert.Equal(t, view.theme.TLSColor, view.eventColor(events.KindTLS))
	assert.Equal(t, view.theme.HTTPColor, view.eventColor(events.KindHTTP))
	assert.Equal(t, view.theme.DNSColor, view.eventColor(events.KindDNS))
	assert.Equal(t, view.theme.TCPColor, view.eventColor(events.KindConn))
	assert.Equal(t, view.theme.Foreground, view.eventColor(events.KindSMTP))
}

func TestEventsViewSelectionMovesAboveBottomWithoutScrollingViewport(t *testing.T) {
	view := NewEventsView()
	items := make([]EventItem, 20)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "example.org"), ArrivalSequence: uint64(i + 1)}
	}
	view.SetEvents(items)
	view.SetSelectedID("event-19")
	view.PrepareLayout(100, 10, 0, 0)
	require.Equal(t, 15, view.offset)

	view.SetSelectedID("event-18")
	view.PrepareLayout(100, 10, 0, 0)
	assert.Equal(t, 15, view.offset, "moving up should leave the bottom row visible")

	items = append(items, EventItem{Event: dnsEvent("event-20", "example.org"), ArrivalSequence: 21})
	view.SetEvents(items)
	view.SetSelectedID("event-20")
	view.PrepareLayout(100, 10, 0, 0)
	assert.Equal(t, 16, view.offset, "following a new last event should scroll by one row")
}

func TestEventsViewNarrowTimelineAndStableSelection(t *testing.T) {
	view := NewEventsView()
	first, second := dnsEvent("one", "example.org"), dnsEvent("two", "example.net")
	view.SetEvents([]EventItem{{Event: first, ArrivalSequence: 1}, {Event: second, ArrivalSequence: 2}})
	view.SelectNext()
	assert.Equal(t, "two", view.SelectedID())
	view.SetEvents([]EventItem{{Event: first, ArrivalSequence: 1}, {Event: second, ArrivalSequence: 2}, {Event: dnsEvent("three", "last.test"), ArrivalSequence: 3}})
	assert.Equal(t, "two", view.SelectedID())
	for _, line := range strings.Split(view.RenderTimeline(24, 2, false), "\n") {
		assert.LessOrEqual(t, len([]rune(line)), 24)
	}
}

func TestEventsViewSanitizesAndBoundsDetails(t *testing.T) {
	event := dnsEvent("one", "bad\nquery\t"+strings.Repeat("x", 800))
	event.Answers = make([]string, 100)
	for i := range event.Answers {
		event.Answers[i] = "answer\nvalue"
	}
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: event, ArrivalSequence: 1}})
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 100, 80, 100)
	details := view.RenderDetails(80, 100, false)
	assert.NotContains(t, details, "bad\nquery")
	assert.Contains(t, details, "query")
	assert.Contains(t, details, "Related packets are no longer buffered.")
	for _, line := range strings.Split(details, "\n") {
		assert.LessOrEqual(t, len([]rune(line)), 82)
	}
}

func TestEventsViewUsesCanonicalLogSchemaFields(t *testing.T) {
	fields := eventFields(dnsEvent("one", "example.org"))
	require.NotEmpty(t, fields)
	assert.Equal(t, "ts", fields[0].Name)
	assert.Equal(t, "time", fields[0].Type)
	assert.True(t, func() bool {
		for _, field := range fields {
			if field.Name == "query" && field.Type == "string" {
				return true
			}
		}
		return false
	}())
}

func TestEventSummaryTrimsMissingLeadingFields(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), EventID: "event"}
	tlsEvent := events.NewTLSEvent(env)
	tlsEvent.Version = "TLS 1.3"
	connEvent := events.NewConnEvent(env)
	connEvent.State = "S0"
	connEvent.Duration = time.Second
	httpEvent := events.NewHTTPEvent(env)
	httpEvent.StatusCode = 200

	for _, event := range []events.Event{tlsEvent, connEvent, httpEvent} {
		summary := eventSummary(event)
		assert.Equal(t, strings.TrimSpace(summary), summary)
		assert.NotEmpty(t, summary)
	}
}

func TestEventsViewProjectsAllMetadataKinds(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), EventID: "event", ProducerSessionID: "session", EventSequence: 4}
	dns := events.NewDNSEvent(env)
	dns.Query = "example.org"
	http := events.NewHTTPEvent(env)
	http.Method = "GET"
	tls := events.NewTLSEvent(env)
	tls.ServerName = "example.org"
	smtp := events.NewSMTPEvent(env)
	smtp.MailFrom = "sender@example.org"
	conn := events.NewConnEvent(env)
	conn.Service = "dns"
	file := events.NewFileMetadataEvent(env)
	file.Filename = "sample.txt"

	for _, event := range []events.Event{dns, http, tls, smtp, conn, file} {
		t.Run(string(event.Kind()), func(t *testing.T) {
			fields := eventFields(event)
			require.NotEmpty(t, fields)
			assert.Equal(t, "ts", fields[0].Name)
		})
	}
}

func TestEventsViewDetailsExposeIdentityAndProvenance(t *testing.T) {
	event := dnsEvent("event-id", "example.org")
	env := event.Envelope()
	env.ProducerSessionID = "producer-session"
	env.EventSequence = 42
	env.Provenance = events.SourceProvenance{CaptureSource: "remote", InterfaceName: "eth0", InterfaceIndex: 2, InputFile: "capture.pcap", ProcessorNodeIDs: []string{"processor-a"}}
	event = events.NewDNSEvent(env)
	event.Query = "example.org"
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: event, ArrivalSequence: 9}})
	view.PrepareLayout(100, 100, 120, 100)
	details := view.RenderDetails(120, 100, false)
	for _, expected := range []string{"Event Identity", "event-id", "producer-session", "Sequence", "42", "Arrival", "9", "Provenance", "remote", "eth0 (index 2)", "capture.pcap", "processor-a"} {
		assert.Contains(t, details, expected)
	}
}

func TestEventsViewDetailsAreStructuredAndScrollable(t *testing.T) {
	event := events.NewTLSEvent(events.Envelope{Timestamp: time.Unix(1, 0), EventID: "event-id", UID: "flow-uid", CommunityID: "community-id"})
	event.Version = "TLS 1.3"
	event.ServerName = "example.org"
	event.Established = true
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: event, ArrivalSequence: 7}})

	view.PrepareLayout(100, 16, 77, 16)
	top := view.RenderDetails(77, 16, false)
	assert.Contains(t, top, "TLS Event")
	assert.Contains(t, top, "Overview")
	assert.Contains(t, top, "Flow")
	assert.NotContains(t, top, "Event Identity")
	assert.NotContains(t, top, "string")

	view.ScrollDetailsToBottom()
	view.PrepareLayout(100, 16, 77, 16)
	bottom := view.RenderDetails(77, 16, false)
	assert.Contains(t, bottom, "Event Identity")
	assert.Contains(t, bottom, "event-id")
	assert.Equal(t, lipgloss.Width(top), lipgloss.Width(bottom))
	assert.Equal(t, lipgloss.Height(top), lipgloss.Height(bottom))
}

func TestEventsViewDetailsScrollResetsForNewSelection(t *testing.T) {
	first := dnsEvent("first", "first.example")
	second := dnsEvent("second", "second.example")
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: first}, {Event: second}})
	view.PrepareLayout(100, 16, 77, 16)
	view.RenderDetails(77, 16, false)
	view.ScrollDetailsToBottom()
	view.SetSelectedID("second")

	view.PrepareLayout(100, 16, 77, 16)
	details := view.RenderDetails(77, 16, false)
	assert.Contains(t, details, "Overview")
	assert.Contains(t, details, "second.example")
	assert.NotContains(t, details, "Event Identity")
}

func TestEventsViewRepeatedAvailabilitySyncPreservesDetailScroll(t *testing.T) {
	event := dnsEvent("event", "example.org")
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: event}})
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 16, 77, 16)
	view.RenderDetails(77, 16, false)
	view.ScrollDetailsToBottom()

	// Reapplying unchanged availability during a presentation refresh must
	// not rebuild the viewport and reset its offset.
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 16, 77, 16)
	details := view.RenderDetails(77, 16, false)
	assert.Contains(t, details, "Event Identity")
	assert.Contains(t, details, "event")
}

func TestEventsViewSetEventsCopiesInputAndPreservesArrivalOrder(t *testing.T) {
	items := []EventItem{
		{Event: dnsEvent("first", "first.example"), ArrivalSequence: 1},
		{Event: dnsEvent("second", "second.example"), ArrivalSequence: 2},
	}
	view := NewEventsView()
	view.SetEvents(items)

	items[0] = EventItem{Event: dnsEvent("replacement", "replacement.example"), ArrivalSequence: 3}
	firstID, firstOK := view.EventIDAtVisibleRow(0)
	secondID, secondOK := view.EventIDAtVisibleRow(1)
	require.True(t, firstOK)
	require.True(t, secondOK)
	assert.Equal(t, "first", firstID)
	assert.Equal(t, "second", secondID)
}

func TestEventsViewAppendPreservesPinnedSelectionAndVisibleRow(t *testing.T) {
	items := make([]EventItem, 20)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "example.org"), ArrivalSequence: uint64(i + 1)}
	}
	view := NewEventsView()
	view.SetEvents(items)
	view.SetSelectedID("event-17")
	view.PrepareLayout(100, 10, 0, 0)
	selectedRow := 17 - view.offset
	selectedID, ok := view.EventIDAtVisibleRow(selectedRow)
	require.True(t, ok)
	require.Equal(t, "event-17", selectedID)

	items = append(items, EventItem{Event: dnsEvent("event-20", "new.example"), ArrivalSequence: 21})
	view.SetEvents(items)

	assert.Equal(t, "event-17", view.SelectedID())
	visibleID, ok := view.EventIDAtVisibleRow(selectedRow)
	require.True(t, ok)
	assert.Equal(t, "event-17", visibleID, "append must not move a selection pinned in history")
}

func TestEventsViewRefreshAfterFrontEvictionKeepsSelectionAtVisibleRow(t *testing.T) {
	items := make([]EventItem, 20)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "example.org"), ArrivalSequence: uint64(i + 1)}
	}
	view := NewEventsView()
	view.SetEvents(items)
	view.SetSelectedID("event-17")
	view.PrepareLayout(100, 10, 0, 0)
	selectedRow := 17 - view.offset

	replacement := append([]EventItem(nil), items[5:]...)
	for i := 20; i < 25; i++ {
		replacement = append(replacement, EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "new.example"), ArrivalSequence: uint64(i + 1)})
	}
	view.SetEvents(replacement)

	assert.Equal(t, "event-17", view.SelectedID())
	visibleID, ok := view.EventIDAtVisibleRow(selectedRow)
	require.True(t, ok)
	assert.Equal(t, "event-17", visibleID, "front eviction must compensate the viewport offset")
}

func TestEventsViewRenderingDoesNotMutatePresentation(t *testing.T) {
	view := NewEventsView()
	items := make([]EventItem, 20)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "example.org")}
	}
	view.SetEvents(items)
	view.SetSelectedID("event-19")
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 10, 77, 16)
	view.ScrollDetailsToBottom()
	before := *view
	before.items = append([]EventItem(nil), view.items...)
	details := view.RenderDetails(77, 16, false)
	timeline := view.View()
	for range 5 {
		assert.Equal(t, timeline, view.View())
		assert.Equal(t, details, view.RenderDetails(77, 16, false))
		// Even render-only geometry/focus changes cannot change hit testing or
		// viewport dimensions. Geometry is committed by PrepareLayout.
		view.RenderTimeline(80, 20, false)
		view.RenderDetails(90, 25, true)
		assert.Equal(t, before, *view)
	}
}

func TestEventsViewLayoutPreparesHitTestingBeforeRendering(t *testing.T) {
	view := NewEventsView()
	items := make([]EventItem, 20)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprintf("event-%d", i), "example.org")}
	}
	view.SetEvents(items)
	view.SetSelectedID("event-19")
	view.PrepareLayout(100, 10, 0, 0)
	id, ok := view.EventIDAtVisibleRow(4)
	require.True(t, ok)
	assert.Equal(t, "event-19", id)
	view.SelectPrevious()
	assert.Equal(t, 15, view.offset)
	view.SetSize(100, 20)
	assert.Equal(t, 5, view.offset)
	view.SetSize(24, 2)
	assert.Equal(t, 0, view.offset, "a viewport with no data rows must not advance beyond the buffer")
}

func TestEventsViewDetailsPreparationPreservesAndInvalidatesCache(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: dnsEvent("first", "first.example")}, {Event: dnsEvent("second", "second.example")}})
	view.SetRelatedPacketsAvailable(true)
	view.PrepareLayout(100, 10, 77, 16)
	view.ScrollDetailsToBottom()
	before := view.detailsViewport
	view.SetEvents(append(append([]EventItem(nil), view.items...), EventItem{Event: dnsEvent("third", "third.example")}))
	view.SetSelectedID("first")
	view.SetRelatedPacketsAvailable(true)
	view.PrepareLayout(100, 10, 77, 16)
	assert.Equal(t, before, view.detailsViewport, "unchanged selection and detail state must retain the scroll cache")

	view.PrepareLayout(100, 10, 0, 0)
	assert.Equal(t, before, view.detailsViewport, "hiding details must retain scroll")
	view.PrepareLayout(100, 10, 77, 16)
	assert.Equal(t, before, view.detailsViewport, "reopening unchanged details must retain scroll")

	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 10, 77, 16)
	assert.Zero(t, view.detailsViewport.YOffset)
	assert.Contains(t, view.RenderDetails(77, 16, false), "Related packets are no longer buffered.")

	view.ScrollDetailsToBottom()
	view.PrepareLayout(100, 10, 90, 16)
	assert.Zero(t, view.detailsViewport.YOffset, "width changes must rewrap detail content")
	assert.Equal(t, 84, view.detailsViewport.Width)
	view.ScrollDetailsToBottom()
	view.SetTheme(view.theme)
	view.PrepareLayout(100, 10, 90, 16)
	assert.Zero(t, view.detailsViewport.YOffset, "theme changes invalidate styled content")

	view.ScrollDetailsToBottom()
	view.SetEvents(nil)
	view.SetEvents([]EventItem{{Event: dnsEvent("first", "replacement.example")}})
	view.PrepareLayout(100, 10, 90, 16)
	assert.Zero(t, view.detailsViewport.YOffset)
	view.SetRelatedPacketsAvailable(true)
	view.PrepareLayout(100, 10, 90, 16)
	assert.Contains(t, view.RenderDetails(90, 16, false), "replacement.example", "clear must invalidate details even if an ID is reused before preparation")
}

// Counting Kind calls detects detail content work without adding a production
// instrumentation hook. The immutable event's ID lookup only calls Envelope.
type detailProjectionCountingEvent struct {
	events.Event
	kindCalls *int
}

func (e detailProjectionCountingEvent) Kind() events.Kind {
	*e.kindCalls++
	return e.Event.Kind()
}

func TestEventsViewPreparesDetailProjectionOnlyWhenInvalidated(t *testing.T) {
	// A five-line timeline has no visible event rows, so Kind calls measure
	// only detail projection rather than legitimate timeline row preparation.
	view := NewEventsView()
	kindCalls := 0
	item := EventItem{Event: detailProjectionCountingEvent{Event: dnsEvent("first", "example.org"), kindCalls: &kindCalls}}
	view.SetEvents([]EventItem{item})
	view.SetRelatedPacketsAvailable(true)
	view.PrepareLayout(100, 5, 77, 16)
	require.Positive(t, kindCalls, "initial layout must prepare details")
	preparedCalls := kindCalls
	for range 5 {
		view.SetEvents([]EventItem{item, {Event: dnsEvent("second", "second.example")}})
		view.SetSelectedID("first")
		view.SetRelatedPacketsAvailable(true)
		view.PrepareLayout(100, 5, 77, 16)
		view.RenderDetails(77, 16, false)
	}
	assert.Equal(t, preparedCalls, kindCalls, "unchanged details must not be projected again during updates or rendering")
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 5, 77, 16)
	assert.Equal(t, 2*preparedCalls, kindCalls, "one invalidation must cause exactly one detail projection")
	view.PrepareLayout(100, 5, 77, 16)
	view.RenderDetails(77, 16, false)
	assert.Equal(t, 2*preparedCalls, kindCalls)
}

func TestEventsViewOfflineLookupPreservesDetailScroll(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: dnsEvent("first", "first.example")}, {Event: dnsEvent("second", "second.example")}})
	view.SetOfflinePacketNavigation(true)
	view.SetRelatedPacketsPending()
	view.PrepareLayout(100, 10, 77, 16)
	view.ScrollDetailsToBottom()
	before := view.detailsViewport.YOffset
	require.Positive(t, before)
	view.SetRelatedPacketsAvailable(true)
	view.PrepareLayout(100, 10, 77, 16)
	assert.Equal(t, before, view.detailsViewport.YOffset)
	view.SetRelatedPacketsAvailable(false)
	view.PrepareLayout(100, 10, 77, 16)
	assert.Equal(t, before, view.detailsViewport.YOffset)
	view.SetSelectedID("second")
	view.PrepareLayout(100, 10, 77, 16)
	assert.Zero(t, view.detailsViewport.YOffset, "selecting another event still resets detail scroll")
}
