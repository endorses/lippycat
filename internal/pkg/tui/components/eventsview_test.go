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
	details := view.RenderDetails(60, 20, false)
	assert.Equal(t, 100, lipgloss.Width(timeline))
	assert.Equal(t, 20, lipgloss.Height(timeline))
	assert.Equal(t, 62, lipgloss.Width(details))
	assert.Equal(t, 20, lipgloss.Height(details))
	assert.Contains(t, timeline, "┏")
	assert.Contains(t, details, "╭")

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
	view.RenderTimeline(100, 10, false)
	require.Equal(t, 15, view.offset)

	view.SetSelectedID("event-18")
	view.RenderTimeline(100, 10, false)
	assert.Equal(t, 15, view.offset, "moving up should leave the bottom row visible")

	items = append(items, EventItem{Event: dnsEvent("event-20", "example.org"), ArrivalSequence: 21})
	view.SetEvents(items)
	view.SetSelectedID("event-20")
	view.RenderTimeline(100, 10, false)
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

	top := view.RenderDetails(77, 16, false)
	assert.Contains(t, top, "TLS Event")
	assert.Contains(t, top, "Overview")
	assert.Contains(t, top, "Flow")
	assert.NotContains(t, top, "Event Identity")
	assert.NotContains(t, top, "string")

	view.ScrollDetailsToBottom()
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
	view.RenderDetails(77, 16, false)
	view.ScrollDetailsToBottom()
	view.SetSelectedID("second")

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
	view.RenderDetails(77, 16, false)
	view.ScrollDetailsToBottom()

	// The model synchronizes this state before every render. Reapplying an
	// unchanged value must not rebuild the viewport and reset its offset.
	view.SetRelatedPacketsAvailable(false)
	details := view.RenderDetails(77, 16, false)
	assert.Contains(t, details, "Event Identity")
	assert.Contains(t, details, "event")
}
