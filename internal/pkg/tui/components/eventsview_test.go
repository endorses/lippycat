//go:build tui || all

package components

import (
	"strings"
	"testing"
	"time"

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
	details := view.RenderDetails(80, 100)
	assert.NotContains(t, details, "bad\nquery")
	assert.Contains(t, details, "query")
	assert.Contains(t, details, "Related packets are no longer buffered.")
	for _, line := range strings.Split(details, "\n") {
		assert.LessOrEqual(t, len([]rune(line)), 80)
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
	details := view.RenderDetails(120, 100)
	for _, expected := range []string{"event-id", "producer-session", "event_sequence: 42", "arrival_sequence: 9", "capture_source: remote", "interface_name: eth0", "input_file: capture.pcap", "processor-a"} {
		assert.Contains(t, details, expected)
	}
}
