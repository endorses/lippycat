//go:build tui || all

package components

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

const (
	maxEventFieldRunes = 512
	maxEventListItems  = 64
)

// EventItem is the immutable presentation record retained by EventStore.
type EventItem struct {
	Event           events.Event
	ArrivalSequence uint64
	ArrivedAt       time.Time
}

// EventsView renders a protocol-neutral event timeline and detail panel.
type EventsView struct {
	items                   []EventItem
	selectedID              string
	width, height           int
	theme                   themes.Theme
	relatedPacketsKnown     bool
	relatedPacketsAvailable bool
}

func NewEventsView() *EventsView { return &EventsView{theme: themes.Solarized()} }

func (v *EventsView) SetTheme(theme themes.Theme) { v.theme = theme }
func (v *EventsView) SetSize(width, height int)   { v.width, v.height = width, height }

func (v *EventsView) SetEvents(items []EventItem) {
	v.items = append(v.items[:0], items...)
	if v.indexByID(v.selectedID) >= 0 {
		return
	}
	if len(v.items) == 0 {
		v.selectedID = ""
		return
	}
	v.selectedID = v.items[0].Event.Envelope().EventID
}

func (v *EventsView) SetSelectedID(id string) {
	if v.indexByID(id) >= 0 {
		v.selectedID = id
	}
}

func (v *EventsView) SelectedID() string { return v.selectedID }

func (v *EventsView) SelectNext() {
	i := v.indexByID(v.selectedID)
	if i >= 0 && i+1 < len(v.items) {
		v.selectedID = v.items[i+1].Event.Envelope().EventID
	}
}

func (v *EventsView) SelectPrevious() {
	i := v.indexByID(v.selectedID)
	if i > 0 {
		v.selectedID = v.items[i-1].Event.Envelope().EventID
	}
}

// SetRelatedPacketsAvailable controls the explicit packet-eviction notice.
func (v *EventsView) SetRelatedPacketsAvailable(available bool) {
	v.relatedPacketsKnown = true
	v.relatedPacketsAvailable = available
}

func (v *EventsView) RenderTimeline(width, height int, focused bool) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	if len(v.items) == 0 {
		return lipgloss.NewStyle().Width(width).Render("No protocol events")
	}
	selected := v.indexByID(v.selectedID)
	if selected < 0 {
		selected = 0
	}
	start := selected - height + 1
	if start < 0 {
		start = 0
	}
	end := min(start+height, len(v.items))
	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		item := v.items[i]
		env := item.Event.Envelope()
		marker := " "
		style := lipgloss.NewStyle()
		if i == selected {
			marker = ">"
			if focused {
				style = style.Foreground(v.theme.SelectionFg).Background(v.theme.SelectionBg).Bold(true)
			}
		}
		endpoints := fmt.Sprintf("%s:%d -> %s:%d", env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort)
		line := fmt.Sprintf("%s %s %-13s %-16s %-35s %s", marker, env.Timestamp.Format("15:04:05.000"), item.Event.Kind(), compactNode(env.NodeID), endpoints, eventSummary(item.Event))
		rows = append(rows, style.Render(truncateRunes(sanitizeEventText(line), width)))
	}
	return strings.Join(rows, "\n")
}

func (v *EventsView) RenderDetails(width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	i := v.indexByID(v.selectedID)
	if i < 0 {
		return "No event selected"
	}
	item := v.items[i]
	env := item.Event.Envelope()
	lines := []string{
		fmt.Sprintf("%s event", strings.ToUpper(string(item.Event.Kind()))),
		"event_id: " + env.EventID,
		"producer_session_id: " + env.ProducerSessionID,
		fmt.Sprintf("event_sequence: %d", env.EventSequence),
		fmt.Sprintf("arrival_sequence: %d", item.ArrivalSequence),
		"capture_source: " + env.Provenance.CaptureSource,
		"interface_name: " + env.Provenance.InterfaceName,
		fmt.Sprintf("interface_index: %d", env.Provenance.InterfaceIndex),
		"input_file: " + env.Provenance.InputFile,
		"processor_node_ids: " + boundedValue(env.Provenance.ProcessorNodeIDs),
	}
	if v.relatedPacketsKnown && !v.relatedPacketsAvailable {
		lines = append(lines[:1], append([]string{"Related packets are no longer buffered.", ""}, lines[1:]...)...)
	}
	for _, field := range eventFields(item.Event) {
		lines = append(lines, fmt.Sprintf("%-18s %-16s %s", field.Name, field.Type, field.Value))
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = truncateRunes(sanitizeEventText(lines[i]), width)
	}
	return strings.Join(lines, "\n")
}

// View renders the full-width timeline using the configured dimensions.
func (v *EventsView) View() string { return v.RenderTimeline(v.width, v.height, true) }

func (v *EventsView) indexByID(id string) int {
	for i, item := range v.items {
		if item.Event != nil && item.Event.Envelope().EventID == id {
			return i
		}
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
	for _, canonical := range schema.Fields {
		value, present := canonicalEventValue(event, canonical.Name)
		if !present {
			continue
		}
		fields = append(fields, eventField{Name: canonical.Name, Type: canonical.Type, Value: sanitizeEventText(value)})
	}
	return fields
}

func canonicalEventValue(event events.Event, name string) (string, bool) {
	env := event.Envelope()
	common := map[string]string{"ts": env.Timestamp.Format(time.RFC3339Nano), "uid": env.UID, "id.orig_h": env.Flow.SourceAddress.String(), "id.orig_p": fmt.Sprint(env.Flow.SourcePort), "id.resp_h": env.Flow.DestinationAddress.String(), "id.resp_p": fmt.Sprint(env.Flow.DestinationPort), "proto": fmt.Sprint(env.Flow.Protocol), "community_id": env.CommunityID, "node_id": env.NodeID, "capture_scope": string(env.CaptureScope), "partial": fmt.Sprint(env.Partial)}
	if value, ok := common[name]; ok {
		return value, true
	}
	values := eventSpecificValues(event)
	value, ok := values[name]
	return value, ok
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
	switch e := event.(type) {
	case events.DNSEvent:
		return fmt.Sprintf("%s qtype=%d rcode=%d", e.Query, e.QType, e.RCode)
	case events.HTTPEvent:
		return fmt.Sprintf("%s %s%s status=%d", e.Method, e.Host, e.URI, e.StatusCode)
	case events.TLSEvent:
		return fmt.Sprintf("%s %s %s", e.ServerName, e.Version, e.ValidationStatus)
	case events.SMTPEvent:
		return fmt.Sprintf("%s -> %s %s", e.MailFrom, strings.Join(e.Recipients, ","), e.Subject)
	case events.ConnEvent:
		return fmt.Sprintf("%s %s %s", e.Service, e.State, e.Duration)
	case events.FileMetadataEvent:
		return fmt.Sprintf("%s %s %dB", e.Filename, e.MIMEType, e.SeenBytes)
	default:
		return ""
	}
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
