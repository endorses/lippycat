//go:build tui || all

package components

import (
	"testing"

	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestNoticeTimelineDetailsUseCanonicalEvidenceFields(t *testing.T) {
	event := noticefixture.Event()
	fields := make(map[string]string)
	for _, field := range eventFields(event) {
		fields[field.Name] = field.Value
	}
	require.Equal(t, "processor", fields["detector_node_id"])
	require.Equal(t, "origin-hunter", fields["node_id"])
	require.Equal(t, "0.93", fields["score"])
	require.Contains(t, fields["evidence_uids"], "Cfirst")
	require.Equal(t, "false", fields["evidence_redacted"])
	require.Equal(t, "⚠", eventKindIcon(event.Kind()))
	view := NewEventsView()
	content := view.renderEventDetailsContent(EventItem{Event: event}, 120)
	require.Contains(t, content, "NOTICE Details")
	require.Contains(t, content, "example.test")
	require.Contains(t, content, "analysis-generation")
	require.Contains(t, eventSummary(event), "security example.test")
	event.EvidenceRedacted, event.Evidence, event.DNS.SourceIPs = true, nil, nil
	fields = make(map[string]string)
	for _, field := range eventFields(event) {
		fields[field.Name] = field.Value
	}
	require.Equal(t, "true", fields["evidence_redacted"])
	require.NotContains(t, fields, "evidence_uids")
	require.NotContains(t, fields, "source_ips")
}
