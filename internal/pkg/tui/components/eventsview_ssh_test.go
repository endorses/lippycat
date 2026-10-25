//go:build tui || all

package components

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/stretchr/testify/require"
)

func sshPresentationEvent() events.SSHEvent {
	event := events.NewSSHEvent(events.Envelope{EventID: "ssh-presentation", Timestamp: time.Unix(1700000000, 0)})
	event.Role, event.RoleEvidence = events.SSHRoleClient, events.SSHRoleEvidenceTCPSYN
	event.Status, event.Reason = events.SSHStatusComplete, events.SSHReasonKEXComplete
	event.Banner, event.ProtocolVersion, event.SoftwareVersion = "SSH-2.0-TestClient_1.0", "2.0", "TestClient_1.0"
	event.KEXAlgorithms, event.ServerHostKeyAlgorithms = "curve25519-sha256,ext-info-c", "ssh-ed25519"
	event.EncryptionClientServer, event.EncryptionServerClient = "aes128-ctr", "aes256-ctr"
	event.MACClientServer, event.MACServerClient = "hmac-sha2-256", "hmac-sha2-512"
	event.CompressionClientServer, event.CompressionServerClient = "none", "zlib@openssh.com,none"
	event.HASSH, event.HASSHAlgorithms, event.HASSHVersion = "cafb69eb1dbb2a4a505b5b25342a4940", "curve25519-sha256,ext-info-c;aes128-ctr;hmac-sha2-256;none", "1.0"
	return event
}

func TestSSHEventDetailsPreserveCanonicalOrderedEvidence(t *testing.T) {
	event := sshPresentationEvent()
	schema, ok := logschema.ByName("ssh")
	require.True(t, ok)
	positions := make(map[string]int)
	for i, field := range schema.Fields {
		positions[field.Name] = i
	}
	fields := make(map[string]string)
	previous := -1
	for _, field := range eventFields(event) {
		position, present := positions[field.Name]
		require.True(t, present)
		require.Greater(t, position, previous)
		previous = position
		fields[field.Name] = field.Value
	}
	require.Equal(t, "client", fields["role"])
	require.Equal(t, "tcp_syn", fields["role_evidence"])
	require.Equal(t, "complete", fields["status"])
	require.Equal(t, "kex_complete", fields["reason"])
	require.Equal(t, event.Banner, fields["banner"])
	require.Equal(t, event.KEXAlgorithms, fields["kex_algorithms"])
	require.Equal(t, event.EncryptionClientServer, fields["encryption_client_server"])
	require.Equal(t, event.EncryptionServerClient, fields["encryption_server_client"])
	require.Equal(t, event.HASSH, fields["hassh"])
	view := NewEventsView()
	text := view.renderEventDetailsContent(EventItem{Event: event}, 160)
	for _, value := range []string{"SSH Details", "TestClient_1.0", "tcp_syn", "kex_complete", "Encryption C→S", "Encryption S→C", event.KEXAlgorithms, event.HASSH, event.HASSHAlgorithms} {
		require.Contains(t, text, value)
	}
	require.NotContains(t, text, "Unavailable")
	require.NotEqual(t, "📋", eventKindIcon(events.KindSSH))
	require.Equal(t, view.theme.SSHColor, view.eventColor(events.KindSSH))
	require.Contains(t, eventSummary(event), "client")
	require.Contains(t, eventSummary(event), event.HASSH)
}

func TestSSHPartialAndUnknownRoleHaveNoSyntheticFingerprintField(t *testing.T) {
	for _, status := range []events.SSHStatus{events.SSHStatusBanner, events.SSHStatusPartial, events.SSHStatusComplete} {
		t.Run(string(status), func(t *testing.T) {
			event := sshPresentationEvent()
			event.Status = status
			event.HASSH, event.HASSHAlgorithms, event.HASSHVersion = "", "", ""
			event.Role, event.RoleEvidence = events.SSHRoleUnknown, events.SSHRoleEvidenceUnknown
			if status != events.SSHStatusComplete {
				event.Reason = events.SSHReasonIncomplete
			}
			for _, field := range eventFields(event) {
				require.NotEqual(t, "hassh", field.Name)
			}
			view := NewEventsView()
			text := view.renderEventDetailsContent(EventItem{Event: event}, 120)
			require.Contains(t, text, "Unavailable")
			if status == events.SSHStatusComplete {
				require.Contains(t, text, "endpoint role unavailable")
			} else {
				require.Contains(t, text, "complete KEXINIT and proven endpoint role required")
			}
		})
	}
}

func TestSSHDetailsAndTimelineEscapeBannerWithoutChangingEvidence(t *testing.T) {
	event := sshPresentationEvent()
	event.Banner = "SSH-2.0-Client\x1b[31m\nforged"
	original := event.Clone()
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: event}})
	view.PrepareLayout(180, 15, 120, 24)
	before := *view
	for range 2 {
		text := view.renderEventDetailsContent(EventItem{Event: event}, 120)
		require.NotContains(t, text, "\x1b[31m")
		view.RenderTimeline(180, 15, true)
		view.RenderDetails(120, 24, true)
		require.Equal(t, before, *view)
	}
	require.Equal(t, original, event)
	// Ordered algorithms remain data; rendering never sorts negotiation markers.
	require.True(t, strings.HasPrefix(event.KEXAlgorithms, "curve25519-sha256,ext-info-c"))
}
