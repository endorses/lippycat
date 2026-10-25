package protoadapter

import (
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/sshfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"strconv"
	"strings"
	"testing"
)

func TestSSHRoundTripPreservesDirectionalEvidenceAndRetryIdentity(t *testing.T) {
	client := sshfixture.Event()
	server := client.Clone()
	server.Role = events.SSHRoleServer
	server.HASSH = "bb851e03510687da787151f064db2868"
	server.HASSHAlgorithms = "curve25519-sha256,ext-info-c;aes256-ctr;hmac-sha2-512;zlib@openssh.com,none"
	unknown := client.Clone()
	unknown.Role, unknown.RoleEvidence = events.SSHRoleUnknown, events.SSHRoleEvidenceConflict
	unknown.HASSH, unknown.HASSHAlgorithms, unknown.HASSHVersion = "", "", ""
	for _, e := range []events.SSHEvent{client, server, unknown} {
		for _, input := range []events.Event{e, &e} {
			wire, err := ToProto(input)
			require.NoError(t, err)
			raw, err := proto.Marshal(wire)
			require.NoError(t, err)
			for range 2 {
				var received eventsv1.ProtocolEvent
				require.NoError(t, proto.Unmarshal(raw, &received))
				got, err := DecodeEvent(&received)
				require.NoError(t, err)
				require.Nil(t, got.Omission)
				require.Equal(t, e, got.Event)
				cloned := got.Event.(events.SSHEvent).Clone()
				cloned.EventEnvelope.Provenance.ProcessorNodeIDs[0] = "changed"
				require.Equal(t, "relay", received.Envelope.Provenance.ProcessorNodeIds[0])
				raw, err = proto.Marshal(got.Wire)
				require.NoError(t, err)
			}
		}
	}
}

func TestSSHValidationRejectsFabricatedOrUnboundedFingerprintEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*events.SSHEvent){
		"role":       func(e *events.SSHEvent) { e.Role = "guessed" },
		"evidence":   func(e *events.SSHEvent) { e.RoleEvidence = events.SSHRoleEvidenceUnknown },
		"hash":       func(e *events.SSHEvent) { e.HASSH = "00000000000000000000000000000000" },
		"list-order": func(e *events.SSHEvent) { e.KEXAlgorithms = "ext-info-c,curve25519-sha256" },
		"unknown-role-hash": func(e *events.SSHEvent) {
			e.Role, e.RoleEvidence = events.SSHRoleUnknown, events.SSHRoleEvidenceUnknown
		},
		"partial-hash":   func(e *events.SSHEvent) { e.Status, e.Reason = events.SSHStatusPartial, events.SSHReasonGap },
		"status":         func(e *events.SSHEvent) { e.Status = "success" },
		"reason":         func(e *events.SSHEvent) { e.Reason = events.SSHReasonGap },
		"banner":         func(e *events.SSHEvent) { e.Banner = "SSH-2.0-other" },
		"banner-utf8":    func(e *events.SSHEvent) { e.Banner += "\xff" },
		"banner-control": func(e *events.SSHEvent) { e.Banner += "\x1b" },
		"banner-size":    func(e *events.SSHEvent) { e.Banner = strings.Repeat("a", 1024) },
		"list-size":      func(e *events.SSHEvent) { e.KEXAlgorithms = strings.Repeat("a,", 20000) },
	} {
		t.Run(name, func(t *testing.T) { e := sshfixture.Event(); mutate(&e); _, err := ToProto(e); require.Error(t, err) })
	}
	wire, err := ToProto(sshfixture.Event())
	require.NoError(t, err)
	wire.GetSsh().Hassh = "forged"
	_, err = DecodeEvent(wire)
	require.Error(t, err)
	_, err = ToProto((*events.SSHEvent)(nil))
	require.Error(t, err)
}

func TestSSHBannerEncodingAndIncompleteAvailability(t *testing.T) {
	for _, raw := range []string{"SSH-2.0-client comment\xff", "SSH-2.0-client comment\t"} {
		e := events.NewSSHEvent(sshfixture.Event().Envelope())
		e.Banner, e.BannerEscaped = strconv.QuoteToASCII(raw), true
		e.ProtocolVersion, e.SoftwareVersion = "2.0", "client"
		wire, err := ToProto(e)
		require.NoError(t, err)
		decoded, err := DecodeEvent(wire)
		require.NoError(t, err)
		got := decoded.Event.(events.SSHEvent)
		value, err := strconv.Unquote(got.Banner)
		require.NoError(t, err)
		require.Equal(t, raw, value)
		require.Empty(t, got.HASSH)
		e.Status, e.Reason = events.SSHStatusPartial, events.SSHReasonNoKEX
		_, err = ToProto(e)
		require.NoError(t, err)
	}
	e := events.NewSSHEvent(sshfixture.Event().Envelope())
	e.Status, e.Reason = events.SSHStatusPartial, events.SSHReasonMissingBanner
	_, err := ToProto(e)
	require.NoError(t, err)
}

func TestSSHAdditiveKindAndUnknownPayloadRetention(t *testing.T) {
	require.EqualValues(t, 13, eventsv1.EventKind_EVENT_KIND_SSH)
	wire, err := ToProto(sshfixture.Event())
	require.NoError(t, err)
	payload, err := proto.Marshal(wire.GetSsh())
	require.NoError(t, err)
	wire.Payload = nil
	raw := protowire.AppendTag(nil, 22, protowire.BytesType)
	raw = protowire.AppendBytes(raw, payload)
	wire.ProtoReflect().SetUnknown(raw)
	omitted, err := DecodeEvent(wire)
	require.NoError(t, err)
	require.Equal(t, OmissionUnsupportedKind, omitted.Omission.Reason)
	forwarded, err := proto.Marshal(omitted.Wire)
	require.NoError(t, err)
	var current eventsv1.ProtocolEvent
	require.NoError(t, proto.Unmarshal(forwarded, &current))
	decoded, err := DecodeEvent(&current)
	require.NoError(t, err)
	require.Equal(t, sshfixture.Event(), decoded.Event)
	kinds, err := RequiredKinds([]string{"ssh"})
	require.NoError(t, err)
	require.Equal(t, []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_SSH}, kinds)
	require.Contains(t, SupportedKinds(false), eventsv1.EventKind_EVENT_KIND_SSH)
}
