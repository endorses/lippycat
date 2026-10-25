package protoadapter

import (
	"math"
	"net/netip"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestNoticeRoundTripRetainsIdentityAuthorityAndOwnedEvidence(t *testing.T) {
	want := noticefixture.Event()
	for _, input := range []events.Event{want, &want} {
		wire, err := ToProto(input)
		require.NoError(t, err)
		encoded, err := proto.Marshal(wire)
		require.NoError(t, err)
		var received eventsv1.ProtocolEvent
		require.NoError(t, proto.Unmarshal(encoded, &received))
		for range 2 { // Serialization/retry never assigns another identity.
			decoded, err := DecodeEvent(&received)
			require.NoError(t, err)
			require.Nil(t, decoded.Omission)
			require.Equal(t, want, decoded.Event)
			copy := decoded.Event.(events.NoticeEvent)
			copy.Evidence[0].UID = "changed"
			copy.DNS.SourceIPs[0] = netip.MustParseAddr("203.0.113.1")
			require.Equal(t, "Cfirst", want.Evidence[0].UID)
			require.Equal(t, "192.0.2.1", received.GetNotice().Dns.SourceIps[0])
			encoded, err = proto.Marshal(decoded.Wire)
			require.NoError(t, err)
			require.NoError(t, proto.Unmarshal(encoded, &received))
		}
	}
}

func TestNoticeValidationRejectsUnboundedOrAmbiguousEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*events.NoticeEvent){
		"schema":             func(e *events.NoticeEvent) { e.SchemaVersion++ },
		"detector authority": func(e *events.NoticeEvent) { e.DetectorGeneration = "" },
		"severity":           func(e *events.NoticeEvent) { e.Severity = "unknown" },
		"status":             func(e *events.NoticeEvent) { e.Status = "unknown" },
		"missing DNS":        func(e *events.NoticeEvent) { e.DNS = nil },
		"invalid domain":     func(e *events.NoticeEvent) { e.DNS.Domain = "bad\nname" },
		"not finite":         func(e *events.NoticeEvent) { e.DNS.Score = math.NaN() },
		"threshold":          func(e *events.NoticeEvent) { e.DNS.Threshold = 2 },
		"below threshold":    func(e *events.NoticeEvent) { e.DNS.Score = 0.6 },
		"entropy":            func(e *events.NoticeEvent) { e.DNS.Entropy = math.Inf(1) },
		"queries":            func(e *events.NoticeEvent) { e.DNS.Queries = 0 },
		"unique subdomains":  func(e *events.NoticeEvent) { e.DNS.UniqueSubdomains = 51 },
		"source order": func(e *events.NoticeEvent) {
			e.DNS.SourceIPs[0], e.DNS.SourceIPs[1] = e.DNS.SourceIPs[1], e.DNS.SourceIPs[0]
		},
		"source duplicate": func(e *events.NoticeEvent) { e.DNS.SourceIPs[1] = e.DNS.SourceIPs[0] },
		"source mapped":    func(e *events.NoticeEvent) { e.DNS.SourceIPs[0] = netip.MustParseAddr("::ffff:192.0.2.1") },
		"source bound":     func(e *events.NoticeEvent) { e.DNS.SourceIPs = make([]netip.Addr, MaxCollectionEntries+1) },
		"reference bound": func(e *events.NoticeEvent) {
			e.Evidence = make([]events.NoticeEvidenceReference, MaxCollectionEntries+1)
		},
		"reference missing":   func(e *events.NoticeEvent) { e.Evidence = nil },
		"reference future":    func(e *events.NoticeEvent) { e.Evidence[1].Timestamp = time.Unix(101, 0) },
		"reference order":     func(e *events.NoticeEvent) { e.Evidence[0], e.Evidence[1] = e.Evidence[1], e.Evidence[0] },
		"reference duplicate": func(e *events.NoticeEvent) { e.Evidence[1] = e.Evidence[0] },
		"false redaction":     func(e *events.NoticeEvent) { e.EvidenceRedacted = true },
	} {
		t.Run(name, func(t *testing.T) {
			e := noticefixture.Event()
			mutate(&e)
			_, err := ToProto(e)
			require.Error(t, err)
		})
	}
}

func TestNoticeRedactionAndCapacityTruncationRemainDistinct(t *testing.T) {
	e := noticefixture.Event()
	e.EvidenceRedacted, e.Evidence, e.DNS.SourceIPs = true, nil, nil
	wire, err := ToProto(e)
	require.NoError(t, err)
	got, omission, err := FromProto(wire)
	require.NoError(t, err)
	require.Nil(t, omission)
	require.Equal(t, e, got)
	require.False(t, got.(events.NoticeEvent).EvidenceTruncated)
	require.False(t, got.(events.NoticeEvent).DNS.SourceIPsTruncated)
}

func TestNoticeMalformedWireAndLegacyOmission(t *testing.T) {
	e := noticefixture.Event()
	wire, err := ToProto(e)
	require.NoError(t, err)
	for _, mutate := range []func(*eventsv1.ProtocolEvent){
		func(p *eventsv1.ProtocolEvent) { p.Payload = (*eventsv1.ProtocolEvent_Notice)(nil) },
		func(p *eventsv1.ProtocolEvent) { p.Payload = &eventsv1.ProtocolEvent_Notice{} },
		func(p *eventsv1.ProtocolEvent) { p.GetNotice().Evidence[0] = nil },
		func(p *eventsv1.ProtocolEvent) { p.GetNotice().Evidence[0].Timestamp = nil },
		func(p *eventsv1.ProtocolEvent) { p.GetNotice().Dns.SourceIps[0] = "192.0.002.1" },
	} {
		copy := proto.Clone(wire).(*eventsv1.ProtocolEvent)
		mutate(copy)
		_, _, err := FromProto(copy)
		require.Error(t, err)
	}
	_, err = ToProto((*events.NoticeEvent)(nil))
	require.Error(t, err)
	// A decoder without the notice oneof alternative retains its opaque field
	// and reports a compatibility omission, rather than fabricating a DNS row.
	payload, err := proto.Marshal(wire.GetNotice())
	require.NoError(t, err)
	unknown := protowire.AppendBytes(protowire.AppendTag(nil, 21, protowire.BytesType), payload)
	wire.Payload = nil
	wire.ProtoReflect().SetUnknown(unknown)
	decoded, err := DecodeEvent(wire)
	require.NoError(t, err)
	require.Nil(t, decoded.Event)
	require.Equal(t, OmissionUnsupportedKind, decoded.Omission.Reason)
	require.Equal(t, unknown, []byte(decoded.Wire.ProtoReflect().GetUnknown()))
	kinds, err := RequiredKinds([]string{"notice", "dns", "notice"})
	require.NoError(t, err)
	require.Equal(t, []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_NOTICE}, kinds)
}
