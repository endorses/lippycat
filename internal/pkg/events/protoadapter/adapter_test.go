package protoadapter

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func testEnvelope(seq uint64) events.Envelope {
	return events.Envelope{Timestamp: time.Unix(123, 456).UTC(), EventID: events.DeliveryEventID("node", "session", seq), ProducerSessionID: "session", EventSequence: seq, UID: "Cuid", CommunityID: "1:community", NodeID: "node", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("2001:db8::2"), SourcePort: 1234, DestinationPort: 443}, Partial: true, CaptureScope: events.CaptureScopeFiltered, Provenance: events.SourceProvenance{CaptureSource: "pcap", InterfaceName: "eth0", InterfaceIndex: 2, InputFile: "sample.pcap", ProcessorNodeIDs: []string{"p1", "p2"}}}
}

func TestEveryMetadataEventPointerRoundTrips(t *testing.T) {
	for _, want := range allEvents() {
		want := want
		t.Run(string(want.Kind()), func(t *testing.T) {
			var pointer events.Event
			switch e := want.(type) {
			case events.ConnEvent:
				pointer = &e
			case events.DNSEvent:
				pointer = &e
			case events.TLSEvent:
				pointer = &e
			case events.HTTPEvent:
				pointer = &e
			case events.SMTPEvent:
				pointer = &e
			case events.FileMetadataEvent:
				pointer = &e
			}
			wire, err := ToProto(pointer)
			require.NoError(t, err)
			got, omission, err := FromProto(wire)
			require.NoError(t, err)
			require.Nil(t, omission)
			require.Equal(t, want, got)
		})
	}
}

func TestTypedNilEventPointerIsRejected(t *testing.T) {
	var dns *events.DNSEvent
	_, err := ToProto(dns)
	require.ErrorContains(t, err, "nil DNS pointer")
}

func allEvents() []events.Event {
	env := testEnvelope(1)
	conn := events.NewConnEvent(env)
	conn.Service, conn.Duration, conn.OriginBytes, conn.ResponseBytes, conn.State, conn.LocalOrigin, conn.LocalResponse, conn.MissedBytes, conn.History, conn.OriginPackets, conn.OriginIPBytes, conn.ResponsePackets, conn.ResponseIPBytes = "http", time.Second+3, 1, 2, "SF", true, false, 4, "ShAD", 5, 6, 7, 8
	dns := events.NewDNSEvent(env)
	dns.IsResponse, dns.TransactionID, dns.RTT, dns.Query, dns.QClass, dns.QType, dns.RCode, dns.Authoritative, dns.Truncated, dns.RecursionDesired, dns.RecursionAvailable, dns.Z, dns.Answers, dns.TTLs, dns.Rejected = true, 42, 7*time.Millisecond, "example.test", 1, 28, 3, true, true, true, true, 2, []string{"2001:db8::1"}, []time.Duration{30 * time.Second}, true
	tls := events.NewTLSEvent(env)
	tls.Version, tls.Cipher, tls.Curve, tls.ServerName, tls.Resumed, tls.LastAlert, tls.NextProtocol, tls.Established, tls.CertificateFileIDs, tls.ClientCertificateFileIDs, tls.Subject, tls.Issuer, tls.ClientSubject, tls.ClientIssuer, tls.ValidationStatus, tls.JA3, tls.JA3S, tls.JA4 = "1.3", "cipher", "curve", "example", true, "alert", "h2", true, []string{"f1"}, []string{"f2"}, "s", "i", "cs", "ci", "ok", "j3", "j3s", "j4"
	http := events.NewHTTPEvent(env)
	http.TransactionDepth, http.Method, http.Host, http.URI, http.Referrer, http.Version, http.UserAgent, http.Origin, http.RequestBodyLength, http.ResponseBodyLength, http.StatusCode, http.InformationalCode, http.StatusMessage, http.InformationalMessage, http.Tags, http.Username, http.Proxies, http.RequestFileIDs, http.RequestFilenames, http.RequestMIMETypes, http.ResponseFileIDs, http.ResponseFilenames, http.ResponseMIMETypes, http.Headers = 3, "POST", "host", "/uri", "ref", "1.1", "ua", "origin", 10, 20, 201, 103, "Created", "Hints", []string{"tag"}, "user", []string{"proxy"}, []string{"rf"}, []string{"rn"}, []string{"rt"}, []string{"sf"}, []string{"sn"}, []string{"st"}, map[string][]string{"x": {"a", "b"}}
	smtp := events.NewSMTPEvent(env)
	smtp.TransactionDepth, smtp.HELO, smtp.MailFrom, smtp.Recipients, smtp.Date, smtp.From, smtp.To, smtp.CC, smtp.ReplyTo, smtp.MessageID, smtp.InReplyTo, smtp.Subject, smtp.OriginatingIP, smtp.Received, smtp.LastReply, smtp.Path, smtp.UserAgent, smtp.TLS, smtp.FileIDs, smtp.IsWebmail = 2, "helo", "from", []string{"r"}, "date", "f", []string{"to"}, []string{"cc"}, "reply", "id", "parent", "subject", netip.MustParseAddr("192.0.2.9"), []string{"received"}, "250", []string{"path"}, "ua", true, []string{"file"}, true
	file := events.NewFileMetadataEvent(env)
	file.FileID, file.Source, file.Depth, file.Analyzers, file.MIMEType, file.Filename, file.Duration, file.LocalOrigin, file.IsOrigin, file.SeenBytes, file.TotalBytes, file.MissingBytes, file.OverflowBytes, file.TimedOut, file.ParentFileID, file.MD5, file.SHA1, file.SHA256, file.ExtractedPath, file.HashComplete = "fid", "HTTP", 2, []string{"sha256"}, "text/plain", "a.txt", time.Second, true, true, 1, 2, 3, 4, true, "parent", "md5", "sha1", "sha256", "/tmp/a", true
	return []events.Event{conn, dns, tls, http, smtp, file}
}

func TestEveryMetadataEventRoundTrips(t *testing.T) {
	for _, want := range allEvents() {
		t.Run(string(want.Kind()), func(t *testing.T) {
			wire, err := ToProto(want)
			require.NoError(t, err)
			got, omission, err := FromProto(wire)
			require.NoError(t, err)
			require.Nil(t, omission)
			require.Equal(t, want, got)
		})
	}
}

func TestFileContentRejected(t *testing.T) {
	_, err := ToProto(events.NewFileContentEvent(testEnvelope(1)))
	require.ErrorIs(t, err, ErrFileContentDisallowed)
}

func TestMalformedInputs(t *testing.T) {
	valid, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	tests := map[string]func(*eventsv1.ProtocolEvent){"missing envelope": func(p *eventsv1.ProtocolEvent) { p.Envelope = nil }, "bad port": func(p *eventsv1.ProtocolEvent) { p.Envelope.Flow.SourcePort = 65536 }, "identity mismatch": func(p *eventsv1.ProtocolEvent) { p.Envelope.EventId = "different" }, "forged event ID": func(p *eventsv1.ProtocolEvent) { p.EventId, p.Envelope.EventId = "forged", "forged" }, "invalid address": func(p *eventsv1.ProtocolEvent) { p.Envelope.Flow.SourceAddress = "bad" }, "unknown scope": func(p *eventsv1.ProtocolEvent) { p.Envelope.CaptureScope = 99 }}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := proto.Clone(valid).(*eventsv1.ProtocolEvent)
			mutate(p)
			_, _, err := FromProto(p)
			require.Error(t, err)
		})
	}
}

func TestDurationOutsideGoRangeIsRejected(t *testing.T) {
	valid, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	valid.GetConn().Duration = &durationpb.Duration{Seconds: 10_000_000_000}

	_, _, err = FromProto(valid)
	require.ErrorContains(t, err, "outside Go duration range")
}

func TestUnknownPayloadIsCompatibilityOmissionAndPreserved(t *testing.T) {
	raw := protowire.AppendTag(nil, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("future"))
	wire, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	wire.Payload = nil
	wire.ProtoReflect().SetUnknown(raw)
	decoded, err := DecodeEvent(wire)
	require.NoError(t, err)
	require.Nil(t, decoded.Event)
	require.Equal(t, OmissionUnsupportedKind, decoded.Omission.Reason)
	round, err := proto.Marshal(decoded.Wire)
	require.NoError(t, err)
	var preserved eventsv1.ProtocolEvent
	require.NoError(t, proto.Unmarshal(round, &preserved))
	require.Equal(t, raw, []byte(preserved.ProtoReflect().GetUnknown()))
}

func TestScalarUnknownFieldDoesNotSubstituteForMissingPayload(t *testing.T) {
	raw := protowire.AppendTag(nil, 99, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 1)
	wire, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	wire.Payload = nil
	wire.ProtoReflect().SetUnknown(raw)

	_, err = DecodeEvent(wire)
	require.ErrorContains(t, err, "missing payload")
}

func TestMalformedUnknownFieldIsRejectedWithUnknownPayload(t *testing.T) {
	raw := protowire.AppendTag(nil, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("future"))
	raw = append(raw, 0x80)
	wire, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	wire.Payload = nil
	wire.ProtoReflect().SetUnknown(raw)

	_, err = DecodeEvent(wire)
	require.ErrorContains(t, err, "malformed unknown field")
}

func TestUnknownPayloadStillRequiresValidEnvelope(t *testing.T) {
	raw := protowire.AppendTag(nil, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("future"))
	var wire eventsv1.ProtocolEvent
	require.NoError(t, proto.Unmarshal(raw, &wire))
	_, err := DecodeEvent(&wire)
	require.ErrorContains(t, err, "missing envelope")
}

func TestNestedUnknownFieldsAreBounded(t *testing.T) {
	wire, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	wire.Envelope.Flow.ProtoReflect().SetUnknown(make([]byte, MaxUnknownBytes+1))

	_, err = DecodeEvent(wire)
	require.ErrorContains(t, err, "unknown fields exceed")
}

func TestBatchUnknownFieldsAreBounded(t *testing.T) {
	wire, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	loss := &eventsv1.EventLoss{
		Kind:                eventsv1.LossKind_LOSS_KIND_CAPTURE,
		Count:               1,
		SourceNodeId:        "node",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 2, Last: 2}},
	}
	loss.EventSequenceRanges[0].ProtoReflect().SetUnknown(make([]byte, MaxUnknownBytes+1))
	batch := &eventsv1.ProtocolEventBatch{
		SourceNodeId:       "node",
		ProducerSessionId:  "session",
		BatchSequence:      1,
		Events:             []*eventsv1.ProtocolEvent{wire},
		Stats:              &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}},
		FirstEventSequence: 1,
		LastEventSequence:  1,
	}

	require.ErrorContains(t, ValidateBatch(batch), "unknown fields exceed")
}

func TestMixedCapabilityBatchSkipsUnsupported(t *testing.T) {
	supported, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	raw := protowire.AppendTag(nil, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("future"))
	unknown := proto.Clone(supported).(*eventsv1.ProtocolEvent)
	unknown.Payload = nil
	unknown.ProtoReflect().SetUnknown(raw)
	unknown.EventSequence = 2
	unknown.Envelope.EventSequence = 2
	unknown.EventId = events.DeliveryEventID("node", "session", 2)
	unknown.Envelope.EventId = unknown.EventId
	b := &eventsv1.ProtocolEventBatch{SourceNodeId: "node", ProducerSessionId: "session", BatchSequence: 1, Events: []*eventsv1.ProtocolEvent{supported, unknown}, FirstEventSequence: 1, LastEventSequence: 2}
	got, omissions, err := DecodeBatch(b)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, omissions, 1)
}

func TestValidationBoundsAndBatchOrdering(t *testing.T) {
	e := events.NewHTTPEvent(testEnvelope(1))
	e.URI = strings.Repeat("x", MaxStringBytes+1)
	_, err := ToProto(e)
	require.Error(t, err)
	p, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	b := &eventsv1.ProtocolEventBatch{SourceNodeId: "node", ProducerSessionId: "session", BatchSequence: 1, Events: []*eventsv1.ProtocolEvent{p}, FirstEventSequence: 2, LastEventSequence: 2}
	require.Error(t, ValidateBatch(b))
	conn := events.NewConnEvent(testEnvelope(1))
	conn.Duration = -time.Second
	_, err = ToProto(conn)
	require.Error(t, err)
	dns := events.NewDNSEvent(testEnvelope(1))
	dns.TTLs = []time.Duration{-time.Second}
	_, err = ToProto(dns)
	require.Error(t, err)
	file := events.NewFileMetadataEvent(testEnvelope(1))
	file.Duration = -time.Second
	_, err = ToProto(file)
	require.Error(t, err)
}

func TestBatchRoundTripAndLossValidation(t *testing.T) {
	input := allEvents()[:2]
	// Give the second event the next producer sequence.
	dns := input[1].(events.DNSEvent)
	dns = events.NewDNSEvent(testEnvelope(2))
	input[1] = dns
	stats := &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_CAPTURE, Count: 2, SourceNodeId: "node", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 3, Last: 4}}}}}
	b, err := ToProtoBatch("node", "session", 1, input, stats, 1)
	require.NoError(t, err)
	got, omissions, err := DecodeBatch(b)
	require.NoError(t, err)
	require.Empty(t, omissions)
	require.Equal(t, input, got)
	b.Stats.Losses[0].EventSequenceRanges[0].Last = 0
	require.Error(t, ValidateBatch(b))
}

func TestBatchValidationAllowsReportedSequenceGaps(t *testing.T) {
	first, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	last, err := ToProto(allEvents()[1])
	require.NoError(t, err)
	last.EventSequence = 3
	last.EventId = events.DeliveryEventID("node", "session", 3)
	last.Envelope.EventSequence = 3
	last.Envelope.EventId = last.EventId

	loss := &eventsv1.EventLoss{
		Kind:                eventsv1.LossKind_LOSS_KIND_DISPATCH,
		Count:               1,
		SourceNodeId:        "node",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 2, Last: 2}},
	}
	batch := &eventsv1.ProtocolEventBatch{
		SourceNodeId:       "node",
		ProducerSessionId:  "session",
		BatchSequence:      1,
		Events:             []*eventsv1.ProtocolEvent{first, last},
		Stats:              &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}},
		FirstEventSequence: 1,
		LastEventSequence:  3,
	}
	require.NoError(t, ValidateBatch(batch))
	batch.Stats = nil
	require.ErrorContains(t, ValidateBatch(batch), "is not reported")
	batch.Stats = &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}}

	batch.Events[0], batch.Events[1] = batch.Events[1], batch.Events[0]
	require.ErrorContains(t, ValidateBatch(batch), "out of sequence")
}

func TestBatchValidationRejectsMalformedMember(t *testing.T) {
	event, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	batch := &eventsv1.ProtocolEventBatch{SourceNodeId: "node", ProducerSessionId: "session", BatchSequence: 1, Events: []*eventsv1.ProtocolEvent{event}, FirstEventSequence: 1, LastEventSequence: 1}

	event.EventId = "forged"
	event.Envelope.EventId = "forged"
	require.ErrorContains(t, ValidateBatch(batch), "event ID does not match")

	event.EventId = events.DeliveryEventID("node", "session", 1)
	event.Envelope.EventId = event.EventId
	event.Envelope.Flow.SourceAddress = "invalid"
	require.ErrorContains(t, ValidateBatch(batch), "decode source address")
}

func TestBatchValidationRejectsContradictoryLossAccounting(t *testing.T) {
	first, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	last, err := ToProto(allEvents()[1])
	require.NoError(t, err)
	last.EventSequence = 3
	last.EventId = events.DeliveryEventID("node", "session", 3)
	last.Envelope.EventSequence = 3
	last.Envelope.EventId = last.EventId
	loss := &eventsv1.EventLoss{Kind: eventsv1.LossKind_LOSS_KIND_DISPATCH, Count: 1, SourceNodeId: "other", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 2, Last: 2}}}
	batch := &eventsv1.ProtocolEventBatch{SourceNodeId: "node", ProducerSessionId: "session", BatchSequence: 1, Events: []*eventsv1.ProtocolEvent{first, last}, Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}}, FirstEventSequence: 1, LastEventSequence: 3}

	require.ErrorContains(t, ValidateBatch(batch), "source does not match")
	loss.SourceNodeId = "node"
	loss.Count = 0
	require.ErrorContains(t, ValidateBatch(batch), "count must be positive")
	loss.Count = 2
	loss.EventSequenceRanges = []*eventsv1.SequenceRange{{First: 2, Last: 3}, {First: 3, Last: 4}}
	require.ErrorContains(t, ValidateBatch(batch), "overlap")
	loss.EventSequenceRanges = []*eventsv1.SequenceRange{{First: 1, Last: ^uint64(0)}}
	require.ErrorContains(t, ValidateBatch(batch), "overflows")

	loss.Count = 1
	loss.EventSequenceRanges = []*eventsv1.SequenceRange{{First: 1, Last: 1}}
	require.ErrorContains(t, ValidateBatch(batch), "overlaps a delivered event")

	loss.EventSequenceRanges = []*eventsv1.SequenceRange{{First: 2, Last: 2}}
	duplicate := proto.Clone(loss).(*eventsv1.EventLoss)
	duplicate.Kind = eventsv1.LossKind_LOSS_KIND_TRANSPORT
	batch.Stats.Losses = []*eventsv1.EventLoss{loss, duplicate}
	require.ErrorContains(t, ValidateBatch(batch), "overlap across loss records")
}

func TestBatchValidationRejectsInvalidCountOnlyLoss(t *testing.T) {
	event, err := ToProto(allEvents()[0])
	require.NoError(t, err)
	loss := &eventsv1.EventLoss{Kind: eventsv1.LossKind_LOSS_KIND_CAPTURE, Count: 1, SourceNodeId: "other"}
	batch := &eventsv1.ProtocolEventBatch{
		SourceNodeId: "node", ProducerSessionId: "session", BatchSequence: 1,
		Events: []*eventsv1.ProtocolEvent{event}, Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}},
		FirstEventSequence: 1, LastEventSequence: 1,
	}

	require.ErrorContains(t, ValidateBatch(batch), "source does not match")
	loss.SourceNodeId = "node"
	loss.Count = 0
	require.ErrorContains(t, ValidateBatch(batch), "count must be positive")
}

func TestNilPayloadIsMalformedWithoutUnknownKind(t *testing.T) {
	_, _, err := FromProto(&eventsv1.ProtocolEvent{})
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrFileContentDisallowed))
}
