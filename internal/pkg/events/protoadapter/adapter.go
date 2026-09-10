// Package protoadapter converts output-neutral events to and from the v1 wire contract.
package protoadapter

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MaxBatchEvents       = 4096
	MaxStringBytes       = 1 << 20
	MaxCollectionEntries = 4096
	MaxHeaderEntries     = 512
	MaxHeaderValues      = 4096
	MaxUnknownBytes      = 1 << 20
)

var ErrFileContentDisallowed = errors.New("file content events are not allowed on the protocol event transport")

type OmissionReason string

const OmissionUnsupportedKind OmissionReason = "unsupported_kind"

// CompatibilityOmission reports a value a newer peer sent which this API can skip.
type CompatibilityOmission struct {
	Reason OmissionReason
}

// DecodedEvent retains the original wire value, including unknown protobuf fields.
// Forwarders which do not alter an event should marshal Wire rather than rebuilding it.
type DecodedEvent struct {
	Event    events.Event
	Wire     *eventsv1.ProtocolEvent
	Omission *CompatibilityOmission
}

func DecodeEvent(in *eventsv1.ProtocolEvent) (DecodedEvent, error) {
	if in == nil {
		return DecodedEvent{}, errors.New("decode protocol event: nil event")
	}
	if err := validateUnknownFields("decode protocol event", in); err != nil {
		return DecodedEvent{}, err
	}
	wire := proto.Clone(in).(*eventsv1.ProtocolEvent)
	env, err := decodeEnvelope(in)
	if err != nil {
		return DecodedEvent{}, err
	}
	if in.Payload == nil {
		unknownPayload, err := hasUnknownMessageField(in.ProtoReflect().GetUnknown())
		if err != nil {
			return DecodedEvent{}, fmt.Errorf("decode protocol event: malformed unknown field: %w", err)
		}
		if unknownPayload {
			return DecodedEvent{Wire: wire, Omission: &CompatibilityOmission{Reason: OmissionUnsupportedKind}}, nil
		}
		return DecodedEvent{}, errors.New("decode protocol event: missing payload")
	}
	var ev events.Event
	switch payload := in.Payload.(type) {
	case *eventsv1.ProtocolEvent_Conn:
		if payload.Conn == nil {
			return DecodedEvent{}, errors.New("decode conn event: nil payload")
		}
		e := events.NewConnEvent(env)
		p := payload.Conn
		e.Service, e.OriginBytes, e.ResponseBytes, e.State = p.Service, p.OriginBytes, p.ResponseBytes, p.State
		e.LocalOrigin, e.LocalResponse, e.MissedBytes, e.History = p.LocalOrigin, p.LocalResponse, p.MissedBytes, p.History
		e.OriginPackets, e.OriginIPBytes, e.ResponsePackets, e.ResponseIPBytes = p.OriginPackets, p.OriginIpBytes, p.ResponsePackets, p.ResponseIpBytes
		if e.Duration, err = decodeDuration("conn duration", p.Duration); err != nil {
			return DecodedEvent{}, err
		}
		ev = e
	case *eventsv1.ProtocolEvent_Dns:
		if payload.Dns == nil {
			return DecodedEvent{}, errors.New("decode DNS event: nil payload")
		}
		p := payload.Dns
		if p.TransactionId > 65535 || p.Qclass > 65535 || p.Qtype > 65535 || p.Rcode > 65535 || p.Z > 255 {
			return DecodedEvent{}, errors.New("decode DNS event: numeric field out of range")
		}
		e := events.NewDNSEvent(env)
		e.IsResponse, e.TransactionID = p.IsResponse, uint16(p.TransactionId)
		if e.RTT, err = decodeDuration("DNS RTT", p.Rtt); err != nil {
			return DecodedEvent{}, err
		}
		e.Query, e.QClass, e.QType, e.RCode = p.Query, uint16(p.Qclass), uint16(p.Qtype), uint16(p.Rcode)
		e.Authoritative, e.Truncated, e.RecursionDesired, e.RecursionAvailable, e.Z = p.Authoritative, p.Truncated, p.RecursionDesired, p.RecursionAvailable, uint8(p.Z)
		e.Answers, e.Rejected = cloneStrings(p.Answers), p.Rejected
		if err = checkStrings("DNS answers", e.Answers, MaxCollectionEntries); err != nil {
			return DecodedEvent{}, err
		}
		if len(p.Ttls) > MaxCollectionEntries {
			return DecodedEvent{}, errors.New("decode DNS event: too many TTLs")
		}
		for _, ttl := range p.Ttls {
			d, x := decodeDuration("DNS TTL", ttl)
			if x != nil {
				return DecodedEvent{}, x
			}
			e.TTLs = append(e.TTLs, d)
		}
		ev = e
	case *eventsv1.ProtocolEvent_Tls:
		if payload.Tls == nil {
			return DecodedEvent{}, errors.New("decode TLS event: nil payload")
		}
		p := payload.Tls
		e := events.NewTLSEvent(env)
		e.Version, e.Cipher, e.Curve, e.ServerName = p.Version, p.Cipher, p.Curve, p.ServerName
		e.Resumed, e.LastAlert, e.NextProtocol, e.Established = p.Resumed, p.LastAlert, p.NextProtocol, p.Established
		e.CertificateFileIDs, e.ClientCertificateFileIDs = cloneStrings(p.CertificateFileIds), cloneStrings(p.ClientCertificateFileIds)
		e.Subject, e.Issuer, e.ClientSubject, e.ClientIssuer, e.ValidationStatus = p.Subject, p.Issuer, p.ClientSubject, p.ClientIssuer, p.ValidationStatus
		e.JA3, e.JA3S, e.JA4 = p.Ja3, p.Ja3S, p.Ja4
		ev = e
	case *eventsv1.ProtocolEvent_Http:
		if payload.Http == nil {
			return DecodedEvent{}, errors.New("decode HTTP event: nil payload")
		}
		p := payload.Http
		if p.StatusCode > 65535 || p.InformationalCode > 65535 {
			return DecodedEvent{}, errors.New("decode HTTP event: status code out of range")
		}
		e := events.NewHTTPEvent(env)
		e.TransactionDepth = p.TransactionDepth
		e.Method, e.Host, e.URI, e.Referrer, e.Version, e.UserAgent, e.Origin = p.Method, p.Host, p.Uri, p.Referrer, p.Version, p.UserAgent, p.Origin
		e.RequestBodyLength, e.ResponseBodyLength, e.StatusCode, e.InformationalCode = p.RequestBodyLength, p.ResponseBodyLength, uint16(p.StatusCode), uint16(p.InformationalCode)
		e.StatusMessage, e.InformationalMessage, e.Tags, e.Username = p.StatusMessage, p.InformationalMessage, cloneStrings(p.Tags), p.Username
		e.Proxies, e.RequestFileIDs, e.RequestFilenames, e.RequestMIMETypes = cloneStrings(p.Proxies), cloneStrings(p.RequestFileIds), cloneStrings(p.RequestFilenames), cloneStrings(p.RequestMimeTypes)
		e.ResponseFileIDs, e.ResponseFilenames, e.ResponseMIMETypes = cloneStrings(p.ResponseFileIds), cloneStrings(p.ResponseFilenames), cloneStrings(p.ResponseMimeTypes)
		if len(p.Headers) > MaxHeaderEntries {
			return DecodedEvent{}, errors.New("decode HTTP event: too many headers")
		}
		if p.Headers != nil {
			e.Headers = make(map[string][]string, len(p.Headers))
		}
		values := 0
		for k, v := range p.Headers {
			if v == nil {
				return DecodedEvent{}, fmt.Errorf("decode HTTP event: nil header values for %q", k)
			}
			values += len(v.Values)
			e.Headers[k] = cloneStrings(v.Values)
		}
		if values > MaxHeaderValues {
			return DecodedEvent{}, errors.New("decode HTTP event: too many header values")
		}
		ev = e
	case *eventsv1.ProtocolEvent_Radius:
		p := payload.Radius
		if p == nil || p.Code > 255 || p.Identifier > 255 || p.Length > 65535 {
			return DecodedEvent{}, errors.New("decode RADIUS event: invalid payload or numeric range")
		}
		e := events.NewRADIUSEvent(env)
		e.Code, e.Identifier, e.Length = uint8(p.Code), uint8(p.Identifier), uint16(p.Length)
		e.ObservationID, e.RequestInstanceID, e.Association = p.ObservationId, p.RequestInstanceId, p.Association
		e.OriginNodeID, e.SourceID, e.CaptureEpoch = p.OriginNodeId, p.SourceId, p.CaptureEpoch
		e.Attributes = cloneStrings(p.Attributes)
		ev = e
	case *eventsv1.ProtocolEvent_Smtp:
		if payload.Smtp == nil {
			return DecodedEvent{}, errors.New("decode SMTP event: nil payload")
		}
		p := payload.Smtp
		e := events.NewSMTPEvent(env)
		e.TransactionDepth, e.HELO, e.MailFrom = p.TransactionDepth, p.Helo, p.MailFrom
		e.Recipients, e.Date, e.From, e.To, e.CC = cloneStrings(p.Recipients), p.Date, p.From, cloneStrings(p.To), cloneStrings(p.Cc)
		e.ReplyTo, e.MessageID, e.InReplyTo, e.Subject = p.ReplyTo, p.MessageId, p.InReplyTo, p.Subject
		if p.OriginatingIp != "" {
			e.OriginatingIP, err = netip.ParseAddr(p.OriginatingIp)
			if err != nil {
				return DecodedEvent{}, fmt.Errorf("decode SMTP originating IP: %w", err)
			}
		}
		e.Received, e.LastReply, e.Path, e.UserAgent, e.TLS, e.FileIDs, e.IsWebmail = cloneStrings(p.Received), p.LastReply, cloneStrings(p.Path), p.UserAgent, p.Tls, cloneStrings(p.FileIds), p.IsWebmail
		ev = e
	case *eventsv1.ProtocolEvent_FileMetadata:
		if payload.FileMetadata == nil {
			return DecodedEvent{}, errors.New("decode file metadata event: nil payload")
		}
		p := payload.FileMetadata
		e := events.NewFileMetadataEvent(env)
		e.FileID, e.Source, e.Depth, e.Analyzers, e.MIMEType, e.Filename = p.FileId, p.Source, p.Depth, cloneStrings(p.Analyzers), p.MimeType, p.Filename
		if e.Duration, err = decodeDuration("file duration", p.Duration); err != nil {
			return DecodedEvent{}, err
		}
		e.LocalOrigin, e.IsOrigin, e.SeenBytes, e.TotalBytes, e.MissingBytes, e.OverflowBytes, e.TimedOut = p.LocalOrigin, p.IsOrigin, p.SeenBytes, p.TotalBytes, p.MissingBytes, p.OverflowBytes, p.TimedOut
		e.ParentFileID, e.MD5, e.SHA1, e.SHA256, e.ExtractedPath, e.HashComplete = p.ParentFileId, p.Md5, p.Sha1, p.Sha256, p.ExtractedPath, p.HashComplete
		ev = e
	default:
		return DecodedEvent{Wire: wire, Omission: &CompatibilityOmission{Reason: OmissionUnsupportedKind}}, nil
	}
	if err := validateEventCollections(ev); err != nil {
		return DecodedEvent{}, err
	}
	return DecodedEvent{Event: ev, Wire: wire}, nil
}

// hasUnknownMessageField reports whether unknown wire data can represent a
// future typed oneof alternative. Protobuf message fields are always
// length-delimited; scalar unknown fields cannot stand in for an event payload.
func hasUnknownMessageField(raw protoreflect.RawFields) (bool, error) {
	found := false
	for len(raw) > 0 {
		_, wireType, size := protowire.ConsumeField(raw)
		if size < 0 {
			return false, protowire.ParseError(size)
		}
		if wireType == protowire.BytesType {
			found = true
		}
		raw = raw[size:]
	}
	return found, nil
}

func FromProto(in *eventsv1.ProtocolEvent) (events.Event, *CompatibilityOmission, error) {
	d, err := DecodeEvent(in)
	return d.Event, d.Omission, err
}

func ToProto(ev events.Event) (*eventsv1.ProtocolEvent, error) {
	if ev == nil {
		return nil, errors.New("encode protocol event: nil event")
	}
	var err error
	ev, err = eventValue(ev)
	if err != nil {
		return nil, err
	}
	if ev.Kind() == events.KindFileContent {
		return nil, ErrFileContentDisallowed
	}
	if err := validateEventCollections(ev); err != nil {
		return nil, err
	}
	env, err := encodeEnvelope(ev.Envelope())
	if err != nil {
		return nil, err
	}
	out := &eventsv1.ProtocolEvent{EventId: ev.Envelope().EventID, EventSequence: ev.Envelope().EventSequence, Envelope: env}
	switch e := ev.(type) {
	case events.RADIUSEvent:
		out.Payload = &eventsv1.ProtocolEvent_Radius{Radius: &eventsv1.RADIUSEvent{Code: uint32(e.Code), Identifier: uint32(e.Identifier), Length: uint32(e.Length), ObservationId: e.ObservationID, RequestInstanceId: e.RequestInstanceID, Association: e.Association, OriginNodeId: e.OriginNodeID, SourceId: e.SourceID, CaptureEpoch: e.CaptureEpoch, Attributes: cloneStrings(e.Attributes)}}
	case events.ConnEvent:
		out.Payload = &eventsv1.ProtocolEvent_Conn{Conn: &eventsv1.ConnEvent{Service: e.Service, Duration: durationpb.New(e.Duration), OriginBytes: e.OriginBytes, ResponseBytes: e.ResponseBytes, State: e.State, LocalOrigin: e.LocalOrigin, LocalResponse: e.LocalResponse, MissedBytes: e.MissedBytes, History: e.History, OriginPackets: e.OriginPackets, OriginIpBytes: e.OriginIPBytes, ResponsePackets: e.ResponsePackets, ResponseIpBytes: e.ResponseIPBytes}}
	case events.DNSEvent:
		p := &eventsv1.DNSEvent{IsResponse: e.IsResponse, TransactionId: uint32(e.TransactionID), Rtt: durationpb.New(e.RTT), Query: e.Query, Qclass: uint32(e.QClass), Qtype: uint32(e.QType), Rcode: uint32(e.RCode), Authoritative: e.Authoritative, Truncated: e.Truncated, RecursionDesired: e.RecursionDesired, RecursionAvailable: e.RecursionAvailable, Z: uint32(e.Z), Answers: cloneStrings(e.Answers), Rejected: e.Rejected}
		for _, ttl := range e.TTLs {
			p.Ttls = append(p.Ttls, durationpb.New(ttl))
		}
		out.Payload = &eventsv1.ProtocolEvent_Dns{Dns: p}
	case events.TLSEvent:
		out.Payload = &eventsv1.ProtocolEvent_Tls{Tls: &eventsv1.TLSEvent{Version: e.Version, Cipher: e.Cipher, Curve: e.Curve, ServerName: e.ServerName, Resumed: e.Resumed, LastAlert: e.LastAlert, NextProtocol: e.NextProtocol, Established: e.Established, CertificateFileIds: cloneStrings(e.CertificateFileIDs), ClientCertificateFileIds: cloneStrings(e.ClientCertificateFileIDs), Subject: e.Subject, Issuer: e.Issuer, ClientSubject: e.ClientSubject, ClientIssuer: e.ClientIssuer, ValidationStatus: e.ValidationStatus, Ja3: e.JA3, Ja3S: e.JA3S, Ja4: e.JA4}}
	case events.HTTPEvent:
		p := &eventsv1.HTTPEvent{TransactionDepth: e.TransactionDepth, Method: e.Method, Host: e.Host, Uri: e.URI, Referrer: e.Referrer, Version: e.Version, UserAgent: e.UserAgent, Origin: e.Origin, RequestBodyLength: e.RequestBodyLength, ResponseBodyLength: e.ResponseBodyLength, StatusCode: uint32(e.StatusCode), InformationalCode: uint32(e.InformationalCode), StatusMessage: e.StatusMessage, InformationalMessage: e.InformationalMessage, Tags: cloneStrings(e.Tags), Username: e.Username, Proxies: cloneStrings(e.Proxies), RequestFileIds: cloneStrings(e.RequestFileIDs), RequestFilenames: cloneStrings(e.RequestFilenames), RequestMimeTypes: cloneStrings(e.RequestMIMETypes), ResponseFileIds: cloneStrings(e.ResponseFileIDs), ResponseFilenames: cloneStrings(e.ResponseFilenames), ResponseMimeTypes: cloneStrings(e.ResponseMIMETypes)}
		if e.Headers != nil {
			p.Headers = make(map[string]*eventsv1.HeaderValues, len(e.Headers))
			for k, v := range e.Headers {
				p.Headers[k] = &eventsv1.HeaderValues{Values: cloneStrings(v)}
			}
		}
		out.Payload = &eventsv1.ProtocolEvent_Http{Http: p}
	case events.SMTPEvent:
		ip := ""
		if e.OriginatingIP.IsValid() {
			ip = e.OriginatingIP.String()
		}
		out.Payload = &eventsv1.ProtocolEvent_Smtp{Smtp: &eventsv1.SMTPEvent{TransactionDepth: e.TransactionDepth, Helo: e.HELO, MailFrom: e.MailFrom, Recipients: cloneStrings(e.Recipients), Date: e.Date, From: e.From, To: cloneStrings(e.To), Cc: cloneStrings(e.CC), ReplyTo: e.ReplyTo, MessageId: e.MessageID, InReplyTo: e.InReplyTo, Subject: e.Subject, OriginatingIp: ip, Received: cloneStrings(e.Received), LastReply: e.LastReply, Path: cloneStrings(e.Path), UserAgent: e.UserAgent, Tls: e.TLS, FileIds: cloneStrings(e.FileIDs), IsWebmail: e.IsWebmail}}
	case events.FileMetadataEvent:
		out.Payload = &eventsv1.ProtocolEvent_FileMetadata{FileMetadata: &eventsv1.FileMetadataEvent{FileId: e.FileID, Source: e.Source, Depth: e.Depth, Analyzers: cloneStrings(e.Analyzers), MimeType: e.MIMEType, Filename: e.Filename, Duration: durationpb.New(e.Duration), LocalOrigin: e.LocalOrigin, IsOrigin: e.IsOrigin, SeenBytes: e.SeenBytes, TotalBytes: e.TotalBytes, MissingBytes: e.MissingBytes, OverflowBytes: e.OverflowBytes, TimedOut: e.TimedOut, ParentFileId: e.ParentFileID, Md5: e.MD5, Sha1: e.SHA1, Sha256: e.SHA256, ExtractedPath: e.ExtractedPath, HashComplete: e.HashComplete}}
	default:
		return nil, fmt.Errorf("encode protocol event: unsupported Go event type %T", ev)
	}
	return out, nil
}

func encodeEnvelope(e events.Envelope) (*eventsv1.EventEnvelope, error) {
	if err := validateEnvelope(e); err != nil {
		return nil, err
	}
	scope := eventsv1.CaptureScope_CAPTURE_SCOPE_UNSPECIFIED
	if e.CaptureScope == events.CaptureScopeFull {
		scope = eventsv1.CaptureScope_CAPTURE_SCOPE_FULL
	}
	if e.CaptureScope == events.CaptureScopeFiltered {
		scope = eventsv1.CaptureScope_CAPTURE_SCOPE_FILTERED
	}
	return &eventsv1.EventEnvelope{Timestamp: timestamppb.New(e.Timestamp), Uid: e.UID, CommunityId: e.CommunityID, NodeId: e.NodeID, Flow: &eventsv1.FlowTuple{Protocol: uint32(e.Flow.Protocol), SourceAddress: e.Flow.SourceAddress.String(), DestinationAddress: e.Flow.DestinationAddress.String(), SourcePort: uint32(e.Flow.SourcePort), DestinationPort: uint32(e.Flow.DestinationPort)}, CaptureScope: scope, Partial: e.Partial, EventId: e.EventID, ProducerSessionId: e.ProducerSessionID, EventSequence: e.EventSequence, Provenance: &eventsv1.SourceProvenance{CaptureSource: e.Provenance.CaptureSource, InterfaceName: e.Provenance.InterfaceName, InterfaceIndex: e.Provenance.InterfaceIndex, InputFile: e.Provenance.InputFile, ProcessorNodeIds: cloneStrings(e.Provenance.ProcessorNodeIDs)}}, nil
}

func decodeEnvelope(in *eventsv1.ProtocolEvent) (events.Envelope, error) {
	p := in.Envelope
	if p == nil {
		return events.Envelope{}, errors.New("decode protocol event: missing envelope")
	}
	if p.Timestamp == nil || !p.Timestamp.IsValid() {
		return events.Envelope{}, errors.New("decode protocol event: invalid timestamp")
	}
	if p.Flow == nil {
		return events.Envelope{}, errors.New("decode protocol event: missing flow")
	}
	if p.EventId != in.EventId || p.EventSequence != in.EventSequence {
		return events.Envelope{}, errors.New("decode protocol event: duplicate identity fields disagree")
	}
	if p.Flow.Protocol > 255 || p.Flow.SourcePort > 65535 || p.Flow.DestinationPort > 65535 {
		return events.Envelope{}, errors.New("decode protocol event: flow numeric field out of range")
	}
	src, e := netip.ParseAddr(p.Flow.SourceAddress)
	if e != nil {
		return events.Envelope{}, fmt.Errorf("decode source address: %w", e)
	}
	dst, e := netip.ParseAddr(p.Flow.DestinationAddress)
	if e != nil {
		return events.Envelope{}, fmt.Errorf("decode destination address: %w", e)
	}
	scope := events.CaptureScope("")
	switch p.CaptureScope {
	case eventsv1.CaptureScope_CAPTURE_SCOPE_FULL:
		scope = events.CaptureScopeFull
	case eventsv1.CaptureScope_CAPTURE_SCOPE_FILTERED:
		scope = events.CaptureScopeFiltered
	default:
		return events.Envelope{}, errors.New("decode protocol event: unknown capture scope")
	}
	out := events.Envelope{Timestamp: p.Timestamp.AsTime(), EventID: in.EventId, ProducerSessionID: p.ProducerSessionId, EventSequence: in.EventSequence, UID: p.Uid, CommunityID: p.CommunityId, NodeID: p.NodeId, Flow: events.FlowTuple{Protocol: uint8(p.Flow.Protocol), SourceAddress: src, DestinationAddress: dst, SourcePort: uint16(p.Flow.SourcePort), DestinationPort: uint16(p.Flow.DestinationPort)}, Partial: p.Partial, CaptureScope: scope}
	if p.Provenance != nil {
		out.Provenance = events.SourceProvenance{CaptureSource: p.Provenance.CaptureSource, InterfaceName: p.Provenance.InterfaceName, InterfaceIndex: p.Provenance.InterfaceIndex, InputFile: p.Provenance.InputFile, ProcessorNodeIDs: cloneStrings(p.Provenance.ProcessorNodeIds)}
	}
	if err := validateEnvelope(out); err != nil {
		return events.Envelope{}, err
	}
	return out, nil
}

func validateEnvelope(e events.Envelope) error {
	if e.Timestamp.IsZero() || !timestamppb.New(e.Timestamp).IsValid() {
		return errors.New("event envelope: invalid timestamp")
	}
	if e.EventID == "" || e.ProducerSessionID == "" || e.EventSequence == 0 || e.NodeID == "" {
		return errors.New("event envelope: identity fields must be non-empty")
	}
	if !events.HasValidDeliveryIdentity(e) {
		return errors.New("event envelope: event ID does not match delivery identity")
	}
	if err := checkString("event ID", e.EventID); err != nil {
		return err
	}
	if err := checkString("node ID", e.NodeID); err != nil {
		return err
	}
	if err := checkString("flow UID", e.UID); err != nil {
		return err
	}
	if err := checkString("community ID", e.CommunityID); err != nil {
		return err
	}
	if err := checkString("producer session ID", e.ProducerSessionID); err != nil {
		return err
	}
	if err := checkStrings("processor node IDs", e.Provenance.ProcessorNodeIDs, MaxCollectionEntries); err != nil {
		return err
	}
	for name, value := range map[string]string{"capture source": e.Provenance.CaptureSource, "interface name": e.Provenance.InterfaceName, "input file": e.Provenance.InputFile} {
		if err := checkString(name, value); err != nil {
			return err
		}
	}
	if !e.Flow.SourceAddress.IsValid() || !e.Flow.DestinationAddress.IsValid() {
		return errors.New("event envelope: invalid flow address")
	}
	if e.Flow.Protocol == 0 {
		return errors.New("event envelope: protocol must be non-zero")
	}
	if e.CaptureScope != events.CaptureScopeFull && e.CaptureScope != events.CaptureScopeFiltered {
		return errors.New("event envelope: invalid capture scope")
	}
	return nil
}
func decodeDuration(name string, d *durationpb.Duration) (time.Duration, error) {
	if d == nil {
		return 0, nil
	}
	if err := d.CheckValid(); err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	v := d.AsDuration()
	// Protobuf durations have a much wider range than time.Duration. AsDuration
	// saturates values outside the Go range, which would silently change event
	// semantics on decode, so require an exact representation.
	if roundTrip := durationpb.New(v); roundTrip.Seconds != d.Seconds || roundTrip.Nanos != d.Nanos {
		return 0, fmt.Errorf("%s: outside Go duration range", name)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s: negative duration", name)
	}
	return v, nil
}
func cloneStrings(v []string) []string { return append([]string(nil), v...) }
func checkString(name, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not UTF-8", name)
	}
	if len(s) > MaxStringBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, MaxStringBytes)
	}
	return nil
}
func checkStrings(name string, v []string, max int) error {
	if len(v) > max {
		return fmt.Errorf("%s exceeds %d entries", name, max)
	}
	for _, s := range v {
		if err := checkString(name, s); err != nil {
			return err
		}
	}
	return nil
}
func validateEventCollections(ev events.Event) error {
	var err error
	ev, err = eventValue(ev)
	if err != nil {
		return err
	}
	if err := validateEnvelope(ev.Envelope()); err != nil {
		return err
	}
	values := []string{}
	collections := [][]string{}
	switch e := ev.(type) {
	case events.DNSEvent:
		values = []string{e.Query}
		collections = [][]string{e.Answers}
		if e.RTT < 0 {
			return errors.New("DNS RTT is negative")
		}
		for _, ttl := range e.TTLs {
			if ttl < 0 {
				return errors.New("DNS TTL is negative")
			}
		}
		if len(e.TTLs) > MaxCollectionEntries {
			return errors.New("DNS TTLs exceed limit")
		}
	case events.TLSEvent:
		values = []string{e.Version, e.Cipher, e.Curve, e.ServerName, e.LastAlert, e.NextProtocol, e.Subject, e.Issuer, e.ClientSubject, e.ClientIssuer, e.ValidationStatus, e.JA3, e.JA3S, e.JA4}
		collections = [][]string{e.CertificateFileIDs, e.ClientCertificateFileIDs}
	case events.HTTPEvent:
		values = []string{e.Method, e.Host, e.URI, e.Referrer, e.Version, e.UserAgent, e.Origin, e.StatusMessage, e.InformationalMessage, e.Username}
		collections = [][]string{e.Tags, e.Proxies, e.RequestFileIDs, e.RequestFilenames, e.RequestMIMETypes, e.ResponseFileIDs, e.ResponseFilenames, e.ResponseMIMETypes}
		if len(e.Headers) > MaxHeaderEntries {
			return errors.New("HTTP headers exceed limit")
		}
		n := 0
		for k, v := range e.Headers {
			if err := checkString("HTTP header name", k); err != nil {
				return err
			}
			n += len(v)
			if err := checkStrings("HTTP header values", v, MaxHeaderValues); err != nil {
				return err
			}
		}
		if n > MaxHeaderValues {
			return errors.New("HTTP header values exceed limit")
		}
	case events.RADIUSEvent:
		values = []string{e.ObservationID, e.RequestInstanceID, e.Association, e.OriginNodeID, e.SourceID, e.CaptureEpoch}
		collections = [][]string{e.Attributes}
		for _, attribute := range e.Attributes {
			kind, value, ok := strings.Cut(attribute, ":hex:")
			if !ok {
				return errors.New("RADIUS attribute must use public hex representation")
			}
			switch kind {
			case "1", "4", "5", "6", "8", "30", "31", "32", "40", "44", "61", "87", "95", "26/3561/1":
			default:
				return errors.New("RADIUS attribute is outside public allowlist")
			}
			if _, err := hex.DecodeString(value); err != nil {
				return fmt.Errorf("RADIUS attribute hex: %w", err)
			}
		}
	case events.SMTPEvent:
		values = []string{e.HELO, e.MailFrom, e.Date, e.From, e.ReplyTo, e.MessageID, e.InReplyTo, e.Subject, e.LastReply, e.UserAgent}
		collections = [][]string{e.Recipients, e.To, e.CC, e.Received, e.Path, e.FileIDs}
		if !e.OriginatingIP.IsValid() && e.OriginatingIP != (netip.Addr{}) {
			return errors.New("SMTP originating IP is invalid")
		}
	case events.ConnEvent:
		values = []string{e.Service, e.State, e.History}
		if e.Duration < 0 {
			return errors.New("connection duration is negative")
		}
	case events.FileMetadataEvent:
		values = []string{e.FileID, e.Source, e.MIMEType, e.Filename, e.ParentFileID, e.MD5, e.SHA1, e.SHA256, e.ExtractedPath}
		collections = [][]string{e.Analyzers}
		if e.Duration < 0 {
			return errors.New("file duration is negative")
		}
	case events.FileContentEvent:
		return ErrFileContentDisallowed
	default:
		return fmt.Errorf("unsupported event type %T", ev)
	}
	for _, s := range values {
		if err := checkString("event string", s); err != nil {
			return err
		}
	}
	for _, v := range collections {
		if err := checkStrings("event collection", v, MaxCollectionEntries); err != nil {
			return err
		}
	}
	return nil
}

func eventValue(ev events.Event) (events.Event, error) {
	switch e := ev.(type) {
	case *events.ConnEvent:
		if e == nil {
			return nil, errors.New("event is a nil connection pointer")
		}
		return *e, nil
	case *events.DNSEvent:
		if e == nil {
			return nil, errors.New("event is a nil DNS pointer")
		}
		return *e, nil
	case *events.TLSEvent:
		if e == nil {
			return nil, errors.New("event is a nil TLS pointer")
		}
		return *e, nil
	case *events.HTTPEvent:
		if e == nil {
			return nil, errors.New("event is a nil HTTP pointer")
		}
		return *e, nil
	case *events.RADIUSEvent:
		if e == nil {
			return nil, errors.New("event is a nil RADIUS pointer")
		}
		return *e, nil
	case *events.SMTPEvent:
		if e == nil {
			return nil, errors.New("event is a nil SMTP pointer")
		}
		return *e, nil
	case *events.FileMetadataEvent:
		if e == nil {
			return nil, errors.New("event is a nil file metadata pointer")
		}
		return *e, nil
	case *events.FileContentEvent:
		if e == nil {
			return nil, errors.New("event is a nil file content pointer")
		}
		return *e, nil
	default:
		return ev, nil
	}
}

// ValidateBatch checks identity, ordering, ranges, loss ranges and size before admission.
func ValidateBatch(b *eventsv1.ProtocolEventBatch) error {
	if b == nil {
		return errors.New("nil event batch")
	}
	if err := validateUnknownFields("event batch", b); err != nil {
		return err
	}
	if b.SourceNodeId == "" || b.ProducerSessionId == "" || b.BatchSequence == 0 {
		return errors.New("event batch identity fields must be non-empty")
	}
	if err := checkString("batch source node ID", b.SourceNodeId); err != nil {
		return err
	}
	if err := checkString("batch producer session ID", b.ProducerSessionId); err != nil {
		return err
	}
	if len(b.Events) > MaxBatchEvents {
		return fmt.Errorf("event batch exceeds %d events", MaxBatchEvents)
	}
	if len(b.Events) == 0 {
		if b.FirstEventSequence != 0 || b.LastEventSequence != 0 {
			return errors.New("empty event batch has non-zero event range")
		}
	} else {
		if b.FirstEventSequence == 0 || b.LastEventSequence < b.FirstEventSequence {
			return errors.New("invalid event batch sequence range")
		}
		var previous uint64
		for i, e := range b.Events {
			if e == nil {
				return fmt.Errorf("event batch event %d is nil", i)
			}
			if e.EventSequence == 0 || e.EventSequence > b.LastEventSequence || (i > 0 && e.EventSequence <= previous) {
				return fmt.Errorf("event batch event %d is out of sequence", i)
			}
			previous = e.EventSequence
			if e.Envelope == nil || e.Envelope.NodeId != b.SourceNodeId {
				return fmt.Errorf("event batch event %d node identity mismatch", i)
			}
			if e.Envelope.ProducerSessionId != b.ProducerSessionId || e.Envelope.EventId != e.EventId || e.Envelope.EventSequence != e.EventSequence {
				return fmt.Errorf("event batch event %d identity mismatch", i)
			}
			if _, err := DecodeEvent(e); err != nil {
				return fmt.Errorf("event batch event %d is invalid: %w", i, err)
			}
		}
		if b.FirstEventSequence != b.Events[0].EventSequence || b.LastEventSequence != b.Events[len(b.Events)-1].EventSequence {
			return errors.New("event batch sequence boundary mismatch")
		}
	}
	type lossRange struct{ first, last uint64 }
	var allLossRanges []lossRange
	if b.Stats != nil {
		if len(b.Stats.Losses) > MaxCollectionEntries {
			return errors.New("too many event losses")
		}
		for _, loss := range b.Stats.Losses {
			if loss == nil || loss.Kind <= eventsv1.LossKind_LOSS_KIND_UNSPECIFIED || loss.Kind > eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION {
				return errors.New("invalid event loss")
			}
			if loss.Count == 0 {
				return errors.New("event loss count must be positive")
			}
			if err := checkString("event loss source node ID", loss.SourceNodeId); err != nil {
				return err
			}
			if loss.SourceNodeId != b.SourceNodeId {
				return errors.New("event loss source does not match batch source")
			}
			if loss.ProducerSessionId != "" {
				if err := checkString("event loss producer session ID", loss.ProducerSessionId); err != nil {
					return err
				}
				if loss.ProducerSessionId != b.ProducerSessionId {
					return errors.New("event loss producer session does not match batch session")
				}
			}
			if len(loss.EventSequenceRanges) > MaxCollectionEntries {
				return errors.New("too many event loss ranges")
			}
			if len(allLossRanges)+len(loss.EventSequenceRanges) > MaxCollectionEntries {
				return errors.New("too many event loss ranges")
			}
			var rangedCount uint64
			var previousLast uint64
			for i, r := range loss.EventSequenceRanges {
				if r == nil || r.First == 0 || r.Last < r.First {
					return errors.New("invalid event loss range")
				}
				if i > 0 && r.First <= previousLast {
					return errors.New("event loss ranges overlap or are out of order")
				}
				if r.First == 1 && r.Last == ^uint64(0) {
					return errors.New("event loss range count overflows")
				}
				rangeCount := r.Last - r.First + 1
				if rangedCount > ^uint64(0)-rangeCount {
					return errors.New("event loss range count overflows")
				}
				rangedCount += rangeCount
				previousLast = r.Last
				allLossRanges = append(allLossRanges, lossRange{first: r.First, last: r.Last})
			}
			if loss.Count < rangedCount {
				return errors.New("event loss count is smaller than its sequence ranges")
			}
		}
	}
	sort.Slice(allLossRanges, func(i, j int) bool {
		if allLossRanges[i].first == allLossRanges[j].first {
			return allLossRanges[i].last < allLossRanges[j].last
		}
		return allLossRanges[i].first < allLossRanges[j].first
	})
	for i, r := range allLossRanges {
		if i > 0 && r.first <= allLossRanges[i-1].last {
			return errors.New("event loss ranges overlap across loss records")
		}
		index := sort.Search(len(b.Events), func(j int) bool {
			return b.Events[j].EventSequence >= r.first
		})
		if index < len(b.Events) && b.Events[index].EventSequence <= r.last {
			return errors.New("event loss range overlaps a delivered event")
		}
	}
	for i := 1; i < len(b.Events); i++ {
		previous := b.Events[i-1].EventSequence
		current := b.Events[i].EventSequence
		if current > previous+1 && !lossesCover(b.Stats, b.SourceNodeId, previous+1, current-1) {
			return fmt.Errorf("event batch gap %d-%d is not reported", previous+1, current-1)
		}
	}
	return nil
}

// validateUnknownFields bounds all opaque compatibility data retained by a
// message, including unknown fields nested in known submessages. Checking only
// the outer message would let an otherwise valid envelope, payload, or loss
// record bypass admission limits with arbitrarily large unknown fields.
func validateUnknownFields(name string, message proto.Message) error {
	var total int
	var visit func(protoreflect.Message) bool
	visit = func(current protoreflect.Message) bool {
		total += len(current.GetUnknown())
		if total > MaxUnknownBytes {
			return false
		}
		current.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			switch {
			case field.IsMap() && field.MapValue().Message() != nil:
				value.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
					return visit(entry.Message())
				})
			case field.IsList() && field.Message() != nil:
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					if !visit(list.Get(i).Message()) {
						return false
					}
				}
			case field.Message() != nil:
				return visit(value.Message())
			}
			return total <= MaxUnknownBytes
		})
		return total <= MaxUnknownBytes
	}
	if !visit(message.ProtoReflect()) {
		return fmt.Errorf("%s: unknown fields exceed %d bytes", name, MaxUnknownBytes)
	}
	return nil
}

func lossesCover(stats *eventsv1.EventBatchStats, sourceNodeID string, first, last uint64) bool {
	if stats == nil {
		return false
	}
	next := first
	for next <= last {
		coveredThrough := uint64(0)
		for _, loss := range stats.Losses {
			if loss == nil || loss.SourceNodeId != sourceNodeID {
				continue
			}
			for _, r := range loss.EventSequenceRanges {
				if r != nil && r.First <= next && r.Last >= next && r.Last > coveredThrough {
					coveredThrough = r.Last
				}
			}
		}
		if coveredThrough < next {
			return false
		}
		if coveredThrough >= last {
			return true
		}
		next = coveredThrough + 1
	}
	return true
}

// ToProtoBatch encodes a contiguous batch and verifies producer identity before
// it can be admitted to a transport queue.
func ToProtoBatch(sourceNodeID, producerSessionID string, batchSequence uint64, input []events.Event, stats *eventsv1.EventBatchStats, semanticProfileRevision uint32) (*eventsv1.ProtocolEventBatch, error) {
	b := &eventsv1.ProtocolEventBatch{SourceNodeId: sourceNodeID, ProducerSessionId: producerSessionID, BatchSequence: batchSequence, SemanticProfileRevision: semanticProfileRevision}
	if stats != nil {
		b.Stats = proto.Clone(stats).(*eventsv1.EventBatchStats)
	}
	for _, ev := range input {
		wire, err := ToProto(ev)
		if err != nil {
			return nil, err
		}
		b.Events = append(b.Events, wire)
	}
	if len(b.Events) != 0 {
		b.FirstEventSequence = b.Events[0].EventSequence
		b.LastEventSequence = b.Events[len(b.Events)-1].EventSequence
	}
	if err := ValidateBatch(b); err != nil {
		return nil, err
	}
	return b, nil
}

func DecodeBatch(b *eventsv1.ProtocolEventBatch) ([]events.Event, []CompatibilityOmission, error) {
	if err := ValidateBatch(b); err != nil {
		return nil, nil, err
	}
	out := make([]events.Event, 0, len(b.Events))
	var omissions []CompatibilityOmission
	for _, p := range b.Events {
		d, err := DecodeEvent(p)
		if err != nil {
			return nil, nil, err
		}
		if d.Omission != nil {
			omissions = append(omissions, *d.Omission)
			continue
		}
		env := d.Event.Envelope()
		if env.ProducerSessionID != "" && env.ProducerSessionID != b.ProducerSessionId {
			return nil, nil, errors.New("event producer session mismatch")
		}
		out = append(out, d.Event)
	}
	return out, omissions, nil
}

// UnknownFieldsEqual is useful to assert transparent forwarding compatibility.
func UnknownFieldsEqual(a, b proto.Message) bool {
	return bytes.Equal(a.ProtoReflect().GetUnknown(), b.ProtoReflect().GetUnknown())
}
