//go:build li

package li

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

const InternetMetadataProfile = "internet_metadata"

var (
	ErrMetadataContentRejected = errors.New("content-bearing event rejected by LI metadata profile")
	ErrUnknownMetadataProfile  = errors.New("unknown LI metadata delivery profile")
)

// MetadataSender is implemented by the asynchronous X2 delivery client.
type MetadataSender interface {
	SendX2(uuid.UUID, []uuid.UUID, []byte) error
}

type MetadataSinkConfig struct {
	Enabled           bool
	Profile           string
	Manager           *Manager
	Sender            MetadataSender
	NFID              string
	AllowFileMetadata bool
}

type MetadataSinkStats struct{ Delivered, Skipped, Rejected atomic.Uint64 }

// MetadataSink maps normalized, content-free protocol observations to X2 IRI.
type MetadataSink struct {
	config MetadataSinkConfig
	attrs  *x2x3.AttributeBuilder
	seq    atomic.Uint32
	stats  MetadataSinkStats
}

func NewMetadataSink(config MetadataSinkConfig) (*MetadataSink, error) {
	if config.Profile == "" {
		config.Profile = InternetMetadataProfile
	}
	if config.Profile != InternetMetadataProfile {
		return nil, fmt.Errorf("%w: %s", ErrUnknownMetadataProfile, config.Profile)
	}
	return &MetadataSink{config: config, attrs: x2x3.NewAttributeBuilder()}, nil
}

func (s *MetadataSink) HandleEvent(_ context.Context, ev events.Event) error {
	if !s.config.Enabled || s.config.Manager == nil || !s.config.Manager.IsEnabled() {
		s.stats.Skipped.Add(1)
		s.audit("skipped", ev, uuid.Nil, "metadata delivery disabled")
		return nil
	}
	if ev.Kind() == events.KindFileContent {
		s.stats.Rejected.Add(1)
		s.audit("rejected", ev, uuid.Nil, ErrMetadataContentRejected.Error())
		return ErrMetadataContentRejected
	}
	if ev.Kind() == events.KindFileMetadata && !s.config.AllowFileMetadata {
		s.stats.Skipped.Add(1)
		s.audit("skipped", ev, uuid.Nil, "profile does not authorize file metadata")
		return nil
	}
	if !metadataKindAllowed(ev.Kind()) {
		s.stats.Skipped.Add(1)
		s.audit("skipped", ev, uuid.Nil, "event kind is not in profile")
		return nil
	}
	tasks := s.config.Manager.GetActiveTasks()
	matched := 0
	for _, task := range tasks {
		if task.DeliveryType != DeliveryX2Only && task.DeliveryType != DeliveryX2andX3 {
			continue
		}
		target, ok := matchingTarget(task.Targets, ev)
		if !ok {
			continue
		}
		matched++
		if s.config.Sender == nil || len(task.DestinationIDs) == 0 {
			s.stats.Skipped.Add(1)
			s.audit("skipped", ev, task.XID, "no X2 delivery destination")
			continue
		}
		pdu, err := s.encode(ev, task.XID, target)
		if err != nil {
			s.stats.Rejected.Add(1)
			s.audit("rejected", ev, task.XID, err.Error())
			return err
		}
		data, err := pdu.MarshalBinary()
		if err != nil {
			s.stats.Rejected.Add(1)
			s.audit("rejected", ev, task.XID, err.Error())
			return fmt.Errorf("marshal metadata X2 PDU: %w", err)
		}
		if err := s.config.Sender.SendX2(task.XID, task.DestinationIDs, data); err != nil {
			s.stats.Rejected.Add(1)
			s.audit("rejected", ev, task.XID, err.Error())
			return fmt.Errorf("queue metadata X2 PDU: %w", err)
		}
		s.stats.Delivered.Add(1)
		s.audit("delivered", ev, task.XID, "")
	}
	if matched == 0 {
		s.stats.Skipped.Add(1)
		s.audit("skipped", ev, uuid.Nil, "no active authorizing task matched")
	}
	return nil
}

func (s *MetadataSink) Flush(context.Context) error { return nil }
func (s *MetadataSink) Close(context.Context) error { return nil }

type MetadataAuditStats struct{ Delivered, Skipped, Rejected uint64 }

func (s *MetadataSink) Stats() MetadataAuditStats {
	return MetadataAuditStats{s.stats.Delivered.Load(), s.stats.Skipped.Load(), s.stats.Rejected.Load()}
}

func metadataKindAllowed(k events.Kind) bool {
	switch k {
	case events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP, events.KindConn, events.KindFileMetadata:
		return true
	default:
		return false
	}
}

type metadataPayload struct {
	Profile  string          `json:"profile"`
	Kind     events.Kind     `json:"kind"`
	Envelope events.Envelope `json:"envelope"`
	Metadata any             `json:"metadata"`
}

func (s *MetadataSink) encode(ev events.Event, xid uuid.UUID, target TargetIdentity) (*x2x3.PDU, error) {
	metadata, err := metadataOnlyValue(ev)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(metadataPayload{InternetMetadataProfile, ev.Kind(), ev.Envelope(), metadata})
	if err != nil {
		return nil, fmt.Errorf("encode metadata payload: %w", err)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(ev.Envelope().UID))
	pdu := x2x3.NewPDU(x2x3.PDUTypeX2, xid, h.Sum64())
	pdu.Header.PayloadFormat = x2x3.PayloadFormatProprietary
	pdu.Header.PayloadDirection = directionForTarget(target, ev.Envelope().Flow)
	pdu.AddAttribute(s.attrs.Timestamp(ev.Envelope().Timestamp))
	pdu.AddAttribute(s.attrs.SequenceNumber(s.seq.Add(1)))
	addFlowAttrs(pdu, s.attrs, ev.Envelope().Flow)
	if s.config.NFID != "" {
		pdu.AddAttribute(s.attrs.NFID(s.config.NFID))
	}
	if ev.Envelope().NodeID != "" {
		pdu.AddAttribute(s.attrs.IPID(ev.Envelope().NodeID))
	}
	pdu.AddAttribute(s.attrs.MatchedTargetIdentifier(target.Value))
	pdu.SetPayload(payload)
	return pdu, nil
}

func metadataOnlyValue(ev events.Event) (any, error) {
	switch e := ev.(type) {
	case events.DNSEvent:
		return e, nil
	case events.TLSEvent:
		return e, nil
	case events.HTTPEvent:
		e.Headers = nil // Headers can contain credentials/cookies and are outside the profile.
		return e, nil
	case events.SMTPEvent:
		// The internet_metadata profile authorizes the SMTP transport envelope,
		// never message headers, body previews, attachment IDs, or content.
		return struct {
			TransactionDepth uint64   `json:"transaction_depth"`
			HELO             string   `json:"helo,omitempty"`
			MailFrom         string   `json:"mail_from,omitempty"`
			Recipients       []string `json:"recipients,omitempty"`
			TLS              bool     `json:"tls"`
		}{e.TransactionDepth, e.HELO, e.MailFrom, e.Recipients, e.TLS}, nil
	case events.ConnEvent:
		return e, nil
	case events.FileMetadataEvent:
		return e, nil
	case events.FileContentEvent:
		return nil, ErrMetadataContentRejected
	default:
		return nil, fmt.Errorf("unsupported metadata event kind %s", ev.Kind())
	}
}

func matchingTarget(targets []TargetIdentity, ev events.Event) (TargetIdentity, bool) {
	for _, target := range targets {
		if targetMatches(target, ev) {
			return target, true
		}
	}
	return TargetIdentity{}, false
}

func targetMatches(target TargetIdentity, ev events.Event) bool {
	flow := ev.Envelope().Flow
	switch target.Type {
	case TargetTypeIPv4Address, TargetTypeIPv6Address:
		addr, err := netip.ParseAddr(strings.TrimSpace(target.Value))
		return err == nil && (flow.SourceAddress == addr || flow.DestinationAddress == addr)
	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		prefix, err := netip.ParsePrefix(strings.TrimSpace(target.Value))
		return err == nil && (prefix.Contains(flow.SourceAddress) || prefix.Contains(flow.DestinationAddress))
	}
	needle := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(target.Value), "sip:"), "tel:"))
	if needle == "" {
		return false
	}
	values := []string{}
	switch e := ev.(type) {
	case events.SMTPEvent:
		values = append(values, e.MailFrom, e.From, e.ReplyTo)
		values = append(values, e.Recipients...)
		values = append(values, e.To...)
		values = append(values, e.CC...)
	case events.HTTPEvent:
		values = append(values, e.Username, e.Host)
	case events.TLSEvent:
		values = append(values, e.ServerName, e.Subject, e.ClientSubject)
	case events.DNSEvent:
		values = append(values, e.Query)
	}
	for _, value := range values {
		v := strings.ToLower(value)
		if v == needle || strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func directionForTarget(target TargetIdentity, flow events.FlowTuple) x2x3.PayloadDirection {
	addr, err := netip.ParseAddr(strings.TrimSpace(target.Value))
	if err != nil {
		return x2x3.PayloadDirectionUnknown
	}
	if flow.SourceAddress == addr {
		return x2x3.PayloadDirectionFromTarget
	}
	if flow.DestinationAddress == addr {
		return x2x3.PayloadDirectionToTarget
	}
	return x2x3.PayloadDirectionUnknown
}

func addFlowAttrs(pdu *x2x3.PDU, b *x2x3.AttributeBuilder, flow events.FlowTuple) {
	if flow.SourceAddress.IsValid() {
		if a, err := b.SourceIP(flow.SourceAddress); err == nil {
			pdu.AddAttribute(a)
		}
	}
	if flow.DestinationAddress.IsValid() {
		if a, err := b.DestIP(flow.DestinationAddress); err == nil {
			pdu.AddAttribute(a)
		}
	}
	if flow.SourcePort != 0 {
		pdu.AddAttribute(b.SourcePort(flow.SourcePort))
	}
	if flow.DestinationPort != 0 {
		pdu.AddAttribute(b.DestPort(flow.DestinationPort))
	}
}

func (s *MetadataSink) audit(action string, ev events.Event, xid uuid.UUID, reason string) {
	logger.Info("LI metadata event audit", "action", action, "profile", s.config.Profile, "event_kind", ev.Kind(), "uid", ev.Envelope().UID, "xid", xid, "reason", reason)
}
