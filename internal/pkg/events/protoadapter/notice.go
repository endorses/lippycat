package protoadapter

import (
	"errors"
	"fmt"
	"math"
	"net/netip"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func encodeNotice(e events.NoticeEvent) *eventsv1.NoticeEvent {
	out := &eventsv1.NoticeEvent{
		SchemaVersion: e.SchemaVersion, Detector: e.Detector, DetectorVersion: e.DetectorVersion,
		Category: e.Category, Severity: string(e.Severity), Status: string(e.Status),
		DetectorNodeId: e.DetectorNodeID, DetectorGeneration: e.DetectorGeneration, EvidenceTruncated: e.EvidenceTruncated, EvidenceRedacted: e.EvidenceRedacted,
	}
	for _, reference := range e.Evidence {
		out.Evidence = append(out.Evidence, &eventsv1.NoticeEvidenceReference{NodeId: reference.NodeID, Uid: reference.UID, Timestamp: timestamppb.New(reference.Timestamp)})
	}
	if e.DNS != nil {
		dns := e.DNS
		out.Dns = &eventsv1.DNSNoticeEvidence{Domain: dns.Domain, Score: dns.Score, Threshold: dns.Threshold, Entropy: dns.Entropy,
			Queries: dns.Queries, UniqueSubdomains: dns.UniqueSubdomains, SourceIps: addrStrings(dns.SourceIPs),
			UniqueSubdomainsTruncated: dns.UniqueSubdomainsTruncated, SourceIpsTruncated: dns.SourceIPsTruncated}
	}
	return out
}

func decodeNotice(in *eventsv1.NoticeEvent, env events.Envelope) (events.NoticeEvent, error) {
	if in == nil {
		return events.NoticeEvent{}, errors.New("decode notice: nil payload")
	}
	if len(in.Evidence) > MaxCollectionEntries || (in.Dns != nil && len(in.Dns.SourceIps) > MaxCollectionEntries) {
		return events.NoticeEvent{}, errors.New("decode notice: evidence exceeds collection limit")
	}
	e := events.NewNoticeEvent(env)
	e.SchemaVersion, e.Detector, e.DetectorVersion, e.Category = in.SchemaVersion, in.Detector, in.DetectorVersion, in.Category
	e.Severity, e.Status = events.NoticeSeverity(in.Severity), events.NoticeStatus(in.Status)
	e.DetectorNodeID, e.DetectorGeneration, e.EvidenceTruncated = in.DetectorNodeId, in.DetectorGeneration, in.EvidenceTruncated
	e.EvidenceRedacted = in.EvidenceRedacted
	for _, reference := range in.Evidence {
		if reference == nil || reference.Timestamp == nil {
			return events.NoticeEvent{}, errors.New("decode notice: missing evidence reference or timestamp")
		}
		if err := reference.Timestamp.CheckValid(); err != nil {
			return events.NoticeEvent{}, fmt.Errorf("decode notice evidence timestamp: %w", err)
		}
		e.Evidence = append(e.Evidence, events.NoticeEvidenceReference{NodeID: reference.NodeId, UID: reference.Uid, Timestamp: reference.Timestamp.AsTime()})
	}
	if in.Dns != nil {
		dns := in.Dns
		e.DNS = &events.DNSNoticeEvidence{Domain: dns.Domain, Score: dns.Score, Threshold: dns.Threshold, Entropy: dns.Entropy,
			Queries: dns.Queries, UniqueSubdomains: dns.UniqueSubdomains, UniqueSubdomainsTruncated: dns.UniqueSubdomainsTruncated, SourceIPsTruncated: dns.SourceIpsTruncated}
		for _, address := range dns.SourceIps {
			parsed, err := netip.ParseAddr(address)
			if err != nil || parsed.String() != address {
				return events.NoticeEvent{}, errors.New("decode notice: invalid or noncanonical source address")
			}
			e.DNS.SourceIPs = append(e.DNS.SourceIPs, parsed)
		}
	}
	return e, nil
}

func validateNotice(e events.NoticeEvent) error {
	if e.SchemaVersion != events.NoticeSchemaVersion {
		return errors.New("notice: unsupported schema version")
	}
	if e.Severity != events.NoticeWarning || e.Status != events.NoticeTriggered {
		return errors.New("notice: unsupported severity or status")
	}
	for _, value := range []string{e.Detector, e.DetectorVersion, e.Category, e.DetectorNodeID, e.DetectorGeneration} {
		if value == "" {
			return errors.New("notice: detector, version, category, and authority are required")
		}
		if err := checkString("notice metadata", value); err != nil {
			return err
		}
	}
	if len(e.Evidence) > MaxCollectionEntries || (len(e.Evidence) == 0 && !e.EvidenceTruncated && !e.EvidenceRedacted) {
		return errors.New("notice: missing or excessive evidence references")
	}
	for i, reference := range e.Evidence {
		if reference.NodeID == "" || reference.UID == "" || reference.Timestamp.IsZero() || reference.Timestamp.After(e.Envelope().Timestamp) {
			return errors.New("notice: incomplete or future evidence reference")
		}
		if err := checkStrings("notice evidence identity", []string{reference.NodeID, reference.UID}, 2); err != nil {
			return err
		}
		if err := timestamppb.New(reference.Timestamp).CheckValid(); err != nil {
			return fmt.Errorf("notice evidence timestamp: %w", err)
		}
		if i > 0 && !noticeEvidenceBefore(e.Evidence[i-1], reference) {
			return errors.New("notice: evidence references must be sorted and unique")
		}
	}
	if e.DNS == nil {
		return errors.New("notice: DNS evidence is required by schema 1")
	}
	dns := e.DNS
	if e.EvidenceRedacted && (len(e.Evidence) > 0 || len(dns.SourceIPs) > 0) {
		return errors.New("notice: redacted evidence must exclude references and source addresses")
	}
	if dns.Domain == "" || len(dns.Domain) > 253 || !safeName(dns.Domain) {
		return errors.New("notice: invalid DNS domain")
	}
	for _, score := range []float64{dns.Score, dns.Threshold} {
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return errors.New("notice: score and threshold must be finite in [0,1]")
		}
	}
	if dns.Score < dns.Threshold {
		return errors.New("notice: triggered score is below threshold")
	}
	if math.IsNaN(dns.Entropy) || math.IsInf(dns.Entropy, 0) || dns.Entropy < 0 || dns.Queries == 0 || uint64(dns.UniqueSubdomains) > dns.Queries {
		return errors.New("notice: invalid DNS entropy or query counts")
	}
	if len(dns.SourceIPs) > MaxCollectionEntries || uint64(len(dns.SourceIPs)) > dns.Queries {
		return errors.New("notice: source addresses exceed collection or query count")
	}
	for i, address := range dns.SourceIPs {
		if !address.IsValid() || address.Zone() != "" || address.Is4In6() || (i > 0 && dns.SourceIPs[i-1].Compare(address) >= 0) {
			return errors.New("notice: source addresses must be canonical, sorted and unique")
		}
	}
	return nil
}

// Evidence order is capture time, then origin node and flow UID. Delivery IDs
// are intentionally not required for pre-dispatch detector observations.
func noticeEvidenceBefore(a, b events.NoticeEvidenceReference) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.Before(b.Timestamp)
	}
	if a.NodeID != b.NodeID {
		return a.NodeID < b.NodeID
	}
	return a.UID < b.UID
}
