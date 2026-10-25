package events

import (
	"net/netip"
	"time"
)

const KindNotice Kind = "notice"

const NoticeSchemaVersion uint32 = 1

const (
	NoticeDetectorDNSTunneling = "dns.tunneling"
	NoticeCategorySecurity     = "security"
)

type NoticeSeverity string
type NoticeStatus string

const (
	NoticeWarning   NoticeSeverity = "warning"
	NoticeTriggered NoticeStatus   = "triggered"
)

// NoticeEvidenceReference identifies an actual contributing observation without
// assuming that a DNS event has already received a dispatcher delivery ID.
type NoticeEvidenceReference struct {
	NodeID, UID string
	Timestamp   time.Time
}

// DNSNoticeEvidence describes the bounded state behind one DNS tunneling
// decision. Truncated cardinalities are retained lower bounds, not exact totals.
type DNSNoticeEvidence struct {
	Domain                                        string
	Score, Threshold, Entropy                     float64
	Queries                                       uint64
	UniqueSubdomains                              uint32
	SourceIPs                                     []netip.Addr
	UniqueSubdomainsTruncated, SourceIPsTruncated bool
}

// NoticeEvent records a detector decision, separately from protocol observations
// and external action outcomes. The envelope anchors it in the triggering flow.
// Detector authority is explicit: an origin NodeID can belong to a hunter even
// when a processor owns analysis. Only that local authority may admit actions;
// forwarding a notice does not grant authority to execute a command.
type NoticeEvent struct {
	eventBase
	SchemaVersion                       uint32
	Detector, DetectorVersion, Category string
	Severity                            NoticeSeverity
	Status                              NoticeStatus
	DetectorNodeID, DetectorGeneration  string
	Evidence                            []NoticeEvidenceReference
	EvidenceTruncated                   bool
	EvidenceRedacted                    bool
	DNS                                 *DNSNoticeEvidence
}

func NewNoticeEvent(env Envelope) NoticeEvent {
	return NoticeEvent{eventBase: eventBase{env}, SchemaVersion: NoticeSchemaVersion, Status: NoticeTriggered}
}

func (NoticeEvent) Kind() Kind   { return KindNotice }
func (NoticeEvent) eventMarker() {}

func (e NoticeEvent) Clone() NoticeEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	e.Evidence = append([]NoticeEvidenceReference(nil), e.Evidence...)
	if e.DNS != nil {
		dns := *e.DNS
		dns.SourceIPs = append([]netip.Addr(nil), dns.SourceIPs...)
		e.DNS = &dns
	}
	return e
}
