// Package noticefixture supplies deterministic detector metadata for integration
// tests without executing commands or synthesizing a flow for a domain finding.
package noticefixture

import (
	"net/netip"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
)

func Event() events.NoticeEvent {
	env := events.Envelope{
		Timestamp: time.Unix(100, 0).UTC(), UID: "Cnotice", CommunityID: "1:notice", NodeID: "origin-hunter",
		ProducerSessionID: "notice-session", EventSequence: 1, CaptureScope: events.CaptureScopeFiltered, Partial: true,
		Flow:       events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53},
		Provenance: events.SourceProvenance{CaptureSource: "fixture", ProcessorNodeIDs: []string{"processor"}},
	}
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, env.EventSequence)
	e := events.NewNoticeEvent(env)
	e.Detector, e.DetectorVersion, e.Category = events.NoticeDetectorDNSTunneling, "1", events.NoticeCategorySecurity
	e.Severity = events.NoticeWarning
	e.DetectorNodeID, e.DetectorGeneration = "processor", "analysis-generation"
	e.Evidence = []events.NoticeEvidenceReference{
		{NodeID: "origin-hunter", UID: "Cfirst", Timestamp: time.Unix(98, 0).UTC()},
		{NodeID: "origin-hunter", UID: "Cnotice", Timestamp: time.Unix(100, 0).UTC()},
	}
	e.DNS = &events.DNSNoticeEvidence{Domain: "example.test", Score: 0.93, Threshold: 0.7, Entropy: 4.5, Queries: 50, UniqueSubdomains: 20,
		SourceIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")}}
	return e
}
