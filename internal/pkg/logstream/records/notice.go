package records

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// Notice writes detector decisions as metadata. It carries no packet/file body
// or command/action payload; event_id retains the immutable producer identity.
func Notice(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.NoticeEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected notice event, got %T", event)
	}
	if ev.DNS == nil {
		return logstream.Record{}, false, fmt.Errorf("notice schema %d requires DNS evidence", ev.SchemaVersion)
	}
	var nodes, uids []string
	var timestamps []time.Time
	for _, reference := range ev.Evidence {
		nodes = append(nodes, reference.NodeID)
		uids = append(uids, reference.UID)
		timestamps = append(timestamps, reference.Timestamp)
	}
	var evidenceNodes, evidenceUIDs, evidenceTimes any = nodes, uids, timestamps
	if len(ev.Evidence) == 0 && (ev.EvidenceTruncated || ev.EvidenceRedacted) {
		evidenceNodes, evidenceUIDs, evidenceTimes = logstream.Unset, logstream.Unset, logstream.Unset
	}
	dns := ev.DNS
	return networkRecord("notice", ev.Envelope(), ev.SchemaVersion, ev.Detector, ev.DetectorVersion, string(ev.Category), string(ev.Severity), string(ev.Status),
		ev.DetectorNodeID, ev.DetectorGeneration, dns.Domain, dns.Score, dns.Threshold, dns.Entropy, dns.Queries, dns.UniqueSubdomains,
		optionalAddresses(dns.SourceIPs), dns.UniqueSubdomainsTruncated, dns.SourceIPsTruncated,
		evidenceNodes, evidenceUIDs, evidenceTimes, ev.EvidenceTruncated, ev.EvidenceRedacted, ev.Envelope().EventID)
}
