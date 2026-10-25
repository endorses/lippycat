package eventanalysis

import (
	"context"
	"net/netip"
	"sort"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func (r *Runtime) observeDNSNotice(env events.Envelope, metadata *data.DNSMetadata, scopes []string) {
	if r.dnsTunneling == nil || (r.cfg.DNSNoticeAuthority != nil && !r.cfg.DNSNoticeAuthority()) {
		return
	}
	if metadata.QueryName == "" || len(metadata.QueryName) > 253 {
		r.stats.Invalid++
		return
	}
	scope := ""
	if len(scopes) > 0 {
		scope = scopes[0]
	}
	decision := r.dnsTunneling.AnalyzeScopedAt(&types.DNSMetadata{QueryName: metadata.QueryName, QueryType: metadata.QueryType, IsResponse: metadata.IsResponse}, env.NodeID, env.Flow.SourceAddress.String(), env.Timestamp, scope)
	if decision.Suppressed {
		r.stats.DNSSuppressed++
	}
	if decision.Alert == nil {
		return
	}
	alert := decision.Alert
	notice := events.NewNoticeEvent(env)
	notice.Detector, notice.DetectorVersion, notice.Category = events.NoticeDetectorDNSTunneling, "1", events.NoticeCategorySecurity
	notice.Severity = events.NoticeWarning
	notice.DetectorNodeID = r.cfg.DetectorNodeID
	if notice.DetectorNodeID == "" {
		notice.DetectorNodeID = env.NodeID
	}
	notice.DetectorGeneration = r.cfg.DetectorGeneration
	// The trigger is a real contributing observation. We intentionally retain one
	// reference rather than claiming this is the domain's complete flow history.
	notice.Evidence = []events.NoticeEvidenceReference{{NodeID: env.NodeID, UID: env.UID, Timestamp: env.Timestamp}}
	notice.EvidenceTruncated = alert.Queries > 1
	evidence := &events.DNSNoticeEvidence{Domain: alert.Domain, Score: alert.Score, Threshold: alert.Threshold, Entropy: alert.Entropy, Queries: uint64(alert.Queries), UniqueSubdomains: uint32(alert.UniqueSubdomains), UniqueSubdomainsTruncated: alert.UniqueSubdomainsTruncated, SourceIPsTruncated: alert.SrcIPsTruncated}
	for _, value := range alert.SrcIPs {
		if addr, err := netip.ParseAddr(value); err == nil {
			evidence.SourceIPs = append(evidence.SourceIPs, addr.Unmap())
		}
	}
	sort.Slice(evidence.SourceIPs, func(i, j int) bool { return evidence.SourceIPs[i].Compare(evidence.SourceIPs[j]) < 0 })
	addresses := evidence.SourceIPs[:0]
	for _, addr := range evidence.SourceIPs {
		if len(addresses) == 0 || addresses[len(addresses)-1] != addr {
			addresses = append(addresses, addr)
		}
	}
	evidence.SourceIPs = addresses
	notice.DNS = evidence
	assigned, ok := r.cfg.Dispatcher.AssignIdentity(notice).(events.NoticeEvent)
	if !ok {
		r.stats.DNSNoticeDropped++
		return
	}
	r.stats.DNSNotices++
	r.stats.Emitted++
	admitted := false
	if r.cfg.LosslessDelivery {
		admitted = r.cfg.Dispatcher.EnqueueLossless(context.Background(), assigned)
	} else {
		admitted = r.cfg.Dispatcher.Enqueue(assigned)
	}
	if !admitted {
		r.stats.Dropped++
		r.stats.DNSNoticeDropped++
	}
	// Local action admission is independent of best-effort output queue pressure.
	// Its worker owns separate bounds, deduplication and outcome counters.
	if r.cfg.OnLocalNotice != nil {
		if err := r.cfg.OnLocalNotice(assigned.Clone()); err != nil {
			r.stats.DNSActionDropped++
		}
	}
}

func (r *Runtime) SuspiciousDomains(threshold float64, limit int) []dns.TunnelingReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dnsTunneling == nil {
		return nil
	}
	return r.dnsTunneling.GetSuspiciousDomains(threshold, limit)
}
