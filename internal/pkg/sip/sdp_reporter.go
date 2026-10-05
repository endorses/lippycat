package sip

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// SDPWarningInterval bounds maintenance warnings per reporting path. Shutdown
// may publish one final aggregate so short offline captures also report failures.
const SDPWarningInterval = 30 * time.Second

type SDPReportingPath uint8

const (
	SDPTrackerPath SDPReportingPath = iota
	SDPBufferPath
	SDPLocalProcessorPath
	SDPDistributedProcessorPath
)

func (p SDPReportingPath) String() string {
	switch p {
	case SDPTrackerPath:
		return "voip-tracker"
	case SDPBufferPath:
		return "voip-buffer"
	case SDPLocalProcessorPath:
		return "voip-local-processor"
	case SDPDistributedProcessorPath:
		return "processor"
	default:
		return "unknown"
	}
}

// SDPDiagnosticReporter consumes counters only from maintenance/shutdown, never
// packet handling. All retained state has fixed size; counters and reporter locks
// are separate, so slow log I/O cannot hold the packet-side counter lock.
type SDPDiagnosticReporter struct {
	counters          *SDPParseCounters
	path              SDPReportingPath
	disabled          atomic.Bool
	mu                sync.Mutex
	seen, published   sdpCounts
	lastReport        time.Time
	stats             SDPReportStats
	pendingSuppressed uint64
	warn              func(string, ...any)
}

type SDPReportStats struct {
	Warnings   uint64
	Suppressed uint64 // New incomplete parses retained during a throttled report.
}

func NewSDPDiagnosticReporter(counters *SDPParseCounters, path SDPReportingPath) *SDPDiagnosticReporter {
	return &SDPDiagnosticReporter{counters: counters, path: path, warn: logger.Warn}
}

// Disable delegates reporting to another parsing owner before packet processing.
// Parse counters remain available. Pairing a tracker with a buffer uses the
// buffer's observations, including unmatched SIP, instead of duplicate parses.
func (r *SDPDiagnosticReporter) Disable() {
	if r != nil {
		r.disabled.Store(true)
	}
}

func (r *SDPDiagnosticReporter) Stats() SDPReportStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *SDPDiagnosticReporter) Report(now time.Time) { r.report(now, false) }
func (r *SDPDiagnosticReporter) Flush()               { r.report(time.Now(), true) }

func (r *SDPDiagnosticReporter) report(now time.Time, final bool) {
	if r == nil || r.disabled.Load() || !logger.Enabled(slog.LevelWarn) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.counters.snapshotCounts()
	newFailures := current.failures - r.seen.failures
	r.seen = current
	if current.failures == r.published.failures {
		return
	}
	if !final && r.stats.Warnings > 0 && now.Sub(r.lastReport) < SDPWarningInterval {
		r.stats.Suppressed += newFailures
		r.pendingSuppressed += newFailures
		return
	}
	reasons := make(map[SDPReason]uint64, len(sdpReasons))
	for i, reason := range sdpReasons {
		if n := current.reasons[i] - r.published.reasons[i]; n > 0 {
			reasons[reason] = n
		}
	}
	failures := current.failures - r.published.failures
	partial := current.partial - r.published.partial
	r.warn("SDP endpoint derivation incomplete",
		"reporting_path", r.path.String(),
		"bodies", current.bodies-r.published.bodies,
		"incomplete", failures, "failed", failures-partial, "partial", partial,
		"resource_limited", current.resourceLimited-r.published.resourceLimited,
		"diagnostics_omitted", current.diagnosticsDropped-r.published.diagnosticsDropped,
		"reasons", reasons, "suppressed", r.pendingSuppressed,
		"suppressed_total", r.stats.Suppressed, "final", final)
	r.published = current
	r.pendingSuppressed = 0
	r.lastReport = now
	r.stats.Warnings++
}
