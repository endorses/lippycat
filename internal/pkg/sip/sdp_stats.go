package sip

import "sync"

var sdpReasons = [...]SDPReason{SDPMediaInvalid, SDPConnectionInvalid, SDPConnectionMissing, SDPRTCPInvalid, SDPBodyLimit, SDPEndpointLimit}

func sdpReasonIndex(reason SDPReason) int {
	for i, candidate := range sdpReasons {
		if reason == candidate {
			return i
		}
	}
	panic("unknown SDP diagnostic reason")
}

// SDPParseCounters is a fixed-size, concurrency-safe per-consumer aggregate.
// It stores no bodies, call identities, or endpoints.
type SDPParseCounters struct {
	mu     sync.Mutex
	counts sdpCounts
}

type sdpCounts struct {
	bodies, failures, partial, resourceLimited, diagnosticsDropped uint64
	reasons                                                        [len(sdpReasons)]uint64
}

type SDPParseStats struct {
	Bodies             uint64
	Failures           uint64
	Partial            uint64
	ResourceLimited    uint64
	DiagnosticsDropped uint64
	Reasons            map[SDPReason]uint64
}

func (c *SDPParseCounters) Observe(r SDPResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts.bodies++
	if !r.Complete {
		c.counts.failures++
	}
	if !r.Complete && len(r.Endpoints) > 0 {
		c.counts.partial++
	}
	if r.ResourceLimited {
		c.counts.resourceLimited++
	}
	c.counts.diagnosticsDropped += r.DiagnosticsDropped
	for i, count := range r.reasonCounts {
		c.counts.reasons[i] += count
	}
}

func (c *SDPParseCounters) snapshotCounts() sdpCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts
}

func (c *SDPParseCounters) Snapshot() SDPParseStats {
	counts := c.snapshotCounts()
	s := SDPParseStats{Bodies: counts.bodies, Failures: counts.failures, Partial: counts.partial, ResourceLimited: counts.resourceLimited, DiagnosticsDropped: counts.diagnosticsDropped, Reasons: make(map[SDPReason]uint64, len(sdpReasons))}
	for i, reason := range sdpReasons {
		s.Reasons[reason] = counts.reasons[i]
	}
	return s
}
