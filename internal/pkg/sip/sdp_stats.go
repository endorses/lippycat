package sip

import "sync/atomic"

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
	bodies, failures, partial, resourceLimited, diagnosticsDropped atomic.Uint64
	reasons                                                        [len(sdpReasons)]atomic.Uint64
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
	c.bodies.Add(1)
	if !r.Complete {
		c.failures.Add(1)
	}
	if !r.Complete && len(r.Endpoints) > 0 {
		c.partial.Add(1)
	}
	if r.ResourceLimited {
		c.resourceLimited.Add(1)
	}
	c.diagnosticsDropped.Add(r.DiagnosticsDropped)
	for i, count := range r.reasonCounts {
		c.reasons[i].Add(count)
	}
}

func (c *SDPParseCounters) Snapshot() SDPParseStats {
	s := SDPParseStats{Bodies: c.bodies.Load(), Failures: c.failures.Load(), Partial: c.partial.Load(), ResourceLimited: c.resourceLimited.Load(), DiagnosticsDropped: c.diagnosticsDropped.Load(), Reasons: make(map[SDPReason]uint64, len(sdpReasons))}
	for i, reason := range sdpReasons {
		s.Reasons[reason] = c.reasons[i].Load()
	}
	return s
}
