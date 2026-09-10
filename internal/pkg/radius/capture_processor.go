package radius

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ObservationMatcher keeps protocol attribution separate from generic filter IDs.
type ObservationMatcher interface {
	MatchRADIUSObservation(*Observation) (bool, []string, []AttributionReference)
	RADIUSEvidenceCurrent(AttributionReference) bool
}

// CaptureProcessor owns validation and bounded association for one capture epoch.
// Process must run before selection, including for nonmatching competitors.
type CaptureProcessor struct {
	lastReport time.Time
	boundary   time.Time
	now        time.Time
	mu         sync.Mutex
	ingress    *Ingress
	correlator *Correlator
	matcher    ObservationMatcher
}

func NewCaptureProcessor(scope CaptureScope, ports ...uint16) (*CaptureProcessor, error) {
	return NewCaptureProcessorWithConfig(scope, CorrelatorConfig{}, ports...)
}

// NewCaptureProcessorWithConfig applies bounded transaction policy at capture ingress.
func NewCaptureProcessorWithConfig(scope CaptureScope, config CorrelatorConfig, ports ...uint16) (*CaptureProcessor, error) {
	if scope.OperatorScope == "" {
		scope.OperatorScope = "local"
	}
	if scope.ProfileRevision == "" {
		scope.ProfileRevision = "unconfigured"
	}
	ingress, err := NewIngress(scope, ports...)
	if err != nil {
		return nil, err
	}
	p := &CaptureProcessor{ingress: ingress}
	config.Now = func() time.Time { return p.now }
	config.EvidenceCurrent = func(ref AttributionReference) bool { return p.matcher != nil && p.matcher.RADIUSEvidenceCurrent(ref) }
	p.correlator, err = NewCorrelator(config)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *CaptureProcessor) Process(packet gopacket.Packet, linkType layers.LinkType, sourceID string, matcher ObservationMatcher) *Observation {
	if p == nil || packet == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !captureCandidate(packet, p.ingress.ports) {
		return nil
	}
	defer func() {
		if time.Since(p.lastReport) >= time.Minute {
			p.logStats()
			p.lastReport = time.Now()
		}
	}()
	p.matcher = matcher
	defer func() { p.matcher = nil }()
	observation, _, err := p.ingress.Observe(packet.Data(), linkType, packet.Metadata().CaptureInfo)
	if err != nil {
		return nil
	}
	if packet.Metadata().Timestamp.After(p.now) {
		p.now = packet.Metadata().Timestamp
	}
	if p.now.IsZero() {
		p.now = time.Now()
	}
	if sourceID == "" {
		sourceID = observation.Scope.SourceID
	}
	if sourceID == "" {
		sourceID = "unknown"
	}
	observation.Scope.SourceID = sourceID
	if matcher != nil {
		_, _, observation.Direct = matcher.MatchRADIUSObservation(observation)
	}
	if !p.boundary.IsZero() && !observation.Capture.Timestamp.After(p.boundary) {
		observation.Association.Status = AssociationMissing
		return observation
	}
	return p.correlator.Process(observation)
}

func (p *CaptureProcessor) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logStats()
	p.correlator.Close()
}

func (p *CaptureProcessor) Stats() (ValidationStats, CorrelatorStats) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ingress.Snapshot(), p.correlator.Stats()
}

// AdvanceBoundary starts a fresh epoch after a live capture configuration change.
// Queued packets from before the boundary retain direct selection but cannot seed
// or inherit association across the capture gap.
func (p *CaptureProcessor) AdvanceBoundary(boundary time.Time) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !boundary.After(p.boundary) {
		return nil
	}
	ingress, err := NewIngress(p.ingress.Scope(), p.ingress.ports...)
	if err != nil {
		p.correlator.Close()
		return err
	}
	p.logStats()
	p.correlator.Close()
	correlator, err := NewCorrelator(p.correlator.config)
	if err != nil {
		return err
	}
	p.ingress, p.correlator, p.boundary = ingress, correlator, boundary
	p.lastReport = time.Time{}
	return nil
}

// captureCandidate avoids charging unrelated traffic to RADIUS validation.
// Noninitial UDP fragments have no visible ports and are conservatively counted
// as fragmented candidates; they never expose identities or seed association.
func captureCandidate(packet gopacket.Packet, ports []uint16) bool {
	if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
		return servicePort(uint16(udp.SrcPort), ports) || servicePort(uint16(udp.DstPort), ports)
	}
	for _, layer := range packet.Layers() {
		switch ip := layer.(type) {
		case *layers.IPv4:
			if ip.Protocol != layers.IPProtocolUDP {
				return false
			}
			if ip.FragOffset != 0 {
				return true
			}
			if len(ip.Payload) >= 4 {
				return servicePort(binary.BigEndian.Uint16(ip.Payload[:2]), ports) || servicePort(binary.BigEndian.Uint16(ip.Payload[2:4]), ports)
			}
		case *layers.IPv6Fragment:
			if ip.NextHeader == layers.IPProtocolUDP {
				return true
			}
		}
	}
	return false
}

// IsCaptureCandidate identifies traffic needing RADIUS validation or a safe
// rejection summary; it never establishes that a message is valid.
func IsCaptureCandidate(packet gopacket.Packet, ports ...uint16) bool {
	return packet != nil && captureCandidate(packet, ports)
}

// logStats exposes epoch-local counters at shutdown and capture-boundary rotation.
func (p *CaptureProcessor) logStats() {
	v, c := p.ingress.Snapshot(), p.correlator.Stats()
	if v == (ValidationStats{}) {
		return
	}
	scope := p.ingress.Scope()
	logger.Info("RADIUS capture counters", "scope", scope.OperatorScope, "epoch", fmt.Sprintf("%x", scope.Epoch), "origin", scope.OriginNodeID, "source", scope.SourceID,
		"valid", v.Valid, "malformed", v.Malformed, "fragmented", v.Fragmented, "unsupported", v.Unsupported,
		"requests", c.Requests, "matched_requests", c.MatchedRequests, "correlated_responses", c.Unique,
		"unmatched_responses", c.Missing, "ambiguous_responses", c.Ambiguous, "expired_responses", c.Expired,
		"incompatible_responses", c.Incompatible, "capacity_suppressed_responses", c.CapacitySuppressed,
		"stale_references", c.StaleReferences, "state_exhaustion", c.CapacityLosses)
}

// CombineMatchers preserves independent ordinary and task attribution groups.
func CombineMatchers(a, b ObservationMatcher) ObservationMatcher {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return combinedMatcher{a, b}
}

type combinedMatcher struct{ a, b ObservationMatcher }

func (m combinedMatcher) MatchRADIUSObservation(o *Observation) (bool, []string, []AttributionReference) {
	am, ai, ar := m.a.MatchRADIUSObservation(o)
	bm, bi, br := m.b.MatchRADIUSObservation(o)
	return am || bm, append(append([]string(nil), ai...), bi...), append(cloneReferences(ar), cloneReferences(br)...)
}
func (m combinedMatcher) RADIUSEvidenceCurrent(r AttributionReference) bool {
	return m.a.RADIUSEvidenceCurrent(r) || m.b.RADIUSEvidenceCurrent(r)
}
