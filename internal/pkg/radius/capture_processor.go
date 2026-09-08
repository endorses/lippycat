package radius

import (
	"encoding/binary"
	"sync"
	"time"

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
	boundary   time.Time
	now        time.Time
	mu         sync.Mutex
	ingress    *Ingress
	correlator *Correlator
	matcher    ObservationMatcher
}

func NewCaptureProcessor(scope CaptureScope, ports ...uint16) (*CaptureProcessor, error) {
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
	p.correlator, err = NewCorrelator(CorrelatorConfig{Now: func() time.Time { return p.now }, EvidenceCurrent: func(ref AttributionReference) bool {
		return p.matcher != nil && p.matcher.RADIUSEvidenceCurrent(ref)
	}})
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
	p.correlator.Close()
	correlator, err := NewCorrelator(p.correlator.config)
	if err != nil {
		return err
	}
	p.ingress, p.correlator, p.boundary = ingress, correlator, boundary
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
