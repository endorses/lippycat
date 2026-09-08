package radius

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Ingress owns one capture source epoch and its validation counters. Opening a
// new reader, a capture gap or reconnect requires constructing a new Ingress and
// discarding old association state. Keep the old scope on any queued observations.
// An Ingress is safe for concurrent Observe calls, but must not be copied.
type Ingress struct {
	ids      *IDGenerator
	scope    CaptureScope
	ports    []uint16
	counters ValidationCounters
}

// NewIngress opens a capture source with a fresh random epoch. Scope values are
// preserved except Epoch, which always changes. Empty provenance is allowed for
// ordinary analysis; it is not sufficient for inherited authorization.
func NewIngress(scope CaptureScope, additionalPorts ...uint16) (*Ingress, error) {
	for _, port := range additionalPorts {
		if port == 0 {
			return nil, fmt.Errorf("RADIUS service port must be nonzero")
		}
	}
	ids, err := NewIDGenerator()
	if err != nil {
		return nil, err
	}
	scope.Epoch = ids.Epoch()
	return &Ingress{ids: ids, scope: scope, ports: append([]uint16(nil), additionalPorts...)}, nil
}

// Scope returns the immutable original capture provenance.
func (i *Ingress) Scope() CaptureScope { return i.scope }

// Observe validates and owns captured bytes before the caller can reuse them.
// Each attempt has exactly one origin validation count. Identity exhaustion is
// an infrastructure error before observation, and does not fabricate a count.
func (i *Ingress) Observe(data []byte, linkType layers.LinkType, capture gopacket.CaptureInfo) (*Observation, Outcome, error) {
	id, err := i.ids.Next()
	if err != nil {
		return nil, "", err
	}
	observation, outcome, err := DecodePacket(data, linkType, capture, i.scope, id, i.ports...)
	i.counters.record(outcome)
	return observation, outcome, err
}

// Snapshot reports only validation at this source, not downstream redecoding.
func (i *Ingress) Snapshot() ValidationStats { return i.counters.Snapshot() }
