package source

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// SetObservationDomains installs a detached capture-source mapping. Domain
// reconfiguration belongs to the existing capture/session restart boundary.
func (s *LocalSource) SetObservationDomains(domains map[string]mediaadmission.DomainID) {
	copy := make(map[string]mediaadmission.DomainID, len(domains))
	for iface, domain := range domains {
		copy[iface] = domain
	}
	s.observationDomains.Store(&copy)
}

func (s *LocalSource) stampObservationDomain(envelope *pipeline.PacketEnvelope) {
	if domains := s.observationDomains.Load(); domains != nil && envelope != nil {
		domain, known := (*domains)[envelope.Source.InterfaceName]
		envelope.Source.ObservationDomain, envelope.Source.ObservationDomainKnown = uint32(domain), known
	}
}
