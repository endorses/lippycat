//go:build linux

package admissionintegration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/ebpfadmission"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func newSession(ctx context.Context, config mediaadmission.Config, options ...SessionOptions) (*Session, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Snapshot maps used by concurrent readers; callers retain their own config.
	original := config.InterfaceDomains
	config.InterfaceDomains = make(map[string]mediaadmission.DomainID, len(original))
	for name, domain := range original {
		config.InterfaceDomains[name] = domain
	}
	s := &Session{Config: config}
	if !config.Enabled {
		return s, nil
	}
	if config.EndpointCapacity > 1<<30 || config.ShadowEvidenceCapacity > 1<<24 {
		return nil, fmt.Errorf("admission map/evidence capacity exceeds supported representation")
	}
	var err error
	s.Metadata, err = mediaadmission.NewMetadataStore(config)
	if err != nil {
		return nil, err
	}
	static := SessionOptions{ESPEnabled: true}
	if len(options) > 0 {
		static = options[len(options)-1]
	}
	ranges := make([]ebpfadmission.PortRange, len(static.RTPPortRanges))
	for i, r := range static.RTPPortRanges {
		ranges[i] = ebpfadmission.PortRange{Start: r.Start, End: r.End}
	}
	domains := uint32(1)
	for _, domain := range config.Domains() {
		if domain >= 4096 {
			return nil, fmt.Errorf("admission domain must be below 4096")
		}
		if uint32(domain) >= domains {
			domains = uint32(domain) + 1
		}
	}
	evidence := uint32(4096)
	for evidence < uint32(config.ShadowEvidenceCapacity)*64 {
		evidence *= 2
	}
	backend, err := ebpfadmission.NewBackend(ebpfadmission.Options{EndpointCapacity: uint32(config.EndpointCapacity), SelectorCapacity: uint32(config.EndpointCapacity), Domains: domains, EvidenceBytes: evidence, SIPPorts: static.SIPPorts, RTPPortRanges: ranges, UDPOnly: static.UDPOnly, ESPEnabled: static.ESPEnabled, ShadowSampleEvery: 1})
	if err != nil {
		return nil, err
	}
	s.closeBackend = backend.Close
	s.Controller, err = mediaadmission.NewController(ctx, config, backend)
	if err != nil {
		return nil, errors.Join(err, backend.Close())
	}
	s.installer, err = NewInstaller(backend, config.InterfaceDomains, 5*time.Second)
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	s.installer.(*Installer).status = s
	if err := s.initTelemetry(ctx, backend); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	s.start(ctx)
	return s, nil
}
