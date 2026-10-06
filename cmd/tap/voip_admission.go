//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
)

// Each domain owns its registry and TCP stream identity. Raw Call-ID remains
// visible to central output, whose historical grouping is not local authority.
type tapVoIPRouting struct {
	config    mediaadmission.Config
	adapter   *voipprocessor.SourceAdapter
	children  map[mediaadmission.DomainID]*voipprocessor.SourceAdapter
	engines   map[mediaadmission.DomainID]*pipeline.ReassemblyEngine
	handlers  []*voip.TapTCPHandler
	bridges   []*voipadmission.Bridge
	injection chan source.InjectedPacket
	shards    int
}

func newTapVoIPRouting(procConfig voipprocessor.Config, streamConfig voip.Config, shards int, session *admissionintegration.Session, grace time.Duration, interfaces []string) (_ *tapVoIPRouting, err error) {
	grace = effectiveTapVoIPGrace(grace)
	cfg := mediaadmission.DefaultConfig()
	if session != nil {
		cfg = session.Config
	} else if procConfig.MaxCalls <= 0 {
		// Disabled admission preserves the processor's historical default
		// substitution before partitioning its process budget.
		procConfig.MaxCalls = voipprocessor.DefaultConfig().MaxCalls
	}
	domains := cfg.Domains()
	// Limits are process budgets. Partition them deterministically instead of
	// multiplying each configured cap by the number of observation domains.
	if procConfig.MaxCalls < len(domains) || (procConfig.MaxEndpointAssociations > 0 && procConfig.MaxEndpointAssociations < len(domains)) || (streamConfig.MaxStreams > 0 && streamConfig.MaxStreams < len(domains)) {
		return nil, fmt.Errorf("VoIP call/endpoint/positive TCP stream limit must accommodate %d observation domains", len(domains))
	}
	r := &tapVoIPRouting{config: cfg, children: make(map[mediaadmission.DomainID]*voipprocessor.SourceAdapter), engines: make(map[mediaadmission.DomainID]*pipeline.ReassemblyEngine), injection: make(chan source.InjectedPacket, 1000), shards: shards}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	for i, domain := range domains {
		childConfig := procConfig
		childConfig.MaxCalls = partitionTapLimit(procConfig.MaxCalls, len(domains), i)
		childConfig.MaxEndpointAssociations = partitionTapLimit(procConfig.MaxEndpointAssociations, len(domains), i)
		childStreams := streamConfig
		childStreams.MaxStreams = partitionTapLimit(streamConfig.MaxStreams, len(domains), i)
		proc := voipprocessor.New(childConfig)
		adapter := voipprocessor.NewSourceAdapter(proc)
		r.children[domain] = adapter
		handler := voip.NewTapTCPHandler(r.injection)
		r.handlers = append(r.handlers, handler)
		handler.SetApplicationFilter(procConfig.ApplicationFilter)
		handler.SetCallRegistry(proc)
		if session != nil {
			bridge, bridgeErr := voipadmission.New(voipadmission.Config{RetirementGrace: grace, Domain: domain, Limits: cfg, Registry: proc.CallRegistry(), Controller: session.Controller, Metadata: session.Metadata, Diagnostics: session, OnError: func(err error) { logger.Error("Tap media admission update failed", "error", err) }})
			if bridgeErr != nil {
				return nil, bridgeErr
			}
			r.bridges = append(r.bridges, bridge)
			if err = proc.SetMetadataObserver(bridge); err != nil {
				return nil, err
			}
			handler.SetMetadataObserver(bridge)
			adapter.SetMediaObserver(bridge)
		}
		factory := voip.NewSipStreamFactoryWithConfig(context.Background(), handler, childStreams, func(callID string) bool { _, active := proc.Call(callID); return active })
		reassemblyConfig := pipeline.DefaultReassemblyConfig()
		reassemblyConfig.ShardCount = shards
		r.engines[domain] = pipeline.NewReassemblyEngine(factory, reassemblyConfig)
	}
	if session == nil {
		r.adapter = r.children[0]
	} else {
		r.adapter, err = voipprocessor.NewScopedSourceAdapter(cfg, r.children, grace)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Normalize before constructing either completion or admission: neither role
// should depend on a downstream constructor mutating shared configuration.
func effectiveTapVoIPGrace(grace time.Duration) time.Duration {
	if grace <= 0 {
		return voip.DefaultConfig().PCAPGracePeriod
	}
	return grace
}

func partitionTapLimit(limit, domains, index int) int {
	if limit == 0 {
		return 0
	}
	n := limit / domains
	if index < limit%domains {
		n++
	}
	return n
}
func (r *tapVoIPRouting) AssemblePacket(info capture.PacketInfo) bool {
	engine := r.engines[r.config.DomainForInterface(info.Interface)]
	if engine == nil {
		return false
	}
	return NewTapTCPAssembler(engine).AssemblePacket(info)
}
func (r *tapVoIPRouting) Start(ctx context.Context) {
	for _, engine := range r.engines {
		go func(engine *pipeline.ReassemblyEngine) {
			if err := engine.Run(ctx); err != nil {
				logger.Error("TCP reassembly engine stopped", "error", err)
			}
		}(engine)
	}
}
func (r *tapVoIPRouting) Close() {
	for _, engine := range r.engines {
		if err := engine.Close(); err != nil {
			logger.Error("Close tap TCP engine", "error", err)
		}
	}
	for _, handler := range r.handlers {
		handler.Close()
	}
	if r.adapter != nil {
		r.adapter.Close()
	} else {
		for _, child := range r.children {
			child.Close()
		}
	}
	for _, bridge := range r.bridges {
		if err := bridge.Close(); err != nil {
			logger.Error("Close tap SIP admission bridge", "error", err)
		}
	}
}
