//go:build hunter || all

package hunt

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	"time"
)

type admissionHunterDomain struct {
	processor *voip.VoIPPacketProcessor
	tcp       *voip.HunterForwardHandler
	tracker   *voip.CallTracker
	buffer    *voip.BufferManager
	assembler *pipeline.ReassemblyEngine
	bridge    *sipadmission.Bridge
}
type admissionHunterRouter struct {
	config  mediaadmission.Config
	domains map[mediaadmission.DomainID]*admissionHunterDomain
}

func (r *admissionHunterRouter) ProcessPacket(packet capture.PacketInfo) bool {
	scope := r.domains[r.config.DomainForInterface(packet.Interface)]
	if scope == nil {
		return false
	}
	return scope.processor.ProcessPacket(packet)
}
func (r *admissionHunterRouter) SetApplicationFilter(filter voip.ApplicationFilter) {
	for _, scope := range r.domains {
		scope.processor.SetApplicationFilter(filter)
	}
}
func (r *admissionHunterRouter) RTPAttributionStats() voip.RTPAttributionStats {
	var result voip.RTPAttributionStats
	for _, scope := range r.domains {
		s := scope.processor.RTPAttributionStats()
		result.OwnershipUnresolved += s.OwnershipUnresolved
		result.OwnershipAmbiguous += s.OwnershipAmbiguous
		result.InheritanceSuppressed += s.InheritanceSuppressed
	}
	return result
}
func (r *admissionHunterRouter) Close() error {
	var errs []error
	for _, scope := range r.domains {
		if scope.assembler != nil {
			errs = append(errs, scope.assembler.Close())
		}
		if scope.processor != nil {
			scope.processor.Close()
		}
		if scope.bridge != nil {
			errs = append(errs, scope.bridge.Close())
		}
		if scope.tracker != nil {
			scope.tracker.Shutdown()
		}
		if scope.buffer != nil {
			scope.buffer.Close()
		}
	}
	return errors.Join(errs...)
}

// admissionHunterConfigs partitions the existing process-wide hard budgets
// across domains actually captured. Duplicate interfaces in one domain share a
// single budget. Zero MaxStreams retains its existing unlimited meaning.
func admissionHunterConfigs(cfg mediaadmission.Config, interfaces []string, config voip.Config) ([]admissionHunterConfig, error) {
	names := make(map[mediaadmission.DomainID]string)
	for _, list := range interfaces {
		for _, name := range strings.Split(list, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			domain := cfg.DomainForInterface(name)
			if _, exists := names[domain]; !exists {
				names[domain] = name
			}
		}
	}
	if len(names) == 0 {
		return nil, errors.New("hunter admission requires a capture interface")
	}
	if config.MaxCalls <= 0 {
		config.MaxCalls = voip.DefaultMaxCalls
	}
	if config.MaxEndpointAssociations <= 0 {
		config.MaxEndpointAssociations = config.MaxCalls * 8
	}
	count := len(names)
	if config.MaxCalls < count || config.MaxEndpointAssociations < count || (config.MaxStreams > 0 && config.MaxStreams < count) {
		return nil, fmt.Errorf("VoIP call/endpoint/positive TCP stream limit must accommodate %d observation domains", count)
	}
	domains := make([]mediaadmission.DomainID, 0, count)
	for domain := range names {
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })
	partition := func(limit, index int) int {
		value := limit / count
		if index < limit%count {
			value++
		}
		return value
	}
	result := make([]admissionHunterConfig, 0, count)
	for index, domain := range domains {
		child := config
		child.MaxCalls = partition(config.MaxCalls, index)
		child.MaxEndpointAssociations = partition(config.MaxEndpointAssociations, index)
		child.MaxStreams = partition(config.MaxStreams, index)
		result = append(result, admissionHunterConfig{domain: domain, representative: names[domain], config: child})
	}
	return result, nil
}

type admissionHunterConfig struct {
	domain         mediaadmission.DomainID
	representative string
	config         voip.Config
}

func newAdmissionHunterRouter(ctx context.Context, h voip.PacketForwarder, session *admissionintegration.Session, interfaces []string, config voip.Config) (*admissionHunterRouter, error) {
	configs, err := admissionHunterConfigs(session.Config, interfaces, config)
	if err != nil {
		return nil, err
	}
	router := &admissionHunterRouter{config: session.Config, domains: make(map[mediaadmission.DomainID]*admissionHunterDomain)}
	for _, child := range configs {
		domain := child.domain
		scope := &admissionHunterDomain{tracker: voip.NewCallTrackerWithConfig(&child.config), buffer: voip.NewBufferManager(5*time.Second, 200)}
		router.domains[domain] = scope
		bridge, err := sipadmission.New(sipadmission.Config{Domain: domain, Limits: session.Config, Registry: scope.tracker.AdmissionRegistry(), Controller: session.Controller, Metadata: session.Metadata, Diagnostics: session, OnError: func(err error) { logger.Error("Hunter media admission is incomplete", "domain", domain, "error", err) }})
		if err != nil {
			return nil, errors.Join(err, router.Close())
		}
		scope.bridge = bridge
		tcp := voip.NewHunterForwardHandler(scope.tracker, h, scope.buffer)
		scope.tcp = tcp
		factory := voip.NewSipStreamFactoryWithConfig(ctx, tcp, child.config, scope.tracker.IsCallActive)
		scope.assembler = pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
		scope.processor = voip.NewVoIPPacketProcessor(scope.tracker, h, scope.buffer)
		scope.processor.SetTCPHandler(tcp)
		scope.processor.SetAssembler(scope.assembler)
		scope.processor.SetMediaAdmission(bridge, child.representative)
	}
	return router, nil
}

func runAdmissionVoIPHunter(ctx context.Context, h *hunter.Hunter, session *admissionintegration.Session, interfaces []string, config voip.Config) error {
	router, err := newAdmissionHunterRouter(ctx, h, session, interfaces, config)
	if err != nil {
		return err
	}
	defer func() {
		if err := router.Close(); err != nil {
			logger.Error("Close hunter admission router", "error", err)
		}
	}()
	h.SetPacketProcessor(router)
	for _, scope := range router.domains {
		go func(scope *admissionHunterDomain) {
			if err := scope.assembler.Run(ctx); err != nil {
				logger.Error("Hunter SIP reassembly stopped", "error", err)
			}
		}(scope)
	}
	if err := h.Start(ctx); err != nil {
		return fmt.Errorf("start admission-enabled hunter: %w", err)
	}
	return nil
}

var _ forwarding.ApplicationFilterReceiver = (*admissionHunterRouter)(nil)
