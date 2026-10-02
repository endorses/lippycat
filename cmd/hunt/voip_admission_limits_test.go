//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestHunterDomainLimitsRemainProcessBudgets(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"right": 1, "unused": 2}
	limits := *voip.DefaultConfig()
	limits.MaxCalls, limits.MaxEndpointAssociations, limits.MaxStreams = 3, 5, 3
	interfaces := []string{" left, same-domain ", "right"}
	children, err := admissionHunterConfigs(cfg, interfaces, limits)
	require.NoError(t, err)
	require.Len(t, children, 2, "uncaptured domains do not consume budget")
	calls, endpoints, streams := 0, 0, 0
	for _, child := range children {
		require.Positive(t, child.config.MaxCalls)
		require.Positive(t, child.config.MaxEndpointAssociations)
		require.Positive(t, child.config.MaxStreams)
		calls += child.config.MaxCalls
		endpoints += child.config.MaxEndpointAssociations
		streams += child.config.MaxStreams
	}
	require.Equal(t, limits.MaxCalls, calls)
	require.Equal(t, limits.MaxEndpointAssociations, endpoints)
	require.Equal(t, limits.MaxStreams, streams)

	maps := &hunterAdmissionMap{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, maps)
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close(context.Background())) }()
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	router, err := newAdmissionHunterRouter(t.Context(), admissionForwarder{}, &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}, interfaces, limits)
	require.NoError(t, err)
	defer func() { require.NoError(t, router.Close()) }()
	totalCalls, totalEndpoints := 0, 0
	for _, scope := range router.domains {
		for i := 0; i < 6; i++ {
			scope.tracker.GetOrCreateCall(fmt.Sprint(i), layers.LinkTypeEthernet)
		}
		registry := scope.tracker.AdmissionRegistry()
		totalCalls += registry.ActiveCallCount()
		for _, call := range registry.ActiveCalls() {
			for i := 0; i < 6; i++ {
				registry.TryAssociateEndpoint(call.CallID, fmt.Sprintf("192.0.2.1:%d", 20000+i))
			}
		}
		totalEndpoints += registry.EndpointAssociationCount()
	}
	require.Equal(t, limits.MaxCalls, totalCalls)
	require.Equal(t, limits.MaxEndpointAssociations, totalEndpoints)
}

func TestHunterDomainLimitsRejectZeroPartitionsAndPreserveUnlimitedStreams(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"right": 1}
	for _, resource := range []string{"calls", "endpoints", "streams"} {
		t.Run(resource, func(t *testing.T) {
			limits := *voip.DefaultConfig()
			switch resource {
			case "calls":
				limits.MaxCalls = 1
			case "endpoints":
				limits.MaxEndpointAssociations = 1
			case "streams":
				limits.MaxStreams = 1
			}
			_, err := admissionHunterConfigs(cfg, []string{"left", "right"}, limits)
			require.Error(t, err, "zero must not turn a finite partition into unlimited/default capacity")
		})
	}
	children, err := admissionHunterConfigs(cfg, []string{"left", "right"}, *voip.DefaultConfig())
	require.NoError(t, err)
	for _, child := range children {
		require.Zero(t, child.config.MaxStreams)
	}
}
