//go:build processor || tap || all

package processor

import (
	"context"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"net"
	"testing"
	"time"
)

func TestNetworkOptionalKindsKeepOldSourcesCompatible(t *testing.T) {
	old := eventForwardingCapabilities(1, 2, 3, 4, 5, 6, 7)
	mode, _, accepted, _, _, err := negotiateEventForwarding(old)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	require.Equal(t, old.EventKinds, accepted)
	_, _, _, _, _, err = negotiateEventForwarding(old, eventsv1.EventKind_EVENT_KIND_DHCP)
	require.ErrorContains(t, err, "required event kind")
	old.AllowPacketFallback = true
	mode, _, _, _, notice, err := negotiateEventForwarding(old, eventsv1.EventKind_EVENT_KIND_DHCP)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, mode)
	require.Contains(t, notice, "explicit packet fallback")
	unknown := eventForwardingCapabilities(1, 2, 3, 4, 5, 6, 7, 999)
	mode, _, accepted, _, notice, err = negotiateEventForwarding(unknown)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	require.NotContains(t, accepted, int32(999))
	require.Contains(t, notice, "compatibility loss")
}

func TestNetworkRequiredInventoryDependsOnSourcePolicy(t *testing.T) {
	disabledPolicy := eventconfig.Default()
	disabledPolicy.Inventory.Enabled = false
	p := &Processor{config: Config{EventAnalysis: &disabledPolicy, LogConfig: &StructuredLogConfig{Enabled: true, Streams: []string{"known_hosts"}}}}
	_, _, _, _, _, packetErr := p.negotiateEventForwarding(nil)
	require.ErrorContains(t, packetErr, "inventory-producing event source")
	disabled := eventForwardingCapabilities(protoadapter.SupportedKindIDs(false)...)
	disabled.AllowPacketFallback = true
	_, _, _, _, _, err := p.negotiateEventForwarding(disabled)
	require.ErrorContains(t, err, "KNOWN_HOST")
	enabled := eventForwardingCapabilities(protoadapter.SupportedKindIDs(true)...)
	// Codec-only relays can transport optional inventory but cannot promise
	// inventory production to a configured consuming stream.
	enabled.StatefulAnalysisFeatures = []string{"relay"}
	_, _, _, _, _, err = p.negotiateEventForwarding(enabled)
	require.ErrorContains(t, err, "KNOWN_HOST")
	generic := &Processor{}
	_, _, _, _, _, err = generic.negotiateEventForwarding(enabled)
	require.NoError(t, err)
	enabled.StatefulAnalysisFeatures = append(enabled.StatefulAnalysisFeatures, protoadapter.InventoryProductionFeature)

	mode, _, accepted, _, _, err := p.negotiateEventForwarding(enabled)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	require.Contains(t, accepted, int32(eventsv1.EventKind_EVENT_KIND_KNOWN_HOST))
	cfg := eventconfig.Default()
	cfg.Inventory.Enabled = true
	cfg.Inventory.LocalCIDRs = []string{"192.0.2.0/24"}
	p.config.EventAnalysis = &cfg
	mode, _, _, _, _, err = p.negotiateEventForwarding(disabled)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, mode)
}

// This exercises the real relay upstream registration and hunter/downstream
// registration handlers, not a hand-built capability declaration alone.
func TestInventoryPromiseAcrossThreeNodeRegistration(t *testing.T) {
	for _, scenario := range []string{"local_policy", "consumer_only", "optional"} {
		t.Run(scenario, func(t *testing.T) {
			centralCfg := Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0"}
			if scenario != "optional" {
				centralCfg.LogConfig = &StructuredLogConfig{Enabled: true, Streams: []string{"known_hosts", "known_services"}}
			}
			central, centralAddress := inventoryRegistrationServer(t, centralCfg)
			relayCfg := Config{ProcessorID: "relay", ListenAddr: "127.0.0.1:0", UpstreamAddr: centralAddress, UpstreamForwardMode: "events", UpstreamEventDeliveryProfile: "memory_only", UpstreamEventSpoolDirectory: t.TempDir()}
			if scenario != "local_policy" {
				policy := eventconfig.Default()
				policy.Inventory.Enabled = false
				relayCfg.EventAnalysis = &policy
			}
			if scenario == "consumer_only" {
				relayCfg.LogConfig = &StructuredLogConfig{Enabled: true, Streams: []string{"known_hosts"}}
			}
			// With no explicit EventAnalysis, local_policy verifies default inventory
			// is resolved and advertised through the upstream registration.
			relay, relayAddress := inventoryRegistrationServer(t, relayCfg)
			require.NoError(t, relay.upstreamManager.Start())
			require.Eventually(t, func() bool { return relay.upstreamManager.GetUpstreamProcessorID() == central.config.ProcessorID }, 5*time.Second, time.Millisecond)
			conn, err := grpc.NewClient(relayAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer func() { require.NoError(t, conn.Close()) }()
			client := management.NewManagementServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			disabled := eventForwardingCapabilities(protoadapter.SupportedKindIDs(false)...)
			result, err := client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "old-source", EventForwarding: disabled})
			if scenario == "optional" {
				require.NoError(t, err)
				require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, result.AcceptedForwardingMode)
				return
			}
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Contains(t, err.Error(), "KNOWN_HOST")
			// Codec-only child relays cannot bypass the same production guarantee.
			codecOnly := eventForwardingCapabilities(protoadapter.SupportedKindIDs(true)...)
			codecOnly.StatefulAnalysisFeatures = []string{"relay"}
			_, err = client.RegisterProcessor(ctx, &management.ProcessorRegistration{ProcessorId: "codec-only-child", ListenAddress: "127.0.0.1:1", EventForwarding: codecOnly})
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			// A host-only downstream policy cannot satisfy the relay's promise of
			// both inventory kinds, even if its own local consumer requests just one.
			hostOnly := eventForwardingCapabilities(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
			hostOnly.StatefulAnalysisFeatures = append(hostOnly.StatefulAnalysisFeatures, protoadapter.InventoryProductionFeature)
			_, err = client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "host-only", EventForwarding: hostOnly})
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Contains(t, err.Error(), "KNOWN_SERVICE")
			disabled.AllowPacketFallback = true
			result, err = client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "fallback-source", EventForwarding: disabled})
			if scenario == "local_policy" {
				require.NoError(t, err)
				require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, result.AcceptedForwardingMode)
			} else {
				require.Equal(t, codes.FailedPrecondition, status.Code(err))
			}
			enabled := eventForwardingCapabilities(protoadapter.SupportedKindIDs(true)...)
			enabled.StatefulAnalysisFeatures = append(enabled.StatefulAnalysisFeatures, protoadapter.InventoryProductionFeature)
			result, err = client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "inventory-source", EventForwarding: enabled})
			require.NoError(t, err)
			require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, result.AcceptedForwardingMode)
		})
	}
}

func inventoryRegistrationServer(t *testing.T, cfg Config) (*Processor, string) {
	t.Helper()
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	p.registerGRPCServices(server)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done) })
	return p, listener.Addr().String()
}
