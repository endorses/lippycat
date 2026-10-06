package admission

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestSelectedDerivationBudgetIsGlobalAcrossDomainBridges(t *testing.T) {
	for _, limit := range []string{"contexts", "bytes", "endpoints"} {
		t.Run(limit, func(t *testing.T) {
			cfg := mediaadmission.DefaultConfig()
			cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, mediaadmission.FailureClosed, time.Hour
			cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"eth0": 0, "eth1": 1}
			switch limit {
			case "contexts":
				cfg.PendingDialogCapacity = 1
			case "bytes":
				cfg.PendingBytes, _ = derivationCost(derivationSide{"from", "to", "from", false}, &derivationState{
					branch: "branch", method: "INVITE", endpoints: make([]mediaadmission.EndpointKey, 2),
				})
			case "endpoints":
				cfg.PendingEndpointCapacity = 2
			}
			maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
			controller, err := mediaadmission.NewController(t.Context(), cfg, maps)
			require.NoError(t, err)
			store, err := mediaadmission.NewMetadataStore(cfg)
			require.NoError(t, err)
			registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
			first, err := New(Config{Domain: 0, Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
			require.NoError(t, err)
			second, err := New(Config{Domain: 1, Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
			require.NoError(t, err)
			t.Cleanup(func() {
				registry.Close()
				check(t, first.Close())
				check(t, second.Close())
				check(t, controller.Close(context.Background()))
			})
			message := offer("domain-zero")
			message.ToTag = "to"
			require.NoError(t, submitDerivation(t, first, registry, message))
			message = offer("domain-one")
			message.ToTag = "to"
			message.Packet.Source.InterfaceName = "eth1"
			require.Error(t, submitDerivation(t, second, registry, message))
			require.Equal(t, 1, second.Stats().UnknownDerivations)
			stats := store.Stats()
			require.Equal(t, 1, stats.SelectedContexts)
			require.Equal(t, 2, stats.SelectedEndpoints)
			require.LessOrEqual(t, stats.SelectedBytes, cfg.PendingBytes)
			require.NotZero(t, stats.SelectedRejected)
			for _, scope := range controller.Status() {
				if scope.Domain == 1 {
					require.Equal(t, mediaadmission.StateDegradedClosed, scope.State)
				}
			}
			// Final removal releases live descriptors but retains charged
			// anti-replay history within this same configured shared pool.
			registry.Remove("domain-zero", callregistry.EndCompleted)
			assertRetiredLifetimeCharges(t, first, 1)
			require.Error(t, second.retrySelected())
			registry.Remove("domain-one", callregistry.EndCompleted)
			require.NoError(t, second.retrySelected())
			require.Zero(t, first.derivationCount)
			require.Zero(t, second.derivationCount)
			stats = store.Stats()
			require.LessOrEqual(t, stats.SelectedContexts, cfg.PendingDialogCapacity)
			require.LessOrEqual(t, stats.SelectedBytes, cfg.PendingBytes)
			require.Zero(t, stats.SelectedEndpoints)
			if limit != "endpoints" {
				message.CallID = "replacement-before-shutdown"
				require.Error(t, submitDerivation(t, second, registry, message), "charged history prevents another live reservation at this configured limit")
				registry.Remove(message.CallID, callregistry.EndCompleted)
			}
			require.NoError(t, first.Close())
			require.NoError(t, second.Close())
			stats = store.Stats()
			require.Zero(t, stats.SelectedContexts)
			require.Zero(t, stats.SelectedBytes)
			require.Zero(t, stats.SelectedEndpoints)
			fresh, err := New(Config{Domain: 1, Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
			require.NoError(t, err)
			t.Cleanup(func() { check(t, fresh.Close()) })
			message.CallID = "replacement-after-shutdown"
			require.NoError(t, submitDerivation(t, fresh, registry, message))
			require.Equal(t, 1, store.Stats().SelectedContexts)
			assertClosedLifetimeCharges(t, fresh)

		})
	}
}

func TestConflictingSDPBytesWithIdenticalEndpointsStayUnknown(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	message := offer("same-endpoints-conflict")
	message.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, message))
	message.SDP = append(message.SDP, []byte("a=rtpmap:0 PCMU/8000\r\n")...)
	require.Error(t, submitDerivation(t, bridge, registry, message))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestResponseFromDifferentSameCSeqTransactionCannotProveRecovery(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	message := offer("wrong-response-branch")
	message.ToTag = "to"
	require.NoError(t, submitDerivation(t, bridge, registry, message))
	message.ResponseCode, message.Method, message.ViaBranch = 200, "200", "other"
	message.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.Error(t, submitDerivation(t, bridge, registry, message))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}
