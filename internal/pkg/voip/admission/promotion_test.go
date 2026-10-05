package admission

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestCurrentDerivationPromotionsSurviveRegistryCapacityFailure(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, update := range []string{"INFO", "opposite-answer"} {
			for _, resolution := range []string{"retry", "supersession-and-rollback"} {
				t.Run(string(policy)+"/"+update+"/"+resolution, func(t *testing.T) {
					cfg := mediaadmission.DefaultConfig()
					cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, policy, time.Hour
					maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
					controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
					require.NoError(t, err)
					store, err := mediaadmission.NewMetadataStore(cfg)
					require.NoError(t, err)
					registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 4})
					bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
					require.NoError(t, err)
					t.Cleanup(func() {
						registry.Close()
						require.NoError(t, bridge.Close())
						require.NoError(t, controller.Close(context.Background()))
					})
					initial := offer("registry-capacity")
					initial.ToTag = "to"
					require.NoError(t, submitDerivation(t, bridge, registry, initial))
					registry.Upsert(callregistry.Call{CallID: "capacity-blocker"})
					blocker, exists := registry.Call("capacity-blocker")
					require.True(t, exists)
					for _, endpoint := range []string{"192.0.2.9:30000", "192.0.2.9:30001"} {
						require.True(t, registry.TryAssociateEndpointForLifetime(blocker.CallID, blocker.Lifetime, endpoint))
					}
					changed := initial
					changed.CSeqNumber, changed.ViaBranch = 2, "changed"
					changed.SDP = derivationSDP("192.0.2.2", 20000, false)
					assertPending := func() {
						t.Helper()
						bridge.mu.Lock()
						pending := append([]mediaadmission.EndpointKey(nil), bridge.selected[initial.CallID].promote...)
						bridge.mu.Unlock()
						var expected []mediaadmission.EndpointKey
						for _, endpoint := range []string{"192.0.2.2:20000", "192.0.2.2:20001"} {
							key, err := parseEndpoint(bridge.cfg.Domain, endpoint)
							require.NoError(t, err)
							expected = append(expected, key)
						}
						require.ElementsMatch(t, expected, pending)
						require.Zero(t, bridge.Stats().UnknownDerivations, "complete SDP alone does not resolve registry rejection")
						state := mediaadmission.StateDegradedOpen
						if policy == mediaadmission.FailureClosed {
							state = mediaadmission.StateDegradedClosed
						}
						require.Equal(t, state, controller.Status()[0].State)
						require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
						require.Equal(t, initial.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
					}
					require.Error(t, submitDerivation(t, bridge, registry, changed))
					assertPending()
					message := changed
					message.SDP = initial.SDP
					if update == "INFO" {
						message.Method, message.CSeqMethod, message.CSeqNumber, message.ViaBranch = "INFO", "INFO", 3, "info"
					} else {
						message.Method, message.ResponseCode = "200", 200
					}
					require.Error(t, submitDerivation(t, bridge, registry, message))
					assertPending()
					if resolution == "supersession-and-rollback" {
						replacement := initial
						replacement.CSeqNumber, replacement.ViaBranch = 3, "replacement"
						require.NoError(t, submitDerivation(t, bridge, registry, replacement))
						assertDerivationState(t, bridge, controller, policy, false)
						// Exact failure restores complete B, whose unaccepted endpoints
						// must be reconstructed even though its unknown flag is false.
						replacement.Method, replacement.ResponseCode, replacement.SDP = "486", 486, nil
						require.Error(t, submitDerivation(t, bridge, registry, replacement))
						assertPending()
					}
					require.True(t, registry.Remove(blocker.CallID, callregistry.EndCompleted))
					require.NoError(t, bridge.retrySelected())
					assertDerivationState(t, bridge, controller, policy, false)
					require.Equal(t, initial.CallID, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
					require.Equal(t, 4, maps.count())
				})
			}
		}
	}
}
