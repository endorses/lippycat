package voip

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/stretchr/testify/require"
)

func TestProcessorRecoveryGracePreservesSharedTrailingIdentity(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, shared := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/shared=%t", mode, policy, shared), func(t *testing.T) {
					cfg := mediaadmission.DefaultConfig()
					cfg.Enabled, cfg.Mode, cfg.FailurePolicy, cfg.RetryInterval = true, mode, policy, time.Hour
					processor := voipprocessor.New(voipprocessor.DefaultConfig())
					t.Cleanup(processor.Close)
					controller, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
					require.NoError(t, err)
					metadata, err := mediaadmission.NewMetadataStore(cfg)
					require.NoError(t, err)
					bridge, err := sipadmission.New(sipadmission.Config{Limits: cfg, RetirementGrace: time.Hour, Registry: processor.CallRegistry(), Controller: controller, Metadata: metadata})
					require.NoError(t, err)
					require.NoError(t, processor.SetMetadataObserver(bridge))
					t.Cleanup(func() { require.NoError(t, bridge.Close()); require.NoError(t, controller.Close(context.Background())) })
					child := voipprocessor.NewSourceAdapter(processor)
					adapter, err := voipprocessor.NewScopedSourceAdapter(cfg, map[mediaadmission.DomainID]*voipprocessor.SourceAdapter{0: child}, time.Hour)
					require.NoError(t, err)
					t.Cleanup(adapter.Close)
					const call = "grace-original"
					compatibilitySend(t, adapter, call, "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
					compatibilitySend(t, adapter, call, "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", compatibilitySDP("192.0.2.2", 20000))
					compatibilitySend(t, adapter, call, "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", "RAck: 102 1 INVITE\r\n", compatibilitySDP("192.0.2.1", 10000))
					compatibilitySend(t, adapter, call, "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
					original, ok := processor.Call(call)
					require.True(t, ok)
					if shared {
						compatibilityExchange(t, adapter, "grace-other", "INVITE", 1, 10000, 22000)
					}
					compatibilityRTP(t, adapter, 10000, 20000, call, original.Lifetime)
					compatibilityExchange(t, adapter, call, "INVITE", 3, 30000, 40000)
					compatibilityRTP(t, adapter, 10000, 20000, call, original.Lifetime)
					compatibilityRTP(t, adapter, 30000, 40000, call, original.Lifetime)
					before := metadata.Stats()
					processor.CompleteCallLifetime(call, original.Lifetime)
					retained, ok := processor.Call(call)
					require.True(t, ok, "authoritative completion keeps its existing grace")
					require.Equal(t, original.Lifetime, retained.Lifetime)
					if mode == mediaadmission.ModeEnforce {
						require.Less(t, metadata.Stats().SelectedEndpoints, before.SelectedEndpoints, "completion cancels charged intermediate cleanup")
					}
					compatibilityRTP(t, adapter, 10000, 20000, call, original.Lifetime)
				})
			}
		}
	}
}
