package voip

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/stretchr/testify/require"
)

// Packets traverse the production parser, processor observer, scoped source
// adapter and media resolver. Registry membership alone would not prove the RTP
// identity delivered to downstream per-call output after a grace retirement.
func TestProcessorUncertainEndpointRecoveryRetiresTrailingIdentity(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, fault := range []string{"partial-initial", "conflicting-reoffer"} {
				for _, shared := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/shared-%t", mode, policy, fault, shared), func(t *testing.T) {
						cfg := mediaadmission.DefaultConfig()
						cfg.Enabled, cfg.Mode, cfg.FailurePolicy, cfg.RetryInterval = true, mode, policy, 10*time.Millisecond
						processor := voipprocessor.New(voipprocessor.DefaultConfig())
						t.Cleanup(processor.Close)
						controller, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
						require.NoError(t, err)
						metadata, err := mediaadmission.NewMetadataStore(cfg)
						require.NoError(t, err)
						bridge, err := sipadmission.New(sipadmission.Config{Limits: cfg, RetirementGrace: 200 * time.Millisecond, Registry: processor.CallRegistry(), Controller: controller, Metadata: metadata})
						require.NoError(t, err)
						require.NoError(t, processor.SetMetadataObserver(bridge))
						t.Cleanup(func() { require.NoError(t, bridge.Close()); require.NoError(t, controller.Close(context.Background())) })
						adapter, err := voipprocessor.NewScopedSourceAdapter(cfg, map[mediaadmission.DomainID]*voipprocessor.SourceAdapter{0: voipprocessor.NewSourceAdapter(processor)}, time.Second)
						require.NoError(t, err)
						t.Cleanup(adapter.Close)

						const callID = "uncertain-original"
						if fault == "conflicting-reoffer" {
							compatibilityExchange(t, adapter, callID, "INVITE", 1, 10000, 20000)
							compatibilitySend(t, adapter, callID, "INVITE sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-conflict", "3 INVITE", "CSeq: 4 INVITE\r\n", compatibilitySDP("192.0.2.1", 50000))
							compatibilitySend(t, adapter, callID, "SIP/2.0 200 OK", "peer", "z9hG4bK-conflict", "3 INVITE", "", compatibilitySDP("192.0.2.2", 60000))
						} else {
							partial := compatibilitySDP("192.0.2.1", 50000) + "m=audio invalid RTP/AVP 0\r\n"
							compatibilitySend(t, adapter, callID, "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-partial", "1 INVITE", "", partial)
							compatibilitySend(t, adapter, callID, "SIP/2.0 200 OK", "peer", "z9hG4bK-partial", "1 INVITE", "", compatibilitySDP("192.0.2.2", 60000))
						}
						original, ok := processor.Call(callID)
						require.True(t, ok)
						require.Equal(t, 1, bridge.Stats().UnknownDerivations)
						if shared {
							compatibilityExchange(t, adapter, "uncertain-independent", "INVITE", 1, 50000, 22000)
						}
						compatibilityRTP(t, adapter, 50000, 60000, callID, original.Lifetime)
						compatibilityExchange(t, adapter, callID, "INVITE", 5, 30000, 40000)
						require.Zero(t, bridge.Stats().UnknownDerivations)
						compatibilityRTP(t, adapter, 50000, 60000, callID, original.Lifetime)
						compatibilityRTP(t, adapter, 30000, 40000, callID, original.Lifetime)
						if fault == "conflicting-reoffer" {
							compatibilityRTP(t, adapter, 10000, 20000, callID, original.Lifetime)
						}

						if mode == mediaadmission.ModeEnforce {
							require.Eventually(t, func() bool {
								return len(processor.CallIDsForEndpoint("192.0.2.2:60000")) == 0
							}, 3*time.Second, 5*time.Millisecond)
							if shared {
								other, exists := processor.Call("uncertain-independent")
								require.True(t, exists)
								require.Equal(t, []string{other.CallID}, processor.CallIDsForEndpoint("192.0.2.1:50000"))
								compatibilityRTP(t, adapter, 50000, 60000, other.CallID, other.Lifetime)
								compatibilityRTP(t, adapter, 50000, 22000, other.CallID, other.Lifetime)
							} else {
								payload := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7}
								result := adapter.ProcessPacketInfo(compatibilityPacket(t, "192.0.2.1", "192.0.2.2", 50000, 60000, payload))
								require.NotNil(t, result)
								require.Equal(t, callregistry.MediaUnresolved, result.GetMediaResolution().Status)
								require.Empty(t, result.GetCallID())
								require.Empty(t, result.GetCallIDs())
							}
						} else {
							// Shadow has no retirement mutation, even after the configured
							// grace has elapsed and the worker has observed the deadline.
							time.Sleep(250 * time.Millisecond)
							compatibilityRTP(t, adapter, 50000, 60000, callID, original.Lifetime)
						}
						compatibilityRTP(t, adapter, 30000, 40000, callID, original.Lifetime)
						if fault == "conflicting-reoffer" {
							compatibilityRTP(t, adapter, 10000, 20000, callID, original.Lifetime)
						}
					})
				}
			}
		}
	}
}
