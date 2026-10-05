package voip

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	"github.com/stretchr/testify/require"
)

type reliablePipelineBackend struct{}

func (reliablePipelineBackend) PutEndpoint(context.Context, mediaadmission.EndpointKey) error {
	return nil
}
func (reliablePipelineBackend) DeleteEndpoint(context.Context, mediaadmission.EndpointKey) error {
	return nil
}
func (reliablePipelineBackend) ListEndpoints(context.Context, mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	return nil, nil
}
func (reliablePipelineBackend) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

type reliablePipelineRegistry struct{ *callregistry.Core }

func (r reliablePipelineRegistry) Observe(result pipeline.SIPResult) (sipflow.RegistryObservation, error) {
	r.Upsert(callregistry.Call{CallID: result.CallID})
	return sipflow.RegistryObservation{}, nil
}
func (r reliablePipelineRegistry) Complete(callID string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	r.Remove(callID, callregistry.EndCompleted)
	return nil, nil
}

type reliablePipelineSelections map[string]bool

func (s reliablePipelineSelections) Selected(callID string) bool { return s[callID] }
func (s reliablePipelineSelections) MarkSelected(callID string)  { s[callID] = true }
func (s reliablePipelineSelections) Forget(callID string)        { delete(s, callID) }

func reliablePipelineMessage(start, toTag, branch, cseq, extra, body string) []byte {
	to := "<sip:peer@example.invalid>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	content := ""
	if body != "" {
		content = "Content-Type: application/sdp\r\n"
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/TCP 192.0.2.1:5070;branch=%s\r\nFrom: <sip:origin@example.invalid>;tag=origin\r\nTo: %s\r\nCall-ID: parsed-reliable\r\nCSeq: %s\r\n%s%sContent-Length: %d\r\n\r\n%s", start, branch, to, cseq, extra, content, len(body), body))
}

func TestReliableRecoveryThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(string(policy)+"/"+transport, func(t *testing.T) {
				cfg := mediaadmission.DefaultConfig()
				cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, policy, time.Hour
				controller, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
				require.NoError(t, err)
				metadata, err := mediaadmission.NewMetadataStore(cfg)
				require.NoError(t, err)
				registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
				bridge, err := sipadmission.New(sipadmission.Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: metadata})
				require.NoError(t, err)
				o, err := sipflow.New(sipflow.Config{SelectionStore: reliablePipelineSelections{}, Registry: reliablePipelineRegistry{registry}, MetadataObserver: bridge})
				require.NoError(t, err)
				require.NoError(t, o.Start(t.Context()))
				t.Cleanup(func() {
					o.Close()
					registry.Close()
					require.NoError(t, bridge.Close())
					require.NoError(t, controller.Close(context.Background()))
				})
				messages := [][]byte{
					reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "Supported: 100rel\r\n", ""),
					reliablePipelineMessage("SIP/2.0 183 Progress", "peer", "invite", "1 INVITE", "Require: timer\r\nRequire: 100rel\r\nRSeq: 101\r\n", "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"),
					reliablePipelineMessage("PRACK sip:peer@example.invalid SIP/2.0", "peer", "prack", "2 PRACK", "RAck: 101 1 INVITE\r\n", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"),
					reliablePipelineMessage("SIP/2.0 200 OK", "peer", "invite", "1 INVITE", "", ""),
					reliablePipelineMessage("ACK sip:peer@example.invalid SIP/2.0", "peer", "ack", "1 ACK", "", ""),
				}
				stream := &bufferedSIPStream{ctx: t.Context()}
				reader := bufio.NewReader(&fragmentReader{reader: bytes.NewReader(bytes.Join(messages, nil)), limit: 5})
				for index, raw := range messages {
					env := &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0"}}
					input := sipflow.Message{Payload: raw, Envelope: env, DirectMatch: true}
					if transport == "tcp" {
						framed, frameErr := stream.readCompleteSipMessageFromReader(reader)
						require.NoError(t, frameErr)
						event, parseErr := sharedsip.Parse(framed, sharedsip.ParseOptions{})
						require.NoError(t, parseErr)
						// TCP passes its parsed event through the same adapter without a second parse.
						input.Event, input.Payload = &event, framed
					}
					got := o.Process(input)
					require.Equal(t, pipeline.OutcomeAccepted, got.Stage.Outcome)
					if index < 2 {
						require.Error(t, got.MetadataError)
						require.NotEqual(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
					} else {
						require.NoError(t, got.MetadataError)
						require.Equal(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
					}
					if index == 1 {
						require.Contains(t, got.SIP.Headers["require"], "100rel")
						require.Equal(t, "101", got.SIP.Headers["rseq"])
					}
					if index == 2 {
						require.Equal(t, "101 1 INVITE", got.SIP.Headers["rack"])
					}
				}
				require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
				require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
				require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:30000", "").CallID)
			})
		}
	}
}
