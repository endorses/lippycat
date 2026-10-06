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

func reliablePipelineFixture(t *testing.T, policy mediaadmission.FailurePolicy, transport string) (*mediaadmission.Controller, *sipadmission.Bridge, *callregistry.Core, func([]byte) sipflow.ProcessResult) {
	t.Helper()
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
	process := func(raw []byte) sipflow.ProcessResult {
		t.Helper()
		input := sipflow.Message{Payload: raw, Envelope: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0"}}, DirectMatch: true}
		if transport == "tcp" {
			stream := &bufferedSIPStream{ctx: t.Context()}
			reader := bufio.NewReader(&fragmentReader{reader: bytes.NewReader(raw), limit: 5})
			framed, err := stream.readCompleteSipMessageFromReader(reader)
			require.NoError(t, err)
			event, err := sharedsip.Parse(framed, sharedsip.ParseOptions{})
			require.NoError(t, err)
			input.Event, input.Payload = &event, framed
		}
		result := o.Process(input)
		require.Equal(t, pipeline.OutcomeAccepted, result.Stage.Outcome)
		return result
	}
	return controller, bridge, registry, process
}

func TestReliableFaultReplacementThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, transport := range []string{"udp", "tcp"} {
			for _, fault := range []string{"mismatched-rack", "unreliable-provisional", "partial-prack", "bodyless-prack-ack-answer"} {
				for _, method := range []string{"INVITE", "UPDATE"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", policy, transport, fault, method), func(t *testing.T) {
						controller, bridge, registry, process := reliablePipelineFixture(t, policy, transport)
						provisionalHeaders := "Require: timer\r\nRequire: 100rel\r\nRSeq: 101\r\n"
						prackHeaders := "RAck: 101 1 INVITE\r\n"
						prackBody := "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"
						ackBody := ""
						switch fault {
						case "mismatched-rack":
							prackHeaders = "RAck: 102 1 INVITE\r\n"
						case "unreliable-provisional":
							provisionalHeaders = "RSeq: 101\r\n"
						case "partial-prack":
							prackBody += "m=video invalid RTP/AVP 96\r\n"
						case "bodyless-prack-ack-answer":
							ackBody, prackBody = prackBody, ""
						}
						process(reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "Supported: 100rel\r\n", ""))
						process(reliablePipelineMessage("SIP/2.0 183 Progress", "peer", "invite", "1 INVITE", provisionalHeaders, "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"))
						process(reliablePipelineMessage("PRACK sip:peer@example.invalid SIP/2.0", "peer", "prack", "2 PRACK", prackHeaders, prackBody))
						process(reliablePipelineMessage("SIP/2.0 200 OK", "peer", "invite", "1 INVITE", "", ""))
						process(reliablePipelineMessage("ACK sip:peer@example.invalid SIP/2.0", "peer", "ack", "1 ACK", "", ackBody))
						degraded := mediaadmission.StateDegradedOpen
						if policy == mediaadmission.FailureClosed {
							degraded = mediaadmission.StateDegradedClosed
						}
						require.Equal(t, 1, bridge.Stats().UnknownDerivations)
						require.Equal(t, degraded, controller.Status()[0].State)
						require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
						process(reliablePipelineMessage(method+" sip:peer@example.invalid SIP/2.0", "peer", "replacement", "3 "+method, "", "c=IN IP4 192.0.2.1\r\nm=audio 30000 RTP/AVP 0\r\n"))
						require.Equal(t, 1, bridge.Stats().UnknownDerivations)
						require.Equal(t, degraded, controller.Status()[0].State)
						answer := process(reliablePipelineMessage("SIP/2.0 200 OK", "peer", "replacement", "3 "+method, "", "c=IN IP4 192.0.2.2\r\nm=audio 40000 RTP/AVP 0\r\n"))
						require.NoError(t, answer.MetadataError)
						require.Zero(t, bridge.Stats().UnknownDerivations)
						require.Equal(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
						require.Zero(t, controller.Status()[0].PendingUpdates)
						require.Equal(t, 4, registry.EndpointAssociationCount())
						for _, endpoint := range []string{"192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001"} {
							require.Empty(t, registry.ResolveMediaEndpoints(endpoint, "").CallID, endpoint)
						}
						for _, endpoint := range []string{"192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001"} {
							require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints(endpoint, "").CallID, endpoint)
						}
					})
				}
			}
		}
	}
}

func TestDuplicateReliableProofThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, duplicate := range []string{"cseq", "rseq", "rack"} {
			t.Run(transport+"/"+duplicate, func(t *testing.T) {
				controller, bridge, _, process := reliablePipelineFixture(t, mediaadmission.FailureClosed, transport)
				provisionalHeaders := "Require: 100rel\r\nRSeq: 101\r\n"
				prackHeaders := "RAck: 101 1 INVITE\r\n"
				prackCSeq := "2 PRACK"
				switch duplicate {
				case "cseq":
					prackCSeq = "2 UPDATE"
					prackHeaders += "CSeq: 2 PRACK\r\n"
				case "rseq":
					provisionalHeaders += "RSeq: 101\r\n"
				case "rack":
					prackHeaders += "RAck: 101 1 INVITE\r\n"
				}
				messages := [][]byte{
					reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "Supported: 100rel\r\n", ""),
					reliablePipelineMessage("SIP/2.0 183 Progress", "peer", "invite", "1 INVITE", provisionalHeaders, "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"),
					reliablePipelineMessage("PRACK sip:peer@example.invalid SIP/2.0", "peer", "prack", prackCSeq, prackHeaders, "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"),
					reliablePipelineMessage("SIP/2.0 200 OK", "peer", "invite", "1 INVITE", "", ""),
					reliablePipelineMessage("ACK sip:peer@example.invalid SIP/2.0", "peer", "ack", "1 ACK", "", ""),
				}
				for index, message := range messages {
					result := process(message)
					require.Equal(t, mediaadmission.StateDegradedClosed, controller.Status()[0].State)
					require.Equal(t, 1, bridge.Stats().UnknownDerivations)
					if index == 2 {
						require.Equal(t, "PRACK", result.SIP.CSeqMethod)
						require.Equal(t, "2 PRACK", result.SIP.Headers["cseq"])
					}
				}
			})
		}
	}
}

func TestDuplicateCSeqTerminalResponseThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, method := range []string{"BYE", "CANCEL"} {
			t.Run(transport+"/"+method, func(t *testing.T) {
				_, _, registry, process := reliablePipelineFixture(t, mediaadmission.FailureClosed, transport)
				process(reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"))
				require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
				result := process(reliablePipelineMessage("SIP/2.0 200 OK", "peer", "terminal", "3 INVITE", "CSeq: 3 "+method+"\r\n", ""))
				require.Equal(t, method, result.SIP.CSeqMethod)
				require.True(t, result.Terminal)
				require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
				require.Zero(t, registry.EndpointAssociationCount())
			})
		}
	}
}
