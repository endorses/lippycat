package voip

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"sync/atomic"
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

// Real UDP parsing and fragmented TCP framing exercise both unaffected-call
// recovery and proof quarantined for a call first selected during pressure.
func TestReplayPressureRecoveryThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, transport := range []string{"udp", "tcp"} {
				for _, scenario := range []string{"healthy", "new", "crossing", "response-first", "replay", "history-loss"} {
					t.Run(string(mode)+"/"+string(policy)+"/"+transport+"/"+scenario, func(t *testing.T) {
						var clock atomic.Pointer[time.Time]
						now := time.Now()
						clock.Store(&now)
						cfg := mediaadmission.DefaultConfig()
						cfg.Enabled, cfg.Mode, cfg.FailurePolicy = true, mode, policy
						cfg.ReplayGuardCapacity = 2
						if scenario == "history-loss" {
							cfg.ReplayGuardCapacity = 1
						}
						cfg.ReplayWindow, cfg.RetryInterval = time.Second, 5*time.Millisecond
						c, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
						require.NoError(t, err)
						metadata, err := mediaadmission.NewMetadataStore(cfg)
						require.NoError(t, err)
						r := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
						b, err := sipadmission.New(sipadmission.Config{Now: func() time.Time { return *clock.Load() }, Limits: cfg, Registry: r, Controller: c, Metadata: metadata})
						require.NoError(t, err)
						o, err := sipflow.New(sipflow.Config{SelectionStore: reliablePipelineSelections{}, Registry: reliablePipelineRegistry{r}, MetadataObserver: b})
						require.NoError(t, err)
						require.NoError(t, o.Start(t.Context()))
						t.Cleanup(func() {
							o.Close()
							r.Close()
							require.NoError(t, b.Close())
							require.NoError(t, c.Close(context.Background()))
						})
						send := func(id, start, tag, branch, cseq, body string) {
							t.Helper()
							raw := []byte(strings.ReplaceAll(string(reliablePipelineMessage(start, tag, branch, cseq, "", body)), "parsed-reliable", id))
							input := sipflow.Message{Payload: raw, Envelope: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0"}}, DirectMatch: true}
							if transport == "tcp" {
								stream := &bufferedSIPStream{ctx: t.Context()}
								framed, err := stream.readCompleteSipMessageFromReader(bufio.NewReader(&fragmentReader{reader: bytes.NewReader(raw), limit: 3}))
								require.NoError(t, err)
								event, err := sharedsip.Parse(framed, sharedsip.ParseOptions{})
								require.NoError(t, err)
								input.Event, input.Payload = &event, framed
							}
							result := o.Process(input)
							require.Equal(t, pipeline.OutcomeAccepted, result.Stage.Outcome)
						}
						request := func(id string) {
							send(id, "INVITE sip:peer@example.invalid SIP/2.0", "", "initial", "1 INVITE", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n")
						}
						response := func(id string) {
							send(id, "SIP/2.0 200 OK", "peer", "initial", "1 INVITE", "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
						}
						exchange := func(id string) { request(id); response(id) }
						id := "synthetic-pipeline-active"
						if scenario == "healthy" {
							exchange(id)
							require.Zero(t, b.Stats().UnknownDerivations)
						}
						for _, retired := range []string{"synthetic-pipeline-guard", "synthetic-pipeline-overflow"} {
							exchange(retired)
							require.True(t, r.Remove(retired, callregistry.EndCompleted))
						}
						switch scenario {
						case "healthy":
							send(id, "INFO sip:peer@example.invalid SIP/2.0", "peer", "info", "2 INFO", "")
							send(id, "OPTIONS sip:peer@example.invalid SIP/2.0", "peer", "options", "3 OPTIONS", "")
							send(id, "SIP/2.0 180 Ringing", "peer", "initial", "1 INVITE", "")
							send(id, "ACK sip:peer@example.invalid SIP/2.0", "peer", "separate-ack", "1 ACK", "")
							require.Zero(t, b.Stats().UnknownDerivations)
						case "new", "history-loss":
							exchange(id)
						case "response-first":
							response(id)
							request(id)
						case "crossing":
							request(id)
						case "replay":
							id = "synthetic-pipeline-overflow"
							exchange(id)
						}
						if scenario != "healthy" {
							require.Empty(t, r.CallIDsForEndpoint("192.0.2.1:10000"), "pressure evidence cannot install endpoints")
						}
						later := now.Add(cfg.ReplayWindow)
						clock.Store(&later)
						if scenario == "crossing" {
							response(id)
						}
						bad := scenario == "replay" || scenario == "history-loss"
						expectedState := mediaadmission.StateEnforcing
						if mode == mediaadmission.ModeShadow {
							expectedState = mediaadmission.StateShadow
						}
						if bad {
							expectedState = mediaadmission.StateDegradedOpen
							if policy == mediaadmission.FailureClosed {
								expectedState = mediaadmission.StateDegradedClosed
							}
						}
						require.Eventually(t, func() bool {
							unknown := b.Stats().UnknownDerivations
							return (bad && unknown == 1 || !bad && unknown == 0) && c.Status()[0].State == expectedState
						}, time.Second, 5*time.Millisecond)
						if bad {
							require.Empty(t, r.CallIDsForEndpoint("192.0.2.1:10000"))
							require.Empty(t, r.CallIDsForEndpoint("192.0.2.2:20000"))
						} else {
							require.Equal(t, []string{id}, r.CallIDsForEndpoint("192.0.2.1:10000"))
							require.Equal(t, []string{id}, r.CallIDsForEndpoint("192.0.2.2:20000"))
						}
					})
				}
			}
		}
	}
}
