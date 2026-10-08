package voip

import (
	"bufio"
	"bytes"
	"context"
	"strings"
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
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, transport := range []string{"udp", "tcp"} {
			for _, established := range []bool{false, true} {
				name := string(policy) + "/" + transport + "/new"
				if established {
					name = string(policy) + "/" + transport + "/healthy"
				}
				t.Run(name, func(t *testing.T) {
					cfg := mediaadmission.DefaultConfig()
					cfg.Enabled = true
					cfg.FailurePolicy = policy
					cfg.ReplayGuardCapacity = 1
					cfg.ReplayWindow = 300 * time.Millisecond
					cfg.RetryInterval = 5 * time.Millisecond
					c, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
					require.NoError(t, err)
					metadata, err := mediaadmission.NewMetadataStore(cfg)
					require.NoError(t, err)
					r := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
					b, err := sipadmission.New(sipadmission.Config{Limits: cfg, Registry: r, Controller: c, Metadata: metadata})
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
					exchange := func(id string) {
						send(id, "INVITE sip:peer@example.invalid SIP/2.0", "", "initial", "1 INVITE", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n")
						send(id, "SIP/2.0 200 OK", "peer", "initial", "1 INVITE", "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
					}
					const id = "synthetic-pipeline-active"
					if established {
						exchange(id)
						require.Zero(t, b.Stats().UnknownDerivations)
					}
					for _, retired := range []string{"synthetic-pipeline-guard", "synthetic-pipeline-overflow"} {
						exchange(retired)
						require.True(t, r.Remove(retired, callregistry.EndCompleted))
					}
					require.NotEqual(t, mediaadmission.StateEnforcing, c.Status()[0].State)
					if established {
						send(id, "INFO sip:peer@example.invalid SIP/2.0", "peer", "info", "2 INFO", "")
						send(id, "OPTIONS sip:peer@example.invalid SIP/2.0", "peer", "options", "3 OPTIONS", "")
						require.Zero(t, b.Stats().UnknownDerivations, "proof-free messages cannot poison retained proof")
					} else {
						exchange(id)
						require.Equal(t, 1, b.Stats().UnknownDerivations)
						require.Empty(t, r.CallIDsForEndpoint("192.0.2.1:10000"), "quarantine must not authorize endpoint ownership")
					}
					require.Eventually(t, func() bool {
						return b.Stats().UnknownDerivations == 0 && c.Status()[0].State == mediaadmission.StateEnforcing
					}, 3*time.Second, 5*time.Millisecond)
					require.Equal(t, []string{id}, r.CallIDsForEndpoint("192.0.2.1:10000"))
					require.Equal(t, []string{id}, r.CallIDsForEndpoint("192.0.2.2:20000"))
				})
			}
		}
	}
}
