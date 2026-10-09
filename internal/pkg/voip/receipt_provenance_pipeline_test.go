package voip

import (
	"context"
	"fmt"
	"strings"
	"sync"
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

type receiptPipelineSelections struct {
	mu  sync.Mutex
	ids map[string]bool
}

func (s *receiptPipelineSelections) Selected(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ids[id]
}
func (s *receiptPipelineSelections) MarkSelected(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids[id] = true
}
func (s *receiptPipelineSelections) Forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, id)
}

type receiptPipelineRegistry struct {
	*callregistry.Core
	hold    atomic.Bool
	target  string
	entered chan pipeline.SIPResult
	release chan struct{}
}

func (r *receiptPipelineRegistry) Observe(result pipeline.SIPResult) (sipflow.RegistryObservation, error) {
	if r.hold.Load() && result.CallID == r.target {
		r.entered <- result
		<-r.release
	}
	r.Upsert(callregistry.Call{CallID: result.CallID})
	return sipflow.RegistryObservation{}, nil
}
func (r *receiptPipelineRegistry) Complete(id string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	r.Remove(id, callregistry.EndCompleted)
	return nil, nil
}

func TestReceiptProvenanceThroughOrchestratorSurvivesTTLAndEviction(t *testing.T) {
	for _, kind := range []string{"ttl", "eviction"} {
		for _, historyLost := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/history-loss-%v", kind, historyLost), func(t *testing.T) {
				var clock atomic.Pointer[time.Time]
				now := time.Now()
				clock.Store(&now)
				cfg := mediaadmission.DefaultConfig()
				cfg.Enabled = true
				cfg.ReplayGuardCapacity = 2
				cfg.PendingDialogCapacity = 4
				cfg.ReplayWindow = time.Second
				cfg.PendingTTL = 2 * time.Second
				cfg.RetryInterval = 5 * time.Millisecond
				c, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
				require.NoError(t, err)
				metadata, err := mediaadmission.NewMetadataStore(cfg)
				require.NoError(t, err)
				core := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
				target := "synthetic-receipt-retired"
				if historyLost {
					target = "synthetic-receipt-genuine"
				}
				registry := &receiptPipelineRegistry{Core: core, target: target, entered: make(chan pipeline.SIPResult, 2), release: make(chan struct{})}
				b, err := sipadmission.New(sipadmission.Config{Now: func() time.Time { return *clock.Load() }, Limits: cfg, Registry: core, Controller: c, Metadata: metadata})
				require.NoError(t, err)
				o, err := sipflow.New(sipflow.Config{SelectionStore: &receiptPipelineSelections{ids: map[string]bool{}}, Registry: registry, MetadataObserver: b})
				require.NoError(t, err)
				require.NoError(t, o.Start(t.Context()))
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(registry.release) }) }
				t.Cleanup(func() {
					release()
					o.Close()
					core.Close()
					require.NoError(t, b.Close())
					require.NoError(t, c.Close(context.Background()))
				})
				message := func(id string, answer bool) sipflow.Message {
					start, tag, body := "INVITE sip:peer@example.invalid SIP/2.0", "", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"
					if answer {
						start, tag, body = "SIP/2.0 200 OK", "peer", "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"
					}
					raw := []byte(strings.ReplaceAll(string(reliablePipelineMessage(start, tag, "initial", "1 INVITE", "", body)), "parsed-reliable", id))
					return sipflow.Message{Payload: raw, Envelope: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0"}}, DirectMatch: true}
				}
				retire := func(id string) {
					require.Equal(t, pipeline.OutcomeAccepted, o.Process(message(id, false)).Stage.Outcome)
					require.Equal(t, pipeline.OutcomeAccepted, o.Process(message(id, true)).Stage.Outcome)
					require.True(t, core.Remove(id, callregistry.EndCompleted))
				}
				retire("synthetic-receipt-guard")
				retire("synthetic-receipt-retired")
				registry.hold.Store(true)
				results := make(chan sipflow.ProcessResult, 2)
				for _, answer := range []bool{false, true} {
					go func(answer bool) { results <- o.Process(message(target, answer)) }(answer)
					select {
					case held := <-registry.entered:
						require.NotNil(t, held.ObservationReceipt, "receipt precedes registry handoff")
					case <-time.After(time.Second):
						t.Fatal("registry observation did not reach barrier")
					}
				}
				if historyLost {
					retire("synthetic-receipt-overflow-again")
				}
				if kind == "eviction" {
					for i := range 6 {
						input := message(fmt.Sprintf("synthetic-receipt-evict-%d", i), false)
						event, err := sharedsip.Parse(input.Payload, sharedsip.ParseOptions{})
						require.NoError(t, err)
						result := pipeline.SIPResultFromEvent(event, input.Envelope)
						require.NoError(t, b.ObserveValidatedReceipt(&result))
					}
					require.NotZero(t, metadata.Stats().Evicted)
				}
				later := now.Add(cfg.ReplayWindow + time.Nanosecond)
				if kind == "ttl" {
					later = later.Add(cfg.PendingTTL)
				}
				clock.Store(&later)
				metadata.Expire(later)
				// The SAME result objects issued before the barrier continue downstream.
				release()
				for range 2 {
					select {
					case result := <-results:
						require.Equal(t, pipeline.OutcomeAccepted, result.Stage.Outcome)
					case <-time.After(time.Second):
						t.Fatal("selection did not resume")
					}
				}
				require.Empty(t, core.CallIDsForEndpoint("192.0.2.1:10000"))
				require.Empty(t, core.CallIDsForEndpoint("192.0.2.2:20000"))
				require.Equal(t, 1, b.Stats().UnknownDerivations)
				registry.hold.Store(false)
				require.Equal(t, pipeline.OutcomeAccepted, o.Process(message(target, false)).Stage.Outcome)
				require.Equal(t, pipeline.OutcomeAccepted, o.Process(message(target, true)).Stage.Outcome)
				require.Zero(t, b.Stats().UnknownDerivations, "a genuinely new identical receipt after expiry remains eligible")
				require.Equal(t, []string{target}, core.CallIDsForEndpoint("192.0.2.1:10000"))
			})
		}
	}
}
