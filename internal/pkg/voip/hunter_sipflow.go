//go:build hunter || all

package voip

import (
	"context"
	"errors"
	"sync"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket/layers"
)

const hunterSIPSinkName = "hunter-grpc"

var errMissingSIPPacket = errors.New("hunter SIP sink received no packet")

type hunterSelectionStore struct {
	mu       sync.RWMutex
	selected map[string]struct{}
}

type hunterSelectionPolicy struct {
	mu     sync.RWMutex
	policy callregistry.SelectionPolicy
}

func newHunterSelectionPolicy() *hunterSelectionPolicy {
	return &hunterSelectionPolicy{policy: callregistry.StickySelectionPolicy{}}
}

func (p *hunterSelectionPolicy) Select(input callregistry.SelectionInput) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policy.Select(input)
}

func (p *hunterSelectionPolicy) set(policy callregistry.SelectionPolicy) {
	if policy == nil {
		return
	}
	p.mu.Lock()
	p.policy = policy
	p.mu.Unlock()
}

func newHunterSelectionStore() *hunterSelectionStore {
	return &hunterSelectionStore{selected: make(map[string]struct{})}
}

func (s *hunterSelectionStore) Selected(callID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.selected[callID]
	return ok
}

func (s *hunterSelectionStore) MarkSelected(callID string) {
	s.mu.Lock()
	s.selected[callID] = struct{}{}
	s.mu.Unlock()
}

func (s *hunterSelectionStore) Forget(callID string) {
	s.mu.Lock()
	delete(s.selected, callID)
	s.mu.Unlock()
}

type hunterForwardSink struct{ forwarder PacketForwarder }

// hunterDialogCompletionPolicy retains sticky selection after a BYE/CANCEL
// request so the corresponding final response is still forwarded. The generic
// sipflow policy also completes on the request, which is appropriate for sinks
// that do not need to observe the response but not for a forwarding hunter.
type hunterDialogCompletionPolicy struct{}

func (hunterDialogCompletionPolicy) Completes(event sharedsip.Event) bool {
	return event.ResponseCode >= 200 && (event.CSeqMethod == "BYE" || event.CSeqMethod == "CANCEL")
}

func (s hunterForwardSink) HandleSIP(ctx context.Context, input sipflow.SinkInput) pipeline.Result {
	if err := ctx.Err(); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: err}
	}
	env := input.Result.Packet
	if env == nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: errMissingSIPPacket}
	}
	packet := captureadapter.ToPacketInfo(env).Packet
	if packet == nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: errMissingSIPPacket}
	}
	metadata := &data.PacketMetadata{Sip: &data.SIPMetadata{
		CallId: input.Result.CallID, FromUser: input.Result.FromUser, ToUser: input.Result.ToUser,
		FromTag: input.Result.FromTag, ToTag: input.Result.ToTag, FromUri: input.Result.FromURI,
		ToUri: input.Result.ToURI, Method: input.Result.Method, CseqMethod: input.Result.CSeqMethod,
		ResponseCode: uint32(input.Result.ResponseCode), PAssertedIdentity: input.Result.PAssertedIdentity,
	}}
	if err := forwardPacketWithFilterProvenance(s.forwarder, packet, metadata, env.Source.InterfaceName, env.LinkType, env.DirectMatchedFilterIDs, env.InheritedMatchedFilterIDs); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomeRetryableFailure, Err: err}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func newHunterSIPOrchestrator(forwarder PacketForwarder, policy callregistry.SelectionPolicy) *sipflow.Orchestrator {
	orchestrator, err := sipflow.New(sipflow.Config{
		SelectionStore:  newHunterSelectionStore(),
		SelectionPolicy: policy,
		Completion:      hunterDialogCompletionPolicy{},
	})
	if err != nil {
		panic(err) // the static hunter composition is programmer-owned
	}
	if err := orchestrator.RegisterSink(hunterSIPSinkName, hunterForwardSink{forwarder: forwarder}, 256); err != nil {
		panic(err)
	}
	if err := orchestrator.Start(context.Background()); err != nil {
		panic(err)
	}
	return orchestrator
}

func envelopeForHunterPacket(info capture.PacketInfo) *pipeline.PacketEnvelope {
	env := captureadapter.FromPacketInfo(info, pipeline.SourceLiveCapture)
	if env.LinkType == 0 {
		env.LinkType = layers.LinkTypeEthernet
	}
	return env
}
