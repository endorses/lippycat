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
	current  func(string) bool
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
	return ok && (s.current == nil || s.current(callID))
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

type hunterForwardSink struct {
	forwarder     PacketForwarder
	capturePolicy *hunterCapturePolicy
}

// hunterDialogCompletionPolicy retains sticky selection after a BYE/CANCEL
// request so the corresponding final response is still forwarded. The generic
// sipflow policy also completes on the request, which is appropriate for sinks
// that do not need to observe the response but not for a forwarding hunter.
type hunterDialogCompletionPolicy struct{}

func (hunterDialogCompletionPolicy) Completes(event sharedsip.Event) bool {
	return event.ResponseCode >= 200 && (event.CSeqMethod == "BYE" || event.CSeqMethod == "CANCEL")
}

func (s hunterForwardSink) HandleSIP(ctx context.Context, input sipflow.SinkInput) pipeline.Result {
	if s.capturePolicy != nil && s.capturePolicy.policies.Signalling == SignallingNone {
		return pipeline.Result{Outcome: pipeline.OutcomeFiltered}
	}
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
	if receipt, ok := input.Attachment.(remoteSignallingReceipt); ok {
		var association RemoteCallAssociation
		current := false
		if s.capturePolicy != nil && s.capturePolicy.remote != nil {
			association, current = s.capturePolicy.remote.ResolveSignalling(receipt.event, packet, env.Source.InterfaceName)
		}
		if !current || association.CallID != input.Result.CallID || !receipt.proof.SameSelection(association) {
			if receipt.required {
				return pipeline.Result{Outcome: pipeline.OutcomeFiltered}
			}
			association.InheritedFilterIDs = nil
		}
		setHunterFilterProvenance(env, env.DirectMatchedFilterIDs, association.InheritedFilterIDs)
	}
	metadata := &data.PacketMetadata{Sip: &data.SIPMetadata{
		CallId: input.Result.CallID, FromUser: input.Result.FromUser, ToUser: input.Result.ToUser,
		FromTag: input.Result.FromTag, ToTag: input.Result.ToTag, FromUri: input.Result.FromURI,
		ToUri: input.Result.ToURI, Method: input.Result.Method, CseqMethod: input.Result.CSeqMethod,
		CseqNumber: input.Result.CSeqNumber, ViaBranch: input.Result.ViaBranch,
		MediaPorts:   sharedsip.MediaPorts(input.Result.SDP),
		ResponseCode: uint32(input.Result.ResponseCode), PAssertedIdentity: input.Result.PAssertedIdentity,
	}}
	var selectionCurrent func() bool
	if receipt, ok := input.Attachment.(remoteSignallingReceipt); ok && receipt.required {
		selectionCurrent = func() bool {
			if s.capturePolicy == nil || s.capturePolicy.remote == nil {
				return false
			}
			current, valid := s.capturePolicy.remote.ResolveSignalling(receipt.event, packet, env.Source.InterfaceName)
			return valid && receipt.proof.SameSelection(current)
		}
	}
	if err := forwardPacketWithSelectionCheck(s.forwarder, packet, metadata, env.Source.InterfaceName, env.LinkType, env.DirectMatchedFilterIDs, env.InheritedMatchedFilterIDs, selectionCurrent); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomeRetryableFailure, Err: err}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func newHunterSIPOrchestrator(forwarder PacketForwarder, policy callregistry.SelectionPolicy, stores ...*hunterSelectionStore) *sipflow.Orchestrator {
	return newHunterPolicySIPOrchestrator(forwarder, policy, nil, stores...)
}

func newHunterPolicySIPOrchestrator(forwarder PacketForwarder, policy callregistry.SelectionPolicy, capturePolicy *hunterCapturePolicy, stores ...*hunterSelectionStore) *sipflow.Orchestrator {
	store := newHunterSelectionStore()
	if len(stores) > 0 {
		store = stores[0]
	}
	orchestrator, err := sipflow.New(sipflow.Config{
		SelectionStore:  store,
		SelectionPolicy: policy,
		Completion:      hunterDialogCompletionPolicy{},
	})
	if err != nil {
		panic(err) // the static hunter composition is programmer-owned
	}
	if err := orchestrator.RegisterSink(hunterSIPSinkName, hunterForwardSink{forwarder: forwarder, capturePolicy: capturePolicy}, 256); err != nil {
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
