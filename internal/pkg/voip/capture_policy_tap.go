//go:build tap || all

package voip

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
)

type tapCapturePolicy struct {
	policies CapturePolicies
	remote   RemoteMediaResolver
}

func (h *TapTCPHandler) SetCapturePolicies(p CapturePolicies, resolver RemoteMediaResolver) error {
	normalized, err := p.Normalize()
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.flow != nil {
		return fmt.Errorf("tap source policy must be configured before reassembly starts")
	}
	h.capturePolicy.policies, h.capturePolicy.remote = normalized, resolver
	return nil
}

type tapRemoteReceipt struct {
	event    sharedsip.Event
	proof    RemoteCallAssociation
	required bool
}

func tapFilterProvenance(env *pipeline.PacketEnvelope, direct, inherited []string) {
	env.DirectMatchedFilterIDs = stableFilterIDs(direct)
	env.InheritedMatchedFilterIDs = stableFilterIDs(inherited)
	env.MatchedFilterIDs = stableFilterIDs(append(append([]string(nil), direct...), inherited...))
}

func (h *TapTCPHandler) handlePolicySIP(info capture.PacketInfo, event *sharedsip.Event, message []byte, id string, options sharedsip.ParseOptions) bool {
	if event == nil {
		parsed, err := sharedsip.Parse(message, options)
		if err != nil {
			return false
		}
		event = &parsed
	}
	if event.CallID != id || ValidateCallIDForSecurity(event.CallID) != nil {
		return false
	}
	env := envelopeForTapPacket(info)
	direct := false
	var directIDs, inherited []string
	o := h.ensureFlow()
	if o == nil {
		return false
	}
	if h.appFilter != nil {
		direct, directIDs = h.matchWithProof(id, info.Packet)
	} else {
		direct = containsUserInHeaders(event.Headers)
	}
	tapFilterProvenance(env, directIDs, nil)
	var result sipflow.ProcessResult
	if h.capturePolicy.policies.Media == MediaLocal {
		result = o.Analyze(sipflow.Message{Payload: message, Event: event, ExpectedCallID: id, Envelope: env, ParseOptions: options, FilterConfigured: true, DirectMatch: direct, Validate: func(event sharedsip.Event) error { return ValidateCallIDForSecurity(event.CallID) }})
		if result.Stage.Outcome != pipeline.OutcomeAccepted {
			if h.capturePolicy.policies.Signalling != SignallingAll || result.Stage.Outcome != pipeline.OutcomeFiltered || result.SIP.CallID == "" {
				return false
			}
			result.Stage = pipeline.Result{Outcome: pipeline.OutcomeAccepted}
		}
	} else {
		selected := direct
		var receipt *tapRemoteReceipt
		if h.capturePolicy.remote != nil {
			if association, ok := h.capturePolicy.remote.ResolveSignalling(*event, info.Packet, info.Interface); ok && association.CallID == event.CallID {
				selected = true
				inherited = association.InheritedFilterIDs
				receipt = &tapRemoteReceipt{event: *event, proof: association, required: !direct && h.capturePolicy.policies.Signalling == SignallingMatched}
			}
		}
		if h.capturePolicy.policies.Signalling == SignallingNone || h.capturePolicy.policies.Signalling == SignallingMatched && !selected {
			return false
		}
		tapFilterProvenance(env, directIDs, inherited)
		result = sipflow.ProcessResult{SIP: pipeline.SIPResultFromEvent(*event, env), Stage: pipeline.Result{Outcome: pipeline.OutcomeAccepted}, Attachment: tapAttachment{remote: receipt}}
	}
	return h.dispatchSIP(o, result)
}

func envelopeForTapPacket(info capture.PacketInfo) *pipeline.PacketEnvelope {
	return captureadapter.FromPacketInfo(info, pipeline.SourceLiveCapture)
}
