//go:build hunter || all

package voip

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	mediaadaptor "github.com/endorses/lippycat/internal/pkg/voip/admission"
)

type remoteSignallingReceipt struct {
	event    sharedsip.Event
	proof    RemoteCallAssociation
	required bool
}

type hunterCapturePolicy struct {
	policies CapturePolicies
	remote   RemoteMediaResolver
}

func defaultHunterCapturePolicy() *hunterCapturePolicy {
	return &hunterCapturePolicy{policies: CapturePolicies{Signalling: SignallingMatched, Media: MediaLocal}}
}

func (p *hunterCapturePolicy) set(policies CapturePolicies, remote RemoteMediaResolver) error {
	policies, err := policies.Normalize()
	if err != nil {
		return err
	}
	p.policies, p.remote = policies, remote
	return nil
}

// policySIP handles non-default combinations without making export-all a local
// media selection, or leaving local media ownership in processor-selected mode.
func (p *hunterCapturePolicy) policySIP(info capture.PacketInfo, event *sharedsip.Event, payload []byte, expectedCallID string, options sharedsip.ParseOptions, filter ApplicationFilter, orchestrator *sipflow.Orchestrator, tracker *CallTracker, buffer *BufferManager, admission *mediaadaptor.Bridge) (bool, bool) {
	if p.policies == (CapturePolicies{Signalling: SignallingMatched, Media: MediaLocal}) {
		return false, false
	}
	if event == nil {
		parsed, err := sharedsip.Parse(payload, options)
		if err != nil {
			return true, false
		}
		event = &parsed
	}
	if event.CallID == "" || (expectedCallID != "" && event.CallID != expectedCallID) || ValidateCallIDForSecurity(event.CallID) != nil {
		return true, false
	}
	direct, directIDs, proof := matchPacketWithSelectionProof(filter, info.Packet)
	if filter == nil {
		direct = containsUserInHeaders(event.Headers)
	}
	env := envelopeForHunterPacket(info)
	setHunterFilterProvenance(env, directIDs, nil)
	result := pipeline.SIPResultFromEvent(*event, env)
	analysis := sipflow.ProcessResult{SIP: result, Stage: pipeline.Result{Outcome: pipeline.OutcomeAccepted}}
	selected := direct
	var inherited []string
	if p.policies.Media == MediaLocal {
		analysis = orchestrator.Analyze(sipflow.Message{Payload: payload, Event: event, ExpectedCallID: expectedCallID, Envelope: env, FilterConfigured: true, DirectMatch: direct})
		if analysis.Stage.Outcome != pipeline.OutcomeAccepted && analysis.Stage.Outcome != pipeline.OutcomeFiltered {
			return true, false
		}
		result = analysis.SIP
		selected = analysis.Stage.Outcome == pipeline.OutcomeAccepted
		if selected {
			if call := tracker.GetOrCreateCall(event.CallID, info.LinkType); call != nil {
				call.SetCallInfoState(event.Method)
			}
			if len(result.SDP) > 0 {
				tracker.ExtractPortFromSDP(string(result.SDP), event.CallID)
			}
			if admission != nil {
				if err := admission.Selected(result); err != nil {
					logger.Debug("Hunter admission publication incomplete", "error", err)
				}
			}
			if buffer != nil {
				if direct {
					buffer.StoreMatchedSelection(event.CallID, directIDs, proof)
				}
				inherited = buffer.MatchedFilterIDs(event.CallID)
				if !analysis.Terminal {
					buffer.MarkCallMatched(event.CallID, &CallMetadata{CallID: event.CallID, From: result.From, To: result.To, FromTag: result.FromTag, ToTag: result.ToTag, Method: result.Method, CSeqMethod: result.CSeqMethod, CSeqNumber: result.CSeqNumber, ViaBranch: result.ViaBranch, SDPBody: string(result.SDP), MediaPorts: sharedsip.MediaPorts(result.SDP)}, info.Interface, info.LinkType)
				}
			}
		}
	} else if p.remote != nil {
		if association, ok := p.remote.ResolveSignalling(*event, info.Packet, info.Interface); ok && association.CallID == event.CallID {
			selected = true
			inherited = association.InheritedFilterIDs
			analysis.Attachment = remoteSignallingReceipt{event: *event, proof: association, required: !direct && p.policies.Signalling == SignallingMatched}
		}
	}
	if p.policies.Signalling == SignallingMatched && !selected {
		return true, false
	}
	// None still dispatches locally selected terminal results through the muted
	// sink so the existing completion lifecycle clears sticky selection normally.
	if p.policies.Signalling == SignallingNone && (p.policies.Media != MediaLocal || !selected) {
		return true, false
	}
	setHunterFilterProvenance(env, directIDs, inherited)
	analysis.SIP = result
	analysis.Stage = pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	analysis = orchestrator.Dispatch(analysis)
	return true, p.policies.Signalling != SignallingNone && analysis.Stage.Outcome == pipeline.OutcomeAccepted
}
