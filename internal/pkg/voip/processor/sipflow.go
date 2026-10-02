package processor

import (
	"context"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
)

type processorSelectionStore struct{ processor *Processor }

func (s processorSelectionStore) Selected(callID string) bool {
	s.processor.mu.RLock()
	defer s.processor.mu.RUnlock()
	_, selected := s.processor.calls[callID]
	return selected
}

// Observe creates the call immediately after selection, so no separate marker
// is needed and the processor's bounded registry remains the source of truth.
func (processorSelectionStore) MarkSelected(string) {}
func (processorSelectionStore) Forget(string)       {}

type processorNoCompletion struct{}

func (processorNoCompletion) Completes(sharedsip.Event) bool { return false }

type processorSIPAttachment struct {
	lifetime   callregistry.Lifetime
	metadata   *CallMetadata
	pbMetadata *data.PacketMetadata
}

type processorSIPRegistry struct{ processor *Processor }

func (r processorSIPRegistry) Observe(result pipeline.SIPResult) (sipflow.RegistryObservation, error) {
	p := r.processor
	if err := validateCallID(result.CallID); err != nil {
		return sipflow.RegistryObservation{}, fmt.Errorf("validate Call-ID: %w", err)
	}
	observedState := p.getOrCreateCall(result.CallID)
	if observedState == nil {
		return sipflow.RegistryObservation{}, fmt.Errorf("processor closed")
	}
	// Serialize the entire observation against expiry/finalization and reuse.
	p.eventMu.Lock()
	defer p.eventMu.Unlock()
	p.mu.RLock()
	sameLifetime := p.calls[result.CallID] == observedState
	p.mu.RUnlock()
	if !sameLifetime {
		return sipflow.RegistryObservation{}, fmt.Errorf("call lifetime retired before SIP observation")
	}
	call, exists := p.registry.Call(result.CallID)
	if !exists {
		return sipflow.RegistryObservation{}, fmt.Errorf("call retired before SIP observation")
	}
	metadata := callMetadataFromResult(result)
	p.updateCallState(result.CallID, result.Method, metadata)
	if len(result.SDP) > 0 {
		for _, port := range extractRTPPortsFromSDP(string(result.SDP), p.config.MaxEndpointsPerCall) {
			p.registry.TryAssociateEndpointForLifetime(result.CallID, call.Lifetime, port)
		}
	}
	return sipflow.RegistryObservation{Attachment: processorSIPAttachment{
		lifetime: call.Lifetime, metadata: metadata, pbMetadata: protobufMetadataFromResult(result, metadata),
	}}, nil
}

func (r processorSIPRegistry) Complete(callID string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	r.processor.CompleteCall(callID)
	return []pipeline.CallLifecycleObservation{{State: pipeline.CallLifecycleCompleted}}, nil
}

func callMetadataFromResult(result pipeline.SIPResult) *CallMetadata {
	metadata := &CallMetadata{
		CallID: result.CallID, From: result.From, To: result.To, FromTag: result.FromTag, ToTag: result.ToTag,
		PAssertedIdentity: result.PAssertedIdentity, Method: result.Method, CSeqMethod: result.CSeqMethod,
		CSeqNumber: result.CSeqNumber, ViaBranch: result.ViaBranch,
		MediaPorts:   sharedsip.MediaPorts(result.SDP),
		ResponseCode: uint32(result.ResponseCode), SDPBody: string(result.SDP), ContentType: result.ContentType,
	}
	if result.Method == "MESSAGE" && len(result.Body) != 0 {
		metadata.Body = extractMessageBody(string(result.Body))
	}
	if pani := result.Headers["p-access-network-info"]; pani != "" {
		metadata.AccessType, metadata.BSSID, metadata.CellID, metadata.LocalIP, metadata.AccessParams = parseAccessNetworkInfo(pani)
	}
	if pvni := result.Headers["p-visited-network-id"]; pvni != "" {
		metadata.VisitedNetworkID = parseVisitedNetworkID(pvni)
	}
	return metadata
}

func protobufMetadataFromResult(result pipeline.SIPResult, metadata *CallMetadata) *data.PacketMetadata {
	pb := &data.PacketMetadata{Sip: &data.SIPMetadata{
		CallId: result.CallID, FromUser: result.FromUser, ToUser: result.ToUser, FromTag: result.FromTag,
		ToTag: result.ToTag, FromUri: result.FromURI, ToUri: result.ToURI, Method: result.Method,
		CseqMethod: result.CSeqMethod, ResponseCode: uint32(result.ResponseCode),
		CseqNumber: result.CSeqNumber, ViaBranch: result.ViaBranch,
		MediaPorts:        sharedsip.MediaPorts(result.SDP),
		PAssertedIdentity: result.PAssertedIdentity, VisitedNetworkId: metadata.VisitedNetworkID,
	}}
	if metadata.AccessType != "" {
		pb.Sip.AccessNetworkInfo = &data.AccessNetworkInfo{
			AccessType: metadata.AccessType, Bssid: metadata.BSSID, CellId: metadata.CellID,
			LocalIp: metadata.LocalIP, Parameters: metadata.AccessParams,
		}
	}
	return pb
}

func newProcessorSIPFlow(p *Processor) *sipflow.Orchestrator {
	flow, err := sipflow.New(sipflow.Config{
		SelectionPolicy: p.selectionPolicy, SelectionStore: processorSelectionStore{processor: p},
		Registry: processorSIPRegistry{processor: p}, Completion: processorNoCompletion{},
	})
	if err != nil {
		panic(err)
	}
	if err := flow.Start(context.Background()); err != nil {
		panic(err)
	}
	return flow
}
