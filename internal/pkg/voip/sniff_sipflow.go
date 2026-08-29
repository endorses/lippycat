package voip

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket/layers"
)

type sniffSelectionStore struct {
	mark bool
}

func (s sniffSelectionStore) Selected(callID string) bool {
	return globalBufferMgr != nil && globalBufferMgr.IsCallMatched(callID)
}

func (s sniffSelectionStore) MarkSelected(callID string) {
	if s.mark && globalBufferMgr != nil {
		globalBufferMgr.MarkCallMatched(callID, nil, "", layers.LinkTypeEthernet)
	}
}

// Sniff retains the decision for the buffer manager's bounded TTL. This keeps
// final responses selected after a BYE/CANCEL request, matching legacy output.
func (sniffSelectionStore) Forget(string) {}

type sniffRegistry struct {
	tracker    *CallTracker
	markBuffer bool
}

func (r sniffRegistry) Observe(result pipeline.SIPResult) (sipflow.RegistryObservation, error) {
	linkType := layers.LinkTypeEthernet
	if result.Packet != nil && result.Packet.LinkType != 0 {
		linkType = result.Packet.LinkType
	}
	call := r.tracker.GetOrCreateCall(result.CallID, linkType)
	if call == nil {
		return sipflow.RegistryObservation{}, ErrShuttingDown
	}
	call.SetCallInfoState(result.Method)
	if len(result.SDP) > 0 && BytesContains(result.SDP, []byte("m=audio")) {
		r.tracker.ExtractPortFromSDP(string(result.SDP), result.CallID)
	}
	if r.markBuffer && globalBufferMgr != nil {
		globalBufferMgr.MarkCallMatched(result.CallID, callMetadataFromSIPResult(result), "", linkType)
	}
	return sipflow.RegistryObservation{}, nil
}

func (sniffRegistry) Complete(string, time.Time) ([]pipeline.CallLifecycleObservation, error) {
	return nil, nil
}

type sniffNeverComplete struct{}

func (sniffNeverComplete) Completes(sharedsip.Event) bool { return false }

type sniffSink struct{ tracker *CallTracker }

const (
	sniffSIPSinkName  = "sniff-output"
	sniffSIPQueueSize = 256
)

func (s sniffSink) HandleSIP(_ context.Context, input sipflow.SinkInput) pipeline.Result {
	pkt, ok := input.Attachment.(capture.PacketInfo)
	if !ok || pkt.Packet == nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure}
	}
	// Virtual-interface delivery has historically preceded session PCAP output.
	injectPacketToVirtualInterface(pkt)
	if s.tracker.config.WriteVoIP {
		WriteSIP(s.tracker, input.Result.CallID, pkt.Packet)
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func newSniffSIPFlow(tracker *CallTracker, markSelection, updateRegistry bool) *sipflow.Orchestrator {
	cfg := sipflow.Config{
		SelectionStore: sniffSelectionStore{mark: markSelection},
		Completion:     sniffNeverComplete{},
	}
	if updateRegistry {
		cfg.Registry = sniffRegistry{tracker: tracker, markBuffer: true}
	}
	flow, err := sipflow.New(cfg)
	if err != nil {
		panic(err)
	}
	if err := flow.RegisterSink(sniffSIPSinkName, sniffSink{tracker: tracker}, sniffSIPQueueSize); err != nil {
		panic(err)
	}
	if err := flow.Start(context.Background()); err != nil {
		panic(err)
	}
	return flow
}

func sniffSIPMessage(packet capture.PacketInfo, payload []byte, opts sharedsip.ParseOptions, tracker *CallTracker, markSelection, updateRegistry bool) (*sipflow.Orchestrator, sipflow.ProcessResult) {
	envelope := &pipeline.PacketEnvelope{LinkType: packet.LinkType}
	if packet.Packet != nil {
		envelope.Data = packet.Packet.Data()
		envelope.CaptureTime = packet.Packet.Metadata().Timestamp
	}
	flow := newSniffSIPFlow(tracker, markSelection, updateRegistry)
	result := flow.Analyze(sipflow.Message{
		Payload:          payload,
		Envelope:         envelope,
		ParseOptions:     opts,
		FilterConfigured: true,
		Match: func(event sharedsip.Event) bool {
			return containsUserInHeaders(event.Headers)
		},
		Validate: func(event sharedsip.Event) error {
			return ValidateCallIDForSecurity(event.CallID)
		},
	})
	return flow, result
}

func callMetadataFromSIPResult(result pipeline.SIPResult) *CallMetadata {
	return &CallMetadata{
		CallID: result.CallID, From: result.From, To: result.To,
		FromTag: result.FromTag, ToTag: result.ToTag,
		PAssertedIdentity: result.PAssertedIdentity, Method: result.Method,
		CSeqMethod: result.CSeqMethod, ResponseCode: uint32(result.ResponseCode),
		SDPBody: string(result.SDP),
	}
}
