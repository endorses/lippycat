//go:build tap || all

package voip

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
)

type tapCallRegistry interface {
	ProcessReassembledSIPResult(pipeline.SIPResult) (*data.PacketMetadata, error)
	CompleteCall(string)
}

type tapSelections struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func (s *tapSelections) Selected(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[id]
	return ok
}
func (s *tapSelections) MarkSelected(id string) { s.mu.Lock(); s.m[id] = struct{}{}; s.mu.Unlock() }
func (s *tapSelections) Forget(id string)       { s.mu.Lock(); delete(s.m, id); s.mu.Unlock() }

type tapTerminalResponses struct{}

func (tapTerminalResponses) Completes(e sharedsip.Event) bool {
	return e.ResponseCode >= 200 && (e.CSeqMethod == "BYE" || e.CSeqMethod == "CANCEL")
}

type tapRegistryAdapter struct{ registry tapCallRegistry }

func (a tapRegistryAdapter) Observe(r pipeline.SIPResult) (sipflow.RegistryObservation, error) {
	if a.registry == nil || r.Packet == nil {
		return sipflow.RegistryObservation{}, nil
	}
	if scoped, ok := a.registry.(interface {
		ProcessReassembledSIPResultWithLifetime(pipeline.SIPResult) (*data.PacketMetadata, callregistry.Lifetime, error)
	}); ok {
		metadata, lifetime, err := scoped.ProcessReassembledSIPResultWithLifetime(r)
		return sipflow.RegistryObservation{Attachment: tapAttachment{metadata: metadata, lifetime: lifetime}}, err
	}
	metadata, err := a.registry.ProcessReassembledSIPResult(r)
	if err != nil {
		return sipflow.RegistryObservation{}, err
	}
	return sipflow.RegistryObservation{Attachment: metadata}, nil
}
func (a tapRegistryAdapter) Complete(id string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	return nil, nil
}

type tapInjectionSink struct{ ch chan<- source.InjectedPacket }

type tapAttachment struct {
	lifetime callregistry.Lifetime
	metadata *data.PacketMetadata
	terminal bool
	complete func()
	accepted chan struct{}
}

func (s tapInjectionSink) HandleSIP(ctx context.Context, in sipflow.SinkInput) pipeline.Result {
	attachment, _ := in.Attachment.(tapAttachment)
	metadata := attachment.metadata
	if metadata == nil {
		metadata, _ = in.Attachment.(*data.PacketMetadata)
	}
	if metadata == nil {
		metadata = metadataFromSIPResult(in.Result)
	}
	if metadata.Sip == nil || in.Result.Packet == nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("tap SIP registry returned no metadata")}
	}
	var done chan struct{}
	var callback func()
	if attachment.terminal {
		done = make(chan struct{})
		var once sync.Once
		callback = func() {
			once.Do(func() {
				if attachment.complete != nil {
					attachment.complete()
				}
				close(done)
			})
		}
	}
	injected := source.InjectedPacket{PacketInfo: captureadapter.ToPacketInfo(in.Result.Packet), Metadata: metadata, CallLifetime: attachment.lifetime, AfterProcess: callback}
	select {
	case s.ch <- injected:
		if attachment.accepted != nil {
			close(attachment.accepted)
		}
	case <-ctx.Done():
		if attachment.accepted != nil {
			close(attachment.accepted)
		}
		return pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: ctx.Err()}
	default:
		if callback != nil {
			callback()
		}
		if attachment.accepted != nil {
			close(attachment.accepted)
		}
		return pipeline.Result{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropQueueFull}
	}
	if !attachment.terminal {
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	}
	select {
	case <-done:
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	case <-ctx.Done():
		return pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: ctx.Err()}
	}
}

func metadataFromSIPResult(r pipeline.SIPResult) *data.PacketMetadata {
	return &data.PacketMetadata{Sip: &data.SIPMetadata{
		CallId: r.CallID, FromUser: r.FromUser, ToUser: r.ToUser,
		FromTag: r.FromTag, ToTag: r.ToTag, FromUri: r.FromURI, ToUri: r.ToURI,
		Method: r.Method, CseqMethod: r.CSeqMethod, CseqNumber: r.CSeqNumber, ViaBranch: r.ViaBranch, ResponseCode: uint32(r.ResponseCode),
		MediaPorts:        sharedsip.MediaPorts(r.SDP),
		PAssertedIdentity: r.PAssertedIdentity,
	}}
}

// TapTCPHandler adapts reassembled TCP messages to shared SIP orchestration.
type TapTCPHandler struct {
	packetChan       chan<- source.InjectedPacket
	appFilter        ApplicationFilter
	registry         tapCallRegistry
	mu               sync.Mutex
	flow             *sipflow.Orchestrator
	metadataObserver sipflow.MetadataObserver
}

func NewTapTCPHandler(ch chan<- source.InjectedPacket) *TapTCPHandler {
	return &TapTCPHandler{packetChan: ch}
}

func (h *TapTCPHandler) SetApplicationFilter(f ApplicationFilter) { h.appFilter = f }
func (h *TapTCPHandler) SetCallRegistry(r tapCallRegistry)        { h.registry = r }

// SetMetadataObserver wires the local admission bridge before reassembly starts.
func (h *TapTCPHandler) SetMetadataObserver(observer sipflow.MetadataObserver) {
	h.metadataObserver = observer
}

func (h *TapTCPHandler) ensureFlow() *sipflow.Orchestrator {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.flow != nil {
		return h.flow
	}
	o, err := sipflow.New(sipflow.Config{MetadataObserver: h.metadataObserver, SelectionPolicy: callregistry.StickySelectionPolicy{}, SelectionStore: &tapSelections{m: make(map[string]struct{})}, Registry: tapRegistryAdapter{h.registry}, Completion: tapTerminalResponses{}})
	if err != nil {
		logger.Error("Failed to create tap SIP orchestration", "error", err)
		return nil
	}
	queueSize := cap(h.packetChan)
	if queueSize < 1 {
		queueSize = 1
	}
	if err = o.RegisterSink("tap_processor", tapInjectionSink{h.packetChan}, queueSize); err == nil {
		err = o.Start(context.Background())
	}
	if err != nil {
		logger.Error("Failed to start tap SIP orchestration", "error", err)
		return nil
	}
	h.flow = o
	return o
}

func (h *TapTCPHandler) Close() {
	h.mu.Lock()
	o := h.flow
	h.mu.Unlock()
	if o != nil {
		o.Close()
	}
}

func (h *TapTCPHandler) HandleSIPMessage(msg []byte, id, src, dst string, nf, tf gopacket.Flow) bool {
	return h.HandleSIPMessageAt(msg, id, src, dst, nf, tf, time.Now())
}

func (h *TapTCPHandler) HandleSIPMessageAt(msg []byte, id, src, dst string, nf, tf gopacket.Flow, at time.Time) bool {
	return h.handleSIPMessage(msg, nil, id, src, dst, nf, tf, at, pipeline.SourceProvenance{})
}

func (h *TapTCPHandler) HandleParsedSIPMessage(msg []byte, event sharedsip.Event, src, dst string, nf, tf gopacket.Flow) bool {
	return h.HandleParsedSIPMessageFromSource(msg, event, src, dst, nf, tf, pipeline.SourceProvenance{})
}

// HandleParsedSIPMessageFromSource retains the actual source of the message's
// final byte. Streams may share framing across interfaces in the same domain;
// their synthesized messages must never inherit an unrelated configured source.
func (h *TapTCPHandler) HandleParsedSIPMessageFromSource(msg []byte, event sharedsip.Event, src, dst string, nf, tf gopacket.Flow, provenance pipeline.SourceProvenance) bool {
	return h.handleSIPMessage(msg, &event, event.CallID, src, dst, nf, tf, event.Timestamp, provenance)
}

func (h *TapTCPHandler) handleSIPMessage(msg []byte, event *sharedsip.Event, id, src, dst string, nf, tf gopacket.Flow, at time.Time, provenance pipeline.SourceProvenance) bool {
	defer discardTCPBufferedPackets(nf, tf)
	if id == "" {
		return false
	}
	pkt, ok := buildSIPPacketInfo(msg, src, dst, nf, at)
	if !ok {
		logger.Warn("TCP SIP synthesis failed", "call_id", SanitizeCallIDForLogging(id))
		return false
	}
	pkt.Interface = provenance.InterfaceName
	pkt.SourceInterfaceID = provenance.InterfaceIndex
	pkt.SourcePath = provenance.InputFile
	pkt.SourceIndex = provenance.ArgumentIndex
	pkt.SourceSequence = provenance.LogicalSequence
	o := h.ensureFlow()
	if o == nil {
		return false
	}
	r := o.Analyze(sipflow.Message{
		Payload: msg, Event: event, ExpectedCallID: id, Envelope: captureadapter.FromPacketInfo(pkt, pipeline.SourceLiveCapture),
		ParseOptions: sharedsip.OptionsForEndpoints(at, src, dst), FilterConfigured: true,
		Match: func(event sharedsip.Event) bool {
			if h.appFilter != nil {
				return h.appFilter.MatchPacket(pkt.Packet)
			}
			return containsUserInHeaders(event.Headers)
		},
		Validate: func(event sharedsip.Event) error {
			if event.CallID != id {
				return fmt.Errorf("reassembled Call-ID %q does not match framed Call-ID %q", event.CallID, id)
			}
			return ValidateCallIDForSecurity(event.CallID)
		},
	})
	if r.Stage.Outcome == pipeline.OutcomeAccepted {
		attachment, _ := r.Attachment.(tapAttachment)
		metadata := attachment.metadata
		if metadata == nil {
			metadata, _ = r.Attachment.(*data.PacketMetadata)
		}
		accepted := make(chan struct{})
		var complete func()
		if r.Terminal && h.registry != nil {
			callID := r.SIP.CallID
			complete = func() {
				if scoped, ok := h.registry.(interface {
					CompleteCallLifetime(string, callregistry.Lifetime)
				}); ok {
					scoped.CompleteCallLifetime(callID, attachment.lifetime)
				} else {
					h.registry.CompleteCall(callID)
				}
			}
		}
		r.Attachment = tapAttachment{lifetime: attachment.lifetime, metadata: metadata, terminal: r.Terminal, complete: complete, accepted: accepted}
		r = o.Dispatch(r)
		if sinkResult, ok := r.Sinks["tap_processor"]; ok && sinkResult.Outcome == pipeline.OutcomeAccepted {
			<-accepted
		} else if complete != nil {
			complete()
		}
	}
	return r.Stage.Outcome == pipeline.OutcomeAccepted
}
