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
	ProcessReassembledSIP(gopacket.Packet) *data.PacketMetadata
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
	return sipflow.RegistryObservation{Attachment: a.registry.ProcessReassembledSIP(r.Packet.Packet())}, nil
}
func (a tapRegistryAdapter) Complete(id string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	return nil, nil
}

type tapInjectionSink struct{ ch chan<- source.InjectedPacket }

type tapAttachment struct {
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
	injected := source.InjectedPacket{PacketInfo: captureadapter.ToPacketInfo(in.Result.Packet), Metadata: metadata, AfterProcess: callback}
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
		Method: r.Method, CseqMethod: r.CSeqMethod, ResponseCode: uint32(r.ResponseCode),
		PAssertedIdentity: r.PAssertedIdentity,
	}}
}

// TapTCPHandler adapts reassembled TCP messages to shared SIP orchestration.
type TapTCPHandler struct {
	packetChan chan<- source.InjectedPacket
	appFilter  ApplicationFilter
	registry   tapCallRegistry
	mu         sync.Mutex
	flow       *sipflow.Orchestrator
}

func NewTapTCPHandler(ch chan<- source.InjectedPacket) *TapTCPHandler {
	return &TapTCPHandler{packetChan: ch}
}
func (h *TapTCPHandler) SetApplicationFilter(f ApplicationFilter) { h.appFilter = f }
func (h *TapTCPHandler) SetCallRegistry(r tapCallRegistry)        { h.registry = r }

func (h *TapTCPHandler) ensureFlow() *sipflow.Orchestrator {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.flow != nil {
		return h.flow
	}
	o, err := sipflow.New(sipflow.Config{SelectionPolicy: callregistry.StickySelectionPolicy{}, SelectionStore: &tapSelections{m: make(map[string]struct{})}, Registry: tapRegistryAdapter{h.registry}, Completion: tapTerminalResponses{}})
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
	return h.handleSIPMessage(msg, nil, id, src, dst, nf, tf, at)
}

func (h *TapTCPHandler) HandleParsedSIPMessage(msg []byte, event sharedsip.Event, src, dst string, nf, tf gopacket.Flow) bool {
	return h.handleSIPMessage(msg, &event, event.CallID, src, dst, nf, tf, event.Timestamp)
}

func (h *TapTCPHandler) handleSIPMessage(msg []byte, event *sharedsip.Event, id, src, dst string, nf, tf gopacket.Flow, at time.Time) bool {
	defer discardTCPBufferedPackets(nf, tf)
	if id == "" {
		return false
	}
	pkt, ok := buildSIPPacketInfo(msg, src, dst, nf, at)
	if !ok {
		logger.Warn("TCP SIP synthesis failed", "call_id", SanitizeCallIDForLogging(id))
		return false
	}
	o := h.ensureFlow()
	if o == nil {
		return false
	}
	r := o.Analyze(sipflow.Message{
		Payload: msg, Event: event, ExpectedCallID: id, Envelope: captureadapter.FromPacketInfo(pkt),
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
		metadata, _ := r.Attachment.(*data.PacketMetadata)
		accepted := make(chan struct{})
		var complete func()
		if r.Terminal && h.registry != nil {
			callID := r.SIP.CallID
			complete = func() { h.registry.CompleteCall(callID) }
		}
		r.Attachment = tapAttachment{metadata: metadata, terminal: r.Terminal, complete: complete, accepted: accepted}
		r = o.Dispatch(r)
		if sinkResult, ok := r.Sinks["tap_processor"]; ok && sinkResult.Outcome == pipeline.OutcomeAccepted {
			<-accepted
		} else if complete != nil {
			complete()
		}
	}
	return r.Stage.Outcome == pipeline.OutcomeAccepted
}
