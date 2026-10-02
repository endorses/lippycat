package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
)

// SourceAdapter wraps a Processor to implement the source.VoIPProcessor interface.
// This allows the Processor to be used with LocalSource in tap mode.
type SourceAdapter struct {
	scoped        *scopedSource
	mediaObserver interface {
		RecordAttributedMedia(string, callregistry.Lifetime)
	}
	proc *Processor
}

// NewSourceAdapter creates a new adapter for use with LocalSource.
func NewSourceAdapter(proc *Processor) *SourceAdapter {
	return &SourceAdapter{proc: proc}
}

// SourceProcessResult implements the source.VoIPResult interface.
// It wraps the processor's ProcessResult for use with LocalSource.
type SourceProcessResult struct {
	isVoIP          bool
	callID          string
	lifetime        callregistry.Lifetime
	callIDs         []string
	mediaResolution callregistry.MediaResolution
	metadata        *data.PacketMetadata
	filterEvaluated bool
	filterMatched   bool
	filterIDs       []string
}

// GetMediaResolution returns the explicit authoritative RTP ownership result.
// Consumers must not infer ownership from an empty or non-empty Call-ID.
func (r *SourceProcessResult) GetMediaResolution() callregistry.MediaResolution {
	return r.mediaResolution
}

// IsVoIPPacket implements source.VoIPResult.
func (r *SourceProcessResult) IsVoIPPacket() bool {
	return r.isVoIP
}

// GetCallID implements source.VoIPResult.
func (r *SourceProcessResult) GetCallID() string {
	return r.callID
}

func (r *SourceProcessResult) GetCallLifetime() callregistry.Lifetime { return r.lifetime }

// GetCallIDs returns every call associated with the packet. The returned slice
// is a copy so callers cannot mutate processor-owned result state.
func (r *SourceProcessResult) GetCallIDs() []string {
	return append([]string(nil), r.callIDs...)
}

// GetMetadata implements source.VoIPResult.
func (r *SourceProcessResult) GetMetadata() *data.PacketMetadata {
	return r.metadata
}

// FilterVerdict reports whether the application filter was already evaluated for
// this packet and, if so, the verdict and any matched filter IDs.
func (r *SourceProcessResult) FilterVerdict() (evaluated, matched bool, ids []string) {
	return r.filterEvaluated, r.filterMatched, r.filterIDs
}

// Process implements the source.VoIPProcessor interface.
// It returns a result that implements source.VoIPResult.
func (a *SourceAdapter) Process(packet gopacket.Packet) *SourceProcessResult {
	if a.scoped != nil {
		return nil
	} // A scoped adapter requires capture provenance.
	return adaptSourceResult(a.proc.Process(packet))
}

// ProcessPacketInfo retains interface identity through SIP metadata observation.
func (a *SourceAdapter) ProcessPacketInfo(info capture.PacketInfo) *SourceProcessResult {
	if a.scoped != nil {
		child := a.scoped.child(info.Interface)
		if child == nil {
			return nil
		}
		return child.ProcessPacketInfo(info)
	}
	return adaptSourceResult(a.proc.ProcessPacketInfo(info))
}

func adaptSourceResult(result *ProcessResult) *SourceProcessResult {
	if result == nil {
		return nil
	}

	return &SourceProcessResult{
		isVoIP:          result.IsVoIP,
		callID:          result.CallID,
		lifetime:        result.CallLifetime,
		callIDs:         result.CallIDs,
		mediaResolution: result.MediaResolution,
		metadata:        result.Metadata,
		filterEvaluated: result.FilterEvaluated,
		filterMatched:   result.FilterMatched,
		filterIDs:       result.FilterIDs,
	}
}

// Close releases resources held by the underlying processor.
func (a *SourceAdapter) Close() {
	if a.scoped != nil {
		a.scoped.close()
		return
	}
	a.proc.Close()
}

// ActiveCalls returns information about currently tracked calls.
func (a *SourceAdapter) ActiveCalls() []CallInfo {
	if a.scoped != nil {
		var calls []CallInfo
		for _, child := range a.scoped.children {
			calls = append(calls, child.ActiveCalls()...)
		}
		return calls
	}
	return a.proc.ActiveCalls()
}

// AddLifecycleObserver subscribes an observer to future call lifecycle events.
func (a *SourceAdapter) AddLifecycleObserver(observer callregistry.LifecycleObserver) {
	if a == nil || a.scoped != nil || a.proc == nil {
		return
	}
	a.proc.AddLifecycleObserver(observer)
}

// SetCompletionHandler delegates terminal cleanup to a shared processor
// lifecycle coordinator.
func (a *SourceAdapter) SetCompletionHandler(handler func(callregistry.Call, callregistry.EndReason)) {
	if a == nil || a.scoped != nil || a.proc == nil {
		return
	}
	a.proc.SetCompletionHandler(handler)
}

// CleanupCallPorts removes all port-to-callID mappings for a given callID.
// This should be called when a call ends to prevent port collisions with new calls.
func (a *SourceAdapter) CleanupCallPorts(callID string) {
	if a.scoped != nil {
		return
	} // An unscoped output event cannot retire a local domain.
	a.proc.FinalizeCallCleanup(callID)
}
