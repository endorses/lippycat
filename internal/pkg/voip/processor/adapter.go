package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/google/gopacket"
)

// SourceAdapter wraps a Processor to implement the source.VoIPProcessor interface.
// This allows the Processor to be used with LocalSource in tap mode.
type SourceAdapter struct {
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
	result := a.proc.Process(packet)
	if result == nil {
		return nil
	}

	return &SourceProcessResult{
		isVoIP:          result.IsVoIP,
		callID:          result.CallID,
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
	a.proc.Close()
}

// ActiveCalls returns information about currently tracked calls.
func (a *SourceAdapter) ActiveCalls() []CallInfo {
	return a.proc.ActiveCalls()
}

// AddLifecycleObserver subscribes an observer to future call lifecycle events.
func (a *SourceAdapter) AddLifecycleObserver(observer callregistry.LifecycleObserver) {
	if a == nil || a.proc == nil {
		return
	}
	a.proc.AddLifecycleObserver(observer)
}

// SetCompletionHandler delegates terminal cleanup to a shared processor
// lifecycle coordinator.
func (a *SourceAdapter) SetCompletionHandler(handler func(callregistry.Call, callregistry.EndReason)) {
	if a == nil || a.proc == nil {
		return
	}
	a.proc.SetCompletionHandler(handler)
}

// CleanupCallPorts removes all port-to-callID mappings for a given callID.
// This should be called when a call ends to prevent port collisions with new calls.
func (a *SourceAdapter) CleanupCallPorts(callID string) {
	a.proc.FinalizeCallCleanup(callID)
}
