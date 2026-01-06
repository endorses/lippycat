package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
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
	isVoIP   bool
	callID   string
	metadata *data.PacketMetadata
}

// IsVoIPPacket implements source.VoIPResult.
func (r *SourceProcessResult) IsVoIPPacket() bool {
	return r.isVoIP
}

// GetCallID implements source.VoIPResult.
func (r *SourceProcessResult) GetCallID() string {
	return r.callID
}

// GetMetadata implements source.VoIPResult.
func (r *SourceProcessResult) GetMetadata() *data.PacketMetadata {
	return r.metadata
}

// Process implements the source.VoIPProcessor interface.
// It returns a result that implements source.VoIPResult.
func (a *SourceAdapter) Process(packet gopacket.Packet) *SourceProcessResult {
	result := a.proc.Process(packet)
	if result == nil {
		return nil
	}

	return &SourceProcessResult{
		isVoIP:   result.IsVoIP,
		callID:   result.CallID,
		metadata: result.Metadata,
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

// CleanupCallPorts removes all port-to-callID mappings for a given callID.
// This should be called when a call ends to prevent port collisions with new calls.
func (a *SourceAdapter) CleanupCallPorts(callID string) {
	a.proc.CleanupCallPorts(callID)
}
