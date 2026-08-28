// Package callregistry defines protocol-domain call lifecycle contracts without
// depending on analyzers, transports, or output resources.
package callregistry

import "time"

type Call struct {
	CallID      string
	State       string
	From        string
	To          string
	Created     time.Time
	LastUpdated time.Time
}

type EndReason string

const (
	EndCompleted EndReason = "completed"
	EndTimeout   EndReason = "timeout"
	EndEvicted   EndReason = "evicted"
	EndShutdown  EndReason = "shutdown"
)

type LifecycleObserver interface {
	OnCallStarted(Call)
	OnCallEnded(Call, EndReason)
}

type Registry interface {
	ActiveCalls() []Call
	Call(callID string) (Call, bool)
	CallIDsForEndpoint(endpoint string) []string
	AssociateEndpoint(callID, endpoint string)
	CompleteCall(callID string)
	Close()
}
