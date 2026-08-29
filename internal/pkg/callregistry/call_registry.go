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

// SelectionInput describes one parsed message's selection context. Filtering
// remains topology-specific; this contract decides how a direct verdict and a
// previously selected dialog combine.
type SelectionInput struct {
	FilterConfigured   bool
	DirectMatch        bool
	PreviouslySelected bool
}

// SelectionPolicy decides whether a message belongs to selected output.
type SelectionPolicy interface {
	Select(SelectionInput) bool
}

// StickySelectionPolicy selects all messages when no filter is configured and,
// with filtering enabled, preserves selection for the rest of a dialog after
// any message directly matches.
type StickySelectionPolicy struct{}

func (StickySelectionPolicy) Select(input SelectionInput) bool {
	return !input.FilterConfigured || input.DirectMatch || input.PreviouslySelected
}

type Registry interface {
	ActiveCalls() []Call
	Call(callID string) (Call, bool)
	CallIDsForEndpoint(endpoint string) []string
	AssociateEndpoint(callID, endpoint string)
	CompleteCall(callID string)
	Close()
}
