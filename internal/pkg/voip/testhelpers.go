package voip

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/google/gopacket/layers"
)

// TestCallTracker creates an isolated CallTracker for testing
func TestCallTracker(t testing.TB) *CallTracker {
	tracker := NewCallTracker()
	t.Cleanup(func() {
		tracker.Shutdown()
	})
	return tracker
}

func adoptCallForTest(tracker *CallTracker, call *CallInfo) {
	call.tracker = tracker
	if call.Created.IsZero() {
		call.Created = time.Now()
	}
	if call.LastUpdated.IsZero() {
		call.LastUpdated = call.Created
	}
	tracker.registry.Upsert(callregistry.Call{CallID: call.CallID, State: call.State, Created: call.Created, LastUpdated: call.LastUpdated})
	tracker.mu.Lock()
	tracker.callMap[call.CallID] = call
	tracker.mu.Unlock()
}

func associateEndpointForTest(tracker *CallTracker, endpoint, callID string) {
	tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	tracker.registerEndpoint(endpoint, callID)
}

func endpointAssociationCountForTest(tracker *CallTracker) int {
	total := 0
	for _, call := range tracker.registry.ActiveCalls() {
		total += len(tracker.registry.EndpointsForCall(call.CallID))
	}
	return total
}

func clearRegistryForTest(tracker *CallTracker) {
	tracker.mu.Lock()
	clear(tracker.callMap)
	tracker.mu.Unlock()
	tracker.registry.Clear()
}
