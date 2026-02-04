//go:build tui || all

package tui

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallTracker_GetCallIDForRTPPacket_DirectMatch(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register media ports for a call
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000, 10001}, false)

	// Direct destination match should work
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	// Direct source match should also work
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "10000", "192.168.1.1", "5000")
	assert.Equal(t, "call-123", callID)
}

func TestCallTracker_GetCallIDForRTPPacket_NoFallback(t *testing.T) {
	// Test that IP-only fallback is NOT used (pure IP:port matching)
	tracker := NewCallTrackerWithCapacity(100)

	// Register media ports for a single call from an IP
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false)

	// Exact port match should work
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	// Non-matching ports should NOT match (no IP-only fallback)
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "should not match when port doesn't match")

	// Even with only one call from that IP, non-matching ports should fail
	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "9999")
	assert.Empty(t, callID, "should not match when port doesn't match")
}

func TestCallTracker_GetCallIDForRTPPacket_MultipleCallsSameIP(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register two different calls from the same IP
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-456", "10.0.0.1", []uint16{20000}, false)

	// Direct port match should work for each call
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "20000")
	assert.Equal(t, "call-456", callID)

	// Non-matching ports should NOT match
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "should not match when port doesn't match")
}

func TestCallTracker_GetCallIDForRTPPacket_NoMatch(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false)

	// Completely unrelated IP/port should not match
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "172.16.0.1", "6000")
	assert.Empty(t, callID)
}

func TestCallTracker_IPIndexCleanupOnEviction(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(2) // Small capacity to trigger eviction

	// Register first call
	tracker.RegisterMediaPorts("call-1", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-2", "10.0.0.2", []uint16{20000}, false)

	// Verify both calls are accessible
	assert.Equal(t, "call-1", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000"))
	assert.Equal(t, "call-2", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000"))

	// Register third call - should evict oldest (call-1)
	tracker.RegisterMediaPorts("call-3", "10.0.0.3", []uint16{30000}, false)

	// call-1 should be gone
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Empty(t, callID, "call-1 should have been evicted")

	// IP fallback for evicted call should also not work
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "IP fallback for evicted call should not work")

	// call-2 and call-3 should still work
	assert.Equal(t, "call-2", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000"))
	assert.Equal(t, "call-3", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.3", "30000"))
}

func TestCallTracker_RegisterRTPOnlyEndpoints(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register RTP-only endpoints
	tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "10.0.0.1", "10000", "10.0.0.2", "20000")

	// Direct port match should work for both endpoints
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "rtp-abc123", callID)

	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000")
	assert.Equal(t, "rtp-abc123", callID)

	// Non-matching ports should NOT match (no fallback)
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "should not match with non-matching port")
}

func TestCallTracker_SyntheticCallMerge(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// First, register RTP-only call
	tracker.RegisterRTPOnlyEndpoints("rtp-synthetic", "10.0.0.1", "10000", "10.0.0.2", "20000")

	// Verify synthetic call works with exact port
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "rtp-synthetic", callID)

	// Now SIP arrives and registers the real call - should return synthetic ID for merging
	syntheticID := tracker.RegisterMediaPorts("real-call-123", "10.0.0.1", []uint16{10000}, false)
	assert.Equal(t, "rtp-synthetic", syntheticID)

	// Now lookup should return real call ID
	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "real-call-123", callID)

	// Non-matching ports should NOT match
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "should not match with non-matching port")
}

func TestCallTracker_Clear(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false)

	// Verify exact match works
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	// Clear
	tracker.Clear()

	// Should no longer match
	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Empty(t, callID)
}

func TestCallTracker_ExactPortMatchOnly(t *testing.T) {
	// Test that we use pure IP:port matching (no fallbacks)
	tracker := NewCallTrackerWithCapacity(100)

	// Simulate INVITE from caller (10.0.0.1) with SDP
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false) // false = request

	// Simulate 200 OK from callee (10.0.0.2) with SDP
	tracker.RegisterMediaPorts("call-123", "10.0.0.2", []uint16{20000}, true) // true = response

	// Direct port match should work
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000")
	assert.Equal(t, "call-123", callID)

	// Non-matching ports should NOT match (no IP-only fallback)
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "10.0.0.2", "8888")
	assert.Empty(t, callID, "should not match when ports don't match exactly")

	// Reverse direction with wrong ports should also not match
	callID = tracker.GetCallIDForRTPPacket("10.0.0.2", "8888", "10.0.0.1", "9999")
	assert.Empty(t, callID, "should not match when ports don't match exactly")
}

func TestCallTracker_MultipleCalls_ExactMatch(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Call 1: between 10.0.0.1 and 10.0.0.2
	tracker.RegisterMediaPorts("call-1", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-1", "10.0.0.2", []uint16{20000}, true)

	// Call 2: ALSO between 10.0.0.1 and 10.0.0.2 (different call-id, same IP pair)
	tracker.RegisterMediaPorts("call-2", "10.0.0.1", []uint16{10002}, false)
	tracker.RegisterMediaPorts("call-2", "10.0.0.2", []uint16{20002}, true)

	// Direct port match should work for call-1
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "call-1", callID)

	// Direct port match should work for call-2
	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10002")
	assert.Equal(t, "call-2", callID)

	// Non-matching ports should NOT match
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "10.0.0.2", "8888")
	assert.Empty(t, callID, "should not match when ports don't match exactly")
}

func BenchmarkGetCallIDForRTPPacket_DirectMatch(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)}, false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Direct match - should be O(1)
		tracker.GetCallIDForRTPPacket("x", "y", "10.0.19.136", "14999") // call-4999
	}
}

func BenchmarkGetCallIDForRTPPacket_SourceMatch(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls with unique IPs
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)}, false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Source match - check when RTP is sent FROM a registered port
		tracker.GetCallIDForRTPPacket("10.0.19.136", "14999", "192.168.1.1", "5000") // call-4999 as source
	}
}

func BenchmarkGetCallIDForRTPPacket_NoMatch(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)}, false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// No match - should be O(1) now
		tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "172.16.0.1", "6000")
	}
}

func TestExtractIPFromEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected string
	}{
		{"10.0.0.1:5060", "10.0.0.1"},
		{"192.168.1.1:10000", "192.168.1.1"},
		{"::1:5060", "::1"},
		{"[2001:db8::1]:5060", "[2001:db8::1]"},
		{"invalid", ""},
		{"", ""},
		{":", ""},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result := extractIPFromEndpoint(tt.endpoint)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractPortFromEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected string
	}{
		{"10.0.0.1:5060", "5060"},
		{"192.168.1.1:10000", "10000"},
		{"::1:5060", "5060"},
		{"[2001:db8::1]:5060", "5060"},
		{"invalid", ""},
		{"", ""},
		{":", ""},
		{"10.0.0.1:", ""},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result := extractPortFromEndpoint(tt.endpoint)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCallTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(1000)
	done := make(chan struct{})

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)}, false)
		}
		close(done)
	}()

	// Reader goroutines
	for j := 0; j < 4; j++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					tracker.GetCallIDForRTPPacket("10.0.1.1", "5000", "10.0.2.2", "10256")
				}
			}
		}()
	}

	<-done

	// Verify final state
	require.Equal(t, 1000, tracker.GetTrackedCallCount())
}

// TestCallTracker_EvictionDoesNotDeleteReassignedEndpoints ensures that when a call
// is evicted, it doesn't delete endpoints that were reassigned to a different call.
func TestCallTracker_EvictionDoesNotDeleteReassignedEndpoints(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(3)

	// Register first call with endpoint E1
	tracker.RegisterMediaPorts("call-A", "10.0.0.1", []uint16{10000}, false)
	assert.Equal(t, "call-A", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000"))

	// Register second call with a different endpoint
	tracker.RegisterMediaPorts("call-B", "10.0.0.2", []uint16{20000}, false)

	// Register third call that uses the SAME endpoint E1 as call-A
	// This should overwrite the rtpEndpointToCallID mapping
	tracker.RegisterMediaPorts("call-C", "10.0.0.1", []uint16{10000}, false)
	assert.Equal(t, "call-C", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000"))

	// Now add a fourth call to trigger LRU eviction of call-A (oldest)
	tracker.RegisterMediaPorts("call-D", "10.0.0.4", []uint16{40000}, false)

	// The key assertion: endpoint E1 should STILL work because it belongs to call-C,
	// even though call-A (which also had E1 in its callIDToEndpoints) was evicted
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "call-C", callID, "Endpoint should still be accessible after evicting old call that shared it")
}

// TestCallTracker_RTPOnlyDoesNotOverwriteSIPCall ensures that registering an RTP-only
// call doesn't overwrite endpoints that already belong to a real SIP call.
// With race recovery: if any endpoint already belongs to a SIP call, the function
// returns that call ID so the caller can use it instead of creating a synthetic call.
func TestCallTracker_RTPOnlyDoesNotOverwriteSIPCall(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register a real SIP call with endpoint E1
	tracker.RegisterMediaPorts("sip-call-123", "10.0.0.1", []uint16{10000}, false)
	assert.Equal(t, "sip-call-123", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000"))

	// Try to register an RTP-only call with overlapping endpoint (src matches SIP call)
	// This should return the SIP call ID (race recovery) instead of registering the synthetic call
	realCallID := tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "10.0.0.1", "10000", "10.0.0.2", "20000")
	assert.Equal(t, "sip-call-123", realCallID, "Should return SIP call ID when endpoint overlaps")

	// The SIP call should STILL own the endpoint
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "sip-call-123", callID, "SIP call should still own the endpoint")

	// The OTHER endpoint (20000) should NOT be registered for the RTP-only call
	// because the RTP-only call was not created (race recovery returned SIP call ID)
	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000")
	assert.Equal(t, "", callID, "No call should own the uncontested endpoint since RTP-only was not created")
}

// TestCallTracker_RTPOnlyRegisteredWhenNoOverlap ensures that RTP-only calls
// are registered normally when there's no overlap with existing SIP calls.
func TestCallTracker_RTPOnlyRegisteredWhenNoOverlap(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register a real SIP call with endpoint E1
	tracker.RegisterMediaPorts("sip-call-123", "10.0.0.1", []uint16{10000}, false)

	// Register an RTP-only call with completely different endpoints
	realCallID := tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "10.0.0.3", "30000", "10.0.0.4", "40000")
	assert.Equal(t, "", realCallID, "Should return empty when no overlap (new RTP-only call created)")

	// The RTP-only call should own both of its endpoints
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.3", "30000")
	assert.Equal(t, "rtp-abc123", callID, "RTP-only call should own its src endpoint")

	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.4", "40000")
	assert.Equal(t, "rtp-abc123", callID, "RTP-only call should own its dst endpoint")
}

// TestCallTracker_GetEndpointsForCallTouchesLRU ensures that reading endpoints
// keeps the call from being evicted (LRU touch on read).
func TestCallTracker_GetEndpointsForCallTouchesLRU(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(3)

	// Register three calls
	tracker.RegisterMediaPorts("call-A", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-B", "10.0.0.2", []uint16{20000}, false)
	tracker.RegisterMediaPorts("call-C", "10.0.0.3", []uint16{30000}, false)
	// LRU order: C, B, A (C is most recent)

	// Access call-A's endpoints - this should move it to front of LRU
	endpoints := tracker.GetEndpointsForCall("call-A")
	assert.NotEmpty(t, endpoints, "call-A should have endpoints")
	// LRU order: A, C, B (A is now most recent due to GetEndpointsForCall)

	// Add a fourth call to trigger eviction
	tracker.RegisterMediaPorts("call-D", "10.0.0.4", []uint16{40000}, false)
	// This should evict call-B (least recently used), NOT call-A

	// call-A should still have endpoints because we touched it
	endpoints = tracker.GetEndpointsForCall("call-A")
	assert.NotEmpty(t, endpoints, "call-A should still have endpoints after GetEndpointsForCall touched LRU")

	// call-B should have been evicted
	endpoints = tracker.GetEndpointsForCall("call-B")
	assert.Empty(t, endpoints, "call-B should have been evicted")
}

// TestCallTracker_EndpointDeduplication ensures that the same endpoint
// is not added multiple times when RegisterMediaPorts is called repeatedly
// (e.g., from INVITE, 200 OK, re-INVITE, etc. for the same call).
func TestCallTracker_EndpointDeduplication(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register the same endpoint multiple times (simulating multiple SIP messages)
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, true)  // 200 OK
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000}, false) // re-INVITE

	// Should only have one endpoint, not three
	endpoints := tracker.GetEndpointsForCall("call-123")
	assert.Len(t, endpoints, 1, "duplicate endpoints should not be added")
	assert.Equal(t, "10.0.0.1:10000", endpoints[0])
}

// TestCallTracker_EndpointDeduplicationWithMultiplePorts ensures deduplication
// works correctly when multiple ports are registered at once.
func TestCallTracker_EndpointDeduplicationWithMultiplePorts(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register multiple ports, then register them again
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000, 10002}, false)
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000, 10002}, true)

	// Should have exactly 2 endpoints
	endpoints := tracker.GetEndpointsForCall("call-123")
	assert.Len(t, endpoints, 2, "should have exactly 2 unique endpoints")
}

// TestCallTracker_RTPOnlyEndpointDeduplication ensures deduplication in
// RegisterRTPOnlyEndpoints (synthetic RTP-only calls).
func TestCallTracker_RTPOnlyEndpointDeduplication(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register the same endpoints multiple times for an RTP-only call
	tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "192.168.1.1", "5000", "10.0.0.1", "10000")
	tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "192.168.1.1", "5000", "10.0.0.1", "10000")

	// Should have 2 unique endpoints (src and dst), not 4
	endpoints := tracker.GetEndpointsForCall("rtp-abc123")
	assert.Len(t, endpoints, 2, "RTP-only endpoints should be deduplicated")
}

// TestCallTracker_RTPLookupTouchesLRU ensures that successful RTP lookups
// touch the LRU to prevent eviction of calls with active RTP traffic.
func TestCallTracker_RTPLookupTouchesLRU(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(3)

	// Register three calls
	tracker.RegisterMediaPorts("call-A", "10.0.0.1", []uint16{10000}, false)
	tracker.RegisterMediaPorts("call-B", "10.0.0.2", []uint16{20000}, false)
	tracker.RegisterMediaPorts("call-C", "10.0.0.3", []uint16{30000}, false)
	// LRU order: C, B, A (C is most recent)

	// Simulate RTP lookup for call-A - this should touch the LRU
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-A", callID)
	// LRU order should now be: A, C, B (A moved to front)

	// Add a fourth call to trigger eviction
	tracker.RegisterMediaPorts("call-D", "10.0.0.4", []uint16{40000}, false)
	// This should evict call-B (least recently used), NOT call-A

	// call-A should still be correlatable because RTP lookup touched it
	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-A", callID, "call-A should still be correlatable after RTP lookup touched LRU")

	// call-B should have been evicted
	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.2", "20000")
	assert.Empty(t, callID, "call-B should have been evicted")
}
