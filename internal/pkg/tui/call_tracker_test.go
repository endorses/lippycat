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
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000, 10001})

	// Direct destination match should work
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	// Direct source match should also work
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "10000", "192.168.1.1", "5000")
	assert.Equal(t, "call-123", callID)
}

func TestCallTracker_GetCallIDForRTPPacket_IPFallback(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register media ports for a single call from an IP
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000})

	// Fallback by source IP should work when only one call from that IP
	callID := tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Equal(t, "call-123", callID)

	// Fallback by destination IP should also work
	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "9999")
	assert.Equal(t, "call-123", callID)
}

func TestCallTracker_GetCallIDForRTPPacket_AmbiguousIP(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register two different calls from the same IP
	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000})
	tracker.RegisterMediaPorts("call-456", "10.0.0.1", []uint16{20000})

	// Direct match should still work
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "10000")
	assert.Equal(t, "call-123", callID)

	callID = tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "10.0.0.1", "20000")
	assert.Equal(t, "call-456", callID)

	// But fallback should NOT work - multiple calls from same IP
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID, "should not match when multiple calls from same IP")
}

func TestCallTracker_GetCallIDForRTPPacket_NoMatch(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000})

	// Completely unrelated IP/port should not match
	callID := tracker.GetCallIDForRTPPacket("192.168.1.1", "5000", "172.16.0.1", "6000")
	assert.Empty(t, callID)
}

func TestCallTracker_IPIndexCleanupOnEviction(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(2) // Small capacity to trigger eviction

	// Register first call
	tracker.RegisterMediaPorts("call-1", "10.0.0.1", []uint16{10000})
	tracker.RegisterMediaPorts("call-2", "10.0.0.2", []uint16{20000})

	// Verify both calls are accessible
	assert.Equal(t, "call-1", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000"))
	assert.Equal(t, "call-2", tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.2", "20000"))

	// Register third call - should evict oldest (call-1)
	tracker.RegisterMediaPorts("call-3", "10.0.0.3", []uint16{30000})

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

func TestCallTracker_RegisterRTPOnlyEndpoints_IPIndex(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// Register RTP-only endpoints
	tracker.RegisterRTPOnlyEndpoints("rtp-abc123", "10.0.0.1", "10000", "10.0.0.2", "20000")

	// Direct match
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "rtp-abc123", callID)

	// IP fallback should work for source IP
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Equal(t, "rtp-abc123", callID)

	// IP fallback should work for destination IP too
	callID = tracker.GetCallIDForRTPPacket("10.0.0.2", "9999", "192.168.1.1", "5000")
	assert.Equal(t, "rtp-abc123", callID)
}

func TestCallTracker_SyntheticCallMerge_IPIndexCleanup(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	// First, register RTP-only call
	tracker.RegisterRTPOnlyEndpoints("rtp-synthetic", "10.0.0.1", "10000", "10.0.0.2", "20000")

	// Verify synthetic call works
	callID := tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "rtp-synthetic", callID)

	// Now SIP arrives and registers the real call - should return synthetic ID for merging
	syntheticID := tracker.RegisterMediaPorts("real-call-123", "10.0.0.1", []uint16{10000})
	assert.Equal(t, "rtp-synthetic", syntheticID)

	// Now lookup should return real call ID
	callID = tracker.GetCallIDForRTPPacket("x", "y", "10.0.0.1", "10000")
	assert.Equal(t, "real-call-123", callID)

	// IP fallback should also return real call ID
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Equal(t, "real-call-123", callID)
}

func TestCallTracker_Clear_ResetsIPIndex(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(100)

	tracker.RegisterMediaPorts("call-123", "10.0.0.1", []uint16{10000})

	// Verify it works
	callID := tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Equal(t, "call-123", callID)

	// Clear
	tracker.Clear()

	// Should no longer match
	callID = tracker.GetCallIDForRTPPacket("10.0.0.1", "9999", "192.168.1.1", "5000")
	assert.Empty(t, callID)
}

func BenchmarkGetCallIDForRTPPacket_DirectMatch(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Direct match - should be O(1)
		tracker.GetCallIDForRTPPacket("x", "y", "10.0.19.136", "14999") // call-4999
	}
}

func BenchmarkGetCallIDForRTPPacket_IPFallback(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls with unique IPs
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// IP fallback - should now be O(1) instead of O(n²)
		tracker.GetCallIDForRTPPacket("10.0.19.136", "9999", "192.168.1.1", "5000") // fallback for call-4999
	}
}

func BenchmarkGetCallIDForRTPPacket_NoMatch(b *testing.B) {
	tracker := NewCallTrackerWithCapacity(5000)

	// Register 5000 calls
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)})
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

func TestCallTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(1000)
	done := make(chan struct{})

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			tracker.RegisterMediaPorts(fmt.Sprintf("call-%d", i), ip, []uint16{uint16(10000 + i)})
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
