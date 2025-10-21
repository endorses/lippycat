package processor

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateCorrelationID tests that correlation IDs are generated consistently
func TestGenerateCorrelationID(t *testing.T) {
	tests := []struct {
		name     string
		tag1     string
		tag2     string
		expected string
	}{
		{
			name:     "Same tags different order produce same ID",
			tag1:     "abc123",
			tag2:     "xyz789",
			expected: generateCorrelationID("abc123", "xyz789"),
		},
		{
			name:     "Empty tag1 returns empty",
			tag1:     "",
			tag2:     "xyz789",
			expected: "",
		},
		{
			name:     "Empty tag2 returns empty",
			tag1:     "abc123",
			tag2:     "",
			expected: "",
		},
		{
			name:     "Both empty returns empty",
			tag1:     "",
			tag2:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCorrelationID(tt.tag1, tt.tag2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestBidirectionalTagNormalization tests that tags are normalized correctly
func TestBidirectionalTagNormalization(t *testing.T) {
	tag1 := "alice-tag-123"
	tag2 := "bob-tag-456"

	// Generate ID with tags in both orders
	id1 := generateCorrelationID(tag1, tag2)
	id2 := generateCorrelationID(tag2, tag1)

	// Both should produce the same correlation ID
	assert.Equal(t, id1, id2, "Correlation ID should be same regardless of tag order")
	assert.NotEmpty(t, id1, "Correlation ID should not be empty")
}

// TestProcessPacket_BidirectionalDialog tests that INVITE and BYE produce same correlation
func TestProcessPacket_BidirectionalDialog(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	// INVITE from Alice to Bob
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.100",
			DstIp: "192.168.1.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-1@alice",
				Method:   "INVITE",
				FromTag:  "alice-tag",
				ToTag:    "bob-tag", // Populated after 180/200 OK
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}

	cc.ProcessPacket(invitePacket, "hunter-1")

	// BYE from Bob to Alice (tags swapped in direction)
	byePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.200",
			DstIp: "192.168.1.100",
			Sip: &data.SIPMetadata{
				CallId:   "call-1@alice",
				Method:   "BYE",
				FromTag:  "bob-tag",   // Now Bob is sender
				ToTag:    "alice-tag", // Alice is receiver
				FromUser: "bob",
				ToUser:   "alice",
			},
		},
	}

	cc.ProcessPacket(byePacket, "hunter-1")

	// Should have only 1 correlated call (same correlation ID)
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1, "Should have exactly 1 correlated call")

	call := calls[0]
	assert.Len(t, call.CallLegs, 1, "Should have 1 call leg")
	assert.Equal(t, CallStateEnded, call.State, "Call state should be ENDED after BYE")
}

// TestProcessPacket_EarlyDialog tests that packets without ToTag are skipped
func TestProcessPacket_EarlyDialog(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	// Initial INVITE without ToTag (early dialog)
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.100",
			DstIp: "192.168.1.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-1@alice",
				Method:   "INVITE",
				FromTag:  "alice-tag",
				ToTag:    "", // Empty in initial INVITE
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}

	cc.ProcessPacket(invitePacket, "hunter-1")

	// Should have 0 correlated calls (ToTag is required)
	calls := cc.GetCorrelatedCalls()
	assert.Len(t, calls, 0, "Should have no correlated calls without ToTag")
}

// TestProcessPacket_MultipleLegs tests tracking multiple call legs across B2BUAs
func TestProcessPacket_MultipleLegs(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	fromTag := "alice-tag"
	toTag := "bob-tag"

	// Leg 1: Kamailio
	leg1Packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.100",
			DstIp: "192.168.1.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-1@kamailio",
				Method:   "INVITE",
				FromTag:  fromTag,
				ToTag:    toTag,
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}

	cc.ProcessPacket(leg1Packet, "hunter-kamailio")

	// Leg 2: FusionPBX (B2BUA created new Call-ID, but tags preserved)
	leg2Packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.200",
			DstIp: "192.168.2.100",
			Sip: &data.SIPMetadata{
				CallId:   "call-2@fusionpbx", // Different Call-ID
				Method:   "INVITE",
				FromTag:  fromTag, // Same tags (preserved)
				ToTag:    toTag,
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}

	cc.ProcessPacket(leg2Packet, "hunter-fusionpbx")

	// Leg 3: Kazoo
	leg3Packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.2.100",
			DstIp: "192.168.3.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-3@kazoo", // Different Call-ID
				Method:   "INVITE",
				FromTag:  fromTag, // Same tags
				ToTag:    toTag,
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}

	cc.ProcessPacket(leg3Packet, "hunter-kazoo")

	// Should have 1 correlated call with 3 legs
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1, "Should have exactly 1 correlated call")

	call := calls[0]
	assert.Len(t, call.CallLegs, 3, "Should have 3 call legs")

	// Verify each leg
	assert.NotNil(t, call.CallLegs["call-1@kamailio"], "Should have Kamailio leg")
	assert.NotNil(t, call.CallLegs["call-2@fusionpbx"], "Should have FusionPBX leg")
	assert.NotNil(t, call.CallLegs["call-3@kazoo"], "Should have Kazoo leg")

	// Verify hunter IDs
	assert.Equal(t, "hunter-kamailio", call.CallLegs["call-1@kamailio"].HunterID)
	assert.Equal(t, "hunter-fusionpbx", call.CallLegs["call-2@fusionpbx"].HunterID)
	assert.Equal(t, "hunter-kazoo", call.CallLegs["call-3@kazoo"].HunterID)
}

// TestCallStateTransitions tests state transitions
func TestCallStateTransitions(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	fromTag := "alice-tag"
	toTag := "bob-tag"
	callID := "call-1@alice"

	// INVITE -> TRYING
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:  callID,
				Method:  "INVITE",
				FromTag: fromTag,
				ToTag:   toTag,
			},
		},
	}
	cc.ProcessPacket(invitePacket, "hunter-1")

	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, CallStateRinging, calls[0].State, "Should be RINGING after INVITE")

	// 180 Ringing -> RINGING
	ringingPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       callID,
				ResponseCode: 180,
				FromTag:      fromTag,
				ToTag:        toTag,
			},
		},
	}
	cc.ProcessPacket(ringingPacket, "hunter-1")

	calls = cc.GetCorrelatedCalls()
	assert.Equal(t, CallStateRinging, calls[0].State, "Should remain RINGING")

	// 200 OK -> ESTABLISHED
	okPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       callID,
				ResponseCode: 200,
				FromTag:      fromTag,
				ToTag:        toTag,
			},
		},
	}
	cc.ProcessPacket(okPacket, "hunter-1")

	calls = cc.GetCorrelatedCalls()
	assert.Equal(t, CallStateEstablished, calls[0].State, "Should be ESTABLISHED after 200 OK")

	// BYE -> ENDED
	byePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:  callID,
				Method:  "BYE",
				FromTag: fromTag,
				ToTag:   toTag,
			},
		},
	}
	cc.ProcessPacket(byePacket, "hunter-1")

	calls = cc.GetCorrelatedCalls()
	assert.Equal(t, CallStateEnded, calls[0].State, "Should be ENDED after BYE")
}

// TestCleanupStaleCalls tests that stale calls are removed
func TestCleanupStaleCalls(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	// Create a call
	packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:  "call-1",
				Method:  "INVITE",
				FromTag: "tag1",
				ToTag:   "tag2",
			},
		},
	}
	cc.ProcessPacket(packet, "hunter-1")

	// Verify call exists
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)

	// Manually trigger cleanup with a short max age
	cc.cleanupStaleCalls(100 * time.Millisecond)

	// Call should still exist (just created)
	calls = cc.GetCorrelatedCalls()
	assert.Len(t, calls, 1, "Call should still exist")

	// Wait for it to become stale
	time.Sleep(200 * time.Millisecond)

	// Cleanup again
	cc.cleanupStaleCalls(100 * time.Millisecond)

	// Call should be removed
	calls = cc.GetCorrelatedCalls()
	assert.Len(t, calls, 0, "Stale call should be removed")
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	var wg sync.WaitGroup
	numGoroutines := 10
	packetsPerGoroutine := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				packet := &data.CapturedPacket{
					TimestampNs: time.Now().UnixNano(),
					Metadata: &data.PacketMetadata{
						Sip: &data.SIPMetadata{
							CallId:  "call-1",
							Method:  "INVITE",
							FromTag: "tag1",
							ToTag:   "tag2",
						},
					},
				}
				cc.ProcessPacket(packet, "hunter-1")
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				cc.GetCorrelatedCalls()
				cc.GetCallCount()
			}
		}()
	}

	wg.Wait()

	// Should have exactly 1 correlated call (all same tags)
	calls := cc.GetCorrelatedCalls()
	assert.Len(t, calls, 1, "Should have 1 correlated call after concurrent access")
}

// TestProcessPacketDisplay tests PacketDisplay support (TUI offline mode)
func TestProcessPacketDisplay(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			CallID:  "call-1@alice",
			Method:  "INVITE",
			FromTag: "alice-tag",
			ToTag:   "bob-tag",
			From:    "alice",
			To:      "bob",
			Status:  200,
		},
	}

	cc.ProcessPacketDisplay(pkt, "local")

	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)

	call := calls[0]
	assert.Len(t, call.CallLegs, 1)
	assert.Equal(t, "call-1@alice", call.CallLegs["call-1@alice"].CallID)
	assert.Equal(t, "local", call.CallLegs["call-1@alice"].HunterID)
	assert.Equal(t, uint32(200), call.CallLegs["call-1@alice"].ResponseCode)
}

// TestGetCorrelatedCall tests retrieving a specific call by ID
func TestGetCorrelatedCall(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:  "call-1",
				Method:  "INVITE",
				FromTag: "tag1",
				ToTag:   "tag2",
			},
		},
	}
	cc.ProcessPacket(packet, "hunter-1")

	// Get correlation ID
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)
	correlationID := calls[0].CorrelationID

	// Retrieve by ID
	call, found := cc.GetCorrelatedCall(correlationID)
	assert.True(t, found, "Call should be found")
	assert.NotNil(t, call)
	assert.Equal(t, correlationID, call.CorrelationID)

	// Try non-existent ID
	_, found = cc.GetCorrelatedCall("non-existent-id")
	assert.False(t, found, "Non-existent call should not be found")
}

// TestPacketCount tests that packet counts are tracked correctly
func TestPacketCount(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	callID := "call-1"
	fromTag := "tag1"
	toTag := "tag2"

	// Send 5 packets for the same call leg
	for i := 0; i < 5; i++ {
		packet := &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:  callID,
					Method:  "INVITE",
					FromTag: fromTag,
					ToTag:   toTag,
				},
			},
		}
		cc.ProcessPacket(packet, "hunter-1")
	}

	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)

	leg := calls[0].CallLegs[callID]
	require.NotNil(t, leg)
	assert.Equal(t, 5, leg.PacketCount, "Should have counted 5 packets")
}
