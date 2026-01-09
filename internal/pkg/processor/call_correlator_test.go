//go:build processor || tap || all

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

// TestCallCorrelator_DeepCopyRaceCondition tests that deep copies prevent race conditions
// when reading correlated calls while they're being modified. This test exercises the
// copyCall() deep copy functionality to ensure CallLegs map is properly isolated.
func TestCallCorrelator_DeepCopyRaceCondition(t *testing.T) {
	cc := NewCallCorrelator()
	defer cc.Stop()

	// Create initial correlated call with multiple legs
	fromTag := "alice-tag"
	toTag := "bob-tag"

	// First leg
	packet1 := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.100",
			DstIp: "192.168.1.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-leg-1",
				Method:   "INVITE",
				FromTag:  fromTag,
				ToTag:    toTag,
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
			},
		},
	}
	cc.ProcessPacket(packet1, "hunter-1")

	// Second leg (B2BUA forwarding)
	packet2 := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.2.100",
			DstIp: "192.168.2.200",
			Sip: &data.SIPMetadata{
				CallId:   "call-leg-2",
				Method:   "INVITE",
				FromTag:  fromTag,
				ToTag:    toTag,
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
			},
		},
	}
	cc.ProcessPacket(packet2, "hunter-2")

	// Concurrent writers and readers
	done := make(chan bool)
	writerCount := 5
	readerCount := 10
	iterations := 50

	// Start multiple writers - create more legs and update existing ones
	for w := 0; w < writerCount; w++ {
		legID := w + 3
		hunterID := "hunter-" + string(rune('A'+w))
		go func(lid int, hID string) {
			for i := 0; i < iterations; i++ {
				packet := &data.CapturedPacket{
					TimestampNs: time.Now().UnixNano(),
					Metadata: &data.PacketMetadata{
						SrcIp: "192.168.1.100",
						DstIp: "192.168.1.200",
						Sip: &data.SIPMetadata{
							CallId:       "call-leg-" + string(rune('0'+lid)),
							Method:       "ACK",
							FromTag:      fromTag,
							ToTag:        toTag,
							FromUser:     "alice@example.com",
							ToUser:       "bob@example.com",
							ResponseCode: uint32(200),
						},
					},
				}
				cc.ProcessPacket(packet, hID)
			}
			done <- true
		}(legID, hunterID)
	}

	// Start multiple readers
	for r := 0; r < readerCount; r++ {
		go func() {
			for i := 0; i < iterations; i++ {
				// Read via different methods to test all code paths
				switch i % 3 {
				case 0:
					calls := cc.GetCorrelatedCalls()
					// Modify returned data to ensure it's truly a copy
					for _, call := range calls {
						call.FromUser = "modified@example.com"
						call.State = CallStateEnded
						// Modify CallLegs map - this is the critical test
						for legID, leg := range call.CallLegs {
							leg.Method = "MODIFIED"
							leg.PacketCount = 999999
							leg.HunterID = "modified-hunter"
							// Try to corrupt the map
							call.CallLegs[legID] = &CallLeg{
								CallID:   "corrupted",
								HunterID: "corrupted",
								Method:   "CORRUPTED",
							}
						}
					}
				case 1:
					correlationID := generateCorrelationID(fromTag, toTag)
					call, exists := cc.GetCorrelatedCall(correlationID)
					if exists {
						// Modify returned data
						call.ToUser = "modified-to@example.com"
						for _, leg := range call.CallLegs {
							leg.ResponseCode = 999
						}
					}
				case 2:
					// Just count to exercise the lock
					_ = cc.GetCallCount()
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < writerCount+readerCount; i++ {
		<-done
	}

	// Verify data integrity - internal state should not be corrupted by reader modifications
	correlationID := generateCorrelationID(fromTag, toTag)
	call, exists := cc.GetCorrelatedCall(correlationID)
	require.True(t, exists, "Correlated call should still exist")

	// Check that reader modifications didn't corrupt internal state
	assert.NotEqual(t, "modified@example.com", call.FromUser, "FromUser should not be modified by readers")
	assert.NotEqual(t, "modified-to@example.com", call.ToUser, "ToUser should not be modified by readers")
	assert.NotEqual(t, CallStateEnded, call.State, "State should not be CallStateEnded from reader modification")

	// Verify original legs are intact
	require.Contains(t, call.CallLegs, "call-leg-1", "Original leg 1 should exist")
	require.Contains(t, call.CallLegs, "call-leg-2", "Original leg 2 should exist")

	leg1 := call.CallLegs["call-leg-1"]
	assert.NotEqual(t, "MODIFIED", leg1.Method, "Leg method should not be modified by readers")
	assert.NotEqual(t, "CORRUPTED", leg1.Method, "Leg method should not be corrupted")
	assert.NotEqual(t, "modified-hunter", leg1.HunterID, "Hunter ID should not be modified")
	assert.NotEqual(t, 999999, leg1.PacketCount, "PacketCount should not be 999999")
	assert.NotEqual(t, uint32(999), leg1.ResponseCode, "ResponseCode should not be 999")

	// Should have multiple legs from the concurrent writers
	assert.GreaterOrEqual(t, len(call.CallLegs), 2, "Should have at least the original 2 legs")

	// Verify state is reasonable
	assert.Contains(t, []CallState{CallStateTrying, CallStateRinging, CallStateEstablished}, call.State, "State should be valid")
}

// TestExtractPhoneSuffix tests phone number suffix extraction
func TestExtractPhoneSuffix(t *testing.T) {
	tests := []struct {
		name      string
		phone     string
		minDigits int
		expected  string
	}{
		{
			name:      "Simple phone number",
			phone:     "12345678901",
			minDigits: 7,
			expected:  "5678901",
		},
		{
			name:      "Phone with country code and prefix",
			phone:     "+1-555-123-4567",
			minDigits: 7,
			expected:  "1234567",
		},
		{
			name:      "Phone with tech prefix (2482)",
			phone:     "2482+1234567890",
			minDigits: 7,
			expected:  "4567890",
		},
		{
			name:      "SIP URI with domain",
			phone:     "alice@example.com",
			minDigits: 7,
			expected:  "", // Not enough digits
		},
		{
			name:      "Phone number with letters",
			phone:     "+1-800-CALL-NOW",
			minDigits: 7,
			expected:  "", // Only 4 digits (1, 8, 0, 0)
		},
		{
			name:      "Short number",
			phone:     "12345",
			minDigits: 7,
			expected:  "", // Less than minDigits
		},
		{
			name:      "Exact length",
			phone:     "1234567",
			minDigits: 7,
			expected:  "1234567",
		},
		{
			name:      "International format",
			phone:     "+49 170 1234567",
			minDigits: 7,
			expected:  "1234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPhoneSuffix(tt.phone, tt.minDigits)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGeneratePhoneCorrelationID tests phone-based correlation ID generation
func TestGeneratePhoneCorrelationID(t *testing.T) {
	// Same suffixes, different order should produce same ID
	id1 := generatePhoneCorrelationID("+1-555-123-4567", "+1-555-765-4321", 7)
	id2 := generatePhoneCorrelationID("+1-555-765-4321", "+1-555-123-4567", 7)
	assert.Equal(t, id1, id2, "Same phone suffixes in different order should produce same ID")
	assert.NotEmpty(t, id1)

	// Different suffixes should produce different IDs
	id3 := generatePhoneCorrelationID("+1-555-123-4567", "+1-555-111-2222", 7)
	assert.NotEqual(t, id1, id3, "Different phone suffixes should produce different IDs")

	// With tech prefix vs without - same suffix should match
	idNoPrefix := generatePhoneCorrelationID("+1234567890", "+0987654321", 7)
	idWithPrefix := generatePhoneCorrelationID("2482+1234567890", "+0987654321", 7)
	assert.Equal(t, idNoPrefix, idWithPrefix, "Tech prefix should not affect suffix matching")
}

// TestPhoneSuffixCorrelation_B2BUA tests B2BUA scenario with different tags but same phone suffixes
func TestPhoneSuffixCorrelation_B2BUA(t *testing.T) {
	config := PhoneCorrelationConfig{
		Enabled:         true,
		MinSuffixDigits: 7,
		TimeWindow:      30 * time.Second,
	}
	cc := NewCallCorrelatorWithConfig(config)
	defer cc.Stop()

	baseTime := time.Now()

	// Leg 1: Alice -> B2BUA (original Call-ID and tags)
	leg1 := &data.CapturedPacket{
		TimestampNs: baseTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.100",
			DstIp: "192.168.1.200",
			Sip: &data.SIPMetadata{
				CallId:   "leg1@alice",
				Method:   "INVITE",
				FromTag:  "alice-tag-original",
				ToTag:    "b2bua-tag-inbound",
				FromUser: "+1234567890", // Alice's number
				ToUser:   "+0987654321", // Bob's number
			},
		},
	}
	cc.ProcessPacket(leg1, "hunter-1")

	// Leg 2: B2BUA -> Bob (NEW Call-ID and NEW tags - B2BUA regenerates)
	leg2 := &data.CapturedPacket{
		TimestampNs: baseTime.Add(100 * time.Millisecond).UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.168.1.200",
			DstIp: "192.168.2.100",
			Sip: &data.SIPMetadata{
				CallId:   "leg2@b2bua", // Different Call-ID!
				Method:   "INVITE",
				FromTag:  "b2bua-tag-out",    // Different From tag!
				ToTag:    "bob-tag-received", // Different To tag!
				FromUser: "+1234567890",      // Same from number (suffix matches)
				ToUser:   "+0987654321",      // Same to number
			},
		},
	}
	cc.ProcessPacket(leg2, "hunter-2")

	// Should have 1 correlated call with 2 legs (correlated by phone suffix)
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1, "Should have 1 correlated call via phone suffix matching")

	call := calls[0]
	assert.Len(t, call.CallLegs, 2, "Should have 2 call legs")
	assert.NotEmpty(t, call.PhonePairKey, "Should have phone pair key set")

	// Both legs should be present
	assert.NotNil(t, call.CallLegs["leg1@alice"], "Should have leg 1")
	assert.NotNil(t, call.CallLegs["leg2@b2bua"], "Should have leg 2")
}

// TestPhoneSuffixCorrelation_TechPrefix tests B2BUA with tech prefix (anonymous calling)
func TestPhoneSuffixCorrelation_TechPrefix(t *testing.T) {
	config := PhoneCorrelationConfig{
		Enabled:         true,
		MinSuffixDigits: 7,
		TimeWindow:      30 * time.Second,
	}
	cc := NewCallCorrelatorWithConfig(config)
	defer cc.Stop()

	baseTime := time.Now()

	// Leg 1: Original call (non-anonymous)
	leg1 := &data.CapturedPacket{
		TimestampNs: baseTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call1@pbx",
				Method:   "INVITE",
				FromTag:  "tag1a",
				ToTag:    "tag1b",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(leg1, "hunter-1")

	// Leg 2: Same call with tech prefix added (anonymous)
	// e.g., "2482" is a proprietary prefix that makes caller anonymous
	leg2 := &data.CapturedPacket{
		TimestampNs: baseTime.Add(50 * time.Millisecond).UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call2@carrier",
				Method:   "INVITE",
				FromTag:  "tag2a",           // Different tag
				ToTag:    "tag2b",           // Different tag
				FromUser: "2482+1234567890", // Same number with tech prefix
				ToUser:   "+0987654321",     // Same destination
			},
		},
	}
	cc.ProcessPacket(leg2, "hunter-2")

	// Should correlate both legs via phone suffix
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1, "Should correlate via phone suffix despite tech prefix")

	call := calls[0]
	assert.Len(t, call.CallLegs, 2, "Should have 2 call legs")
}

// TestPhoneSuffixCorrelation_TimeWindow tests that time window is respected
func TestPhoneSuffixCorrelation_TimeWindow(t *testing.T) {
	config := PhoneCorrelationConfig{
		Enabled:         true,
		MinSuffixDigits: 7,
		TimeWindow:      1 * time.Second, // Very short window
	}
	cc := NewCallCorrelatorWithConfig(config)
	defer cc.Stop()

	baseTime := time.Now()

	// Leg 1
	leg1 := &data.CapturedPacket{
		TimestampNs: baseTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call1",
				Method:   "INVITE",
				FromTag:  "tag1a",
				ToTag:    "tag1b",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(leg1, "hunter-1")

	// Leg 2: Same phones, but outside time window (2 seconds later)
	leg2 := &data.CapturedPacket{
		TimestampNs: baseTime.Add(2 * time.Second).UnixNano(), // Outside 1s window
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call2",
				Method:   "INVITE",
				FromTag:  "tag2a",
				ToTag:    "tag2b",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(leg2, "hunter-2")

	// Should have 2 separate calls (outside time window)
	calls := cc.GetCorrelatedCalls()
	assert.Len(t, calls, 2, "Should NOT correlate legs outside time window")
}

// TestPhoneSuffixCorrelation_Disabled tests that phone correlation can be disabled
func TestPhoneSuffixCorrelation_Disabled(t *testing.T) {
	config := PhoneCorrelationConfig{
		Enabled:         false, // Disabled
		MinSuffixDigits: 7,
		TimeWindow:      30 * time.Second,
	}
	cc := NewCallCorrelatorWithConfig(config)
	defer cc.Stop()

	baseTime := time.Now()

	// Leg 1
	leg1 := &data.CapturedPacket{
		TimestampNs: baseTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call1",
				Method:   "INVITE",
				FromTag:  "tag1a",
				ToTag:    "tag1b",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(leg1, "hunter-1")

	// Leg 2: Different tags (B2BUA style)
	leg2 := &data.CapturedPacket{
		TimestampNs: baseTime.Add(100 * time.Millisecond).UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call2",
				Method:   "INVITE",
				FromTag:  "tag2a",
				ToTag:    "tag2b",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(leg2, "hunter-2")

	// Should have 2 separate calls (phone correlation disabled)
	calls := cc.GetCorrelatedCalls()
	assert.Len(t, calls, 2, "Should NOT correlate when phone correlation is disabled")
}

// TestPhoneSuffixCorrelation_CleanupIncludesPhonePair tests that cleanup removes phone pair index
func TestPhoneSuffixCorrelation_CleanupIncludesPhonePair(t *testing.T) {
	config := PhoneCorrelationConfig{
		Enabled:         true,
		MinSuffixDigits: 7,
		TimeWindow:      30 * time.Second,
	}
	cc := NewCallCorrelatorWithConfig(config)
	defer cc.Stop()

	// Create a call with phone numbers
	packet := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call-1",
				Method:   "INVITE",
				FromTag:  "tag1",
				ToTag:    "tag2",
				FromUser: "+1234567890",
				ToUser:   "+0987654321",
			},
		},
	}
	cc.ProcessPacket(packet, "hunter-1")

	// Verify call exists and has phone pair key
	calls := cc.GetCorrelatedCalls()
	require.Len(t, calls, 1)
	require.NotEmpty(t, calls[0].PhonePairKey)

	// Verify phone pair is indexed
	cc.mu.RLock()
	phonePairCount := len(cc.callsByPhonePair)
	cc.mu.RUnlock()
	assert.Equal(t, 1, phonePairCount, "Should have 1 phone pair indexed")

	// Wait for it to become stale and cleanup
	time.Sleep(200 * time.Millisecond)
	cc.cleanupStaleCalls(100 * time.Millisecond)

	// Phone pair should be cleaned up
	cc.mu.RLock()
	phonePairCountAfter := len(cc.callsByPhonePair)
	cc.mu.RUnlock()
	assert.Equal(t, 0, phonePairCountAfter, "Phone pair should be cleaned up")
}
