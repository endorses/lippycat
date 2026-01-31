package voip

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCallAggregator(t *testing.T) {
	ca := NewCallAggregator()

	assert.NotNil(t, ca, "NewCallAggregator should return non-nil")
	assert.Empty(t, ca.GetCalls(), "Initial call list should be empty")
}

func TestCallAggregator_ProcessSIPInvite(t *testing.T) {
	ca := NewCallAggregator()

	// Process INVITE
	packet := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "test-call-123",
				Method:       "INVITE",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 0,
			},
		},
	}

	ca.ProcessPacket(packet, "hunter-1")

	calls := ca.GetCalls()
	assert.Len(t, calls, 1, "Should have 1 call")
	assert.Equal(t, "test-call-123", calls[0].CallID)
	assert.Equal(t, "alicent@example.com", calls[0].From)
	assert.Equal(t, "robb@example.com", calls[0].To)
	assert.Equal(t, CallStateTrying, calls[0].State)
	assert.Contains(t, calls[0].Hunters, "hunter-1")
}

func TestCallAggregator_CallStateTransitions(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	tests := []struct {
		name          string
		method        string
		responseCode  uint32
		expectedState CallState
	}{
		{
			name:          "INVITE -> TRYING",
			method:        "INVITE",
			responseCode:  0,
			expectedState: CallStateTrying,
		},
		{
			name:          "180 Ringing -> RINGING",
			method:        "",
			responseCode:  180,
			expectedState: CallStateRinging,
		},
		{
			name:          "183 Session Progress -> PROGRESS",
			method:        "",
			responseCode:  183,
			expectedState: CallStateProgress,
		},
		{
			name:          "200 OK -> ACTIVE",
			method:        "",
			responseCode:  200,
			expectedState: CallStateActive,
		},
		{
			name:          "ACK -> ACTIVE",
			method:        "ACK",
			responseCode:  0,
			expectedState: CallStateActive,
		},
		{
			name:          "BYE -> ENDING",
			method:        "BYE",
			responseCode:  0,
			expectedState: CallStateEnding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:       callID,
						Method:       tt.method,
						FromUser:     "alicent@example.com",
						ToUser:       "robb@example.com",
						ResponseCode: tt.responseCode,
					},
				},
			}

			ca.ProcessPacket(packet, "hunter-1")

			call, exists := ca.GetCall(callID)
			assert.True(t, exists, "Call should exist")
			assert.Equal(t, tt.expectedState, call.State, "State should match")
		})
	}
}

func TestCallAggregator_FailedCallStates(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-failed"

	tests := []struct {
		name          string
		method        string
		responseCode  uint32
		description   string
		expectedState CallState
	}{
		{
			name:          "CANCEL",
			method:        "CANCEL",
			responseCode:  0,
			description:   "Call cancelled before answer",
			expectedState: CallStateCancelled,
		},
		{
			name:          "486 Busy",
			method:        "",
			responseCode:  486,
			description:   "Callee busy",
			expectedState: CallStateBusy,
		},
		{
			name:          "4xx Response",
			method:        "",
			responseCode:  404,
			description:   "Not found",
			expectedState: CallStateFailed,
		},
		{
			name:          "5xx Response",
			method:        "",
			responseCode:  503,
			description:   "Service unavailable",
			expectedState: CallStateFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset for each test
			ca = NewCallAggregator()

			// First send INVITE
			invitePacket := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   callID,
						Method:   "INVITE",
						FromUser: "alicent@example.com",
						ToUser:   "robb@example.com",
					},
				},
			}
			ca.ProcessPacket(invitePacket, "hunter-1")

			// Then send failure/cancel/busy
			failPacket := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:       callID,
						Method:       tt.method,
						ResponseCode: tt.responseCode,
					},
				},
			}
			ca.ProcessPacket(failPacket, "hunter-1")

			call, exists := ca.GetCall(callID)
			assert.True(t, exists, "Call should exist")
			assert.Equal(t, tt.expectedState, call.State, "State should be %s", tt.expectedState.String())
			assert.NotZero(t, call.EndTime, "End time should be set")
		})
	}
}

func TestCallAggregator_MultipleHunters(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	// Process packet from hunter-1
	packet1 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet1, "hunter-1")

	// Process packet from hunter-2
	packet2 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "ACK",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet2, "hunter-2")

	call, exists := ca.GetCall(callID)
	assert.True(t, exists, "Call should exist")
	assert.Len(t, call.Hunters, 2, "Should have 2 hunters")
	assert.Contains(t, call.Hunters, "hunter-1")
	assert.Contains(t, call.Hunters, "hunter-2")
}

func TestCallAggregator_PacketCounting(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	// Send 5 packets
	for i := 0; i < 5; i++ {
		packet := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   callID,
					Method:   "INVITE",
					FromUser: "alicent@example.com",
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")
	}

	call, exists := ca.GetCall(callID)
	assert.True(t, exists, "Call should exist")
	assert.Equal(t, 5, call.PacketCount, "Should have 5 packets")
}

func TestCallAggregator_GetCall_NotFound(t *testing.T) {
	ca := NewCallAggregator()

	call, exists := ca.GetCall("non-existent-call")
	assert.False(t, exists, "Call should not exist")
	assert.Nil(t, call, "Call should be nil")
}

func TestCallAggregator_MultipleCalls(t *testing.T) {
	ca := NewCallAggregator()

	// Create 3 different calls
	for i := 0; i < 3; i++ {
		callID := "call-" + string(rune('A'+i))
		packet := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   callID,
					Method:   "INVITE",
					FromUser: "user" + string(rune('A'+i)) + "@example.com",
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")
	}

	calls := ca.GetCalls()
	assert.Len(t, calls, 3, "Should have 3 calls")
}

func TestCallAggregator_RTPProcessing(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	// First create call with SIP
	sipPacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(sipPacket, "hunter-1")

	// Then send RTP packet
	rtpPacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Rtp: &data.RTPMetadata{
				Ssrc:      12345,
				Sequence:  1,
				Timestamp: 1000,
			},
		},
	}
	ca.ProcessPacket(rtpPacket, "hunter-1")

	// RTP processing doesn't update call state in current implementation
	// But shouldn't panic or cause errors
	assert.True(t, true, "RTP packet processing completed")
}

func TestCallAggregator_NilMetadata(t *testing.T) {
	ca := NewCallAggregator()

	// Packet with no metadata
	packet := &data.CapturedPacket{
		Metadata: nil,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		ca.ProcessPacket(packet, "hunter-1")
	}, "Should handle nil metadata gracefully")

	calls := ca.GetCalls()
	assert.Empty(t, calls, "Should have no calls")
}

func TestCallAggregator_EmptyCallID(t *testing.T) {
	ca := NewCallAggregator()

	packet := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "", // Empty call ID
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}

	ca.ProcessPacket(packet, "hunter-1")

	calls := ca.GetCalls()
	assert.Empty(t, calls, "Should not create call with empty ID")
}

func TestCallAggregator_CallDuration(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	// INVITE
	inviteTime := time.Now()
	invitePacket := &data.CapturedPacket{
		TimestampNs: inviteTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(invitePacket, "hunter-1")

	call1, _ := ca.GetCall(callID)
	startTime := call1.StartTime

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// BYE
	byeTime := time.Now()
	byePacket := &data.CapturedPacket{
		TimestampNs: byeTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	ca.ProcessPacket(byePacket, "hunter-1")

	call2, _ := ca.GetCall(callID)
	assert.Equal(t, CallStateEnding, call2.State, "BYE transitions to ENDING state for timewait")
	assert.NotZero(t, call2.EndTime, "End time should be set")
	assert.True(t, call2.EndTime.After(startTime), "End time should be after start time")
}

func TestCallStateString(t *testing.T) {
	tests := []struct {
		state    CallState
		expected string
	}{
		{CallStateNew, "NEW"},
		{CallStateTrying, "TRYING"},
		{CallStateRinging, "RINGING"},
		{CallStateProgress, "PROGRESS"},
		{CallStateActive, "ACTIVE"},
		{CallStateEnding, "ENDING"},
		{CallStateEnded, "ENDED"},
		{CallStateFailed, "FAILED"},
		{CallStateCancelled, "CANCELLED"},
		{CallStateBusy, "BUSY"},
		{CallStateRTPOnly, "RTP-ONLY"},
		{CallState(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestCallAggregator_UpdateExistingCall(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-123"

	// First INVITE
	packet1 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet1, "hunter-1")

	call1, _ := ca.GetCall(callID)
	assert.Equal(t, CallStateTrying, call1.State)
	assert.Equal(t, 1, call1.PacketCount)

	// 200 OK response
	packet2 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       callID,
				ResponseCode: 200,
			},
		},
	}
	ca.ProcessPacket(packet2, "hunter-1")

	call2, _ := ca.GetCall(callID)
	assert.Equal(t, CallStateActive, call2.State, "State should transition to ACTIVE")
	assert.Equal(t, 2, call2.PacketCount, "Packet count should increment")
	assert.Equal(t, "alicent@example.com", call2.From, "From should be preserved")
	assert.Equal(t, "robb@example.com", call2.To, "To should be preserved")
}

func TestCallAggregator_ConcurrentAccess(t *testing.T) {
	ca := NewCallAggregator()

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			packet := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   "call-" + string(rune('A'+i)),
						Method:   "INVITE",
						FromUser: "alicent@example.com",
						ToUser:   "robb@example.com",
					},
				},
			}
			ca.ProcessPacket(packet, "hunter-1")
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			ca.GetCalls()
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Should not panic or deadlock
	calls := ca.GetCalls()
	assert.LessOrEqual(t, 1, len(calls), "Should have at least 1 call")
}

func TestCallAggregator_ResponseCodesTransitions(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  uint32
		initialState  CallState
		expectedState CallState
	}{
		{
			name:          "180 Ringing",
			responseCode:  180,
			initialState:  CallStateTrying,
			expectedState: CallStateRinging,
		},
		{
			name:          "183 Session Progress",
			responseCode:  183,
			initialState:  CallStateTrying,
			expectedState: CallStateProgress,
		},
		{
			name:          "200 OK",
			responseCode:  200,
			initialState:  CallStateTrying,
			expectedState: CallStateActive,
		},
		{
			name:          "486 Busy",
			responseCode:  486,
			initialState:  CallStateTrying,
			expectedState: CallStateBusy,
		},
		{
			name:          "487 Request Terminated",
			responseCode:  487,
			initialState:  CallStateTrying,
			expectedState: CallStateCancelled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := NewCallAggregator()
			callID := "test-call-" + tt.name

			// Setup initial state
			invitePacket := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   callID,
						Method:   "INVITE",
						FromUser: "alicent@example.com",
						ToUser:   "robb@example.com",
					},
				},
			}
			ca.ProcessPacket(invitePacket, "hunter-1")

			// Send response
			responsePacket := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:       callID,
						ResponseCode: tt.responseCode,
					},
				},
			}
			ca.ProcessPacket(responsePacket, "hunter-1")

			call, exists := ca.GetCall(callID)
			assert.True(t, exists, "Call should exist")
			assert.Equal(t, tt.expectedState, call.State, "State should match expected")
		})
	}
}

// TestCallAggregator_DeepCopyRaceCondition tests that deep copies prevent race conditions
// when reading calls while they're being modified. This test exercises the deep copy
// functionality to ensure pointer and slice fields are properly isolated.
func TestCallAggregator_DeepCopyRaceCondition(t *testing.T) {
	ca := NewCallAggregator()
	callID := "test-call-race"

	// Create initial call with RTP stats and hunters
	sipPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(sipPacket, "hunter-1")

	// Add RTP packet to populate RTPStats
	rtpPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
			},
			Rtp: &data.RTPMetadata{
				Ssrc:        12345,
				Sequence:    100,
				Timestamp:   1000,
				PayloadType: 0, // G.711 µ-law
			},
		},
	}
	ca.ProcessPacket(rtpPacket, "hunter-1")

	// Concurrent writers and readers
	done := make(chan bool)
	writerCount := 5
	readerCount := 10
	iterations := 50

	// Start multiple writers
	for w := 0; w < writerCount; w++ {
		hunterID := "hunter-" + string(rune('A'+w))
		go func(hID string) {
			for i := 0; i < iterations; i++ {
				// Alternate between SIP and RTP packets
				if i%2 == 0 {
					packet := &data.CapturedPacket{
						TimestampNs: time.Now().UnixNano(),
						Metadata: &data.PacketMetadata{
							Sip: &data.SIPMetadata{
								CallId:   callID,
								Method:   "ACK",
								FromUser: "alicent@example.com",
								ToUser:   "robb@example.com",
							},
						},
					}
					ca.ProcessPacket(packet, hID)
				} else {
					packet := &data.CapturedPacket{
						TimestampNs: time.Now().UnixNano(),
						Metadata: &data.PacketMetadata{
							Sip: &data.SIPMetadata{
								CallId: callID,
							},
							Rtp: &data.RTPMetadata{
								Ssrc:        12345,
								Sequence:    uint32(100 + i),
								Timestamp:   uint32(1000 + i*160),
								PayloadType: 0,
							},
						},
					}
					ca.ProcessPacket(packet, hID)
				}
			}
			done <- true
		}(hunterID)
	}

	// Start multiple readers
	for r := 0; r < readerCount; r++ {
		go func() {
			for i := 0; i < iterations; i++ {
				// Read via different methods to test all code paths
				switch i % 4 {
				case 0:
					calls := ca.GetCalls()
					// Modify returned data to ensure it's truly a copy
					for idx := range calls {
						calls[idx].PacketCount = 999999
						if calls[idx].RTPStats != nil {
							calls[idx].RTPStats.PacketLoss = 100.0
						}
						if len(calls[idx].Hunters) > 0 {
							calls[idx].Hunters[0] = "modified-hunter"
						}
					}
				case 1:
					calls := ca.GetActiveCalls()
					// Modify returned data
					for idx := range calls {
						calls[idx].State = CallStateFailed
					}
				case 2:
					call, exists := ca.GetCall(callID)
					if exists {
						// Modify returned data
						call.From = "modified@example.com"
						if call.RTPStats != nil {
							call.RTPStats.Jitter = 999.0
						}
					}
				case 3:
					// Just count to exercise the lock
					_ = ca.GetCallCount()
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
	call, exists := ca.GetCall(callID)
	assert.True(t, exists, "Call should still exist")
	assert.NotEqual(t, "modified@example.com", call.From, "Internal state should not be modified by readers")
	assert.NotEqual(t, 999999, call.PacketCount, "PacketCount should not be 999999")

	if call.RTPStats != nil {
		assert.NotEqual(t, 100.0, call.RTPStats.PacketLoss, "RTPStats should not show 100% loss from reader modification")
		assert.NotEqual(t, 999.0, call.RTPStats.Jitter, "RTPStats jitter should not be modified by readers")
	}

	if len(call.Hunters) > 0 {
		assert.NotContains(t, call.Hunters, "modified-hunter", "Hunters list should not contain modified values")
		// Should contain actual hunter IDs
		assert.Contains(t, call.Hunters, "hunter-1", "Should contain original hunter")
	}

	// Verify state is reasonable
	assert.Contains(t, []CallState{CallStateTrying, CallStateRinging, CallStateProgress, CallStateActive}, call.State, "State should be valid")
}

// TestCallAggregator_LRUEvictionRace tests that concurrent reads during LRU
// eviction are safe. This specifically tests the scenario where:
// 1. Reader holds a reference to a call
// 2. Writer evicts that call from the LRU cache
// 3. Reader's copy remains valid and isolated from internal state changes
//
// This test exercises the fix for the eviction race condition documented in
// the code review (issue #8).
func TestCallAggregator_LRUEvictionRace(t *testing.T) {
	// Use small LRU capacity to trigger frequent evictions
	const lruCapacity = 10
	ca := NewCallAggregatorWithCapacity(lruCapacity)

	// Track successful reads of evicted calls
	var successfulReadsAfterEviction atomic.Int64
	var evictedCallsRead atomic.Int64

	// First, fill the LRU cache completely
	for i := 0; i < lruCapacity; i++ {
		callID := fmt.Sprintf("call-%03d", i)
		packet := &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   callID,
					Method:   "INVITE",
					FromUser: fmt.Sprintf("user%d@example.com", i),
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")

		// Add RTP to populate stats
		rtpPacket := &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{CallId: callID},
				Rtp: &data.RTPMetadata{
					Ssrc:        uint32(12345 + i),
					Sequence:    uint32(100 + i),
					Timestamp:   uint32(1000 + i*160),
					PayloadType: 0,
				},
			},
		}
		ca.ProcessPacket(rtpPacket, "hunter-1")
	}

	require.Equal(t, lruCapacity, ca.GetCallCount(), "LRU cache should be full")

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Reader goroutines: continuously read calls that may be evicted
	readerCount := 5
	for r := 0; r < readerCount; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// Try to read older calls that are likely to be evicted
					for i := 0; i < lruCapacity*2; i++ {
						callID := fmt.Sprintf("call-%03d", i)
						call, exists := ca.GetCall(callID)
						if exists {
							// Verify the copy is valid and isolated
							originalFrom := call.From

							// Mutate the copy to prove isolation
							call.From = "mutated@example.com"
							call.PacketCount = 999999
							if call.RTPStats != nil {
								call.RTPStats.PacketLoss = 100.0
							}

							// Re-read to verify internal state wasn't affected
							call2, exists2 := ca.GetCall(callID)
							if exists2 {
								if call2.From == originalFrom && call2.From != "mutated@example.com" {
									successfulReadsAfterEviction.Add(1)
								}
							} else {
								// Call was evicted between reads - this is expected
								evictedCallsRead.Add(1)
							}
						}
					}
				}
			}
		}(r)
	}

	// Writer goroutines: continuously add new calls, causing evictions
	writerCount := 3
	callCounter := atomic.Int64{}
	callCounter.Store(int64(lruCapacity)) // Start after initial calls

	for w := 0; w < writerCount; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			hunterID := fmt.Sprintf("hunter-%d", writerID)
			for {
				select {
				case <-done:
					return
				default:
					callNum := callCounter.Add(1)
					callID := fmt.Sprintf("call-%03d", callNum)

					packet := &data.CapturedPacket{
						TimestampNs: time.Now().UnixNano(),
						Metadata: &data.PacketMetadata{
							Sip: &data.SIPMetadata{
								CallId:   callID,
								Method:   "INVITE",
								FromUser: fmt.Sprintf("user%d@example.com", callNum),
								ToUser:   "robb@example.com",
							},
						},
					}
					ca.ProcessPacket(packet, hunterID)

					// Small delay to allow interleaving
					time.Sleep(100 * time.Microsecond)
				}
			}
		}(w)
	}

	// Let the test run for a while to trigger many evictions
	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()

	// Verify LRU cache maintained correct size
	finalCount := ca.GetCallCount()
	assert.LessOrEqual(t, finalCount, lruCapacity, "Should not exceed LRU capacity")

	// Verify we had meaningful concurrent activity
	t.Logf("Successful isolated reads: %d", successfulReadsAfterEviction.Load())
	t.Logf("Evicted calls encountered: %d", evictedCallsRead.Load())
	t.Logf("Final call count: %d", finalCount)

	// Sanity check: we should have had some concurrent activity
	assert.Greater(t, successfulReadsAfterEviction.Load()+evictedCallsRead.Load(), int64(0),
		"Test should have exercised concurrent read paths")

	// Verify all remaining calls have valid, uncorrupted data
	calls := ca.GetCalls()
	for _, call := range calls {
		assert.NotEqual(t, "mutated@example.com", call.From, "Internal state should not be corrupted")
		assert.NotEqual(t, 999999, call.PacketCount, "PacketCount should not be corrupted")
		if call.RTPStats != nil {
			assert.NotEqual(t, 100.0, call.RTPStats.PacketLoss, "RTPStats should not be corrupted")
		}
	}
}

// TestNewCallAggregatorWithCapacity tests the configurable capacity constructor
func TestNewCallAggregatorWithCapacity(t *testing.T) {
	tests := []struct {
		name         string
		capacity     int
		expectedMax  int
		callsToAdd   int
		expectedSize int
	}{
		{
			name:         "normal capacity",
			capacity:     5,
			expectedMax:  5,
			callsToAdd:   3,
			expectedSize: 3,
		},
		{
			name:         "zero capacity defaults to 1000",
			capacity:     0,
			expectedMax:  1000,
			callsToAdd:   3,
			expectedSize: 3,
		},
		{
			name:         "negative capacity defaults to 1000",
			capacity:     -1,
			expectedMax:  1000,
			callsToAdd:   3,
			expectedSize: 3,
		},
		{
			name:         "eviction when full",
			capacity:     3,
			expectedMax:  3,
			callsToAdd:   5,
			expectedSize: 3, // Evicted 2 oldest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := NewCallAggregatorWithCapacity(tt.capacity)
			assert.Equal(t, tt.expectedMax, ca.maxCalls, "maxCalls should match expected")

			// Add calls
			for i := 0; i < tt.callsToAdd; i++ {
				packet := &data.CapturedPacket{
					Metadata: &data.PacketMetadata{
						Sip: &data.SIPMetadata{
							CallId:   fmt.Sprintf("call-%d", i),
							Method:   "INVITE",
							FromUser: "alicent@example.com",
							ToUser:   "robb@example.com",
						},
					},
				}
				ca.ProcessPacket(packet, "hunter-1")
			}

			assert.Equal(t, tt.expectedSize, ca.GetCallCount(), "Call count should match expected")
		})
	}
}

// TestCallAggregator_EvictionOrder verifies LRU eviction behavior
func TestCallAggregator_EvictionOrder(t *testing.T) {
	ca := NewCallAggregatorWithCapacity(3)

	// Add calls 0, 1, 2
	for i := 0; i < 3; i++ {
		packet := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   fmt.Sprintf("call-%d", i),
					Method:   "INVITE",
					FromUser: "alicent@example.com",
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")
	}

	// Verify all 3 exist
	for i := 0; i < 3; i++ {
		_, exists := ca.GetCall(fmt.Sprintf("call-%d", i))
		assert.True(t, exists, "call-%d should exist", i)
	}

	// Touch call-0 to make it most recently used
	// (call-1 is now least recently used)
	packet0Update := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call-0",
				Method:   "ACK",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet0Update, "hunter-1")

	// Add call 3, should evict call-1 (LRU, not call-0 which was just touched)
	packet3 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call-3",
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet3, "hunter-1")

	// Verify eviction - call-1 should be evicted (LRU)
	_, exists0 := ca.GetCall("call-0")
	assert.True(t, exists0, "call-0 should still exist (was recently touched)")

	_, exists1 := ca.GetCall("call-1")
	assert.False(t, exists1, "call-1 should be evicted (LRU)")

	_, exists2 := ca.GetCall("call-2")
	assert.True(t, exists2, "call-2 should still exist")

	_, exists3 := ca.GetCall("call-3")
	assert.True(t, exists3, "call-3 should exist")

	// Touch call-2 to make it most recently used
	packet2Update := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call-2",
				Method:   "ACK",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet2Update, "hunter-1")

	// Add call 4, should evict call-0 (now LRU since call-2 was touched)
	packet4 := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   "call-4",
				Method:   "INVITE",
				FromUser: "alicent@example.com",
				ToUser:   "robb@example.com",
			},
		},
	}
	ca.ProcessPacket(packet4, "hunter-1")

	_, exists0After := ca.GetCall("call-0")
	assert.False(t, exists0After, "call-0 should be evicted (now LRU)")

	_, exists2After := ca.GetCall("call-2")
	assert.True(t, exists2After, "call-2 should still exist (was recently touched)")

	// Final state should be: call-2, call-3, call-4
	assert.Equal(t, 3, ca.GetCallCount())
}

// TestCallAggregator_LRUActiveCallSurvival verifies active calls survive when buffer is full
func TestCallAggregator_LRUActiveCallSurvival(t *testing.T) {
	ca := NewCallAggregatorWithCapacity(3)

	// Add 3 calls
	for i := 0; i < 3; i++ {
		packet := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   fmt.Sprintf("call-%d", i),
					Method:   "INVITE",
					FromUser: "alicent@example.com",
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")
	}

	// Keep call-0 active with RTP packets while adding new calls
	// This simulates an active call that keeps receiving packets
	for i := 3; i < 10; i++ {
		// Touch call-0 with RTP
		rtpPacket := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{CallId: "call-0"},
				Rtp: &data.RTPMetadata{
					Ssrc:        12345,
					Sequence:    uint32(100 + i),
					Timestamp:   uint32(1000 + i*160),
					PayloadType: 0,
				},
			},
		}
		ca.ProcessPacket(rtpPacket, "hunter-1")

		// Add new call
		newPacket := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   fmt.Sprintf("call-%d", i),
					Method:   "INVITE",
					FromUser: "alicent@example.com",
					ToUser:   "robb@example.com",
				},
			},
		}
		ca.ProcessPacket(newPacket, "hunter-1")
	}

	// call-0 should survive because it was kept active
	_, exists0 := ca.GetCall("call-0")
	assert.True(t, exists0, "call-0 should survive (kept active with RTP)")

	// Should have exactly 3 calls
	assert.Equal(t, 3, ca.GetCallCount())
}

func TestCallAggregator_NonCallMethodsIgnored(t *testing.T) {
	// Verify that non-call SIP methods (OPTIONS, REGISTER, etc.) don't create call entries
	ca := NewCallAggregator()

	nonCallMethods := []string{"OPTIONS", "REGISTER", "SUBSCRIBE", "NOTIFY", "PUBLISH", "MESSAGE", "INFO", "PRACK", "UPDATE", "REFER"}

	for _, method := range nonCallMethods {
		packet := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:       fmt.Sprintf("non-call-%s", method),
					Method:       method,
					FromUser:     "alicent@example.com",
					ToUser:       "robb@example.com",
					ResponseCode: 0,
				},
			},
		}
		ca.ProcessPacket(packet, "hunter-1")
	}

	// None of these should create call entries
	assert.Equal(t, 0, ca.GetCallCount(), "Non-call methods should not create call entries")

	// Now add an INVITE - this should create a call
	invitePacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "real-call-123",
				Method:       "INVITE",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 0,
			},
		},
	}
	ca.ProcessPacket(invitePacket, "hunter-1")

	assert.Equal(t, 1, ca.GetCallCount(), "INVITE should create a call entry")

	// Subsequent non-call methods with same Call-ID should update the existing call
	optionsPacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "real-call-123",
				Method:       "OPTIONS",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 0,
			},
		},
	}
	ca.ProcessPacket(optionsPacket, "hunter-1")

	// Should still only have 1 call (OPTIONS updated existing call)
	assert.Equal(t, 1, ca.GetCallCount(), "OPTIONS on existing call should not create new entry")
}

func TestCallAggregator_ResponseDoesNotCreateCall(t *testing.T) {
	// Verify that responses alone don't create calls (only INVITE does)
	ca := NewCallAggregator()

	// 180 Ringing response without prior INVITE should NOT create a call
	packet := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "missed-invite-call",
				Method:       "",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 180,
			},
		},
	}
	ca.ProcessPacket(packet, "hunter-1")

	assert.Equal(t, 0, ca.GetCallCount(), "180 Ringing without INVITE should not create call")

	// 200 OK response (e.g., to OPTIONS) should NOT create calls
	okPacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "options-response-call",
				Method:       "",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 200,
			},
		},
	}
	ca.ProcessPacket(okPacket, "hunter-1")

	assert.Equal(t, 0, ca.GetCallCount(), "200 OK without INVITE should not create call")

	// But responses SHOULD update existing calls
	// First create a call with INVITE
	invitePacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "real-call",
				Method:       "INVITE",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 0,
			},
		},
	}
	ca.ProcessPacket(invitePacket, "hunter-1")
	assert.Equal(t, 1, ca.GetCallCount(), "INVITE should create call")

	call, _ := ca.GetCall("real-call")
	assert.Equal(t, CallStateTrying, call.State)

	// Now 200 OK should update it to ACTIVE
	okResponsePacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       "real-call",
				Method:       "",
				FromUser:     "alicent@example.com",
				ToUser:       "robb@example.com",
				ResponseCode: 200,
			},
		},
	}
	ca.ProcessPacket(okResponsePacket, "hunter-1")

	call, _ = ca.GetCall("real-call")
	assert.Equal(t, CallStateActive, call.State, "200 OK should update existing call to ACTIVE")
}
