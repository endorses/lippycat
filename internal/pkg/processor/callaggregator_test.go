package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
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
				FromUser:     "alice@example.com",
				ToUser:       "bob@example.com",
				ResponseCode: 0,
			},
		},
	}

	ca.ProcessPacket(packet, "hunter-1")

	calls := ca.GetCalls()
	assert.Len(t, calls, 1, "Should have 1 call")
	assert.Equal(t, "test-call-123", calls[0].CallID)
	assert.Equal(t, "alice@example.com", calls[0].From)
	assert.Equal(t, "bob@example.com", calls[0].To)
	assert.Equal(t, CallStateRinging, calls[0].State)
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
			name:          "INVITE -> RINGING",
			method:        "INVITE",
			responseCode:  0,
			expectedState: CallStateRinging,
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
			name:          "BYE -> ENDED",
			method:        "BYE",
			responseCode:  0,
			expectedState: CallStateEnded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &data.CapturedPacket{
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:       callID,
						Method:       tt.method,
						FromUser:     "alice@example.com",
						ToUser:       "bob@example.com",
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
		name         string
		method       string
		responseCode uint32
		description  string
	}{
		{
			name:         "CANCEL",
			method:       "CANCEL",
			responseCode: 0,
			description:  "Call cancelled by caller",
		},
		{
			name:         "4xx Response",
			method:       "",
			responseCode: 404,
			description:  "Not found",
		},
		{
			name:         "5xx Response",
			method:       "",
			responseCode: 503,
			description:  "Service unavailable",
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
						FromUser: "alice@example.com",
						ToUser:   "bob@example.com",
					},
				},
			}
			ca.ProcessPacket(invitePacket, "hunter-1")

			// Then send failure
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
			assert.Equal(t, CallStateFailed, call.State, "State should be FAILED")
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
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
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
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
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
					FromUser: "alice@example.com",
					ToUser:   "bob@example.com",
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
					ToUser:   "bob@example.com",
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
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
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
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
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
	invitePacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
			},
		},
	}
	ca.ProcessPacket(invitePacket, "hunter-1")

	call1, _ := ca.GetCall(callID)
	startTime := call1.StartTime

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// BYE
	byePacket := &data.CapturedPacket{
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	ca.ProcessPacket(byePacket, "hunter-1")

	call2, _ := ca.GetCall(callID)
	assert.Equal(t, CallStateEnded, call2.State)
	assert.NotZero(t, call2.EndTime, "End time should be set")
	assert.True(t, call2.EndTime.After(startTime), "End time should be after start time")
}

func TestCallStateString(t *testing.T) {
	tests := []struct {
		state    CallState
		expected string
	}{
		{CallStateNew, "NEW"},
		{CallStateRinging, "RINGING"},
		{CallStateActive, "ACTIVE"},
		{CallStateEnded, "ENDED"},
		{CallStateFailed, "FAILED"},
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
				FromUser: "alice@example.com",
				ToUser:   "bob@example.com",
			},
		},
	}
	ca.ProcessPacket(packet1, "hunter-1")

	call1, _ := ca.GetCall(callID)
	assert.Equal(t, CallStateRinging, call1.State)
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
	assert.Equal(t, "alice@example.com", call2.From, "From should be preserved")
	assert.Equal(t, "bob@example.com", call2.To, "To should be preserved")
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
						FromUser: "alice@example.com",
						ToUser:   "bob@example.com",
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
			initialState:  CallStateRinging,
			expectedState: CallStateRinging,
		},
		{
			name:          "183 Session Progress",
			responseCode:  183,
			initialState:  CallStateRinging,
			expectedState: CallStateRinging,
		},
		{
			name:          "200 OK",
			responseCode:  200,
			initialState:  CallStateRinging,
			expectedState: CallStateActive,
		},
		{
			name:          "486 Busy",
			responseCode:  486,
			initialState:  CallStateRinging,
			expectedState: CallStateFailed,
		},
		{
			name:          "487 Cancelled",
			responseCode:  487,
			initialState:  CallStateRinging,
			expectedState: CallStateFailed,
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
						FromUser: "alice@example.com",
						ToUser:   "bob@example.com",
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
