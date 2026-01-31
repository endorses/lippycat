//go:build tui || all

package filters

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/assert"
)

func TestCallStateFilter_SingleState(t *testing.T) {
	filter := NewCallStateFilter("active")

	// Should match active calls
	activeCall := components.Call{
		CallID: "test-call-1",
		State:  components.CallStateActive,
	}
	assert.True(t, filter.Match(activeCall), "Should match active call")

	// Should NOT match ringing calls
	ringingCall := components.Call{
		CallID: "test-call-2",
		State:  components.CallStateRinging,
	}
	assert.False(t, filter.Match(ringingCall), "Should NOT match ringing call")

	// Should NOT match ended calls
	endedCall := components.Call{
		CallID: "test-call-3",
		State:  components.CallStateEnded,
	}
	assert.False(t, filter.Match(endedCall), "Should NOT match ended call")
}

func TestCallStateFilter_MultipleStates(t *testing.T) {
	filter := NewCallStateFilter("ringing,ended")

	// Should match ringing calls
	ringingCall := components.Call{
		CallID: "test-call-1",
		State:  components.CallStateRinging,
	}
	assert.True(t, filter.Match(ringingCall), "Should match ringing call")

	// Should match ended calls
	endedCall := components.Call{
		CallID: "test-call-2",
		State:  components.CallStateEnded,
	}
	assert.True(t, filter.Match(endedCall), "Should match ended call")

	// Should NOT match active calls
	activeCall := components.Call{
		CallID: "test-call-3",
		State:  components.CallStateActive,
	}
	assert.False(t, filter.Match(activeCall), "Should NOT match active call")
}

func TestCallStateFilter_CaseInsensitive(t *testing.T) {
	filter := NewCallStateFilter("ACTIVE")

	activeCall := components.Call{
		CallID: "test-call-1",
		State:  components.CallStateActive,
	}
	assert.True(t, filter.Match(activeCall), "Should match with case-insensitive comparison")
}

func TestCallStateFilter_NonCallRecord(t *testing.T) {
	filter := NewCallStateFilter("active")

	// Should NOT match packets (non-call records)
	packet := components.PacketDisplay{
		Protocol: "SIP",
		SrcIP:    "192.168.1.1",
	}
	assert.False(t, filter.Match(packet), "Should NOT match packet records")
}

func TestCallStateFilter_String(t *testing.T) {
	filter1 := NewCallStateFilter("active")
	assert.Equal(t, "state:active", filter1.String())

	filter2 := NewCallStateFilter("ringing,ended")
	assert.Equal(t, "state:ringing,ended", filter2.String())
}

func TestCallStateFilter_SupportedRecordTypes(t *testing.T) {
	filter := NewCallStateFilter("active")
	types := filter.SupportedRecordTypes()

	assert.Equal(t, []string{"call"}, types)
}

func TestCallStateFilter_Selectivity(t *testing.T) {
	// Single state should be more selective
	single := NewCallStateFilter("active")
	assert.Equal(t, 0.7, single.Selectivity())

	// Two states should be less selective
	two := NewCallStateFilter("active,ringing")
	assert.Equal(t, 0.5, two.Selectivity())

	// Three+ states should be least selective
	three := NewCallStateFilter("active,ringing,ended")
	assert.Equal(t, 0.3, three.Selectivity())

	// Single wildcard is less selective than exact match
	wildcard := NewCallStateFilter("E:*")
	assert.Equal(t, 0.5, wildcard.Selectivity())
}

func TestCallStateFilter_ErrorCode(t *testing.T) {
	// Filter for specific error code
	filter := NewCallStateFilter("E:404")

	// Should match E:404
	failedCall404 := components.Call{
		CallID:           "test-call-1",
		State:            components.CallStateFailed,
		LastResponseCode: 404,
	}
	assert.True(t, filter.Match(failedCall404), "Should match E:404 call")

	// Should NOT match E:503
	failedCall503 := components.Call{
		CallID:           "test-call-2",
		State:            components.CallStateFailed,
		LastResponseCode: 503,
	}
	assert.False(t, filter.Match(failedCall503), "Should NOT match E:503 call")

	// Should NOT match active calls
	activeCall := components.Call{
		CallID: "test-call-3",
		State:  components.CallStateActive,
	}
	assert.False(t, filter.Match(activeCall), "Should NOT match active call")
}

func TestCallStateFilter_WildcardAnyError(t *testing.T) {
	// Filter for any error state with E:*
	filter := NewCallStateFilter("E:*")

	// Should match E:404
	failedCall404 := components.Call{
		CallID:           "test-call-1",
		State:            components.CallStateFailed,
		LastResponseCode: 404,
	}
	assert.True(t, filter.Match(failedCall404), "Should match E:404 call")

	// Should match E:503
	failedCall503 := components.Call{
		CallID:           "test-call-2",
		State:            components.CallStateFailed,
		LastResponseCode: 503,
	}
	assert.True(t, filter.Match(failedCall503), "Should match E:503 call")

	// Should match E:401
	failedCall401 := components.Call{
		CallID:           "test-call-3",
		State:            components.CallStateFailed,
		LastResponseCode: 401,
	}
	assert.True(t, filter.Match(failedCall401), "Should match E:401 call")

	// Should NOT match active calls
	activeCall := components.Call{
		CallID: "test-call-4",
		State:  components.CallStateActive,
	}
	assert.False(t, filter.Match(activeCall), "Should NOT match active call")
}

func TestCallStateFilter_Wildcard4xxErrors(t *testing.T) {
	// Filter for 4xx errors only with E:4*
	filter := NewCallStateFilter("E:4*")

	// Should match E:404
	failedCall404 := components.Call{
		CallID:           "test-call-1",
		State:            components.CallStateFailed,
		LastResponseCode: 404,
	}
	assert.True(t, filter.Match(failedCall404), "Should match E:404 call")

	// Should match E:401
	failedCall401 := components.Call{
		CallID:           "test-call-2",
		State:            components.CallStateFailed,
		LastResponseCode: 401,
	}
	assert.True(t, filter.Match(failedCall401), "Should match E:401 call")

	// Should NOT match E:503 (5xx error)
	failedCall503 := components.Call{
		CallID:           "test-call-3",
		State:            components.CallStateFailed,
		LastResponseCode: 503,
	}
	assert.False(t, filter.Match(failedCall503), "Should NOT match E:503 call")
}

func TestCallStateFilter_FailedAlias(t *testing.T) {
	// "failed" should be an alias for "E:*"
	filter := NewCallStateFilter("failed")

	// Should match E:404
	failedCall404 := components.Call{
		CallID:           "test-call-1",
		State:            components.CallStateFailed,
		LastResponseCode: 404,
	}
	assert.True(t, filter.Match(failedCall404), "Should match E:404 call with 'failed' filter")

	// Should match E:503
	failedCall503 := components.Call{
		CallID:           "test-call-2",
		State:            components.CallStateFailed,
		LastResponseCode: 503,
	}
	assert.True(t, filter.Match(failedCall503), "Should match E:503 call with 'failed' filter")

	// Should NOT match active calls
	activeCall := components.Call{
		CallID: "test-call-3",
		State:  components.CallStateActive,
	}
	assert.False(t, filter.Match(activeCall), "Should NOT match active call with 'failed' filter")

	// String representation should show the expanded pattern
	assert.Equal(t, "state:e:*", filter.String())
}

func TestCallStateFilter_CombinedStatesAndErrors(t *testing.T) {
	// Filter for active OR any error
	filter := NewCallStateFilter("active,E:*")

	// Should match active calls
	activeCall := components.Call{
		CallID: "test-call-1",
		State:  components.CallStateActive,
	}
	assert.True(t, filter.Match(activeCall), "Should match active call")

	// Should match E:404
	failedCall := components.Call{
		CallID:           "test-call-2",
		State:            components.CallStateFailed,
		LastResponseCode: 404,
	}
	assert.True(t, filter.Match(failedCall), "Should match E:404 call")

	// Should NOT match ringing calls
	ringingCall := components.Call{
		CallID: "test-call-3",
		State:  components.CallStateRinging,
	}
	assert.False(t, filter.Match(ringingCall), "Should NOT match ringing call")
}
