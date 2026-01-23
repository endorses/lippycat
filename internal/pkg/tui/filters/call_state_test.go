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
}
