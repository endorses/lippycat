//go:build hunter || all

package forwarding

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
)

func TestHandleFlowControl_PauseAndResume(t *testing.T) {
	m := &Manager{}

	// Initially not paused
	assert.False(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())

	// PAUSE
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_PAUSE,
	})
	assert.True(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, m.GetFlowControlState())

	// RESUME
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_RESUME,
	})
	assert.False(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_RESUME, m.GetFlowControlState())
}

func TestHandleFlowControl_SlowAndContinue(t *testing.T) {
	m := &Manager{}

	// SLOW
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_SLOW,
	})
	assert.Equal(t, data.FlowControl_FLOW_SLOW, m.GetFlowControlState())
	assert.False(t, m.IsPaused()) // SLOW does not pause

	// CONTINUE
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_CONTINUE,
	})
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())
}

func TestHandleFlowControl_StateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  data.FlowControl
		initialPaused bool
		signal        data.FlowControl
		expectedState data.FlowControl
		expectedPause bool
	}{
		{
			name:          "CONTINUE to PAUSE",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectedState: data.FlowControl_FLOW_PAUSE,
			expectedPause: true,
		},
		{
			name:          "PAUSE to RESUME",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_RESUME,
			expectedState: data.FlowControl_FLOW_RESUME,
			expectedPause: false,
		},
		{
			name:          "CONTINUE to SLOW",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_SLOW,
			expectedState: data.FlowControl_FLOW_SLOW,
			expectedPause: false,
		},
		{
			name:          "SLOW to CONTINUE",
			initialState:  data.FlowControl_FLOW_SLOW,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
			expectedPause: false,
		},
		{
			name:          "PAUSE to CONTINUE (stays paused until RESUME)",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
			expectedPause: true, // paused flag only cleared by RESUME
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{}
			m.flowControlState.Store(int32(tt.initialState))
			m.paused.Store(tt.initialPaused)

			m.HandleFlowControl(&data.StreamControl{
				FlowControl: tt.signal,
			})

			assert.Equal(t, tt.expectedState, m.GetFlowControlState())
			assert.Equal(t, tt.expectedPause, m.IsPaused())
		})
	}
}

func TestHandleFlowControl_AckSequence(t *testing.T) {
	m := &Manager{}

	// Verify no panic with ack sequence
	m.HandleFlowControl(&data.StreamControl{
		AckSequence: 42,
		FlowControl: data.FlowControl_FLOW_CONTINUE,
	})
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())
}

func TestHandleFlowControl_ErrorMessage(t *testing.T) {
	m := &Manager{}

	// Verify no panic with error message
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_PAUSE,
		Error:       "processor overloaded",
	})
	assert.True(t, m.IsPaused())
}
