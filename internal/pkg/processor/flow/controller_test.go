package flow

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
)

func TestController_Determine_NoPCAPQueue(t *testing.T) {
	c := NewController(false)
	// No PCAP queue configured

	// Without PCAP queue, should always return CONTINUE
	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should return CONTINUE when no PCAP queue configured")
}

func TestController_Determine_QueueEmpty(t *testing.T) {
	queueSize := 100
	currentDepth := 0

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should return RESUME when queue is empty (0%% < 30%% threshold)")
}

func TestController_Determine_QueueSlightlyFull(t *testing.T) {
	queueSize := 100
	currentDepth := 40 // 40% full

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should return CONTINUE when queue 30-70%% full")
}

func TestController_Determine_QueueMediumFull(t *testing.T) {
	queueSize := 100
	currentDepth := 75 // 75% full

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_SLOW, flowControl,
		"should return SLOW when queue 70-90%% full")
}

func TestController_Determine_QueueAlmostFull(t *testing.T) {
	queueSize := 100
	currentDepth := 95 // 95% full

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return PAUSE when queue > 90%% full")
}

func TestController_Determine_QueueFull(t *testing.T) {
	queueSize := 100
	currentDepth := 100 // 100% full

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return PAUSE when queue is full")
}

func TestController_Determine_QueueDraining(t *testing.T) {
	queueSize := 100
	currentDepth := 25 // 25% full

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should return RESUME when queue < 30%% full")
}

func TestController_Determine_QueueThresholds(t *testing.T) {
	testCases := []struct {
		name            string
		queueSize       int
		fillPercentage  int
		expectedControl data.FlowControl
		description     string
	}{
		{
			name:            "Empty queue",
			queueSize:       100,
			fillPercentage:  0,
			expectedControl: data.FlowControl_FLOW_RESUME,
			description:     "0% < 30% resume threshold",
		},
		{
			name:            "Low utilization",
			queueSize:       100,
			fillPercentage:  25,
			expectedControl: data.FlowControl_FLOW_RESUME,
			description:     "25% < 30% resume threshold",
		},
		{
			name:            "Medium-low utilization",
			queueSize:       100,
			fillPercentage:  40,
			expectedControl: data.FlowControl_FLOW_CONTINUE,
			description:     "40% > 30% resume, < 70% slow",
		},
		{
			name:            "Medium-high utilization",
			queueSize:       100,
			fillPercentage:  75,
			expectedControl: data.FlowControl_FLOW_SLOW,
			description:     "75% > 70% slow threshold",
		},
		{
			name:            "High utilization",
			queueSize:       100,
			fillPercentage:  95,
			expectedControl: data.FlowControl_FLOW_PAUSE,
			description:     "95% > 90% pause threshold",
		},
		{
			name:            "Very high utilization",
			queueSize:       100,
			fillPercentage:  98,
			expectedControl: data.FlowControl_FLOW_PAUSE,
			description:     "98% > 90% pause threshold",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fillCount := tc.queueSize * tc.fillPercentage / 100

			c := NewController(false)
			c.SetPCAPQueue(
				func() int { return fillCount },
				func() int { return tc.queueSize },
			)

			flowControl := c.Determine()
			assert.Equal(t, tc.expectedControl, flowControl,
				"flow control mismatch for %s", tc.description)
		})
	}
}

func TestController_Determine_DynamicBehavior(t *testing.T) {
	queueSize := 100
	currentDepth := 95 // Start at 95%

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	// Should request PAUSE (> 90%)
	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should PAUSE when queue fills up to 95%")

	// Drain queue to 75%
	currentDepth = 75

	// Hysteresis holds PAUSE until the queue crosses the low watermark.
	flowControl = c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should remain paused while queue is above the resume threshold")

	// Drain queue to 25%
	currentDepth = 25

	// Should request RESUME (below 30%)
	flowControl = c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should RESUME when queue drains below 30%")

	// Drain queue to 0%
	currentDepth = 0

	// Should return RESUME (0% < 30%)
	flowControl = c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should be RESUME when queue is empty (0% < 30%)")
}

func TestController_Determine_EdgeCases(t *testing.T) {
	t.Run("Queue size 1", func(t *testing.T) {
		currentDepth := 0

		c := NewController(false)
		c.SetPCAPQueue(
			func() int { return currentDepth },
			func() int { return 1 },
		)

		// Empty
		flowControl := c.Determine()
		assert.NotEqual(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should not PAUSE when queue is empty")

		// Full (100% utilization)
		currentDepth = 1
		flowControl = c.Determine()
		assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should PAUSE when queue is full")
	})

	t.Run("Very large queue", func(t *testing.T) {
		queueSize := 10000
		currentDepth := 9500 // 95% full

		c := NewController(false)
		c.SetPCAPQueue(
			func() int { return currentDepth },
			func() int { return queueSize },
		)

		flowControl := c.Determine()
		assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should PAUSE even with large queue when > 90% full")
	})
}

func TestController_Determine_Integration(t *testing.T) {
	// Simulate realistic processor operation with varying load
	queueSize := 100
	currentDepth := 0

	c := NewController(false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	scenarios := []struct {
		name          string
		depth         int
		expectedState data.FlowControl
	}{
		{"Start empty", 0, data.FlowControl_FLOW_RESUME},       // 0% < 30%
		{"Light load", 30, data.FlowControl_FLOW_CONTINUE},     // 30% >= 30%, < 70%
		{"Medium load", 65, data.FlowControl_FLOW_CONTINUE},    // 65% >= 30%, < 70%
		{"Medium-heavy load", 75, data.FlowControl_FLOW_SLOW},  // 75% > 70%, <= 90%
		{"Heavy load", 95, data.FlowControl_FLOW_PAUSE},        // 95% > 90%
		{"Drain slightly", 85, data.FlowControl_FLOW_PAUSE},    // hold until <30%
		{"Continue draining", 65, data.FlowControl_FLOW_PAUSE}, // hold until <30%
		{"Drain more", 25, data.FlowControl_FLOW_RESUME},       // 25% < 30%
		{"Drain last", 0, data.FlowControl_FLOW_RESUME},        // 0% < 30%
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			currentDepth = scenario.depth

			flowControl := c.Determine()
			utilization := currentDepth * 100 / queueSize

			t.Logf("Queue: %d/%d (%d%%), FlowControl: %v, Expected: %v",
				currentDepth, queueSize, utilization, flowControl, scenario.expectedState)

			assert.Equal(t, scenario.expectedState, flowControl,
				"flow control state should match expected for scenario")
		})
	}
}

func TestController_Determine_UpstreamWithoutQueueMetricDoesNotInferBacklog(t *testing.T) {
	c := NewController(true)
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, c.Determine())
}

func TestController_Determine_Combined_PCAP_and_Upstream(t *testing.T) {
	queueSize := 100
	currentDepth := 95 // PCAP queue 95% full (should PAUSE)

	c := NewController(true)
	c.SetUpstreamQueue(func() int { return 80 }, func() int { return 100 })
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	// Most severe signal (PAUSE) should win
	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return most severe signal (PAUSE over SLOW)")
}

func TestController_Determine_UpstreamSlowBeatsPCAPResume(t *testing.T) {
	depth, capacity := 80, 100
	c := NewController(true)
	c.SetPCAPQueue(func() int { return 0 }, func() int { return 100 })
	c.SetUpstreamQueue(func() int { return depth }, func() int { return capacity })

	assert.Equal(t, data.FlowControl_FLOW_SLOW, c.Determine())
}

func TestController_Determine_ResumeRequiresAllSourcesBelowLowWatermark(t *testing.T) {
	pcapDepth, upstreamDepth := 95, 80
	c := NewController(true)
	c.SetPCAPQueue(func() int { return pcapDepth }, func() int { return 100 })
	c.SetUpstreamQueue(func() int { return upstreamDepth }, func() int { return 100 })

	assert.Equal(t, data.FlowControl_FLOW_PAUSE, c.Determine())

	// A drained PCAP queue must not release PAUSE while the upstream queue is
	// still in the neutral hysteresis band.
	pcapDepth, upstreamDepth = 0, 50
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, c.Determine())

	upstreamDepth = 20
	assert.Equal(t, data.FlowControl_FLOW_RESUME, c.Determine())
}

func TestController_Determine_SlowResumeRequiresAllSourcesBelowLowWatermark(t *testing.T) {
	pcapDepth, upstreamDepth := 75, 0
	c := NewController(true)
	c.SetPCAPQueue(func() int { return pcapDepth }, func() int { return 100 })
	c.SetUpstreamQueue(func() int { return upstreamDepth }, func() int { return 100 })

	assert.Equal(t, data.FlowControl_FLOW_SLOW, c.Determine())

	// A drained upstream queue must not release SLOW while PCAP remains above
	// the resume threshold.
	pcapDepth = 40
	assert.Equal(t, data.FlowControl_FLOW_SLOW, c.Determine())

	pcapDepth = 20
	assert.Equal(t, data.FlowControl_FLOW_RESUME, c.Determine())
}

func TestFlowControlSeverityDoesNotDependOnProtobufNumbers(t *testing.T) {
	assert.Equal(t, data.FlowControl_FLOW_PAUSE,
		moreSevere(data.FlowControl_FLOW_RESUME, data.FlowControl_FLOW_PAUSE))
	assert.Equal(t, data.FlowControl_FLOW_SLOW,
		moreSevere(data.FlowControl_FLOW_RESUME, data.FlowControl_FLOW_SLOW))
}

func TestFlowControlTransitionHysteresis(t *testing.T) {
	tests := []struct {
		name               string
		previous, pressure data.FlowControl
		want               data.FlowControl
	}{
		{"pause held through slow band", data.FlowControl_FLOW_PAUSE, data.FlowControl_FLOW_SLOW, data.FlowControl_FLOW_PAUSE},
		{"pause held through neutral band", data.FlowControl_FLOW_PAUSE, data.FlowControl_FLOW_CONTINUE, data.FlowControl_FLOW_PAUSE},
		{"pause releases below low watermark", data.FlowControl_FLOW_PAUSE, data.FlowControl_FLOW_RESUME, data.FlowControl_FLOW_RESUME},
		{"slow held through neutral band", data.FlowControl_FLOW_SLOW, data.FlowControl_FLOW_CONTINUE, data.FlowControl_FLOW_SLOW},
		{"slow releases below low watermark", data.FlowControl_FLOW_SLOW, data.FlowControl_FLOW_RESUME, data.FlowControl_FLOW_RESUME},
		{"resume settles to continue", data.FlowControl_FLOW_RESUME, data.FlowControl_FLOW_CONTINUE, data.FlowControl_FLOW_CONTINUE},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, transition(tc.previous, tc.pressure))
		})
	}
}
