package flow

import (
	"sync/atomic"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
)

func TestController_Determine_NoPCAPQueue(t *testing.T) {
	c := NewController(nil, nil, false)
	// No PCAP queue configured

	// Without PCAP queue, should always return CONTINUE
	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should return CONTINUE when no PCAP queue configured")
}

func TestController_Determine_QueueEmpty(t *testing.T) {
	queueSize := 100
	currentDepth := 0

	c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

			c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
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

	// Should request SLOW (> 70%)
	flowControl = c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_SLOW, flowControl,
		"should SLOW when queue is 75% full")

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

		c := NewController(nil, nil, false)
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

		c := NewController(nil, nil, false)
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

	c := NewController(nil, nil, false)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	scenarios := []struct {
		name          string
		depth         int
		expectedState data.FlowControl
	}{
		{"Start empty", 0, data.FlowControl_FLOW_RESUME},          // 0% < 30%
		{"Light load", 30, data.FlowControl_FLOW_CONTINUE},        // 30% >= 30%, < 70%
		{"Medium load", 65, data.FlowControl_FLOW_CONTINUE},       // 65% >= 30%, < 70%
		{"Medium-heavy load", 75, data.FlowControl_FLOW_SLOW},     // 75% > 70%, <= 90%
		{"Heavy load", 95, data.FlowControl_FLOW_PAUSE},           // 95% > 90%
		{"Drain slightly", 85, data.FlowControl_FLOW_SLOW},        // 85% > 70%, <= 90%
		{"Continue draining", 65, data.FlowControl_FLOW_CONTINUE}, // 65% >= 30%, < 70%
		{"Drain more", 25, data.FlowControl_FLOW_RESUME},          // 25% < 30%
		{"Drain last", 0, data.FlowControl_FLOW_RESUME},           // 0% < 30%
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

func TestController_Determine_UpstreamBacklog(t *testing.T) {
	packetsReceived := atomic.Uint64{}
	packetsForwarded := atomic.Uint64{}

	c := NewController(&packetsReceived, &packetsForwarded, true)

	// Start with no backlog
	packetsReceived.Store(1000)
	packetsForwarded.Store(1000)

	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should CONTINUE with no backlog")

	// Create large backlog (>10000)
	packetsReceived.Store(20000)
	packetsForwarded.Store(5000)

	flowControl = c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_SLOW, flowControl,
		"should SLOW with large upstream backlog")
}

func TestController_Determine_Combined_PCAP_and_Upstream(t *testing.T) {
	queueSize := 100
	currentDepth := 95 // PCAP queue 95% full (should PAUSE)

	packetsReceived := atomic.Uint64{}
	packetsForwarded := atomic.Uint64{}
	packetsReceived.Store(20000)
	packetsForwarded.Store(5000) // Large backlog (should SLOW)

	c := NewController(&packetsReceived, &packetsForwarded, true)
	c.SetPCAPQueue(
		func() int { return currentDepth },
		func() int { return queueSize },
	)

	// Most severe signal (PAUSE) should win
	flowControl := c.Determine()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return most severe signal (PAUSE over SLOW)")
}
