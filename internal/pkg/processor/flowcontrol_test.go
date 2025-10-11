package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
)

func TestDetermineFlowControl_NoPCAPQueue(t *testing.T) {
	p := &Processor{
		config: Config{},
		// pcapWriteQueue is nil
	}

	// Without PCAP queue, should always return CONTINUE
	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should return CONTINUE when no PCAP queue configured")
}

func TestDetermineFlowControl_QueueEmpty(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should return RESUME when queue is empty (0% < 30% threshold)")
}

func TestDetermineFlowControl_QueueSlightlyFull(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Fill queue to 40% (above RESUME threshold of 30%, below SLOW threshold of 70%)
	for i := 0; i < 40; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, flowControl,
		"should return CONTINUE when queue 30-70% full")
}

func TestDetermineFlowControl_QueueMediumFull(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Fill queue to 75% (above SLOW threshold of 70%, below PAUSE threshold of 90%)
	for i := 0; i < 75; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_SLOW, flowControl,
		"should return SLOW when queue 70-90% full")
}

func TestDetermineFlowControl_QueueAlmostFull(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Fill queue to 95% (above PAUSE threshold of 90%)
	for i := 0; i < 95; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return PAUSE when queue > 90% full")
}

func TestDetermineFlowControl_QueueFull(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Fill queue to 100%
	for i := 0; i < queueSize; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should return PAUSE when queue is full")
}

func TestDetermineFlowControl_QueueDraining(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Fill queue to 25% (below RESUME threshold of 30%)
	for i := 0; i < 25; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should return RESUME when queue < 30% full")
}

func TestDetermineFlowControl_QueueThresholds(t *testing.T) {
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
			p := &Processor{
				config:         Config{},
				pcapWriteQueue: make(chan []*data.CapturedPacket, tc.queueSize),
			}

			// Fill queue to specified percentage
			fillCount := tc.queueSize * tc.fillPercentage / 100
			for i := 0; i < fillCount; i++ {
				p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
			}

			flowControl := p.determineFlowControl()
			assert.Equal(t, tc.expectedControl, flowControl,
				"flow control mismatch for %s", tc.description)
		})
	}
}

func TestDetermineFlowControl_DynamicBehavior(t *testing.T) {
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	// Simulate queue filling up to 95%
	for i := 0; i < 95; i++ {
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
	}

	// Should request PAUSE (> 90%)
	flowControl := p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
		"should PAUSE when queue fills up to 95%")

	// Drain queue to 75%
	for i := 0; i < 20; i++ {
		<-p.pcapWriteQueue
	}

	// Should request SLOW (> 70%)
	flowControl = p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_SLOW, flowControl,
		"should SLOW when queue is 75% full")

	// Drain queue to 25%
	for i := 0; i < 50; i++ {
		<-p.pcapWriteQueue
	}

	// Should request RESUME (below 30%)
	flowControl = p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should RESUME when queue drains below 30%")

	// Drain queue to 0%
	for i := 0; i < 25; i++ {
		<-p.pcapWriteQueue
	}

	// Should return RESUME (0% < 30%)
	flowControl = p.determineFlowControl()
	assert.Equal(t, data.FlowControl_FLOW_RESUME, flowControl,
		"should be RESUME when queue is empty (0% < 30%)")
}

func TestDetermineFlowControl_EdgeCases(t *testing.T) {
	t.Run("Queue size 1", func(t *testing.T) {
		p := &Processor{
			config:         Config{},
			pcapWriteQueue: make(chan []*data.CapturedPacket, 1),
		}

		// Empty
		flowControl := p.determineFlowControl()
		assert.NotEqual(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should not PAUSE when queue is empty")

		// Full (100% utilization)
		p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
		flowControl = p.determineFlowControl()
		assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should PAUSE when queue is full")
	})

	t.Run("Very large queue", func(t *testing.T) {
		queueSize := 10000
		p := &Processor{
			config:         Config{},
			pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
		}

		// Fill to 95% (9500 packets)
		for i := 0; i < 9500; i++ {
			p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}
		}

		flowControl := p.determineFlowControl()
		assert.Equal(t, data.FlowControl_FLOW_PAUSE, flowControl,
			"should PAUSE even with large queue when > 90% full")
	})
}

func TestFlowControl_Integration(t *testing.T) {
	// Simulate realistic processor operation with varying load
	queueSize := 100
	p := &Processor{
		config:         Config{},
		pcapWriteQueue: make(chan []*data.CapturedPacket, queueSize),
	}

	scenarios := []struct {
		name          string
		fillCount     int
		drainCount    int
		expectedState data.FlowControl
	}{
		{"Start empty", 0, 0, data.FlowControl_FLOW_RESUME},          // 0% < 30%
		{"Light load", 30, 0, data.FlowControl_FLOW_CONTINUE},        // 30% >= 30%, < 70%
		{"Medium load", 35, 0, data.FlowControl_FLOW_CONTINUE},       // 65% >= 30%, < 70%
		{"Medium-heavy load", 10, 0, data.FlowControl_FLOW_SLOW},     // 75% > 70%, <= 90%
		{"Heavy load", 20, 0, data.FlowControl_FLOW_PAUSE},           // 95% > 90%
		{"Drain slightly", 0, 10, data.FlowControl_FLOW_SLOW},        // 85% > 70%, <= 90%
		{"Continue draining", 0, 20, data.FlowControl_FLOW_CONTINUE}, // 65% >= 30%, < 70%
		{"Drain more", 0, 40, data.FlowControl_FLOW_RESUME},          // 25% < 30%
		{"Drain last", 0, 25, data.FlowControl_FLOW_RESUME},          // 0% < 30%
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Fill queue
			for i := 0; i < scenario.fillCount; i++ {
				select {
				case p.pcapWriteQueue <- []*data.CapturedPacket{{Data: []byte("test")}}:
				default:
					t.Logf("Queue full, couldn't add all packets")
					break
				}
			}

			// Drain queue
			for i := 0; i < scenario.drainCount; i++ {
				select {
				case <-p.pcapWriteQueue:
				default:
					t.Logf("Queue empty, couldn't drain all packets")
					break
				}
			}

			flowControl := p.determineFlowControl()
			currentSize := len(p.pcapWriteQueue)
			utilization := currentSize * 100 / queueSize

			t.Logf("Queue: %d/%d (%d%%), FlowControl: %v, Expected: %v",
				currentSize, queueSize, utilization, flowControl, scenario.expectedState)

			assert.Equal(t, scenario.expectedState, flowControl,
				"flow control state should match expected for scenario")
		})
	}
}
