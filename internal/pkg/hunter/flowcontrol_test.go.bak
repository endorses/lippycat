package hunter

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
)

func TestHandleFlowControl_Pause(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Initially not paused
	assert.False(t, h.paused.Load(), "hunter should not be paused initially")

	// Send PAUSE signal
	ctrl := &data.StreamControl{
		AckSequence: 1,
		FlowControl: data.FlowControl_FLOW_PAUSE,
	}
	h.handleFlowControl(ctrl)

	// Verify hunter is paused
	assert.True(t, h.paused.Load(), "hunter should be paused after PAUSE signal")
	assert.Equal(t, int32(data.FlowControl_FLOW_PAUSE), h.flowControlState.Load(),
		"flow control state should be PAUSE")
}

func TestHandleFlowControl_Resume(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Start paused
	h.paused.Store(true)
	h.flowControlState.Store(int32(data.FlowControl_FLOW_PAUSE))

	// Send RESUME signal
	ctrl := &data.StreamControl{
		AckSequence: 2,
		FlowControl: data.FlowControl_FLOW_RESUME,
	}
	h.handleFlowControl(ctrl)

	// Verify hunter is resumed
	assert.False(t, h.paused.Load(), "hunter should not be paused after RESUME signal")
	assert.Equal(t, int32(data.FlowControl_FLOW_RESUME), h.flowControlState.Load(),
		"flow control state should be RESUME")
}

func TestHandleFlowControl_Slow(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Send SLOW signal
	ctrl := &data.StreamControl{
		AckSequence: 3,
		FlowControl: data.FlowControl_FLOW_SLOW,
	}
	h.handleFlowControl(ctrl)

	// Verify state is updated (hunter doesn't pause, just slows down)
	assert.False(t, h.paused.Load(), "hunter should not pause on SLOW signal")
	assert.Equal(t, int32(data.FlowControl_FLOW_SLOW), h.flowControlState.Load(),
		"flow control state should be SLOW")
}

func TestHandleFlowControl_Continue(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Start in SLOW state
	h.flowControlState.Store(int32(data.FlowControl_FLOW_SLOW))

	// Send CONTINUE signal
	ctrl := &data.StreamControl{
		AckSequence: 4,
		FlowControl: data.FlowControl_FLOW_CONTINUE,
	}
	h.handleFlowControl(ctrl)

	// Verify state is updated to normal
	assert.False(t, h.paused.Load(), "hunter should not be paused on CONTINUE signal")
	assert.Equal(t, int32(data.FlowControl_FLOW_CONTINUE), h.flowControlState.Load(),
		"flow control state should be CONTINUE")
}

func TestHandleFlowControl_StateTransitions(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	testCases := []struct {
		name          string
		initialState  data.FlowControl
		initialPaused bool
		signal        data.FlowControl
		expectPaused  bool
	}{
		{
			name:          "CONTINUE to PAUSE",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			initialPaused: false,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectPaused:  true,
		},
		{
			name:          "PAUSE to RESUME",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_RESUME,
			expectPaused:  false,
		},
		{
			name:          "SLOW to PAUSE",
			initialState:  data.FlowControl_FLOW_SLOW,
			initialPaused: false,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectPaused:  true,
		},
		{
			name:          "PAUSE to CONTINUE",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectPaused:  true, // CONTINUE doesn't unpause, only RESUME does
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup initial state
			h.flowControlState.Store(int32(tc.initialState))
			h.paused.Store(tc.initialPaused)

			// Send signal
			ctrl := &data.StreamControl{
				AckSequence: 1,
				FlowControl: tc.signal,
			}
			h.handleFlowControl(ctrl)

			// Verify expected state
			assert.Equal(t, tc.expectPaused, h.paused.Load(),
				"paused state should match expectation")
			assert.Equal(t, int32(tc.signal), h.flowControlState.Load(),
				"flow control state should be updated")
		})
	}
}

func TestFlowControl_ConcurrentStateUpdates(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Simulate concurrent flow control updates
	var wg sync.WaitGroup
	signals := []data.FlowControl{
		data.FlowControl_FLOW_PAUSE,
		data.FlowControl_FLOW_RESUME,
		data.FlowControl_FLOW_SLOW,
		data.FlowControl_FLOW_CONTINUE,
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(seq int) {
			defer wg.Done()
			ctrl := &data.StreamControl{
				AckSequence: uint64(seq),
				FlowControl: signals[seq%len(signals)],
			}
			h.handleFlowControl(ctrl)
		}(i)
	}

	wg.Wait()

	// Verify state is one of the valid values
	finalState := data.FlowControl(h.flowControlState.Load())
	assert.Contains(t, signals, finalState,
		"final state should be one of the valid flow control states")
}

func TestFlowControl_PauseResumeCycle(t *testing.T) {
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
	}

	// Cycle through pause/resume multiple times
	for i := 0; i < 10; i++ {
		// Pause
		pauseCtrl := &data.StreamControl{
			AckSequence: uint64(i * 2),
			FlowControl: data.FlowControl_FLOW_PAUSE,
		}
		h.handleFlowControl(pauseCtrl)
		assert.True(t, h.paused.Load(), "should be paused after PAUSE signal")

		// Resume
		resumeCtrl := &data.StreamControl{
			AckSequence: uint64(i*2 + 1),
			FlowControl: data.FlowControl_FLOW_RESUME,
		}
		h.handleFlowControl(resumeCtrl)
		assert.False(t, h.paused.Load(), "should not be paused after RESUME signal")
	}
}

func TestBatchQueue_Backpressure(t *testing.T) {
	maxBatches := 5
	h := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: maxBatches,
		},
		batchQueue: make(chan []*data.CapturedPacket, maxBatches),
	}

	// Fill the queue to capacity
	for i := 0; i < maxBatches; i++ {
		batch := []*data.CapturedPacket{
			{Data: []byte("test packet")},
		}
		select {
		case h.batchQueue <- batch:
			h.batchQueueSize.Add(1)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("queue should not block when not full (batch %d)", i)
		}
	}

	// Verify queue is full
	assert.Equal(t, int32(maxBatches), h.batchQueueSize.Load(),
		"queue size should equal max batches")

	// Attempt to add one more - should block or be rejected
	batch := []*data.CapturedPacket{
		{Data: []byte("overflow packet")},
	}
	select {
	case h.batchQueue <- batch:
		t.Fatal("queue should block when full")
	case <-time.After(100 * time.Millisecond):
		// Expected - queue is full
	}

	// Drain one batch
	<-h.batchQueue
	h.batchQueueSize.Add(-1)

	// Now adding should succeed
	select {
	case h.batchQueue <- batch:
		h.batchQueueSize.Add(1)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("queue should accept batch after draining")
	}

	assert.Equal(t, int32(maxBatches), h.batchQueueSize.Load(),
		"queue should be full again after adding")
}
