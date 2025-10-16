package hunter

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests the hunter constructor
func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:50051",
				BatchSize:     100,
				BufferSize:    8192,
			},
			wantErr: false,
		},
		{
			name: "empty hunter ID",
			config: Config{
				HunterID:      "",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:50051",
			},
			wantErr:     true,
			errContains: "hunter ID is required",
		},
		{
			name: "empty processor address",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "",
			},
			wantErr:     true,
			errContains: "processor address is required",
		},
		{
			name: "default flow control settings",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:50051",
				// MaxBufferedBatches and SendTimeout not set - should use defaults
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hunter, err := New(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, hunter)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, hunter)
				assert.Equal(t, tt.config.HunterID, hunter.config.HunterID)
				assert.Equal(t, tt.config.ProcessorAddr, hunter.config.ProcessorAddr)

				// Verify defaults were applied
				if tt.config.MaxBufferedBatches == 0 {
					assert.Equal(t, 10, hunter.config.MaxBufferedBatches, "default MaxBufferedBatches should be 10")
				}
				if tt.config.SendTimeout == 0 {
					assert.Equal(t, 5*time.Second, hunter.config.SendTimeout, "default SendTimeout should be 5s")
				}

				// Verify batch queue was created with correct capacity
				// Batch queue is now managed by forwarding manager
			}
		})
	}
}

// TestCapturedPacket tests packet structure
func TestCapturedPacket(t *testing.T) {
	// Test basic packet creation
	packet := &data.CapturedPacket{
		Data:           []byte{0x01, 0x02, 0x03},
		TimestampNs:    1234567890,
		CaptureLength:  3,
		OriginalLength: 3,
	}

	assert.Equal(t, []byte{0x01, 0x02, 0x03}, packet.Data)
	assert.Equal(t, int64(1234567890), packet.TimestampNs)
	assert.Equal(t, uint32(3), packet.CaptureLength)
	assert.Equal(t, uint32(3), packet.OriginalLength)
}

// TestGetStatsCollector tests statistics collector retrieval
func TestGetStatsCollector(t *testing.T) {
	hunter, err := New(Config{
		ProcessorAddr: "localhost:50051",
		HunterID:      "test-hunter",
		Interfaces:    []string{"eth0"},
		BatchSize:     10,
		BufferSize:    100,
	})
	require.NoError(t, err)

	statsCollector := hunter.GetStatsCollector()
	assert.NotNil(t, statsCollector)

	// Initially all stats should be zero
	assert.Equal(t, uint64(0), statsCollector.GetCaptured())
	assert.Equal(t, uint64(0), statsCollector.GetMatched())
	assert.Equal(t, uint64(0), statsCollector.GetForwarded())
	assert.Equal(t, uint64(0), statsCollector.GetDropped())
	assert.Equal(t, uint64(0), statsCollector.GetBufferBytes())
}

// TestStatsAtomic tests that stats can be safely updated from multiple goroutines
func TestStatsAtomic(t *testing.T) {
	hunter, err := New(Config{
		ProcessorAddr: "localhost:50051",
		HunterID:      "test-hunter",
		Interfaces:    []string{"eth0"},
		BatchSize:     10,
		BufferSize:    100,
	})
	require.NoError(t, err)

	// Increment stats from multiple goroutines
	const numGoroutines = 10
	const incrementsPerGoroutine = 100

	done := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < incrementsPerGoroutine; j++ {
				hunter.statsCollector.IncrementCaptured()
				hunter.statsCollector.IncrementMatched()
				hunter.statsCollector.IncrementForwarded(1)
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	expected := uint64(numGoroutines * incrementsPerGoroutine)
	assert.Equal(t, expected, hunter.statsCollector.GetCaptured())
	assert.Equal(t, expected, hunter.statsCollector.GetMatched())
	assert.Equal(t, expected, hunter.statsCollector.GetForwarded())
}

// TestMin tests the min helper function
func TestMin(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a < b", 5, 10, 5},
		{"a > b", 10, 5, 5},
		{"a == b", 7, 7, 7},
		{"negative numbers", -5, -10, -10},
		{"zero", 0, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := min(tt.a, tt.b)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestFlowControlStateTransitions tests flow control state machine
func TestFlowControlStateTransitions_Extended(t *testing.T) {
	tests := []struct {
		name          string
		initialState  data.FlowControl
		signal        data.FlowControl
		expectedState data.FlowControl
	}{
		{
			name:          "CONTINUE to PAUSE",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectedState: data.FlowControl_FLOW_PAUSE,
		},
		{
			name:          "PAUSE to RESUME",
			initialState:  data.FlowControl_FLOW_PAUSE,
			signal:        data.FlowControl_FLOW_RESUME,
			expectedState: data.FlowControl_FLOW_RESUME,
		},
		{
			name:          "RESUME to CONTINUE",
			initialState:  data.FlowControl_FLOW_RESUME,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
		},
		{
			name:          "CONTINUE to SLOW",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_SLOW,
			expectedState: data.FlowControl_FLOW_SLOW,
		},
		{
			name:          "SLOW to CONTINUE",
			initialState:  data.FlowControl_FLOW_SLOW,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
		},
	}
	_ = tests // Keep test cases for documentation

	// Flow control is now managed by forwarding.Manager
	// TODO: Create tests in forwarding/manager_test.go
	t.Skip("Flow control logic moved to forwarding.Manager")
}

// TestBatchSizeConfiguration tests batch size limits
func TestBatchSizeConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		batchSize     int
		expectedBatch int
	}{
		{
			name:          "zero batch size",
			batchSize:     0,
			expectedBatch: 0,
		},
		{
			name:          "custom batch size",
			batchSize:     500,
			expectedBatch: 500,
		},
		{
			name:          "small batch size",
			batchSize:     10,
			expectedBatch: 10,
		},
		{
			name:          "large batch size",
			batchSize:     10000,
			expectedBatch: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hunter, err := New(Config{
				HunterID:      "test-hunter",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:50051",
				BatchSize:     tt.batchSize,
			})

			require.NoError(t, err)
			assert.NotNil(t, hunter)
			assert.Equal(t, tt.expectedBatch, hunter.config.BatchSize)
		})
	}
}

// TestContextCancellation tests proper cleanup on context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Start a goroutine that should exit on context cancellation
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()

	// Cancel context
	cancel()

	// Wait for goroutine to exit with timeout
	select {
	case <-done:
		// Success - goroutine exited
	case <-time.After(1 * time.Second):
		t.Fatal("goroutine did not exit on context cancellation")
	}
}
