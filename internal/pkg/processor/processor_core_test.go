package processor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests the processor constructor
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
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
			},
			wantErr: false,
		},
		{
			name: "empty listen address",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "",
			},
			wantErr:     true,
			errContains: "listen address is required",
		},
		{
			name: "with protocol detection enabled",
			config: Config{
				ProcessorID:     "test-processor",
				ListenAddr:      "localhost:50051",
				EnableDetection: true,
			},
			wantErr: false,
		},
		{
			name: "with upstream processor",
			config: Config{
				ProcessorID:  "test-processor",
				ListenAddr:   "localhost:50051",
				UpstreamAddr: "upstream:50052",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := New(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, processor)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, processor)
				assert.Equal(t, tt.config.ProcessorID, processor.config.ProcessorID)
				assert.Equal(t, tt.config.ListenAddr, processor.config.ListenAddr)
				assert.NotNil(t, processor.hunters)
				assert.NotNil(t, processor.filters)
				assert.NotNil(t, processor.filterChannels)

				// Verify protocol detector is initialized when enabled
				if tt.config.EnableDetection {
					assert.NotNil(t, processor.detector)
				} else {
					assert.Nil(t, processor.detector)
				}
			}
		})
	}
}

// TestGetHunterStatus tests hunter status retrieval
func TestGetHunterStatus(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters: make(map[string]*ConnectedHunter),
	}

	// Add test hunters
	now := time.Now().Unix()
	hunter1 := &ConnectedHunter{
		ID:          "hunter-1",
		Interfaces:  []string{"eth0"},
		ConnectedAt: now,
	}
	hunter2 := &ConnectedHunter{
		ID:          "hunter-2",
		Interfaces:  []string{"wlan0"},
		ConnectedAt: now - 300, // 5 minutes ago
	}

	processor.hunters["hunter-1"] = hunter1
	processor.hunters["hunter-2"] = hunter2

	// Verify hunter count
	assert.Equal(t, 2, len(processor.hunters))

	// Verify hunters can be retrieved
	retrieved1, exists := processor.hunters["hunter-1"]
	assert.True(t, exists)
	assert.Equal(t, "hunter-1", retrieved1.ID)
	assert.Equal(t, []string{"eth0"}, retrieved1.Interfaces)

	retrieved2, exists := processor.hunters["hunter-2"]
	assert.True(t, exists)
	assert.Equal(t, "hunter-2", retrieved2.ID)
	assert.Equal(t, []string{"wlan0"}, retrieved2.Interfaces)
}

// TestFlowControlConstants tests flow control enum values
func TestFlowControlConstants(t *testing.T) {
	// Verify flow control constants are defined
	assert.Equal(t, int32(0), int32(data.FlowControl_FLOW_CONTINUE))
	assert.Equal(t, int32(1), int32(data.FlowControl_FLOW_SLOW))
	assert.Equal(t, int32(2), int32(data.FlowControl_FLOW_PAUSE))
	assert.Equal(t, int32(3), int32(data.FlowControl_FLOW_RESUME))
}

// TestFilterOperations tests filter addition and retrieval
func TestFilterOperations(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		filters: make(map[string]*management.Filter),
	}

	// Add a filter
	filter1 := &management.Filter{
		Id:      "filter-1",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alice@example.com",
		Enabled: true,
	}

	processor.filters["filter-1"] = filter1

	// Verify filter was added
	assert.Equal(t, 1, len(processor.filters))

	// Retrieve filter
	retrieved, exists := processor.filters["filter-1"]
	assert.True(t, exists)
	assert.Equal(t, "filter-1", retrieved.Id)
	assert.Equal(t, management.FilterType_FILTER_SIP_USER, retrieved.Type)
	assert.Equal(t, "alice@example.com", retrieved.Pattern)
	assert.True(t, retrieved.Enabled)

	// Add another filter
	filter2 := &management.Filter{
		Id:      "filter-2",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.168.1.0/24",
		Enabled: true,
	}

	processor.filters["filter-2"] = filter2

	// Verify both filters exist
	assert.Equal(t, 2, len(processor.filters))

	// Delete a filter
	delete(processor.filters, "filter-1")
	assert.Equal(t, 1, len(processor.filters))

	_, exists = processor.filters["filter-1"]
	assert.False(t, exists)

	_, exists = processor.filters["filter-2"]
	assert.True(t, exists)
}

// TestConnectedHunter tests ConnectedHunter structure
func TestConnectedHunter(t *testing.T) {
	now := time.Now().Unix()

	hunter := &ConnectedHunter{
		ID:              "hunter-1",
		Interfaces:      []string{"eth0"},
		RemoteAddr:      "192.168.1.100:12345",
		ConnectedAt:     now,
		LastHeartbeat:   now,
		PacketsReceived: 1000,
		Status:          management.HunterStatus_STATUS_HEALTHY,
	}

	assert.Equal(t, "hunter-1", hunter.ID)
	assert.Equal(t, []string{"eth0"}, hunter.Interfaces)
	assert.Equal(t, "192.168.1.100:12345", hunter.RemoteAddr)
	assert.Equal(t, now, hunter.ConnectedAt)
	assert.Equal(t, now, hunter.LastHeartbeat)
	assert.Equal(t, uint64(1000), hunter.PacketsReceived)
	assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, hunter.Status)
}

// TestStats tests processor statistics
func TestStats(t *testing.T) {
	stats := &Stats{}

	// Initialize stats
	stats.TotalPacketsReceived = 1000
	stats.TotalPacketsForwarded = 900
	stats.TotalHunters = 10
	stats.HealthyHunters = 8
	stats.WarningHunters = 1
	stats.ErrorHunters = 1

	// Verify stats
	assert.Equal(t, uint64(1000), stats.TotalPacketsReceived)
	assert.Equal(t, uint64(900), stats.TotalPacketsForwarded)
	assert.Equal(t, uint32(10), stats.TotalHunters)
	assert.Equal(t, uint32(8), stats.HealthyHunters)
	assert.Equal(t, uint32(1), stats.WarningHunters)
	assert.Equal(t, uint32(1), stats.ErrorHunters)
}

// TestContextCancellation tests proper cleanup
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("goroutine did not exit on context cancellation")
	}
}

// TestMaxHunters tests max hunters limit
func TestMaxHunters(t *testing.T) {
	const maxHunters = 3

	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
			MaxHunters:  maxHunters,
		},
		hunters: make(map[string]*ConnectedHunter),
	}

	// Add hunters up to the limit
	for i := 0; i < maxHunters; i++ {
		hunterID := fmt.Sprintf("hunter-%d", i+1)
		processor.hunters[hunterID] = &ConnectedHunter{
			ID:          hunterID,
			Interfaces:  []string{"eth0"},
			ConnectedAt: time.Now().Unix(),
		}
	}

	assert.Equal(t, maxHunters, len(processor.hunters))

	// Verify we can check if at capacity
	atCapacity := len(processor.hunters) >= processor.config.MaxHunters && processor.config.MaxHunters > 0
	assert.True(t, atCapacity)
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid minimal config",
			config: Config{
				ProcessorID: "proc-1",
				ListenAddr:  "localhost:50051",
			},
			wantErr: false,
		},
		{
			name: "valid with all options",
			config: Config{
				ProcessorID:     "proc-1",
				ListenAddr:      "localhost:50051",
				MaxHunters:      10,
				EnableDetection: true,
				UpstreamAddr:    "upstream:50052",
				TLSEnabled:      true,
				TLSCertFile:     "/path/to/cert.pem",
				TLSKeyFile:      "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "missing listen address",
			config: Config{
				ProcessorID: "proc-1",
				ListenAddr:  "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
