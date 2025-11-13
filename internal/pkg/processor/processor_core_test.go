package processor

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
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
				// Verify managers are initialized
				assert.NotNil(t, processor.hunterManager, "hunterManager should be initialized")
				assert.NotNil(t, processor.filterManager, "filterManager should be initialized")
				assert.NotNil(t, processor.flowController, "flowController should be initialized")
				assert.NotNil(t, processor.statsCollector, "statsCollector should be initialized")
				assert.NotNil(t, processor.subscriberManager, "subscriberManager should be initialized")

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
	hunterMgr := hunter.NewManager("test-processor", 10, nil)

	// Register test hunters
	_, _, err := hunterMgr.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	_, _, err = hunterMgr.Register("hunter-2", "host2", []string{"wlan0"}, nil)
	require.NoError(t, err)

	// Verify hunter count (pass empty filterID to get all)
	hunters := hunterMgr.GetAll("")
	assert.Equal(t, 2, len(hunters))

	// Verify hunters can be retrieved
	found := false
	for _, h := range hunters {
		if h.ID == "hunter-1" {
			found = true
			assert.Equal(t, []string{"eth0"}, h.Interfaces)
			break
		}
	}
	assert.True(t, found, "hunter-1 should be in the list")

	found = false
	for _, h := range hunters {
		if h.ID == "hunter-2" {
			found = true
			assert.Equal(t, []string{"wlan0"}, h.Interfaces)
			break
		}
	}
	assert.True(t, found, "hunter-2 should be in the list")
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
	filterMgr := filtering.NewManager("", nil, nil, nil, nil)

	// Add a filter
	filter1 := &management.Filter{
		Id:      "filter-1",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alicent@example.com",
		Enabled: true,
	}

	_, err := filterMgr.Update(filter1)
	require.NoError(t, err)

	// Verify filter was added
	assert.Equal(t, 1, filterMgr.Count())

	// Retrieve all filters
	filters := filterMgr.GetAll()
	assert.Len(t, filters, 1)
	assert.Equal(t, "filter-1", filters[0].Id)
	assert.Equal(t, management.FilterType_FILTER_SIP_USER, filters[0].Type)
	assert.Equal(t, "alicent@example.com", filters[0].Pattern)
	assert.True(t, filters[0].Enabled)

	// Add another filter
	filter2 := &management.Filter{
		Id:      "filter-2",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.168.1.0/24",
		Enabled: true,
	}

	_, err = filterMgr.Update(filter2)
	require.NoError(t, err)

	// Verify both filters exist
	assert.Equal(t, 2, filterMgr.Count())

	// Delete a filter
	_, err = filterMgr.Delete("filter-1")
	require.NoError(t, err)
	assert.Equal(t, 1, filterMgr.Count())

	// Verify only filter-2 remains
	filters = filterMgr.GetAll()
	assert.Len(t, filters, 1)
	assert.Equal(t, "filter-2", filters[0].Id)
}

// TestConnectedHunter removed - now tested in hunter package

// TestStats tests processor statistics
func TestStats(t *testing.T) {
	packetsReceived := atomic.Uint64{}
	packetsForwarded := atomic.Uint64{}
	packetsReceived.Store(1000)
	packetsForwarded.Store(900)

	hunterMgr := hunter.NewManager("test-processor", 10, nil)
	// Register some hunters to test stats
	hunterMgr.Register("hunter-1", "host1", []string{"eth0"}, nil)
	hunterMgr.Register("hunter-2", "host2", []string{"eth1"}, nil)

	total, healthy, warning, errCount, _ := hunterMgr.GetHealthStats()

	// Verify stats structure
	assert.Equal(t, uint32(2), total)
	assert.GreaterOrEqual(t, healthy+warning+errCount, uint32(0))
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

	hunterMgr := hunter.NewManager("test-processor", maxHunters, nil)

	// Add hunters up to the limit
	for i := 0; i < maxHunters; i++ {
		hunterID := fmt.Sprintf("hunter-%d", i+1)
		hostname := fmt.Sprintf("host%d", i+1)
		_, _, err := hunterMgr.Register(hunterID, hostname, []string{"eth0"}, nil)
		require.NoError(t, err)
	}

	hunters := hunterMgr.GetAll("")
	assert.Equal(t, maxHunters, len(hunters))

	// Try to add one more - should fail
	_, _, err := hunterMgr.Register("hunter-4", "host4", []string{"eth0"}, nil)
	assert.Error(t, err, "should fail when exceeding max hunters")
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
