//go:build processor || tap || all

package processor

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/flow"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/stats"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterHunter_MaxHuntersExceeded(t *testing.T) {
	// Create minimal processor for testing
	packetsReceived := atomic.Uint64{}
	packetsForwarded := atomic.Uint64{}

	hunterMgr := hunter.NewManager("test-processor", 2, nil)
	p := &Processor{
		config: Config{
			MaxHunters: 2,
		},
		hunterManager:  hunterMgr,
		filterManager:  filtering.NewManager("", nil, hunterMgr, nil, nil),
		flowController: flow.NewController(&packetsReceived, &packetsForwarded, false),
		statsCollector: stats.NewCollector("test-processor", &packetsReceived, &packetsForwarded),
	}

	// Register 2 hunters (fill to capacity)
	_, err := p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-1",
		Hostname: "host1",
	})
	assert.NoError(t, err)

	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-2",
		Hostname: "host2",
	})
	assert.NoError(t, err)

	// Try to register 3rd hunter (should fail with ResourceExhausted)
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-3",
		Hostname: "host3",
	})

	assert.Error(t, err, "should return error when max hunters exceeded")

	// Verify it's the correct gRPC status code
	st, ok := status.FromError(err)
	assert.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.ResourceExhausted, st.Code(),
		"should return ResourceExhausted status code")
	assert.Contains(t, st.Message(), "maximum number of hunters reached",
		"error message should explain the limit")
}

func TestRegisterHunter_AllowsReregistration(t *testing.T) {
	// Create minimal processor for testing
	packetsReceived := atomic.Uint64{}
	packetsForwarded := atomic.Uint64{}

	hunterMgr := hunter.NewManager("test-processor", 2, nil)
	p := &Processor{
		config: Config{
			MaxHunters: 2,
		},
		hunterManager:  hunterMgr,
		filterManager:  filtering.NewManager("", nil, hunterMgr, nil, nil),
		flowController: flow.NewController(&packetsReceived, &packetsForwarded, false),
		statsCollector: stats.NewCollector("test-processor", &packetsReceived, &packetsForwarded),
	}

	// Register hunter
	_, err := p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-1",
		Hostname: "host1",
	})
	assert.NoError(t, err)

	// Re-register same hunter (should succeed even at capacity)
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-1",
		Hostname: "host1-updated",
	})
	assert.NoError(t, err, "should allow re-registration of existing hunter")
}

func TestDeleteFilter_NotFound(t *testing.T) {
	p := &Processor{
		config:        Config{},
		filterManager: filtering.NewManager("", nil, nil, nil, nil),
	}

	// Try to delete non-existent filter
	_, err := p.DeleteFilter(context.Background(), &management.FilterDeleteRequest{
		FilterId: "non-existent-filter",
	})

	assert.Error(t, err, "should return error when filter not found")

	// Verify it's the correct gRPC status code
	st, ok := status.FromError(err)
	assert.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code(),
		"should return NotFound status code")
	assert.Contains(t, st.Message(), "filter not found",
		"error message should indicate filter not found")
	assert.Contains(t, st.Message(), "non-existent-filter",
		"error message should include filter ID")
}

func TestDeleteFilter_Success(t *testing.T) {
	p := &Processor{
		config:        Config{},
		filterManager: filtering.NewManager("", nil, nil, nil, nil),
	}

	// Add a filter
	testFilter := &management.Filter{
		Id:      "test-filter",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alicent",
	}
	p.filterManager.Update(testFilter)

	// Delete it
	result, err := p.DeleteFilter(context.Background(), &management.FilterDeleteRequest{
		FilterId: "test-filter",
	})

	assert.NoError(t, err, "should successfully delete existing filter")
	assert.NotNil(t, result, "should return result")
	assert.True(t, result.Success, "result should indicate success")

	// Verify filter was removed
	assert.Equal(t, 0, p.filterManager.Count(), "filter should be removed")
}
