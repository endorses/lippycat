package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"os"
)

// TestRouteToProcessor_LocalProcessor tests routing to the local processor
func TestRouteToProcessor_LocalProcessor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Test with empty processor ID (local)
	decision, err := mgr.RouteToProcessor(context.Background(), "")
	require.NoError(t, err)
	assert.True(t, decision.IsLocal)
	assert.Equal(t, int32(0), decision.Depth)
	assert.Equal(t, 5*time.Second, decision.RecommendedTimeout) // Base timeout for local
	assert.True(t, decision.TargetReachable)

	// Test with explicit local processor ID
	decision, err = mgr.RouteToProcessor(context.Background(), "processor-a")
	require.NoError(t, err)
	assert.True(t, decision.IsLocal)
	assert.Equal(t, int32(0), decision.Depth)
	assert.Equal(t, 5*time.Second, decision.RecommendedTimeout)
	assert.True(t, decision.TargetReachable)
}

// TestRouteToProcessor_DownstreamProcessor tests routing to a downstream processor
func TestRouteToProcessor_DownstreamProcessor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Add a direct downstream processor (depth 1)
	processorB := &ProcessorNode{
		ID:             "processor-b",
		ParentID:       "processor-a",
		HierarchyDepth: 1,
		Reachable:      true,
	}
	mgr.AddProcessor(processorB)

	// Route to processor-b
	decision, err := mgr.RouteToProcessor(context.Background(), "processor-b")
	require.NoError(t, err)
	assert.False(t, decision.IsLocal)
	assert.Equal(t, "processor-b", decision.DownstreamProcessorID)
	assert.Equal(t, int32(1), decision.Depth)
	// Timeout: 5s base + (1 hop * 500ms) = 5.5s
	assert.Equal(t, 5*time.Second+500*time.Millisecond, decision.RecommendedTimeout)
	assert.True(t, decision.TargetReachable)
}

// TestRouteToProcessor_MultiLevelHierarchy tests routing through multiple levels
func TestRouteToProcessor_MultiLevelHierarchy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Build hierarchy: A → B → C
	processorB := &ProcessorNode{
		ID:             "processor-b",
		ParentID:       "processor-a",
		HierarchyDepth: 1,
		Reachable:      true,
	}
	mgr.AddProcessor(processorB)

	processorC := &ProcessorNode{
		ID:             "processor-c",
		ParentID:       "processor-b",
		HierarchyDepth: 2,
		Reachable:      true,
	}
	mgr.AddProcessor(processorC)

	// Route to processor-c (should route through processor-b)
	decision, err := mgr.RouteToProcessor(context.Background(), "processor-c")
	require.NoError(t, err)
	assert.False(t, decision.IsLocal)
	assert.Equal(t, "processor-b", decision.DownstreamProcessorID) // Route through B
	assert.Equal(t, int32(2), decision.Depth)
	// Timeout: 5s base + (2 hops * 500ms) = 6s
	assert.Equal(t, 6*time.Second, decision.RecommendedTimeout)
	assert.True(t, decision.TargetReachable)
}

// TestRouteToProcessor_DeepHierarchy tests timeout scaling for deep hierarchies
func TestRouteToProcessor_DeepHierarchy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Build 7-level hierarchy: A → B → C → D → E → F → G
	processorB := &ProcessorNode{
		ID:             "processor-b",
		ParentID:       "processor-a",
		HierarchyDepth: 1,
		Reachable:      true,
	}
	mgr.AddProcessor(processorB)

	processorC := &ProcessorNode{
		ID:             "processor-c",
		ParentID:       "processor-b",
		HierarchyDepth: 2,
		Reachable:      true,
	}
	mgr.AddProcessor(processorC)

	processorD := &ProcessorNode{
		ID:             "processor-d",
		ParentID:       "processor-c",
		HierarchyDepth: 3,
		Reachable:      true,
	}
	mgr.AddProcessor(processorD)

	processorE := &ProcessorNode{
		ID:             "processor-e",
		ParentID:       "processor-d",
		HierarchyDepth: 4,
		Reachable:      true,
	}
	mgr.AddProcessor(processorE)

	processorF := &ProcessorNode{
		ID:             "processor-f",
		ParentID:       "processor-e",
		HierarchyDepth: 5,
		Reachable:      true,
	}
	mgr.AddProcessor(processorF)

	processorG := &ProcessorNode{
		ID:             "processor-g",
		ParentID:       "processor-f",
		HierarchyDepth: 6,
		Reachable:      true,
	}
	mgr.AddProcessor(processorG)

	// Route to processor-g (7-level chain)
	decision, err := mgr.RouteToProcessor(context.Background(), "processor-g")
	require.NoError(t, err)
	assert.False(t, decision.IsLocal)
	assert.Equal(t, "processor-b", decision.DownstreamProcessorID) // Still routes through B
	assert.Equal(t, int32(6), decision.Depth)
	// Timeout: 5s base + (6 hops * 500ms) = 8s
	assert.Equal(t, 8*time.Second, decision.RecommendedTimeout)
	assert.True(t, decision.TargetReachable)
}

// TestRouteToProcessor_UnreachableProcessor tests handling of unreachable processors
func TestRouteToProcessor_UnreachableProcessor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Add an unreachable processor
	processorB := &ProcessorNode{
		ID:                "processor-b",
		ParentID:          "processor-a",
		HierarchyDepth:    1,
		Reachable:         false,
		UnreachableReason: "connection timeout",
	}
	mgr.AddProcessor(processorB)

	// Attempt to route to unreachable processor
	decision, err := mgr.RouteToProcessor(context.Background(), "processor-b")
	assert.Error(t, err)
	assert.Nil(t, decision)
	assert.Contains(t, err.Error(), "unreachable")
	assert.Contains(t, err.Error(), "connection timeout")
}

// TestRouteToProcessor_NotFound tests handling of non-existent processor
func TestRouteToProcessor_NotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Attempt to route to non-existent processor
	decision, err := mgr.RouteToProcessor(context.Background(), "processor-nonexistent")
	assert.Error(t, err)
	assert.Nil(t, decision)
	assert.Contains(t, err.Error(), "not found")
}

// TestCalculateChainTimeout tests the timeout calculation function
func TestCalculateChainTimeout(t *testing.T) {
	tests := []struct {
		name     string
		hops     int32
		expected time.Duration
	}{
		{
			name:     "single hop",
			hops:     1,
			expected: 5*time.Second + 500*time.Millisecond,
		},
		{
			name:     "two hops",
			hops:     2,
			expected: 6 * time.Second,
		},
		{
			name:     "three hops",
			hops:     3,
			expected: 6*time.Second + 500*time.Millisecond,
		},
		{
			name:     "seven hops (deep hierarchy)",
			hops:     7,
			expected: 8*time.Second + 500*time.Millisecond,
		},
		{
			name:     "ten hops (maximum recommended)",
			hops:     10,
			expected: 10 * time.Second,
		},
		{
			name:     "zero hops (local)",
			hops:     0,
			expected: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateChainTimeout(tt.hops)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateRoutingConnection tests the connection validation
func TestValidateRoutingConnection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Add a reachable processor
	processorB := &ProcessorNode{
		ID:             "processor-b",
		ParentID:       "processor-a",
		HierarchyDepth: 1,
		Reachable:      true,
	}
	mgr.AddProcessor(processorB)

	// Validate reachable connection
	err := mgr.ValidateRoutingConnection("processor-b")
	assert.NoError(t, err)

	// Add an unreachable processor
	processorC := &ProcessorNode{
		ID:                "processor-c",
		ParentID:          "processor-a",
		HierarchyDepth:    1,
		Reachable:         false,
		UnreachableReason: "network partition",
	}
	mgr.AddProcessor(processorC)

	// Validate unreachable connection
	err = mgr.ValidateRoutingConnection("processor-c")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unreachable")
	assert.Contains(t, err.Error(), "network partition")

	// Validate non-existent processor
	err = mgr.ValidateRoutingConnection("processor-nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestFindDownstreamForTarget tests the downstream routing logic
func TestFindDownstreamForTarget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "processor-a")

	// Build hierarchy: A → B → C → D
	processorB := &ProcessorNode{
		ID:             "processor-b",
		ParentID:       "processor-a",
		HierarchyDepth: 1,
		Reachable:      true,
	}
	mgr.AddProcessor(processorB)

	processorC := &ProcessorNode{
		ID:             "processor-c",
		ParentID:       "processor-b",
		HierarchyDepth: 2,
		Reachable:      true,
	}
	mgr.AddProcessor(processorC)

	processorD := &ProcessorNode{
		ID:             "processor-d",
		ParentID:       "processor-c",
		HierarchyDepth: 3,
		Reachable:      true,
	}
	mgr.AddProcessor(processorD)

	// Test finding downstream for direct child
	downstream := mgr.FindDownstreamForTarget("processor-b")
	assert.Equal(t, "processor-b", downstream)

	// Test finding downstream for indirect child (should return direct child)
	downstream = mgr.FindDownstreamForTarget("processor-c")
	assert.Equal(t, "processor-b", downstream)

	downstream = mgr.FindDownstreamForTarget("processor-d")
	assert.Equal(t, "processor-b", downstream)

	// Test finding downstream for non-existent processor
	downstream = mgr.FindDownstreamForTarget("processor-nonexistent")
	assert.Equal(t, "", downstream)
}

// TestFormatRoutingError tests the routing error formatting
func TestFormatRoutingError(t *testing.T) {
	tests := []struct {
		name           string
		processorChain []string
		err            error
		expectedMsg    string
	}{
		{
			name:           "single processor",
			processorChain: []string{"processor-a"},
			err:            assert.AnError,
			expectedMsg:    "processor-a: assert.AnError",
		},
		{
			name:           "two processors",
			processorChain: []string{"processor-a", "processor-b"},
			err:            assert.AnError,
			expectedMsg:    "processor-a -> processor-b: assert.AnError",
		},
		{
			name:           "three processors",
			processorChain: []string{"processor-a", "processor-b", "processor-c"},
			err:            assert.AnError,
			expectedMsg:    "processor-a -> processor-b -> processor-c: assert.AnError",
		},
		{
			name:           "empty chain",
			processorChain: []string{},
			err:            assert.AnError,
			expectedMsg:    "assert.AnError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatRoutingError(tt.processorChain, tt.err)
			assert.Contains(t, result.Error(), tt.expectedMsg)
		})
	}
}
