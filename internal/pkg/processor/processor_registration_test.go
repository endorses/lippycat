//go:build processor || tap || all

package processor

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterProcessor_CycleDetection tests that cycles in the processor hierarchy are detected and rejected
func TestRegisterProcessor_CycleDetection(t *testing.T) {
	tests := []struct {
		name          string
		processorID   string
		upstreamChain []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "no cycle - empty upstream chain",
			processorID:   "downstream-1",
			upstreamChain: []string{},
			expectError:   false,
		},
		{
			name:          "no cycle - upstream chain without current processor",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "intermediate"},
			expectError:   false,
		},
		{
			name:          "cycle detected - current processor in chain",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "test-processor", "intermediate"},
			expectError:   true,
			errorContains: "cycle detected",
		},
		{
			name:          "cycle detected - current processor at start of chain",
			processorID:   "downstream-1",
			upstreamChain: []string{"test-processor", "intermediate"},
			expectError:   true,
			errorContains: "cycle detected",
		},
		{
			name:          "cycle detected - current processor at end of chain",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "intermediate", "test-processor"},
			expectError:   true,
			errorContains: "cycle detected",
		},
		{
			name:          "cycle detected - simple A -> B -> A case",
			processorID:   "processor-a",
			upstreamChain: []string{"test-processor"},
			expectError:   true,
			errorContains: "cycle detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create processor with ID "test-processor"
			processor, err := New(Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
			})
			require.NoError(t, err)
			require.NotNil(t, processor)

			// Attempt to register a downstream processor
			req := &management.ProcessorRegistration{
				ProcessorId:   tt.processorID,
				ListenAddress: "localhost:50052",
				Version:       "v1.0.0",
				UpstreamChain: tt.upstreamChain,
			}

			resp, err := processor.RegisterProcessor(context.Background(), req)
			require.NoError(t, err, "RPC call should not return gRPC error")
			require.NotNil(t, resp)

			if tt.expectError {
				assert.False(t, resp.Accepted, "registration should be rejected for cycle")
				assert.Contains(t, resp.Error, tt.errorContains, "error message should contain expected text")
			} else {
				assert.True(t, resp.Accepted, "registration should be accepted")
				assert.Empty(t, resp.Error, "error should be empty for successful registration")
			}
		})
	}
}

// TestRegisterProcessor_DepthLimit tests that hierarchy depth limits are enforced
func TestRegisterProcessor_DepthLimit(t *testing.T) {
	tests := []struct {
		name          string
		upstreamChain []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "depth 0 - direct connection",
			upstreamChain: []string{},
			expectError:   false,
		},
		{
			name:          "depth 1 - one upstream",
			upstreamChain: []string{"root"},
			expectError:   false,
		},
		{
			name:          "depth 5 - medium chain",
			upstreamChain: []string{"root", "p1", "p2", "p3", "p4"},
			expectError:   false,
		},
		{
			name:          "depth 9 - near limit",
			upstreamChain: []string{"root", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"},
			expectError:   false,
		},
		{
			name:          "depth 10 - at limit",
			upstreamChain: []string{"root", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"},
			expectError:   true,
			errorContains: "hierarchy depth 11 exceeds maximum allowed depth 10",
		},
		{
			name:          "depth 15 - well over limit",
			upstreamChain: []string{"root", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14"},
			expectError:   true,
			errorContains: "hierarchy depth 16 exceeds maximum allowed depth 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create processor
			processor, err := New(Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
			})
			require.NoError(t, err)
			require.NotNil(t, processor)

			// Attempt to register a downstream processor
			req := &management.ProcessorRegistration{
				ProcessorId:   "downstream-1",
				ListenAddress: "localhost:50052",
				Version:       "v1.0.0",
				UpstreamChain: tt.upstreamChain,
			}

			resp, err := processor.RegisterProcessor(context.Background(), req)
			require.NoError(t, err, "RPC call should not return gRPC error")
			require.NotNil(t, resp)

			if tt.expectError {
				assert.False(t, resp.Accepted, "registration should be rejected for depth limit")
				assert.Contains(t, resp.Error, tt.errorContains, "error message should contain expected text")
			} else {
				assert.True(t, resp.Accepted, "registration should be accepted")
				assert.Empty(t, resp.Error, "error should be empty for successful registration")
			}
		})
	}
}

// TestRegisterProcessor_CombinedValidation tests both cycle detection and depth limit together
func TestRegisterProcessor_CombinedValidation(t *testing.T) {
	tests := []struct {
		name          string
		processorID   string
		upstreamChain []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "valid - no cycle, within depth",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "p1", "p2"},
			expectError:   false,
		},
		{
			name:          "cycle detected - checked before depth limit",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "p1", "p2", "test-processor", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"},
			expectError:   true,
			errorContains: "hierarchy depth", // Depth check happens first
		},
		{
			name:          "depth limit with cycle - depth checked first",
			processorID:   "downstream-1",
			upstreamChain: []string{"root", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"},
			expectError:   true,
			errorContains: "hierarchy depth", // Depth limit is checked before cycle
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create processor with ID "test-processor"
			processor, err := New(Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
			})
			require.NoError(t, err)
			require.NotNil(t, processor)

			// Attempt to register a downstream processor
			req := &management.ProcessorRegistration{
				ProcessorId:   tt.processorID,
				ListenAddress: "localhost:50052",
				Version:       "v1.0.0",
				UpstreamChain: tt.upstreamChain,
			}

			resp, err := processor.RegisterProcessor(context.Background(), req)
			require.NoError(t, err, "RPC call should not return gRPC error")
			require.NotNil(t, resp)

			if tt.expectError {
				assert.False(t, resp.Accepted, "registration should be rejected")
				assert.Contains(t, resp.Error, tt.errorContains, "error message should contain expected text")
			} else {
				assert.True(t, resp.Accepted, "registration should be accepted")
				assert.Empty(t, resp.Error, "error should be empty for successful registration")
			}
		})
	}
}
