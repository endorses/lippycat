//go:build tui || all

package store

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClient is a mock implementation of the Close() interface for testing
type mockClient struct {
	closed bool
}

func (m *mockClient) Close() {
	m.closed = true
}

func TestGetRootProcessorForAddress(t *testing.T) {
	tests := []struct {
		name           string
		setupHierarchy func(*ConnectionManager)
		targetAddr     string
		expectRoot     string
		expectError    bool
		errorContains  string
	}{
		{
			name: "directly connected processor is its own root",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:  "processor-a:50051",
			expectRoot:  "processor-a:50051",
			expectError: false,
		},
		{
			name: "two-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				// Root processor (connected to TUI)
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				// Downstream processor (not directly connected)
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr:  "processor-b:50051",
			expectRoot:  "processor-a:50051",
			expectError: false,
		},
		{
			name: "three-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				// Root processor (connected to TUI)
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				// Intermediate processor (not directly connected)
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
				// Leaf processor (not directly connected)
				cm.Processors["processor-c:50051"] = &ProcessorConnection{
					Address:      "processor-c:50051",
					ProcessorID:  "processor-c",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
			},
			targetAddr:  "processor-c:50051",
			expectRoot:  "processor-a:50051",
			expectError: false,
		},
		{
			name: "processor not found",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:    "processor-z:50051",
			expectRoot:    "",
			expectError:   true,
			errorContains: "not found in hierarchy",
		},
		{
			name: "no upstream and not connected",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateDisconnected,
					Client:       nil,
					UpstreamAddr: "",
				}
			},
			targetAddr:    "processor-a:50051",
			expectRoot:    "",
			expectError:   true,
			errorContains: "has no upstream and is not connected",
		},
		{
			name: "cycle detection",
			setupHierarchy: func(cm *ConnectionManager) {
				// Create a cycle: A -> B -> C -> A
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-c:50051",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
				cm.Processors["processor-c:50051"] = &ProcessorConnection{
					Address:      "processor-c:50051",
					ProcessorID:  "processor-c",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
			},
			targetAddr:    "processor-a:50051",
			expectRoot:    "",
			expectError:   true,
			errorContains: "cycle detected",
		},
		{
			name: "cache hit on second call",
			setupHierarchy: func(cm *ConnectionManager) {
				// Root processor (connected to TUI)
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				// Downstream processor (not directly connected)
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr:  "processor-b:50051",
			expectRoot:  "processor-a:50051",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConnectionManager()
			tt.setupHierarchy(cm)

			rootAddr, client, err := cm.GetRootProcessorForAddress(tt.targetAddr)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Empty(t, rootAddr)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectRoot, rootAddr)
				assert.NotNil(t, client)

				// For cache test, call again and verify cache is used
				if tt.name == "cache hit on second call" {
					rootAddr2, client2, err2 := cm.GetRootProcessorForAddress(tt.targetAddr)
					require.NoError(t, err2)
					assert.Equal(t, tt.expectRoot, rootAddr2)
					assert.NotNil(t, client2)
					assert.Equal(t, client, client2) // Same client instance
				}
			}
		})
	}
}

func TestInvalidateRootProcessorCache(t *testing.T) {
	cm := NewConnectionManager()

	// Setup hierarchy
	cm.Processors["processor-a:50051"] = &ProcessorConnection{
		Address:      "processor-a:50051",
		ProcessorID:  "processor-a",
		State:        ProcessorStateConnected,
		Client:       &mockClient{},
		UpstreamAddr: "",
	}
	cm.Processors["processor-b:50051"] = &ProcessorConnection{
		Address:      "processor-b:50051",
		ProcessorID:  "processor-b",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-a:50051",
	}

	// Populate cache
	rootAddr, _, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)
	assert.Equal(t, "processor-a:50051", rootAddr)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Invalidate specific entry
	cm.InvalidateRootProcessorCache("processor-b:50051")

	// Verify cache entry is removed
	cm.mu.RLock()
	assert.NotContains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Populate cache again
	_, _, err = cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Invalidate all entries
	cm.InvalidateRootProcessorCache("")

	// Verify all cache entries are removed
	cm.mu.RLock()
	assert.Empty(t, cm.rootProcessorCache)
	cm.mu.RUnlock()
}

func TestAddProcessorInvalidatesCache(t *testing.T) {
	cm := NewConnectionManager()

	// Setup hierarchy
	cm.Processors["processor-a:50051"] = &ProcessorConnection{
		Address:      "processor-a:50051",
		ProcessorID:  "processor-a",
		State:        ProcessorStateConnected,
		Client:       &mockClient{},
		UpstreamAddr: "",
	}
	cm.Processors["processor-b:50051"] = &ProcessorConnection{
		Address:      "processor-b:50051",
		ProcessorID:  "processor-b",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-a:50051",
	}

	// Populate cache
	_, _, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Add a new processor (should invalidate cache)
	cm.AddProcessor("processor-c:50051", &ProcessorConnection{
		Address:      "processor-c:50051",
		ProcessorID:  "processor-c",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-b:50051",
	})

	// Verify cache is cleared
	cm.mu.RLock()
	assert.Empty(t, cm.rootProcessorCache)
	cm.mu.RUnlock()
}

func TestRemoveProcessorInvalidatesCache(t *testing.T) {
	cm := NewConnectionManager()

	// Setup hierarchy
	cm.Processors["processor-a:50051"] = &ProcessorConnection{
		Address:      "processor-a:50051",
		ProcessorID:  "processor-a",
		State:        ProcessorStateConnected,
		Client:       &mockClient{},
		UpstreamAddr: "",
	}
	cm.Processors["processor-b:50051"] = &ProcessorConnection{
		Address:      "processor-b:50051",
		ProcessorID:  "processor-b",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-a:50051",
	}

	// Populate cache
	_, _, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Remove a processor (should invalidate cache)
	cm.RemoveProcessor("processor-b:50051")

	// Verify cache is cleared
	cm.mu.RLock()
	assert.Empty(t, cm.rootProcessorCache)
	cm.mu.RUnlock()
}

func TestCloseAllInvalidatesCache(t *testing.T) {
	cm := NewConnectionManager()

	// Setup hierarchy
	cm.Processors["processor-a:50051"] = &ProcessorConnection{
		Address:      "processor-a:50051",
		ProcessorID:  "processor-a",
		State:        ProcessorStateConnected,
		Client:       &mockClient{},
		UpstreamAddr: "",
	}
	cm.Processors["processor-b:50051"] = &ProcessorConnection{
		Address:      "processor-b:50051",
		ProcessorID:  "processor-b",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-a:50051",
	}

	// Populate cache
	_, _, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Close all (should invalidate cache)
	cm.CloseAll()

	// Verify cache is cleared
	cm.mu.RLock()
	assert.Empty(t, cm.rootProcessorCache)
	cm.mu.RUnlock()
}

func TestGetRootProcessorForAddress_DisconnectedRootInCache(t *testing.T) {
	cm := NewConnectionManager()

	// Setup hierarchy with connected root
	cm.Processors["processor-a:50051"] = &ProcessorConnection{
		Address:      "processor-a:50051",
		ProcessorID:  "processor-a",
		State:        ProcessorStateConnected,
		Client:       &mockClient{},
		UpstreamAddr: "",
	}
	cm.Processors["processor-b:50051"] = &ProcessorConnection{
		Address:      "processor-b:50051",
		ProcessorID:  "processor-b",
		State:        ProcessorStateUnknown,
		Client:       nil,
		UpstreamAddr: "processor-a:50051",
	}

	// Populate cache
	rootAddr, _, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.NoError(t, err)
	assert.Equal(t, "processor-a:50051", rootAddr)

	// Verify cache is populated
	cm.mu.RLock()
	assert.Contains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()

	// Disconnect the root processor
	cm.Processors["processor-a:50051"].State = ProcessorStateDisconnected
	cm.Processors["processor-a:50051"].Client = nil

	// Try to get root again - should detect stale cache and return error
	rootAddr, client, err := cm.GetRootProcessorForAddress("processor-b:50051")
	require.Error(t, err)
	assert.Empty(t, rootAddr)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "has no upstream and is not connected")

	// Verify stale cache entry was removed
	cm.mu.RLock()
	assert.NotContains(t, cm.rootProcessorCache, "processor-b:50051")
	cm.mu.RUnlock()
}

func TestGetHierarchyDepth(t *testing.T) {
	tests := []struct {
		name           string
		setupHierarchy func(*ConnectionManager)
		targetAddr     string
		expectDepth    int
	}{
		{
			name: "directly connected processor has depth 0",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:  "processor-a:50051",
			expectDepth: 0,
		},
		{
			name: "two-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr:  "processor-b:50051",
			expectDepth: 1,
		},
		{
			name: "three-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
				cm.Processors["processor-c:50051"] = &ProcessorConnection{
					Address:      "processor-c:50051",
					ProcessorID:  "processor-c",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
			},
			targetAddr:  "processor-c:50051",
			expectDepth: 2,
		},
		{
			name: "processor not found returns -1",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:  "processor-z:50051",
			expectDepth: -1,
		},
		{
			name: "cycle detected returns -1",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr:  "processor-a:50051",
			expectDepth: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConnectionManager()
			tt.setupHierarchy(cm)

			depth := cm.GetHierarchyDepth(tt.targetAddr)
			assert.Equal(t, tt.expectDepth, depth)
		})
	}
}

func TestGetProcessorPath(t *testing.T) {
	tests := []struct {
		name           string
		setupHierarchy func(*ConnectionManager)
		targetAddr     string
		expectPath     []string
	}{
		{
			name: "directly connected processor",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr: "processor-a:50051",
			expectPath: []string{"processor-a:50051"},
		},
		{
			name: "two-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr: "processor-b:50051",
			expectPath: []string{"processor-a:50051", "processor-b:50051"},
		},
		{
			name: "three-level hierarchy",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
				cm.Processors["processor-c:50051"] = &ProcessorConnection{
					Address:      "processor-c:50051",
					ProcessorID:  "processor-c",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
			},
			targetAddr: "processor-c:50051",
			expectPath: []string{"processor-a:50051", "processor-b:50051", "processor-c:50051"},
		},
		{
			name: "processor not found returns nil",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr: "processor-z:50051",
			expectPath: nil,
		},
		{
			name: "cycle detected returns nil",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-b:50051",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr: "processor-a:50051",
			expectPath: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConnectionManager()
			tt.setupHierarchy(cm)

			path := cm.GetProcessorPath(tt.targetAddr)
			assert.Equal(t, tt.expectPath, path)
		})
	}
}

func TestEstimateOperationLatency(t *testing.T) {
	tests := []struct {
		name           string
		setupHierarchy func(*ConnectionManager)
		targetAddr     string
		expectLatency  int
	}{
		{
			name: "directly connected processor (depth 0)",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:    "processor-a:50051",
			expectLatency: 100, // Base latency
		},
		{
			name: "depth 1 processor",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				cm.Processors["processor-b:50051"] = &ProcessorConnection{
					Address:      "processor-b:50051",
					ProcessorID:  "processor-b",
					State:        ProcessorStateUnknown,
					Client:       nil,
					UpstreamAddr: "processor-a:50051",
				}
			},
			targetAddr:    "processor-b:50051",
			expectLatency: 150, // 100 + (1 * 50)
		},
		{
			name: "depth 7 processor (warning threshold)",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
				currentUpstream := "processor-a:50051"
				for i := 1; i <= 7; i++ {
					addr := fmt.Sprintf("processor-%d:50051", i)
					cm.Processors[addr] = &ProcessorConnection{
						Address:      addr,
						ProcessorID:  fmt.Sprintf("processor-%d", i),
						State:        ProcessorStateUnknown,
						Client:       nil,
						UpstreamAddr: currentUpstream,
					}
					currentUpstream = addr
				}
			},
			targetAddr:    "processor-7:50051",
			expectLatency: 450, // 100 + (7 * 50)
		},
		{
			name: "processor not found returns -1",
			setupHierarchy: func(cm *ConnectionManager) {
				cm.Processors["processor-a:50051"] = &ProcessorConnection{
					Address:      "processor-a:50051",
					ProcessorID:  "processor-a",
					State:        ProcessorStateConnected,
					Client:       &mockClient{},
					UpstreamAddr: "",
				}
			},
			targetAddr:    "processor-z:50051",
			expectLatency: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewConnectionManager()
			tt.setupHierarchy(cm)

			latency := cm.EstimateOperationLatency(tt.targetAddr)
			assert.Equal(t, tt.expectLatency, latency)
		})
	}
}
