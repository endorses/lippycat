package voip

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCPUAffinityManager(t *testing.T) {
	cam := NewCPUAffinityManager()

	assert.NotNil(t, cam)
	assert.Equal(t, runtime.NumCPU(), cam.numCPUs)
	assert.NotNil(t, cam.pinnedCores)
}

func TestGetTopology(t *testing.T) {
	topo, err := GetTopology()
	assert.NoError(t, err)
	assert.NotNil(t, topo)

	assert.Greater(t, topo.NumCPUs, 0)
	assert.Greater(t, topo.NumNUMANodes, 0)
	assert.Equal(t, topo.NumCPUs, len(topo.CPUList))

	t.Logf("Topology: %d CPUs, %d NUMA nodes, SMT=%v",
		topo.NumCPUs, topo.NumNUMANodes, topo.SMTEnabled)
}

func TestGetNextAvailableCPU(t *testing.T) {
	cam := NewCPUAffinityManager()

	// Get several CPUs
	cpus := make(map[int]bool)
	for i := 0; i < cam.numCPUs*2; i++ {
		cpu := cam.GetNextAvailableCPU()
		cpus[cpu] = true
		assert.GreaterOrEqual(t, cpu, 0)
		assert.Less(t, cpu, cam.numCPUs)
	}

	// Should have seen all CPUs
	assert.Equal(t, cam.numCPUs, len(cpus))
}

func TestGetCurrentCPU(t *testing.T) {
	cpu, err := GetCurrentCPU()
	if err != nil {
		t.Skip("GetCurrentCPU not available on this system")
	}

	assert.GreaterOrEqual(t, cpu, 0)
	assert.Less(t, cpu, runtime.NumCPU())

	t.Logf("Current CPU: %d", cpu)
}

func TestDistributeCPUs(t *testing.T) {
	tests := []struct {
		name       string
		numWorkers int
	}{
		{"single worker", 1},
		{"few workers", 4},
		{"many workers", runtime.NumCPU()},
		{"more than CPUs", runtime.NumCPU() * 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpus := DistributeCPUs(tt.numWorkers)

			assert.Equal(t, tt.numWorkers, len(cpus))

			// All CPUs should be valid
			for _, cpu := range cpus {
				assert.GreaterOrEqual(t, cpu, 0)
				assert.Less(t, cpu, runtime.NumCPU())
			}

			t.Logf("Distributed %d workers across CPUs: %v", tt.numWorkers, cpus)
		})
	}
}

func TestOptimalCPUForCapture(t *testing.T) {
	cpu, err := OptimalCPUForCapture("eth0")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, cpu, 0)
	assert.Less(t, cpu, runtime.NumCPU())

	t.Logf("Optimal CPU for eth0: %d", cpu)
}

func TestCPUTopologyInfo(t *testing.T) {
	topo, err := GetTopology()
	assert.NoError(t, err)

	// Log detailed topology
	t.Logf("CPU Topology:")
	t.Logf("  Total CPUs: %d", topo.NumCPUs)
	t.Logf("  NUMA Nodes: %d", topo.NumNUMANodes)
	t.Logf("  Cores/NUMA: %d", topo.CoresPerNUMA)
	t.Logf("  SMT: %v", topo.SMTEnabled)

	// Verify consistency
	if topo.NumNUMANodes > 0 {
		expectedCores := topo.NumCPUs / topo.NumNUMANodes
		assert.Equal(t, expectedCores, topo.CoresPerNUMA)
	}
}

func BenchmarkGetCurrentCPU(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = GetCurrentCPU()
	}
}

func BenchmarkGetNextAvailableCPU(b *testing.B) {
	cam := NewCPUAffinityManager()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cam.GetNextAvailableCPU()
	}
}