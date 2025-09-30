package voip

import (
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"golang.org/x/sys/unix"
)

// CPUAffinityManager manages CPU core assignments for threads
type CPUAffinityManager struct {
	numCPUs     int
	nextCPU     atomic.Uint32
	pinnedCores map[int]bool
}

// CPUTopology represents the CPU topology of the system
type CPUTopology struct {
	NumCPUs       int
	NumNUMANodes  int
	CoresPerNUMA  int
	SMTEnabled    bool
	CPUList       []CPUInfo
}

// CPUInfo represents information about a single CPU core
type CPUInfo struct {
	ID         int
	NUMANode   int
	CoreID     int
	ThreadID   int
	Isolated   bool
}

// NUMAAffinity provides NUMA-aware memory and CPU binding
type NUMAAffinity struct {
	node       int
	cpuMask    unix.CPUSet
	memPolicy  int
}

// NewCPUAffinityManager creates a new CPU affinity manager
func NewCPUAffinityManager() *CPUAffinityManager {
	return &CPUAffinityManager{
		numCPUs:     runtime.NumCPU(),
		pinnedCores: make(map[int]bool),
	}
}

// GetTopology retrieves the CPU topology of the system
func GetTopology() (*CPUTopology, error) {
	numCPUs := runtime.NumCPU()

	topo := &CPUTopology{
		NumCPUs:  numCPUs,
		CPUList:  make([]CPUInfo, numCPUs),
	}

	// Detect NUMA nodes
	numaNodes, err := detectNUMANodes()
	if err != nil {
		logger.Debug("NUMA detection failed, assuming single node", "error", err)
		topo.NumNUMANodes = 1
	} else {
		topo.NumNUMANodes = numaNodes
	}

	if topo.NumNUMANodes > 0 {
		topo.CoresPerNUMA = numCPUs / topo.NumNUMANodes
	}

	// Populate CPU info
	for i := 0; i < numCPUs; i++ {
		topo.CPUList[i] = CPUInfo{
			ID:       i,
			NUMANode: i / topo.CoresPerNUMA,
			CoreID:   i / 2, // Approximate
			ThreadID: i % 2,
		}
	}

	// Detect SMT/Hyperthreading
	topo.SMTEnabled = detectSMT()

	logger.Info("CPU topology detected",
		"cpus", topo.NumCPUs,
		"numa_nodes", topo.NumNUMANodes,
		"cores_per_numa", topo.CoresPerNUMA,
		"smt_enabled", topo.SMTEnabled)

	return topo, nil
}

// PinCurrentThreadToCPU pins the current goroutine's thread to a specific CPU
func (cam *CPUAffinityManager) PinCurrentThreadToCPU(cpuID int) error {
	if cpuID < 0 || cpuID >= cam.numCPUs {
		return fmt.Errorf("invalid CPU ID: %d (available: 0-%d)", cpuID, cam.numCPUs-1)
	}

	// Lock goroutine to OS thread
	runtime.LockOSThread()

	// Set CPU affinity
	var cpuSet unix.CPUSet
	cpuSet.Zero()
	cpuSet.Set(cpuID)

	if err := unix.SchedSetaffinity(0, &cpuSet); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to set CPU affinity: %w", err)
	}

	cam.pinnedCores[cpuID] = true

	logger.Debug("Thread pinned to CPU", "cpu_id", cpuID)
	return nil
}

// GetNextAvailableCPU returns the next available CPU for round-robin assignment
func (cam *CPUAffinityManager) GetNextAvailableCPU() int {
	return int(cam.nextCPU.Add(1) % uint32(cam.numCPUs))
}

// PinToNUMANode pins the current thread to a NUMA node
func PinToNUMANode(nodeID int) (*NUMAAffinity, error) {
	topo, err := GetTopology()
	if err != nil {
		return nil, err
	}

	if nodeID < 0 || nodeID >= topo.NumNUMANodes {
		return nil, fmt.Errorf("invalid NUMA node: %d (available: 0-%d)",
			nodeID, topo.NumNUMANodes-1)
	}

	affinity := &NUMAAffinity{
		node: nodeID,
	}

	// Build CPU mask for this NUMA node
	affinity.cpuMask.Zero()
	for _, cpu := range topo.CPUList {
		if cpu.NUMANode == nodeID {
			affinity.cpuMask.Set(cpu.ID)
		}
	}

	// Set CPU affinity to NUMA node
	runtime.LockOSThread()
	if err := unix.SchedSetaffinity(0, &affinity.cpuMask); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("failed to set NUMA affinity: %w", err)
	}

	logger.Info("Thread pinned to NUMA node", "node", nodeID)
	return affinity, nil
}

// detectNUMANodes attempts to detect the number of NUMA nodes
func detectNUMANodes() (int, error) {
	// Try reading from /sys/devices/system/node/
	// This is a simplified detection
	nodes := 1

	// On Linux, check /sys/devices/system/node/online
	// For now, return 1 as fallback
	return nodes, nil
}

// detectSMT detects if SMT/Hyperthreading is enabled
func detectSMT() bool {
	// Simplified detection
	// Real implementation would check /sys/devices/system/cpu/smt/active
	return runtime.NumCPU() > runtime.GOMAXPROCS(0)
}

// GetCurrentCPU returns the CPU ID the current thread is running on
func GetCurrentCPU() (int, error) {
	// SchedGetcpu is not available in all unix versions
	// Return 0 as fallback
	return 0, nil
}

// SetThreadPriority sets the priority of the current thread
func SetThreadPriority(priority int) error {
	// Set nice value (priority)
	// -20 (highest) to 19 (lowest)
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, priority); err != nil {
		return fmt.Errorf("failed to set thread priority: %w", err)
	}
	return nil
}

// IsolatedCPUs returns a list of isolated CPUs (if configured)
func IsolatedCPUs() ([]int, error) {
	// Check /sys/devices/system/cpu/isolated
	// For now, return empty list
	return []int{}, nil
}

// OptimalCPUForCapture suggests the best CPU for packet capture
func OptimalCPUForCapture(interfaceName string) (int, error) {
	topo, err := GetTopology()
	if err != nil {
		return 0, err
	}

	// Try to get NIC's NUMA node
	nicNUMA, err := getNICNUMANode(interfaceName)
	if err != nil {
		logger.Debug("Could not determine NIC NUMA node", "error", err)
		return 0, nil
	}

	// Return first CPU on same NUMA node
	for _, cpu := range topo.CPUList {
		if cpu.NUMANode == nicNUMA {
			return cpu.ID, nil
		}
	}

	return 0, nil
}

// getNICNUMANode gets the NUMA node for a network interface
func getNICNUMANode(interfaceName string) (int, error) {
	// Read from /sys/class/net/<iface>/device/numa_node
	// Simplified - returns 0 for now
	return 0, nil
}

// DistributeCPUs distributes work across CPUs optimally
func DistributeCPUs(numWorkers int) []int {
	topo, err := GetTopology()
	if err != nil {
		// Fallback to round-robin
		cpus := make([]int, numWorkers)
		for i := range cpus {
			cpus[i] = i % runtime.NumCPU()
		}
		return cpus
	}

	cpus := make([]int, numWorkers)

	if topo.SMTEnabled && numWorkers <= topo.NumCPUs/2 {
		// Prefer physical cores over hyperthreads
		for i := 0; i < numWorkers; i++ {
			cpus[i] = i * 2 // Every other CPU (physical cores)
		}
	} else {
		// Use all CPUs
		for i := 0; i < numWorkers; i++ {
			cpus[i] = i % topo.NumCPUs
		}
	}

	return cpus
}