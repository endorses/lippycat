package voip

import (
	"fmt"
	"runtime"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// PerCPUQueue provides lock-free per-CPU packet queues
type PerCPUQueue struct {
	queues   []CPUQueue
	numCPUs  int
	strategy DistributionStrategy
}

// CPUQueue represents a single CPU's packet queue
type CPUQueue struct {
	_       CachePadding
	packets chan []byte
	stats   QueueStats
	cpuID   int
	_       CachePadding
}

// QueueStats holds per-queue statistics
type QueueStats struct {
	Enqueued  PaddedCounter
	Dequeued  PaddedCounter
	Dropped   PaddedCounter
	QueueFull PaddedCounter
}

// DistributionStrategy determines how packets are distributed
type DistributionStrategy int

const (
	// StrategyRoundRobin distributes packets in round-robin fashion
	StrategyRoundRobin DistributionStrategy = iota
	// StrategyFlowHash distributes by flow hash (5-tuple)
	StrategyFlowHash
	// StrategyCallID distributes by Call-ID hash
	StrategyCallID
	// StrategyRandom distributes randomly
	StrategyRandom
)

// PerCPUQueueConfig configures per-CPU queues
type PerCPUQueueConfig struct {
	NumQueues   int
	QueueSize   int
	Strategy    DistributionStrategy
	EnableStats bool
}

// NewPerCPUQueue creates a new per-CPU queue system
func NewPerCPUQueue(config *PerCPUQueueConfig) *PerCPUQueue {
	if config == nil {
		config = DefaultPerCPUQueueConfig()
	}

	numCPUs := config.NumQueues
	if numCPUs == 0 {
		numCPUs = runtime.NumCPU()
	}

	pcq := &PerCPUQueue{
		queues:   make([]CPUQueue, numCPUs),
		numCPUs:  numCPUs,
		strategy: config.Strategy,
	}

	// Initialize per-CPU queues
	for i := 0; i < numCPUs; i++ {
		pcq.queues[i] = CPUQueue{
			packets: make(chan []byte, config.QueueSize),
			cpuID:   i,
		}
	}

	logger.Info("Per-CPU queues initialized",
		"num_queues", numCPUs,
		"queue_size", config.QueueSize,
		"strategy", config.Strategy)

	return pcq
}

// DefaultPerCPUQueueConfig returns default configuration
func DefaultPerCPUQueueConfig() *PerCPUQueueConfig {
	return &PerCPUQueueConfig{
		NumQueues:   runtime.NumCPU(),
		QueueSize:   1000,
		Strategy:    StrategyFlowHash,
		EnableStats: true,
	}
}

// Enqueue adds a packet to the appropriate CPU queue
func (pcq *PerCPUQueue) Enqueue(pkt []byte, hash uint32) error {
	// Select queue based on strategy
	queueID := pcq.selectQueue(hash)

	queue := &pcq.queues[queueID]

	// Try non-blocking send
	select {
	case queue.packets <- pkt:
		queue.stats.Enqueued.Inc()
		return nil
	default:
		// Queue full
		queue.stats.QueueFull.Inc()
		queue.stats.Dropped.Inc()
		return fmt.Errorf("queue %d full", queueID)
	}
}

// EnqueueToCPU adds a packet to a specific CPU queue
func (pcq *PerCPUQueue) EnqueueToCPU(cpuID int, pkt []byte) error {
	if cpuID < 0 || cpuID >= pcq.numCPUs {
		return fmt.Errorf("invalid CPU ID: %d", cpuID)
	}

	queue := &pcq.queues[cpuID]

	select {
	case queue.packets <- pkt:
		queue.stats.Enqueued.Inc()
		return nil
	default:
		queue.stats.QueueFull.Inc()
		queue.stats.Dropped.Inc()
		return fmt.Errorf("queue %d full", cpuID)
	}
}

// Dequeue gets a packet from a specific CPU queue
func (pcq *PerCPUQueue) Dequeue(cpuID int) ([]byte, bool) {
	if cpuID < 0 || cpuID >= pcq.numCPUs {
		return nil, false
	}

	queue := &pcq.queues[cpuID]

	select {
	case pkt := <-queue.packets:
		queue.stats.Dequeued.Inc()
		return pkt, true
	default:
		return nil, false
	}
}

// GetQueue returns the channel for a specific CPU queue
func (pcq *PerCPUQueue) GetQueue(cpuID int) <-chan []byte {
	if cpuID < 0 || cpuID >= pcq.numCPUs {
		return nil
	}
	return pcq.queues[cpuID].packets
}

// selectQueue selects the appropriate queue based on strategy
func (pcq *PerCPUQueue) selectQueue(hash uint32) int {
	switch pcq.strategy {
	case StrategyRoundRobin:
		// Use hash as pseudo-round-robin
		return int(hash % uint32(pcq.numCPUs))
	case StrategyFlowHash, StrategyCallID:
		// Hash-based distribution
		return int(hash % uint32(pcq.numCPUs))
	case StrategyRandom:
		// Use hash as random
		return int(hash % uint32(pcq.numCPUs))
	default:
		return 0
	}
}

// GetStats returns statistics for a specific queue
func (pcq *PerCPUQueue) GetStats(cpuID int) *QueueStats {
	if cpuID < 0 || cpuID >= pcq.numCPUs {
		return nil
	}
	return &pcq.queues[cpuID].stats
}

// GetTotalStats returns aggregate statistics across all queues
func (pcq *PerCPUQueue) GetTotalStats() QueueStats {
	var total QueueStats

	for i := 0; i < pcq.numCPUs; i++ {
		stats := &pcq.queues[i].stats
		total.Enqueued.Add(stats.Enqueued.Get())
		total.Dequeued.Add(stats.Dequeued.Get())
		total.Dropped.Add(stats.Dropped.Get())
		total.QueueFull.Add(stats.QueueFull.Get())
	}

	return total
}

// GetLoad returns the load for each queue (0.0-1.0)
func (pcq *PerCPUQueue) GetLoad() []float64 {
	loads := make([]float64, pcq.numCPUs)

	for i := 0; i < pcq.numCPUs; i++ {
		queue := &pcq.queues[i]
		queueLen := len(queue.packets)
		queueCap := cap(queue.packets)
		if queueCap > 0 {
			loads[i] = float64(queueLen) / float64(queueCap)
		}
	}

	return loads
}

// NumQueues returns the number of queues
func (pcq *PerCPUQueue) NumQueues() int {
	return pcq.numCPUs
}

// Close closes all queues
func (pcq *PerCPUQueue) Close() {
	for i := 0; i < pcq.numCPUs; i++ {
		close(pcq.queues[i].packets)
	}
}

// WorkStealingQueue implements work-stealing for load balancing
type WorkStealingQueue struct {
	queues     []CPUQueue
	numCPUs    int
	stealStats []PaddedCounter // Steal attempts per CPU
}

// NewWorkStealingQueue creates a work-stealing queue system
func NewWorkStealingQueue(config *PerCPUQueueConfig) *WorkStealingQueue {
	if config == nil {
		config = DefaultPerCPUQueueConfig()
	}

	numCPUs := config.NumQueues
	if numCPUs == 0 {
		numCPUs = runtime.NumCPU()
	}

	wsq := &WorkStealingQueue{
		queues:     make([]CPUQueue, numCPUs),
		numCPUs:    numCPUs,
		stealStats: make([]PaddedCounter, numCPUs),
	}

	for i := 0; i < numCPUs; i++ {
		wsq.queues[i] = CPUQueue{
			packets: make(chan []byte, config.QueueSize),
			cpuID:   i,
		}
	}

	logger.Info("Work-stealing queues initialized",
		"num_queues", numCPUs,
		"queue_size", config.QueueSize)

	return wsq
}

// Enqueue adds work to a specific queue
func (wsq *WorkStealingQueue) Enqueue(cpuID int, pkt []byte) error {
	if cpuID < 0 || cpuID >= wsq.numCPUs {
		return fmt.Errorf("invalid CPU ID: %d", cpuID)
	}

	queue := &wsq.queues[cpuID]

	select {
	case queue.packets <- pkt:
		queue.stats.Enqueued.Inc()
		return nil
	default:
		queue.stats.QueueFull.Inc()
		return fmt.Errorf("queue %d full", cpuID)
	}
}

// Dequeue attempts to dequeue from local queue, then steals from others
func (wsq *WorkStealingQueue) Dequeue(cpuID int) ([]byte, bool) {
	if cpuID < 0 || cpuID >= wsq.numCPUs {
		return nil, false
	}

	// Try local queue first
	queue := &wsq.queues[cpuID]
	select {
	case pkt := <-queue.packets:
		queue.stats.Dequeued.Inc()
		return pkt, true
	default:
	}

	// Try stealing from other queues
	for i := 1; i < wsq.numCPUs; i++ {
		victimID := (cpuID + i) % wsq.numCPUs
		victimQueue := &wsq.queues[victimID]

		select {
		case pkt := <-victimQueue.packets:
			victimQueue.stats.Dequeued.Inc()
			wsq.stealStats[cpuID].Inc()
			return pkt, true
		default:
		}
	}

	return nil, false
}

// GetStealStats returns steal statistics for a CPU
func (wsq *WorkStealingQueue) GetStealStats(cpuID int) uint64 {
	if cpuID < 0 || cpuID >= wsq.numCPUs {
		return 0
	}
	return wsq.stealStats[cpuID].Get()
}

// Close closes all queues
func (wsq *WorkStealingQueue) Close() {
	for i := 0; i < wsq.numCPUs; i++ {
		close(wsq.queues[i].packets)
	}
}

// FlowHash computes a hash for packet distribution
func FlowHash(srcIP, dstIP uint32, srcPort, dstPort uint16, proto uint8) uint32 {
	// Simple 5-tuple hash
	hash := srcIP
	hash = hash*31 + dstIP
	hash = hash*31 + uint32(srcPort)
	hash = hash*31 + uint32(dstPort)
	hash = hash*31 + uint32(proto)
	return hash
}

// CallIDHash computes a hash from a Call-ID string
func CallIDHash(callID string) uint32 {
	// FNV-1a hash
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)

	hash := uint32(offset32)
	for i := 0; i < len(callID); i++ {
		hash ^= uint32(callID[i])
		hash *= prime32
	}
	return hash
}
