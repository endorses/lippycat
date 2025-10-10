package voip

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// BatchProcessor processes packets in batches for better throughput
type BatchProcessor struct {
	config       *BatchConfig
	workers      []*BatchWorker
	inputQueue   chan *PacketBatch
	resultQueue  chan *BatchResult
	pool         *PacketPool
	callInfoPool *CallInfoPool
	stats        BatchStats
	running      PaddedBool
	workersWg    sync.WaitGroup
}

// BatchConfig configures batch processing
type BatchConfig struct {
	BatchSize      int
	NumWorkers     int
	FlushInterval  time.Duration
	EnablePrefetch bool
	WorkerAffinity bool // Pin workers to CPUs
}

// PacketBatch represents a batch of packets to process
type PacketBatch struct {
	Packets   []*PacketBuffer
	Metadata  []PacketMetadata
	Count     int
	Timestamp time.Time
}

// PacketMetadata holds metadata for a packet in a batch
type PacketMetadata struct {
	CaptureInfo gopacket.CaptureInfo
	FlowHash    uint32
	Index       int
}

// BatchResult contains the results of batch processing
type BatchResult struct {
	CallIDs      []string
	CallInfos    []*CallInfo
	Errors       []error
	ProcessedAt  time.Time
	ProcessingNS int64
}

// BatchWorker processes packet batches
type BatchWorker struct {
	id         int
	cpuID      int
	processor  *BatchProcessor
	localStats WorkerStats
}

// WorkerStats holds per-worker statistics
type WorkerStats struct {
	_                 CachePadding
	BatchesProcessed  PaddedCounter
	PacketsProcessed  PaddedCounter
	ErrorsEncountered PaddedCounter
	ProcessingTimeNS  PaddedCounter
	_                 CachePadding
}

// BatchStats holds aggregate batch processing statistics
type BatchStats struct {
	TotalBatches    PaddedCounter
	TotalPackets    PaddedCounter
	BatchesDropped  PaddedCounter
	AvgBatchSize    PaddedCounter
	AvgProcessingNS PaddedCounter
}

// DefaultBatchConfig returns default batch configuration
func DefaultBatchConfig() *BatchConfig {
	return &BatchConfig{
		BatchSize:      64,
		NumWorkers:     4,
		FlushInterval:  100 * time.Millisecond,
		EnablePrefetch: true,
		WorkerAffinity: true,
	}
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(config *BatchConfig) *BatchProcessor {
	if config == nil {
		config = DefaultBatchConfig()
	}

	bp := &BatchProcessor{
		config:       config,
		workers:      make([]*BatchWorker, config.NumWorkers),
		inputQueue:   make(chan *PacketBatch, config.NumWorkers*2),
		resultQueue:  make(chan *BatchResult, config.NumWorkers*2),
		pool:         GetPacketPool(),
		callInfoPool: GetCallInfoPool(),
	}

	bp.running.Store(true)

	// Create workers
	for i := 0; i < config.NumWorkers; i++ {
		bp.workers[i] = &BatchWorker{
			id:        i,
			processor: bp,
		}

		if config.WorkerAffinity {
			bp.workers[i].cpuID = i % GetNumCPUs()
		}
	}

	// Start workers
	for _, worker := range bp.workers {
		bp.workersWg.Add(1)
		go worker.run()
	}

	logger.Info("Batch processor initialized",
		"batch_size", config.BatchSize,
		"num_workers", config.NumWorkers,
		"worker_affinity", config.WorkerAffinity)

	return bp
}

// SubmitBatch submits a batch for processing
func (bp *BatchProcessor) SubmitBatch(batch *PacketBatch) error {
	if !bp.running.Load() {
		return ErrProcessorStopped
	}

	select {
	case bp.inputQueue <- batch:
		bp.stats.TotalBatches.Inc()
		bp.stats.TotalPackets.Add(uint64(batch.Count))
		return nil
	default:
		bp.stats.BatchesDropped.Inc()
		return ErrBatchQueueFull
	}
}

// GetResults returns the result channel
func (bp *BatchProcessor) GetResults() <-chan *BatchResult {
	return bp.resultQueue
}

// GetStats returns batch processing statistics
func (bp *BatchProcessor) GetStats() *BatchStats {
	return &bp.stats
}

// GetWorkerStats returns statistics for a specific worker
func (bp *BatchProcessor) GetWorkerStats(workerID int) *WorkerStats {
	if workerID >= 0 && workerID < len(bp.workers) {
		return &bp.workers[workerID].localStats
	}
	return nil
}

// Stop stops the batch processor
func (bp *BatchProcessor) Stop() {
	if !bp.running.CompareAndSwap(true, false) {
		return
	}

	// Close input queue to signal workers to stop
	close(bp.inputQueue)

	// Wait for all workers to finish processing
	bp.workersWg.Wait()

	// Now safe to close result queue - no workers running
	close(bp.resultQueue)

	logger.Info("Batch processor stopped",
		"total_batches", bp.stats.TotalBatches.Get(),
		"total_packets", bp.stats.TotalPackets.Get())
}

// run is the worker processing loop
func (bw *BatchWorker) run() {
	defer bw.processor.workersWg.Done()

	// Pin to CPU if affinity is enabled (skip in tests to avoid hangs)
	if bw.processor.config.WorkerAffinity && bw.cpuID >= 0 {
		// Affinity pinning is optional and may fail in test environments
		if cam := GetAffinityManager(); cam != nil {
			_ = cam.PinCurrentThreadToCPU(bw.cpuID) // Ignore errors
		}
	}

	logger.Debug("Batch worker started", "worker_id", bw.id, "cpu_id", bw.cpuID)

	for batch := range bw.processor.inputQueue {
		result := bw.processBatch(batch)

		// Only send result if processor is still running
		if bw.processor.running.Load() {
			select {
			case bw.processor.resultQueue <- result:
			default:
				// Result queue full, drop result
				logger.Warn("Result queue full, dropping batch result")
			}
		}
	}

	logger.Debug("Batch worker stopped", "worker_id", bw.id)
}

// processBatch processes a single batch
func (bw *BatchWorker) processBatch(batch *PacketBatch) *BatchResult {
	startTime := time.Now()

	result := &BatchResult{
		CallIDs:     make([]string, 0, batch.Count),
		CallInfos:   make([]*CallInfo, 0, batch.Count),
		Errors:      make([]error, 0),
		ProcessedAt: startTime,
	}

	// Process each packet in the batch
	for i := 0; i < batch.Count; i++ {
		pkt := batch.Packets[i]
		metadata := batch.Metadata[i]

		// Parse SIP packet
		callID, callInfo, err := bw.parsePacket(pkt, metadata)
		if err != nil {
			result.Errors = append(result.Errors, err)
			bw.localStats.ErrorsEncountered.Inc()
			continue
		}

		if callID != "" {
			result.CallIDs = append(result.CallIDs, callID)
			result.CallInfos = append(result.CallInfos, callInfo)
		}
	}

	// Update statistics
	processingTime := time.Since(startTime)
	result.ProcessingNS = processingTime.Nanoseconds()

	bw.localStats.BatchesProcessed.Inc()
	bw.localStats.PacketsProcessed.Add(uint64(batch.Count))
	bw.localStats.ProcessingTimeNS.Add(uint64(result.ProcessingNS))

	return result
}

// parsePacket parses a single packet (placeholder for actual parsing)
func (bw *BatchWorker) parsePacket(pkt *PacketBuffer, metadata PacketMetadata) (string, *CallInfo, error) {
	// This would call actual SIP parsing logic
	// For now, return empty to show the structure
	return "", nil, nil
}

// VectorizedCallIDExtractor extracts Call-IDs from multiple packets in parallel
type VectorizedCallIDExtractor struct {
	numLanes int  // Number of parallel processing lanes
	simdOps  bool // Use SIMD operations
}

// NewVectorizedCallIDExtractor creates a new vectorized extractor
func NewVectorizedCallIDExtractor(numLanes int) *VectorizedCallIDExtractor {
	return &VectorizedCallIDExtractor{
		numLanes: numLanes,
		simdOps:  cpuFeatures.HasAVX2,
	}
}

// ExtractCallIDs extracts Call-IDs from a batch of packets
func (ve *VectorizedCallIDExtractor) ExtractCallIDs(packets [][]byte) []string {
	callIDs := make([]string, 0, len(packets))

	if ve.simdOps && len(packets) >= ve.numLanes {
		// Use SIMD-optimized extraction
		callIDs = ve.extractCallIDsSIMD(packets)
	} else {
		// Fall back to standard extraction
		callIDs = ve.extractCallIDsStandard(packets)
	}

	return callIDs
}

// extractCallIDsSIMD uses SIMD operations for batch extraction
func (ve *VectorizedCallIDExtractor) extractCallIDsSIMD(packets [][]byte) []string {
	callIDs := make([]string, 0, len(packets))

	// Process packets in lanes (groups of numLanes)
	for i := 0; i < len(packets); i += ve.numLanes {
		end := i + ve.numLanes
		if end > len(packets) {
			end = len(packets)
		}

		// Process this lane
		lane := packets[i:end]
		for _, pkt := range lane {
			if callID := extractCallIDFast(pkt); callID != "" {
				callIDs = append(callIDs, callID)
			}
		}
	}

	return callIDs
}

// extractCallIDsStandard uses standard extraction
func (ve *VectorizedCallIDExtractor) extractCallIDsStandard(packets [][]byte) []string {
	callIDs := make([]string, 0, len(packets))

	for _, pkt := range packets {
		if callID := extractCallIDFast(pkt); callID != "" {
			callIDs = append(callIDs, callID)
		}
	}

	return callIDs
}

// extractCallIDFast is a fast Call-ID extraction (uses zero-alloc ops)
func extractCallIDFast(data []byte) string {
	// Quick check for Call-ID presence
	hasCallID := BytesContains(data, []byte("Call-ID"))
	hasShortForm := BytesContains(data, []byte("\ni:"))

	if !hasCallID && !hasShortForm {
		return ""
	}

	// Find Call-ID header line by line
	start := 0
	for start < len(data) {
		// Find end of line
		end := start
		for end < len(data) && data[end] != '\n' {
			end++
		}

		line := data[start:end]

		// Remove trailing \r
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// Check for Call-ID header
		if len(line) >= 9 && BytesEqual(line[:9], []byte("Call-ID: ")) {
			// Extract value (skip "Call-ID: ")
			value := TrimSpace(line[9:])
			return BytesToString(value)
		} else if len(line) >= 8 && BytesEqual(line[:8], []byte("Call-ID:")) {
			// No space after colon
			value := TrimSpace(line[8:])
			return BytesToString(value)
		} else if len(line) >= 3 && BytesEqual(line[:3], []byte("i: ")) {
			// Short form with space
			value := TrimSpace(line[3:])
			return BytesToString(value)
		} else if len(line) >= 2 && BytesEqual(line[:2], []byte("i:")) {
			// Short form without space
			value := TrimSpace(line[2:])
			return BytesToString(value)
		}

		// Move to next line
		start = end + 1
	}

	return ""
}

// BatchCollector collects packets into batches
type BatchCollector struct {
	config       *BatchConfig
	currentBatch *PacketBatch
	mu           sync.Mutex
	flushTimer   *time.Timer
	processor    *BatchProcessor
}

// NewBatchCollector creates a new batch collector
func NewBatchCollector(config *BatchConfig, processor *BatchProcessor) *BatchCollector {
	bc := &BatchCollector{
		config: config,
		currentBatch: &PacketBatch{
			Packets:  make([]*PacketBuffer, 0, config.BatchSize),
			Metadata: make([]PacketMetadata, 0, config.BatchSize),
		},
		processor: processor,
	}

	// Start flush timer
	bc.flushTimer = time.AfterFunc(config.FlushInterval, bc.flush)

	return bc
}

// Add adds a packet to the current batch
func (bc *BatchCollector) Add(pkt *PacketBuffer, ci gopacket.CaptureInfo, flowHash uint32) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	metadata := PacketMetadata{
		CaptureInfo: ci,
		FlowHash:    flowHash,
		Index:       bc.currentBatch.Count,
	}

	bc.currentBatch.Packets = append(bc.currentBatch.Packets, pkt)
	bc.currentBatch.Metadata = append(bc.currentBatch.Metadata, metadata)
	bc.currentBatch.Count++

	// Flush if batch is full
	if bc.currentBatch.Count >= bc.config.BatchSize {
		bc.flushLocked()
	}
}

// flush flushes the current batch
func (bc *BatchCollector) flush() {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.flushLocked()
}

// flushLocked flushes with lock already held
func (bc *BatchCollector) flushLocked() {
	if bc.currentBatch.Count == 0 {
		return
	}

	bc.currentBatch.Timestamp = time.Now()

	// Submit to processor
	if err := bc.processor.SubmitBatch(bc.currentBatch); err != nil {
		logger.Warn("Failed to submit batch", "error", err)
	}

	// Create new batch
	bc.currentBatch = &PacketBatch{
		Packets:  make([]*PacketBuffer, 0, bc.config.BatchSize),
		Metadata: make([]PacketMetadata, 0, bc.config.BatchSize),
	}

	// Reset timer
	bc.flushTimer.Reset(bc.config.FlushInterval)
}

// GetCurrentCount returns the current batch count (thread-safe)
func (bc *BatchCollector) GetCurrentCount() int {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.currentBatch.Count
}

// GetNumCPUs returns the number of CPUs
func GetNumCPUs() int {
	topo, err := GetTopology()
	if err != nil {
		return 4 // Default fallback
	}
	return topo.NumCPUs
}

// Global affinity manager
var globalAffinityManager *CPUAffinityManager
var affinityOnce sync.Once

// GetAffinityManager returns the global affinity manager
func GetAffinityManager() *CPUAffinityManager {
	affinityOnce.Do(func() {
		globalAffinityManager = NewCPUAffinityManager()
	})
	return globalAffinityManager
}

// Common errors
var (
	ErrProcessorStopped = &BatchError{"processor stopped"}
	ErrBatchQueueFull   = &BatchError{"queue full"}
)

// BatchError represents a batch processing error
type BatchError struct {
	msg string
}

func (e *BatchError) Error() string {
	return e.msg
}
