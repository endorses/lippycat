//go:build cuda
// +build cuda

package voip

/*
#cgo CFLAGS: -I/opt/cuda/include
#cgo LDFLAGS: -L/opt/cuda/lib64 -L. -lcudart -lcuda -lcuda_kernels

#include <cuda_runtime.h>
#include <cuda.h>
#include <stdlib.h>

// Error checking helper
int checkCudaError(cudaError_t err) {
    return (int)err;
}

// Allocate device memory
cudaError_t allocateDeviceMemory(void** devPtr, size_t size) {
    return cudaMalloc(devPtr, size);
}

// Free device memory
cudaError_t freeDeviceMemory(void* devPtr) {
    return cudaFree(devPtr);
}

// Copy host to device
cudaError_t copyHostToDevice(void* dst, const void* src, size_t size) {
    return cudaMemcpy(dst, src, size, cudaMemcpyHostToDevice);
}

// Copy device to host
cudaError_t copyDeviceToHost(void* dst, const void* src, size_t size) {
    return cudaMemcpy(dst, src, size, cudaMemcpyDeviceToHost);
}

// Get device count
cudaError_t getDeviceCount(int* count) {
    return cudaGetDeviceCount(count);
}

// Set device
cudaError_t setDevice(int device) {
    return cudaSetDevice(device);
}

// Get device properties
cudaError_t getDeviceProperties(struct cudaDeviceProp* prop, int device) {
    return cudaGetDeviceProperties(prop, device);
}

// Synchronize device
cudaError_t syncDevice() {
    return cudaDeviceSynchronize();
}

// Pattern matching kernel wrapper
extern void launchPatternMatchKernel(
    const char* d_packets,
    const int* d_packetOffsets,
    int numPackets,
    const char* d_patterns,
    const int* d_patternLengths,
    int numPatterns,
    int* d_results,
    int* d_resultCount,
    cudaStream_t stream
);


// Aho-Corasick kernel wrapper
// Each thread processes one username, traversing the automaton states
extern void launchACMatchKernel(
    const char* d_usernames,
    const int* d_usernameOffsets,
    int numUsernames,
    const int* d_transitions,   // [numStates][256] dense transition table
    const int* d_failure,       // [numStates] failure links
    const int* d_outputs,       // [numStates] output pattern indices (packed)
    const int* d_outputOffsets, // [numStates+1] offsets into d_outputs
    int numStates,
    int* d_results,             // [numUsernames * maxMatches] matched pattern IDs
    int* d_resultCounts,        // [numUsernames] number of matches per username
    int maxMatchesPerUsername,
    cudaStream_t stream
);
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// CUDABackendImpl is the real CUDA implementation
type CUDABackendImpl struct {
	config        *GPUConfig
	deviceID      int
	devicePtr     unsafe.Pointer
	packetBuffer  unsafe.Pointer
	patternBuffer unsafe.Pointer
	resultBuffer  unsafe.Pointer
	offsetBuffer  unsafe.Pointer
	stream        C.cudaStream_t
	deviceProps   C.struct_cudaDeviceProp
	maxPacketSize int
	maxBatchSize  int
	initialized   bool

	// Aho-Corasick automaton data on GPU
	acTransitions   unsafe.Pointer // [numStates][256] int32 dense transition table
	acFailure       unsafe.Pointer // [numStates] int32 failure links
	acOutputs       unsafe.Pointer // Packed output pattern indices
	acOutputOffsets unsafe.Pointer // [numStates+1] int32 offsets into acOutputs
	acNumStates     int
	acNumPatterns   int
	acBuilt         bool

	// Username matching buffers
	usernameBuffer       unsafe.Pointer // Flattened username data
	usernameOffsetBuffer unsafe.Pointer // Offsets into username buffer
	acResultBuffer       unsafe.Pointer // Match results per username
	acResultCountBuffer  unsafe.Pointer // Match count per username
	maxUsernamesBatch    int
	maxMatchesPerUser    int
}

// NewCUDABackendImpl creates a real CUDA backend implementation
func NewCUDABackendImpl() *CUDABackendImpl {
	return &CUDABackendImpl{}
}

// NewCUDABackend creates a new CUDA backend (interface-compatible wrapper)
func NewCUDABackend() GPUBackend {
	return NewCUDABackendImpl()
}

// Initialize initializes the CUDA backend
func (cb *CUDABackendImpl) Initialize(config *GPUConfig) error {
	// Check device count
	var deviceCount C.int
	err := C.getDeviceCount(&deviceCount)
	if err != 0 || deviceCount == 0 {
		return fmt.Errorf("no CUDA devices found: %d", err)
	}

	cb.config = config
	cb.deviceID = config.DeviceID

	// Set device
	if cerr := C.setDevice(C.int(cb.deviceID)); cerr != 0 {
		return fmt.Errorf("failed to set CUDA device %d: %d", cb.deviceID, cerr)
	}

	// Get device properties
	if cerr := C.getDeviceProperties(&cb.deviceProps, C.int(cb.deviceID)); cerr != 0 {
		return fmt.Errorf("failed to get device properties: %d", cerr)
	}

	deviceName := C.GoString(&cb.deviceProps.name[0])
	logger.Info("CUDA device initialized",
		"device_id", cb.deviceID,
		"name", deviceName,
		"compute_capability", fmt.Sprintf("%d.%d", cb.deviceProps.major, cb.deviceProps.minor),
		"total_memory_mb", int64(cb.deviceProps.totalGlobalMem)/(1024*1024))

	cb.maxBatchSize = config.MaxBatchSize
	cb.maxPacketSize = 2048 // 2KB per packet

	cb.initialized = true
	return nil
}

// AllocatePacketBuffers allocates GPU memory for packet buffers
func (cb *CUDABackendImpl) AllocatePacketBuffers(maxPackets int, maxPacketSize int) error {
	if !cb.initialized {
		return ErrGPUNotAvailable
	}

	cb.maxBatchSize = maxPackets
	cb.maxPacketSize = maxPacketSize

	totalPacketMem := maxPackets * maxPacketSize

	// Allocate packet buffer
	var packetBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&packetBuf, C.size_t(totalPacketMem)); cerr != 0 {
		return fmt.Errorf("failed to allocate packet buffer: %d", cerr)
	}
	cb.packetBuffer = packetBuf

	// Allocate offset buffer (one int per packet)
	var offsetBuf unsafe.Pointer
	offsetSize := (maxPackets + 1) * 4 // int32 per offset
	if cerr := C.allocateDeviceMemory(&offsetBuf, C.size_t(offsetSize)); cerr != 0 {
		C.freeDeviceMemory(cb.packetBuffer)
		return fmt.Errorf("failed to allocate offset buffer: %d", cerr)
	}
	cb.offsetBuffer = offsetBuf

	// Allocate pattern buffer (1MB)
	var patternBuf unsafe.Pointer
	patternSize := 1024 * 1024
	if cerr := C.allocateDeviceMemory(&patternBuf, C.size_t(patternSize)); cerr != 0 {
		C.freeDeviceMemory(cb.packetBuffer)
		C.freeDeviceMemory(cb.offsetBuffer)
		return fmt.Errorf("failed to allocate pattern buffer: %d", cerr)
	}
	cb.patternBuffer = patternBuf

	// Allocate result buffer (4 ints per result * maxPackets * 10 patterns)
	var resultBuf unsafe.Pointer
	resultSize := maxPackets * 10 * 4 * 4 // max 10 patterns, 4 ints per result
	if cerr := C.allocateDeviceMemory(&resultBuf, C.size_t(resultSize)); cerr != 0 {
		C.freeDeviceMemory(cb.packetBuffer)
		C.freeDeviceMemory(cb.offsetBuffer)
		C.freeDeviceMemory(cb.patternBuffer)
		return fmt.Errorf("failed to allocate result buffer: %d", cerr)
	}
	cb.resultBuffer = resultBuf

	logger.Info("CUDA buffers allocated",
		"packet_buffer_mb", totalPacketMem/(1024*1024),
		"pattern_buffer_kb", patternSize/1024,
		"result_buffer_kb", resultSize/1024)

	return nil
}

// TransferPacketsToGPU copies packets from CPU to GPU
func (cb *CUDABackendImpl) TransferPacketsToGPU(packets [][]byte) error {
	if !cb.initialized {
		return ErrGPUNotAvailable
	}

	if cb.packetBuffer == nil {
		if err := cb.AllocatePacketBuffers(cb.maxBatchSize, cb.maxPacketSize); err != nil {
			return err
		}
	}

	// Flatten packets into single buffer with offsets
	totalSize := 0
	offsets := make([]int32, len(packets)+1)
	offsets[0] = 0

	for i, pkt := range packets {
		totalSize += len(pkt)
		offsets[i+1] = int32(totalSize)
	}

	// Create flat buffer
	flatBuffer := make([]byte, totalSize)
	offset := 0
	for _, pkt := range packets {
		copy(flatBuffer[offset:], pkt)
		offset += len(pkt)
	}

	// Copy packet data to GPU
	if cerr := C.copyHostToDevice(cb.packetBuffer, unsafe.Pointer(&flatBuffer[0]), C.size_t(totalSize)); cerr != 0 {
		return fmt.Errorf("failed to copy packets to GPU: %d", cerr)
	}

	// Copy offsets to GPU
	if cerr := C.copyHostToDevice(cb.offsetBuffer, unsafe.Pointer(&offsets[0]), C.size_t(len(offsets)*4)); cerr != 0 {
		return fmt.Errorf("failed to copy offsets to GPU: %d", cerr)
	}

	return nil
}

// ExecutePatternMatching executes CUDA kernel for pattern matching
func (cb *CUDABackendImpl) ExecutePatternMatching(patterns []GPUPattern) error {
	if !cb.initialized {
		return ErrGPUNotAvailable
	}

	// Prepare pattern data
	totalPatternSize := 0
	for _, p := range patterns {
		totalPatternSize += p.PatternLen
	}

	flatPatterns := make([]byte, totalPatternSize)
	patternLengths := make([]int32, len(patterns))

	offset := 0
	for i, p := range patterns {
		copy(flatPatterns[offset:], p.Pattern[:p.PatternLen])
		patternLengths[i] = int32(p.PatternLen)
		offset += p.PatternLen
	}

	// Copy patterns to GPU
	if cerr := C.copyHostToDevice(cb.patternBuffer, unsafe.Pointer(&flatPatterns[0]), C.size_t(totalPatternSize)); cerr != 0 {
		return fmt.Errorf("failed to copy patterns to GPU: %d", cerr)
	}

	// Launch kernel (implementation in .cu file)
	// For now, return success - kernel implementation needed
	logger.Debug("CUDA pattern matching kernel would execute here")

	return nil
}

// TransferResultsFromGPU copies results back from GPU
func (cb *CUDABackendImpl) TransferResultsFromGPU() ([]GPUResult, error) {
	if !cb.initialized {
		return nil, ErrGPUNotAvailable
	}

	// Synchronize device
	if cerr := C.syncDevice(); cerr != 0 {
		return nil, fmt.Errorf("failed to synchronize device: %d", cerr)
	}

	// Read result count first (stored at beginning of result buffer)
	var resultCount int32
	if cerr := C.copyDeviceToHost(unsafe.Pointer(&resultCount), cb.resultBuffer, 4); cerr != 0 {
		return nil, fmt.Errorf("failed to read result count: %d", cerr)
	}

	if resultCount == 0 {
		return []GPUResult{}, nil
	}

	// Read results (4 ints per result: packetIdx, patternID, offset, length)
	resultData := make([]int32, resultCount*4)
	if cerr := C.copyDeviceToHost(
		unsafe.Pointer(&resultData[0]),
		unsafe.Pointer(uintptr(cb.resultBuffer)+4),
		C.size_t(resultCount*4*4)); cerr != 0 {
		return nil, fmt.Errorf("failed to copy results from GPU: %d", cerr)
	}

	// Convert to GPUResult structs
	results := make([]GPUResult, resultCount)
	for i := 0; i < int(resultCount); i++ {
		results[i] = GPUResult{
			PacketIndex: int(resultData[i*4+0]),
			PatternID:   int(resultData[i*4+1]),
			Offset:      int(resultData[i*4+2]),
			Length:      int(resultData[i*4+3]),
			Matched:     true,
		}
	}

	return results, nil
}

// Cleanup releases CUDA resources
func (cb *CUDABackendImpl) Cleanup() error {
	// Free Aho-Corasick buffers
	cb.freeACBuffers()

	if cb.packetBuffer != nil {
		C.freeDeviceMemory(cb.packetBuffer)
		cb.packetBuffer = nil
	}
	if cb.offsetBuffer != nil {
		C.freeDeviceMemory(cb.offsetBuffer)
		cb.offsetBuffer = nil
	}
	if cb.patternBuffer != nil {
		C.freeDeviceMemory(cb.patternBuffer)
		cb.patternBuffer = nil
	}
	if cb.resultBuffer != nil {
		C.freeDeviceMemory(cb.resultBuffer)
		cb.resultBuffer = nil
	}

	cb.initialized = false
	logger.Info("CUDA backend cleaned up")
	return nil
}

// Name returns the backend name
func (cb *CUDABackendImpl) Name() string {
	if cb.initialized {
		deviceName := C.GoString(&cb.deviceProps.name[0])
		return fmt.Sprintf("cuda-%s", deviceName)
	}
	return "cuda"
}

// IsAvailable checks if CUDA is available
func (cb *CUDABackendImpl) IsAvailable() bool {
	var deviceCount C.int
	err := C.getDeviceCount(&deviceCount)
	return err == 0 && deviceCount > 0
}

// BuildAutomaton builds an Aho-Corasick automaton from patterns and uploads to GPU.
// The automaton is serialized into dense arrays for efficient GPU traversal.
func (cb *CUDABackendImpl) BuildAutomaton(patterns []ahocorasick.Pattern) error {
	if !cb.initialized {
		return ErrGPUNotAvailable
	}

	// Free previous automaton if exists
	cb.freeACBuffers()

	if len(patterns) == 0 {
		cb.acBuilt = false
		return nil
	}

	// Build CPU automaton first using DenseAhoCorasick
	ac := ahocorasick.NewDenseAhoCorasick()
	if err := ac.Build(patterns); err != nil {
		return fmt.Errorf("failed to build AC automaton: %w", err)
	}

	// Serialize automaton to flat arrays for GPU
	numStates, transitions, failure, outputs, outputOffsets := cb.serializeAutomaton(ac)
	cb.acNumStates = numStates
	cb.acNumPatterns = len(patterns)

	// Allocate and copy transitions to GPU: [numStates][256] int32
	transitionSize := numStates * 256 * 4
	var transitionBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&transitionBuf, C.size_t(transitionSize)); cerr != 0 {
		return fmt.Errorf("failed to allocate AC transitions: %d", cerr)
	}
	cb.acTransitions = transitionBuf
	if cerr := C.copyHostToDevice(transitionBuf, unsafe.Pointer(&transitions[0]), C.size_t(transitionSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to copy AC transitions to GPU: %d", cerr)
	}

	// Allocate and copy failure links to GPU
	failureSize := numStates * 4
	var failureBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&failureBuf, C.size_t(failureSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate AC failure links: %d", cerr)
	}
	cb.acFailure = failureBuf
	if cerr := C.copyHostToDevice(failureBuf, unsafe.Pointer(&failure[0]), C.size_t(failureSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to copy AC failure links to GPU: %d", cerr)
	}

	// Allocate and copy output offsets to GPU
	outputOffsetsSize := (numStates + 1) * 4
	var outputOffsetsBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&outputOffsetsBuf, C.size_t(outputOffsetsSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate AC output offsets: %d", cerr)
	}
	cb.acOutputOffsets = outputOffsetsBuf
	if cerr := C.copyHostToDevice(outputOffsetsBuf, unsafe.Pointer(&outputOffsets[0]), C.size_t(outputOffsetsSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to copy AC output offsets to GPU: %d", cerr)
	}

	// Allocate and copy outputs to GPU
	if len(outputs) > 0 {
		outputsSize := len(outputs) * 4
		var outputsBuf unsafe.Pointer
		if cerr := C.allocateDeviceMemory(&outputsBuf, C.size_t(outputsSize)); cerr != 0 {
			cb.freeACBuffers()
			return fmt.Errorf("failed to allocate AC outputs: %d", cerr)
		}
		cb.acOutputs = outputsBuf
		if cerr := C.copyHostToDevice(outputsBuf, unsafe.Pointer(&outputs[0]), C.size_t(outputsSize)); cerr != 0 {
			cb.freeACBuffers()
			return fmt.Errorf("failed to copy AC outputs to GPU: %d", cerr)
		}
	}

	// Allocate username matching buffers
	cb.maxUsernamesBatch = cb.maxBatchSize
	cb.maxMatchesPerUser = 16 // Max patterns that can match a single username

	// Username buffer (estimate 64 bytes avg per username)
	usernameBufferSize := cb.maxUsernamesBatch * 64
	var usernameBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&usernameBuf, C.size_t(usernameBufferSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate username buffer: %d", cerr)
	}
	cb.usernameBuffer = usernameBuf

	// Username offsets
	usernameOffsetsSize := (cb.maxUsernamesBatch + 1) * 4
	var usernameOffsetsBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&usernameOffsetsBuf, C.size_t(usernameOffsetsSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate username offsets: %d", cerr)
	}
	cb.usernameOffsetBuffer = usernameOffsetsBuf

	// Results buffer
	resultsSize := cb.maxUsernamesBatch * cb.maxMatchesPerUser * 4
	var resultsBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&resultsBuf, C.size_t(resultsSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate AC results buffer: %d", cerr)
	}
	cb.acResultBuffer = resultsBuf

	// Result counts buffer
	resultCountsSize := cb.maxUsernamesBatch * 4
	var resultCountsBuf unsafe.Pointer
	if cerr := C.allocateDeviceMemory(&resultCountsBuf, C.size_t(resultCountsSize)); cerr != 0 {
		cb.freeACBuffers()
		return fmt.Errorf("failed to allocate AC result counts: %d", cerr)
	}
	cb.acResultCountBuffer = resultCountsBuf

	cb.acBuilt = true

	logger.Info("CUDA AC automaton built and uploaded",
		"pattern_count", len(patterns),
		"state_count", numStates,
		"transition_size_mb", transitionSize/(1024*1024))

	return nil
}

// serializeAutomaton extracts the automaton data into flat arrays.
// Returns: numStates, transitions[numStates*256], failure[numStates], outputs[], outputOffsets[numStates+1]
func (cb *CUDABackendImpl) serializeAutomaton(ac *ahocorasick.DenseAhoCorasick) (int, []int32, []int32, []int32, []int32) {
	numStates := ac.StateCount()
	transitions, failure, outputs, outputOffsets, _, _ := ac.ExportStates()
	return numStates, transitions, failure, outputs, outputOffsets
}

// MatchUsernames matches usernames against the built Aho-Corasick automaton.
// Each GPU thread processes one username, traversing the automaton states.
func (cb *CUDABackendImpl) MatchUsernames(usernames [][]byte) ([][]int, error) {
	if !cb.initialized {
		return nil, ErrGPUNotAvailable
	}

	results := make([][]int, len(usernames))
	if !cb.acBuilt || len(usernames) == 0 {
		return results, nil
	}

	numUsernames := len(usernames)
	if numUsernames > cb.maxUsernamesBatch {
		// Process in batches
		for batchStart := 0; batchStart < numUsernames; batchStart += cb.maxUsernamesBatch {
			batchEnd := batchStart + cb.maxUsernamesBatch
			if batchEnd > numUsernames {
				batchEnd = numUsernames
			}
			batchResults, err := cb.matchUsernamesBatch(usernames[batchStart:batchEnd])
			if err != nil {
				return nil, err
			}
			for i, r := range batchResults {
				results[batchStart+i] = r
			}
		}
		return results, nil
	}

	return cb.matchUsernamesBatch(usernames)
}

// matchUsernamesBatch processes a single batch of usernames.
func (cb *CUDABackendImpl) matchUsernamesBatch(usernames [][]byte) ([][]int, error) {
	numUsernames := len(usernames)
	results := make([][]int, numUsernames)

	// Flatten usernames
	totalSize := 0
	offsets := make([]int32, numUsernames+1)
	offsets[0] = 0

	for i, u := range usernames {
		totalSize += len(u)
		offsets[i+1] = int32(totalSize)
	}

	if totalSize == 0 {
		return results, nil
	}

	// Create flat buffer
	flatBuffer := make([]byte, totalSize)
	offset := 0
	for _, u := range usernames {
		copy(flatBuffer[offset:], u)
		offset += len(u)
	}

	// Copy usernames to GPU
	if cerr := C.copyHostToDevice(cb.usernameBuffer, unsafe.Pointer(&flatBuffer[0]), C.size_t(totalSize)); cerr != 0 {
		return nil, fmt.Errorf("failed to copy usernames to GPU: %d", cerr)
	}

	// Copy offsets to GPU
	if cerr := C.copyHostToDevice(cb.usernameOffsetBuffer, unsafe.Pointer(&offsets[0]), C.size_t((numUsernames+1)*4)); cerr != 0 {
		return nil, fmt.Errorf("failed to copy username offsets to GPU: %d", cerr)
	}

	// Launch AC matching kernel
	C.launchACMatchKernel(
		(*C.char)(cb.usernameBuffer),
		(*C.int)(cb.usernameOffsetBuffer),
		C.int(numUsernames),
		(*C.int)(cb.acTransitions),
		(*C.int)(cb.acFailure),
		(*C.int)(cb.acOutputs),
		(*C.int)(cb.acOutputOffsets),
		C.int(cb.acNumStates),
		(*C.int)(cb.acResultBuffer),
		(*C.int)(cb.acResultCountBuffer),
		C.int(cb.maxMatchesPerUser),
		cb.stream,
	)

	// Synchronize
	if cerr := C.syncDevice(); cerr != 0 {
		return nil, fmt.Errorf("failed to synchronize after AC kernel: %d", cerr)
	}

	// Read result counts
	resultCounts := make([]int32, numUsernames)
	if cerr := C.copyDeviceToHost(unsafe.Pointer(&resultCounts[0]), cb.acResultCountBuffer, C.size_t(numUsernames*4)); cerr != 0 {
		return nil, fmt.Errorf("failed to read AC result counts: %d", cerr)
	}

	// Read results
	allResults := make([]int32, numUsernames*cb.maxMatchesPerUser)
	if cerr := C.copyDeviceToHost(unsafe.Pointer(&allResults[0]), cb.acResultBuffer, C.size_t(numUsernames*cb.maxMatchesPerUser*4)); cerr != 0 {
		return nil, fmt.Errorf("failed to read AC results: %d", cerr)
	}

	// Unpack results
	for i := 0; i < numUsernames; i++ {
		count := int(resultCounts[i])
		if count > 0 {
			if count > cb.maxMatchesPerUser {
				count = cb.maxMatchesPerUser
			}
			patternIDs := make([]int, count)
			for j := 0; j < count; j++ {
				patternIDs[j] = int(allResults[i*cb.maxMatchesPerUser+j])
			}
			results[i] = patternIDs
		}
	}

	return results, nil
}

// freeACBuffers releases all Aho-Corasick related GPU buffers.
func (cb *CUDABackendImpl) freeACBuffers() {
	if cb.acTransitions != nil {
		C.freeDeviceMemory(cb.acTransitions)
		cb.acTransitions = nil
	}
	if cb.acFailure != nil {
		C.freeDeviceMemory(cb.acFailure)
		cb.acFailure = nil
	}
	if cb.acOutputs != nil {
		C.freeDeviceMemory(cb.acOutputs)
		cb.acOutputs = nil
	}
	if cb.acOutputOffsets != nil {
		C.freeDeviceMemory(cb.acOutputOffsets)
		cb.acOutputOffsets = nil
	}
	if cb.usernameBuffer != nil {
		C.freeDeviceMemory(cb.usernameBuffer)
		cb.usernameBuffer = nil
	}
	if cb.usernameOffsetBuffer != nil {
		C.freeDeviceMemory(cb.usernameOffsetBuffer)
		cb.usernameOffsetBuffer = nil
	}
	if cb.acResultBuffer != nil {
		C.freeDeviceMemory(cb.acResultBuffer)
		cb.acResultBuffer = nil
	}
	if cb.acResultCountBuffer != nil {
		C.freeDeviceMemory(cb.acResultCountBuffer)
		cb.acResultCountBuffer = nil
	}
	cb.acBuilt = false
}
