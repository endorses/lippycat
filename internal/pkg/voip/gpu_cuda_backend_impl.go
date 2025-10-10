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
*/
import "C"
import (
	"fmt"
	"unsafe"

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
