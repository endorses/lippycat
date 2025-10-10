package voip

import (
	"sync/atomic"
	"unsafe"
)

// Cache line size for most modern CPUs (x86-64, ARM64)
const CacheLineSize = 64

// CachePadding provides padding to prevent false sharing
type CachePadding [CacheLineSize]byte

// Padded wraps a value with cache line padding
type Padded[T any] struct {
	_     CachePadding
	Value T
	_     CachePadding
}

// NewPadded creates a new cache-line padded value
func NewPadded[T any](value T) *Padded[T] {
	return &Padded[T]{Value: value}
}

// PaddedAtomic provides cache-line padded atomic operations
type PaddedAtomic struct {
	_     CachePadding
	value atomic.Uint64
	_     CachePadding
}

// NewPaddedAtomic creates a new padded atomic uint64
func NewPaddedAtomic(initial uint64) *PaddedAtomic {
	pa := &PaddedAtomic{}
	pa.value.Store(initial)
	return pa
}

// Load atomically loads the value
func (pa *PaddedAtomic) Load() uint64 {
	return pa.value.Load()
}

// Store atomically stores a value
func (pa *PaddedAtomic) Store(val uint64) {
	pa.value.Store(val)
}

// Add atomically adds to the value
func (pa *PaddedAtomic) Add(delta uint64) uint64 {
	return pa.value.Add(delta)
}

// CompareAndSwap atomically performs compare-and-swap
func (pa *PaddedAtomic) CompareAndSwap(old, new uint64) bool {
	return pa.value.CompareAndSwap(old, new)
}

// PaddedCounter provides a cache-line padded counter
type PaddedCounter struct {
	_     CachePadding
	count atomic.Uint64
	_     CachePadding
}

// NewPaddedCounter creates a new padded counter
func NewPaddedCounter() *PaddedCounter {
	return &PaddedCounter{}
}

// Inc increments the counter
func (pc *PaddedCounter) Inc() {
	pc.count.Add(1)
}

// Add adds a value to the counter
func (pc *PaddedCounter) Add(n uint64) {
	pc.count.Add(n)
}

// Get returns the current count
func (pc *PaddedCounter) Get() uint64 {
	return pc.count.Load()
}

// Reset resets the counter to zero
func (pc *PaddedCounter) Reset() {
	pc.count.Store(0)
}

// PerCPUCounter provides per-CPU counters to eliminate contention
type PerCPUCounter struct {
	counters []PaddedCounter
	numCPUs  int
}

// NewPerCPUCounter creates a new per-CPU counter
func NewPerCPUCounter(numCPUs int) *PerCPUCounter {
	return &PerCPUCounter{
		counters: make([]PaddedCounter, numCPUs),
		numCPUs:  numCPUs,
	}
}

// Inc increments the counter for the current CPU
func (pcc *PerCPUCounter) Inc(cpuID int) {
	if cpuID >= 0 && cpuID < pcc.numCPUs {
		pcc.counters[cpuID].Inc()
	}
}

// Add adds a value for the current CPU
func (pcc *PerCPUCounter) Add(cpuID int, n uint64) {
	if cpuID >= 0 && cpuID < pcc.numCPUs {
		pcc.counters[cpuID].Add(n)
	}
}

// Sum returns the total across all CPUs
func (pcc *PerCPUCounter) Sum() uint64 {
	var total uint64
	for i := 0; i < pcc.numCPUs; i++ {
		total += pcc.counters[i].Get()
	}
	return total
}

// GetCPU returns the counter for a specific CPU
func (pcc *PerCPUCounter) GetCPU(cpuID int) uint64 {
	if cpuID >= 0 && cpuID < pcc.numCPUs {
		return pcc.counters[cpuID].Get()
	}
	return 0
}

// Reset resets all CPU counters
func (pcc *PerCPUCounter) Reset() {
	for i := 0; i < pcc.numCPUs; i++ {
		pcc.counters[i].Reset()
	}
}

// AlignedAlloc allocates memory aligned to cache line boundaries
func AlignedAlloc(size int) []byte {
	// Allocate extra space for alignment
	buf := make([]byte, size+CacheLineSize)

	// Find aligned offset
	offset := uintptr(unsafe.Pointer(&buf[0])) % CacheLineSize
	if offset != 0 {
		offset = CacheLineSize - offset
	}

	return buf[offset : offset+uintptr(size)]
}

// IsAligned checks if a pointer is cache-line aligned
func IsAligned(ptr unsafe.Pointer) bool {
	return uintptr(ptr)%CacheLineSize == 0
}

// PaddedBool provides a cache-line padded boolean
type PaddedBool struct {
	_     CachePadding
	value atomic.Bool
	_     CachePadding
}

// NewPaddedBool creates a new padded boolean
func NewPaddedBool(initial bool) *PaddedBool {
	pb := &PaddedBool{}
	pb.value.Store(initial)
	return pb
}

// Load atomically loads the boolean
func (pb *PaddedBool) Load() bool {
	return pb.value.Load()
}

// Store atomically stores a boolean
func (pb *PaddedBool) Store(val bool) {
	pb.value.Store(val)
}

// CompareAndSwap atomically performs compare-and-swap
func (pb *PaddedBool) CompareAndSwap(old, new bool) bool {
	return pb.value.CompareAndSwap(old, new)
}

// PaddedPointer provides a cache-line padded pointer
type PaddedPointer[T any] struct {
	_     CachePadding
	value atomic.Pointer[T]
	_     CachePadding
}

// NewPaddedPointer creates a new padded pointer
func NewPaddedPointer[T any](initial *T) *PaddedPointer[T] {
	pp := &PaddedPointer[T]{}
	if initial != nil {
		pp.value.Store(initial)
	}
	return pp
}

// Load atomically loads the pointer
func (pp *PaddedPointer[T]) Load() *T {
	return pp.value.Load()
}

// Store atomically stores a pointer
func (pp *PaddedPointer[T]) Store(val *T) {
	pp.value.Store(val)
}

// CompareAndSwap atomically performs compare-and-swap
func (pp *PaddedPointer[T]) CompareAndSwap(old, new *T) bool {
	return pp.value.CompareAndSwap(old, new)
}

// Stats for cache line analysis
type CacheLineStats struct {
	Size       int
	Aligned    bool
	FalseShare bool // Detected false sharing
}

// AnalyzeStruct analyzes a struct for cache line efficiency
func AnalyzeStruct(ptr unsafe.Pointer, size int) CacheLineStats {
	return CacheLineStats{
		Size:    size,
		Aligned: IsAligned(ptr),
	}
}
