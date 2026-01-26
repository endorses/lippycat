//go:build tui || all

package components

import (
	"sync"
)

// CPUTracker tracks CPU usage samples over time for sparkline visualization.
// Uses a ring buffer to store samples, similar to RateTracker but simpler.
type CPUTracker struct {
	mu         sync.RWMutex
	samples    []float64
	maxSamples int
	head       int // Next write position
	count      int // Number of valid samples

	// Peak tracking
	peakCPUPercent float64

	// Cached samples for sparkline rendering
	cachedSamples      []float64
	cachedSamplesWidth int
	samplesValid       bool
}

// NewCPUTracker creates a new CPU tracker with the specified capacity.
// Default: 60 samples at 1s intervals = 1 minute of history.
func NewCPUTracker(maxSamples int) *CPUTracker {
	if maxSamples <= 0 {
		maxSamples = 60 // 1 minute at 1s intervals
	}

	return &CPUTracker{
		samples:    make([]float64, maxSamples),
		maxSamples: maxSamples,
	}
}

// DefaultCPUTracker creates a CPU tracker with default settings (60 samples).
func DefaultCPUTracker() *CPUTracker {
	return NewCPUTracker(60)
}

// Record adds a new CPU percentage sample.
// cpuPercent should be 0-100 (or -1 if unavailable).
func (ct *CPUTracker) Record(cpuPercent float64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Skip unavailable readings
	if cpuPercent < 0 {
		return
	}

	// Update peak
	if cpuPercent > ct.peakCPUPercent {
		ct.peakCPUPercent = cpuPercent
	}

	// Store sample
	ct.samples[ct.head] = cpuPercent
	ct.head = (ct.head + 1) % ct.maxSamples
	if ct.count < ct.maxSamples {
		ct.count++
	}

	// Invalidate samples cache
	ct.samplesValid = false
}

// GetSamples returns CPU samples for sparkline rendering.
// Returns samples from oldest to newest, up to maxPoints.
// Results are cached and reused if maxPoints matches the cached width.
func (ct *CPUTracker) GetSamples(maxPoints int) []float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.count == 0 || maxPoints <= 0 {
		return nil
	}

	// Return cached samples if valid and width matches
	if ct.samplesValid && ct.cachedSamplesWidth == maxPoints && len(ct.cachedSamples) > 0 {
		return ct.cachedSamples
	}

	// Compute samples
	var samples []float64

	// If we have fewer samples than maxPoints, use all samples
	if ct.count <= maxPoints {
		samples = make([]float64, ct.count)
		for i := 0; i < ct.count; i++ {
			// Read from oldest to newest
			idx := (ct.head - ct.count + i + ct.maxSamples) % ct.maxSamples
			samples[i] = ct.samples[idx]
		}
	} else {
		// Downsample by averaging groups
		samples = make([]float64, maxPoints)
		groupSize := ct.count / maxPoints
		remainder := ct.count % maxPoints

		sampleIdx := 0
		for i := 0; i < maxPoints; i++ {
			// Some groups get an extra sample to distribute remainder evenly
			currentGroupSize := groupSize
			if i < remainder {
				currentGroupSize++
			}

			var sum float64
			for j := 0; j < currentGroupSize; j++ {
				idx := (ct.head - ct.count + sampleIdx + ct.maxSamples) % ct.maxSamples
				sum += ct.samples[idx]
				sampleIdx++
			}
			samples[i] = sum / float64(currentGroupSize)
		}
	}

	// Cache the result
	ct.cachedSamples = samples
	ct.cachedSamplesWidth = maxPoints
	ct.samplesValid = true

	return samples
}

// GetCurrent returns the most recent CPU percentage.
// Returns -1 if no samples are available.
func (ct *CPUTracker) GetCurrent() float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if ct.count == 0 {
		return -1
	}

	lastIdx := (ct.head - 1 + ct.maxSamples) % ct.maxSamples
	return ct.samples[lastIdx]
}

// GetPeak returns the peak CPU percentage seen.
func (ct *CPUTracker) GetPeak() float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.peakCPUPercent
}

// GetAverage returns the average CPU percentage across all samples.
func (ct *CPUTracker) GetAverage() float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if ct.count == 0 {
		return 0
	}

	var sum float64
	for i := 0; i < ct.count; i++ {
		idx := (ct.head - ct.count + i + ct.maxSamples) % ct.maxSamples
		sum += ct.samples[idx]
	}
	return sum / float64(ct.count)
}

// SampleCount returns the number of samples currently stored.
func (ct *CPUTracker) SampleCount() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.count
}

// Reset clears all samples and resets the tracker.
func (ct *CPUTracker) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.head = 0
	ct.count = 0
	ct.peakCPUPercent = 0
	ct.samplesValid = false
	ct.cachedSamples = nil
}

// Resize changes the tracker capacity, preserving existing samples.
// If newCapacity is smaller than current count, oldest samples are discarded.
func (ct *CPUTracker) Resize(newCapacity int) {
	if newCapacity <= 0 {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if newCapacity == ct.maxSamples {
		return // No change needed
	}

	// Extract current samples in order (oldest to newest)
	oldSamples := make([]float64, ct.count)
	for i := 0; i < ct.count; i++ {
		idx := (ct.head - ct.count + i + ct.maxSamples) % ct.maxSamples
		oldSamples[i] = ct.samples[idx]
	}

	// Create new buffer
	ct.samples = make([]float64, newCapacity)
	ct.maxSamples = newCapacity

	// Copy samples, keeping most recent if we're shrinking
	copyCount := ct.count
	startIdx := 0
	if copyCount > newCapacity {
		startIdx = copyCount - newCapacity
		copyCount = newCapacity
	}

	for i := 0; i < copyCount; i++ {
		ct.samples[i] = oldSamples[startIdx+i]
	}

	ct.head = copyCount % newCapacity
	ct.count = copyCount

	// Invalidate cache
	ct.samplesValid = false
	ct.cachedSamples = nil
}
