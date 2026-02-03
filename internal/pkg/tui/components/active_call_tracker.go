//go:build tui || all

package components

import (
	"sync"
)

// ActiveCallTracker tracks active call counts over time for sparkline visualization.
// Uses a ring buffer to store samples, similar to CPUTracker.
type ActiveCallTracker struct {
	mu         sync.RWMutex
	samples    []float64
	maxSamples int
	head       int // Next write position
	count      int // Number of valid samples

	// Peak tracking
	peakActiveCalls int

	// Cached samples for sparkline rendering
	cachedSamples      []float64
	cachedSamplesWidth int
	samplesValid       bool
}

// NewActiveCallTracker creates a new active call tracker with the specified capacity.
// Default: 300 samples at 1s intervals = 5 minutes of history.
func NewActiveCallTracker(maxSamples int) *ActiveCallTracker {
	if maxSamples <= 0 {
		maxSamples = 300 // 5 minutes at 1s intervals
	}

	return &ActiveCallTracker{
		samples:    make([]float64, maxSamples),
		maxSamples: maxSamples,
	}
}

// DefaultActiveCallTracker creates an active call tracker with default settings (300 samples).
func DefaultActiveCallTracker() *ActiveCallTracker {
	return NewActiveCallTracker(300)
}

// Record adds a new active call count sample.
func (act *ActiveCallTracker) Record(activeCalls int) {
	act.mu.Lock()
	defer act.mu.Unlock()

	// Update peak
	if activeCalls > act.peakActiveCalls {
		act.peakActiveCalls = activeCalls
	}

	// Store sample
	act.samples[act.head] = float64(activeCalls)
	act.head = (act.head + 1) % act.maxSamples
	if act.count < act.maxSamples {
		act.count++
	}

	// Invalidate samples cache
	act.samplesValid = false
}

// GetSamples returns active call samples for sparkline rendering.
// Returns samples from oldest to newest, up to maxPoints.
// Results are cached and reused if maxPoints matches the cached width.
// If maxPoints exceeds the current buffer capacity, the buffer is grown automatically.
func (act *ActiveCallTracker) GetSamples(maxPoints int) []float64 {
	act.mu.Lock()
	defer act.mu.Unlock()

	if act.count == 0 || maxPoints <= 0 {
		return nil
	}

	// Grow buffer if sparkline width exceeds current capacity
	if maxPoints > act.maxSamples {
		act.growBufferLocked(maxPoints)
	}

	// Return cached samples if valid and width matches
	if act.samplesValid && act.cachedSamplesWidth == maxPoints && len(act.cachedSamples) > 0 {
		return act.cachedSamples
	}

	// Compute samples
	var samples []float64

	// If we have fewer samples than maxPoints, use all samples
	if act.count <= maxPoints {
		samples = make([]float64, act.count)
		for i := 0; i < act.count; i++ {
			// Read from oldest to newest
			idx := (act.head - act.count + i + act.maxSamples) % act.maxSamples
			samples[i] = act.samples[idx]
		}
	} else {
		// Downsample by averaging groups
		samples = make([]float64, maxPoints)
		groupSize := act.count / maxPoints
		remainder := act.count % maxPoints

		sampleIdx := 0
		for i := 0; i < maxPoints; i++ {
			// Some groups get an extra sample to distribute remainder evenly
			currentGroupSize := groupSize
			if i < remainder {
				currentGroupSize++
			}

			var sum float64
			for j := 0; j < currentGroupSize; j++ {
				idx := (act.head - act.count + sampleIdx + act.maxSamples) % act.maxSamples
				sum += act.samples[idx]
				sampleIdx++
			}
			samples[i] = sum / float64(currentGroupSize)
		}
	}

	// Cache the result
	act.cachedSamples = samples
	act.cachedSamplesWidth = maxPoints
	act.samplesValid = true

	return samples
}

// growBufferLocked increases the buffer capacity to accommodate larger sparkline widths.
// Must be called with lock held.
func (act *ActiveCallTracker) growBufferLocked(newSize int) {
	// Create new buffer
	newSamples := make([]float64, newSize)

	// Copy existing samples in order (oldest to newest)
	for i := 0; i < act.count; i++ {
		oldIdx := (act.head - act.count + i + act.maxSamples) % act.maxSamples
		newSamples[i] = act.samples[oldIdx]
	}

	// Update state - samples are now stored linearly starting at index 0
	act.samples = newSamples
	act.maxSamples = newSize
	act.head = act.count // Next write position is right after existing samples
	act.samplesValid = false
}

// GetCurrent returns the most recent active call count.
// Returns 0 if no samples are available.
func (act *ActiveCallTracker) GetCurrent() int {
	act.mu.RLock()
	defer act.mu.RUnlock()

	if act.count == 0 {
		return 0
	}

	lastIdx := (act.head - 1 + act.maxSamples) % act.maxSamples
	return int(act.samples[lastIdx])
}

// GetPeak returns the peak active call count seen.
func (act *ActiveCallTracker) GetPeak() int {
	act.mu.RLock()
	defer act.mu.RUnlock()
	return act.peakActiveCalls
}

// GetAverage returns the average active call count over all samples.
// Returns 0 if no samples are available.
func (act *ActiveCallTracker) GetAverage() float64 {
	act.mu.RLock()
	defer act.mu.RUnlock()

	if act.count == 0 {
		return 0
	}

	var sum float64
	for i := 0; i < act.count; i++ {
		idx := (act.head - act.count + i + act.maxSamples) % act.maxSamples
		sum += act.samples[idx]
	}
	return sum / float64(act.count)
}

// SampleCount returns the number of samples currently stored.
func (act *ActiveCallTracker) SampleCount() int {
	act.mu.RLock()
	defer act.mu.RUnlock()
	return act.count
}

// Reset clears all samples and resets the tracker.
func (act *ActiveCallTracker) Reset() {
	act.mu.Lock()
	defer act.mu.Unlock()

	act.head = 0
	act.count = 0
	act.peakActiveCalls = 0
	act.samplesValid = false
	act.cachedSamples = nil
}

// Resize changes the tracker capacity, preserving existing samples.
// If newCapacity is smaller than current count, oldest samples are discarded.
func (act *ActiveCallTracker) Resize(newCapacity int) {
	if newCapacity <= 0 {
		return
	}

	act.mu.Lock()
	defer act.mu.Unlock()

	if newCapacity == act.maxSamples {
		return // No change needed
	}

	// Extract current samples in order (oldest to newest)
	oldSamples := make([]float64, act.count)
	for i := 0; i < act.count; i++ {
		idx := (act.head - act.count + i + act.maxSamples) % act.maxSamples
		oldSamples[i] = act.samples[idx]
	}

	// Create new buffer
	act.samples = make([]float64, newCapacity)
	act.maxSamples = newCapacity

	// Copy samples, keeping most recent if we're shrinking
	copyCount := act.count
	startIdx := 0
	if copyCount > newCapacity {
		startIdx = copyCount - newCapacity
		copyCount = newCapacity
	}

	for i := 0; i < copyCount; i++ {
		act.samples[i] = oldSamples[startIdx+i]
	}

	act.head = copyCount % newCapacity
	act.count = copyCount

	// Invalidate cache
	act.samplesValid = false
	act.cachedSamples = nil
}
