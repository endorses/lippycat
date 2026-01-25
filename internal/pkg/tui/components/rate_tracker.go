//go:build tui || all

package components

import (
	"sync"
	"time"
)

// RateSample represents a single rate sample at a point in time
type RateSample struct {
	Timestamp time.Time
	Packets   int64
	Bytes     int64
}

// RateStats contains computed rate statistics
type RateStats struct {
	CurrentPacketsPerSec float64
	CurrentBytesPerSec   float64
	AvgPacketsPerSec     float64
	AvgBytesPerSec       float64
	PeakPacketsPerSec    float64
	PeakBytesPerSec      float64
}

// RateTracker tracks packet and byte rates over a configurable time window.
// It uses a ring buffer to store samples and provides rate calculations.
type RateTracker struct {
	mu         sync.RWMutex
	samples    []RateSample
	maxSamples int
	interval   time.Duration
	head       int  // Next write position
	count      int  // Number of valid samples
	started    bool // Whether tracking has started

	// Cumulative counters for delta calculation
	lastPackets int64
	lastBytes   int64
	lastTime    time.Time

	// Peak tracking
	peakPacketsPerSec float64
	peakBytesPerSec   float64
}

// NewRateTracker creates a new rate tracker with the specified capacity and sampling interval.
// Default: 300 samples at 1s intervals = 5 minutes of history.
func NewRateTracker(maxSamples int, interval time.Duration) *RateTracker {
	if maxSamples <= 0 {
		maxSamples = 300 // 5 minutes at 1s intervals
	}
	if interval <= 0 {
		interval = time.Second
	}

	return &RateTracker{
		samples:    make([]RateSample, maxSamples),
		maxSamples: maxSamples,
		interval:   interval,
	}
}

// DefaultRateTracker creates a rate tracker with default settings (300 samples, 1s interval).
func DefaultRateTracker() *RateTracker {
	return NewRateTracker(300, time.Second)
}

// Record adds a new sample based on cumulative packet and byte counts.
// Call this periodically (e.g., every second) with the current total counts.
func (rt *RateTracker) Record(totalPackets, totalBytes int64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()

	if !rt.started {
		// First sample - just record baseline
		rt.lastPackets = totalPackets
		rt.lastBytes = totalBytes
		rt.lastTime = now
		rt.started = true
		return
	}

	// Calculate delta since last sample
	elapsed := now.Sub(rt.lastTime).Seconds()
	if elapsed <= 0 {
		return // Avoid division by zero
	}

	deltaPackets := totalPackets - rt.lastPackets
	deltaBytes := totalBytes - rt.lastBytes

	// Detect counter reset (e.g., after reconnection to processor)
	// If counters decreased, re-baseline instead of recording negative rates
	if deltaPackets < 0 || deltaBytes < 0 {
		rt.lastPackets = totalPackets
		rt.lastBytes = totalBytes
		rt.lastTime = now
		return // Skip this sample, next one will be valid
	}

	packetsPerSec := float64(deltaPackets) / elapsed
	bytesPerSec := float64(deltaBytes) / elapsed

	// Update peaks
	if packetsPerSec > rt.peakPacketsPerSec {
		rt.peakPacketsPerSec = packetsPerSec
	}
	if bytesPerSec > rt.peakBytesPerSec {
		rt.peakBytesPerSec = bytesPerSec
	}

	// Store sample
	rt.samples[rt.head] = RateSample{
		Timestamp: now,
		Packets:   deltaPackets,
		Bytes:     deltaBytes,
	}

	rt.head = (rt.head + 1) % rt.maxSamples
	if rt.count < rt.maxSamples {
		rt.count++
	}

	// Update baseline for next delta
	rt.lastPackets = totalPackets
	rt.lastBytes = totalBytes
	rt.lastTime = now
}

// GetStats returns computed rate statistics.
func (rt *RateTracker) GetStats() RateStats {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if rt.count == 0 {
		return RateStats{}
	}

	// Get most recent sample for current rate
	lastIdx := (rt.head - 1 + rt.maxSamples) % rt.maxSamples
	lastSample := rt.samples[lastIdx]
	elapsed := rt.interval.Seconds()

	// Calculate current rate from most recent sample
	currentPacketsPerSec := float64(lastSample.Packets) / elapsed
	currentBytesPerSec := float64(lastSample.Bytes) / elapsed

	// Calculate average across all samples
	var totalPackets, totalBytes int64
	for i := 0; i < rt.count; i++ {
		idx := (rt.head - 1 - i + rt.maxSamples) % rt.maxSamples
		totalPackets += rt.samples[idx].Packets
		totalBytes += rt.samples[idx].Bytes
	}

	avgPacketsPerSec := float64(totalPackets) / (float64(rt.count) * elapsed)
	avgBytesPerSec := float64(totalBytes) / (float64(rt.count) * elapsed)

	return RateStats{
		CurrentPacketsPerSec: currentPacketsPerSec,
		CurrentBytesPerSec:   currentBytesPerSec,
		AvgPacketsPerSec:     avgPacketsPerSec,
		AvgBytesPerSec:       avgBytesPerSec,
		PeakPacketsPerSec:    rt.peakPacketsPerSec,
		PeakBytesPerSec:      rt.peakBytesPerSec,
	}
}

// GetRatesForWindow returns rate samples for the specified time window.
// Returns up to maxPoints samples, evenly distributed across the window.
func (rt *RateTracker) GetRatesForWindow(window TimeWindow, maxPoints int) []float64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if rt.count == 0 || maxPoints <= 0 {
		return nil
	}

	// Determine how many samples to use based on window
	windowDuration := window.Duration()
	samplesInWindow := int(windowDuration / rt.interval)
	if samplesInWindow > rt.count {
		samplesInWindow = rt.count
	}
	if samplesInWindow <= 0 {
		return nil
	}

	// If we have fewer samples than maxPoints, return all samples
	if samplesInWindow <= maxPoints {
		rates := make([]float64, samplesInWindow)
		for i := 0; i < samplesInWindow; i++ {
			// Read from oldest to newest
			idx := (rt.head - samplesInWindow + i + rt.maxSamples) % rt.maxSamples
			rates[i] = float64(rt.samples[idx].Packets) / rt.interval.Seconds()
		}
		return rates
	}

	// Downsample by averaging groups
	rates := make([]float64, maxPoints)
	groupSize := samplesInWindow / maxPoints
	remainder := samplesInWindow % maxPoints

	sampleIdx := 0
	for i := 0; i < maxPoints; i++ {
		// Some groups get an extra sample to distribute remainder evenly
		currentGroupSize := groupSize
		if i < remainder {
			currentGroupSize++
		}

		var sum float64
		for j := 0; j < currentGroupSize; j++ {
			idx := (rt.head - samplesInWindow + sampleIdx + rt.maxSamples) % rt.maxSamples
			sum += float64(rt.samples[idx].Packets)
			sampleIdx++
		}
		rates[i] = (sum / float64(currentGroupSize)) / rt.interval.Seconds()
	}

	return rates
}

// SampleCount returns the number of samples currently stored.
func (rt *RateTracker) SampleCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.count
}

// GetSamples returns rate samples for sparkline rendering.
// Returns samples from oldest to newest, up to maxPoints.
// This is the width-based version that doesn't depend on time windows.
func (rt *RateTracker) GetSamples(maxPoints int) []float64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if rt.count == 0 || maxPoints <= 0 {
		return nil
	}

	// If we have fewer samples than maxPoints, use all samples
	if rt.count <= maxPoints {
		rates := make([]float64, rt.count)
		for i := 0; i < rt.count; i++ {
			// Read from oldest to newest
			idx := (rt.head - rt.count + i + rt.maxSamples) % rt.maxSamples
			rates[i] = float64(rt.samples[idx].Packets) / rt.interval.Seconds()
		}
		return rates
	}

	// Downsample by averaging groups
	rates := make([]float64, maxPoints)
	groupSize := rt.count / maxPoints
	remainder := rt.count % maxPoints

	sampleIdx := 0
	for i := 0; i < maxPoints; i++ {
		// Some groups get an extra sample to distribute remainder evenly
		currentGroupSize := groupSize
		if i < remainder {
			currentGroupSize++
		}

		var sum float64
		for j := 0; j < currentGroupSize; j++ {
			idx := (rt.head - rt.count + sampleIdx + rt.maxSamples) % rt.maxSamples
			sum += float64(rt.samples[idx].Packets)
			sampleIdx++
		}
		rates[i] = (sum / float64(currentGroupSize)) / rt.interval.Seconds()
	}

	return rates
}

// Resize changes the tracker capacity, preserving existing samples.
// If newCapacity is smaller than current count, oldest samples are discarded.
func (rt *RateTracker) Resize(newCapacity int) {
	if newCapacity <= 0 {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if newCapacity == rt.maxSamples {
		return // No change needed
	}

	// Extract current samples in order (oldest to newest)
	oldSamples := make([]RateSample, rt.count)
	for i := 0; i < rt.count; i++ {
		idx := (rt.head - rt.count + i + rt.maxSamples) % rt.maxSamples
		oldSamples[i] = rt.samples[idx]
	}

	// Create new buffer
	rt.samples = make([]RateSample, newCapacity)
	rt.maxSamples = newCapacity

	// Copy samples, keeping most recent if we're shrinking
	copyCount := rt.count
	startIdx := 0
	if copyCount > newCapacity {
		startIdx = copyCount - newCapacity
		copyCount = newCapacity
	}

	for i := 0; i < copyCount; i++ {
		rt.samples[i] = oldSamples[startIdx+i]
	}

	rt.head = copyCount % newCapacity
	rt.count = copyCount
}

// Reset clears all samples and resets the tracker.
func (rt *RateTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.head = 0
	rt.count = 0
	rt.started = false
	rt.lastPackets = 0
	rt.lastBytes = 0
	rt.lastTime = time.Time{}
	rt.peakPacketsPerSec = 0
	rt.peakBytesPerSec = 0
}
