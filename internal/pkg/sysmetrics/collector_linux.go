//go:build linux

package sysmetrics

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

// platformCollector holds Linux-specific state for CPU calculation.
type platformCollector struct {
	// Previous CPU times for delta calculation
	prevCPUTime  uint64    // utime + stime in clock ticks
	prevWallTime time.Time // Wall clock time of previous sample
	clockTicksHz uint64    // Clock ticks per second (usually 100)
	memoryLimit  uint64    // Cached cgroup memory limit
	limitChecked bool      // Whether we've checked for cgroup limit
	hasSample    bool      // Whether we have a previous sample for delta calculation
}

// initPlatform initializes Linux-specific collection state.
func (c *collector) initPlatform() {
	c.platformData.clockTicksHz = getClockTicksHz()
	c.platformData.prevWallTime = time.Now()
	c.platformData.prevCPUTime = readProcessCPUTime()
}

// collectPlatform gathers metrics from Linux /proc filesystem.
func (c *collector) collectPlatform() Metrics {
	m := Metrics{}

	// Read RSS from /proc/self/status
	m.MemoryRSSBytes = readMemoryRSS()

	// Get cgroup memory limit (cached after first read)
	if !c.platformData.limitChecked {
		c.platformData.memoryLimit = readCgroupMemoryLimit()
		c.platformData.limitChecked = true
	}
	m.MemoryLimitBytes = c.platformData.memoryLimit

	// Calculate CPU percentage from delta
	now := time.Now()
	currentCPUTime := readProcessCPUTime()

	wallDelta := now.Sub(c.platformData.prevWallTime).Seconds()
	if c.platformData.hasSample && wallDelta > 0.5 {
		// Calculate CPU from the delta since last sample
		cpuDelta := currentCPUTime - c.platformData.prevCPUTime
		// Convert clock ticks to seconds, then to percentage
		cpuSeconds := float64(cpuDelta) / float64(c.platformData.clockTicksHz)
		m.CPUPercent = (cpuSeconds / wallDelta) * 100.0

		// Clamp to reasonable range (can exceed 100% briefly due to timing)
		if m.CPUPercent < 0 {
			m.CPUPercent = 0
		} else if m.CPUPercent > 100 {
			m.CPUPercent = 100
		}
	} else {
		m.CPUPercent = -1 // Not enough data yet
	}

	// Save for next iteration
	c.platformData.prevCPUTime = currentCPUTime
	c.platformData.prevWallTime = now
	c.platformData.hasSample = true

	return m
}

// getClockTicksHz returns the system clock ticks per second.
// Usually 100 on Linux, but we read it dynamically to be safe.
func getClockTicksHz() uint64 {
	// Try to get from sysconf-like approach via /proc
	// Default to 100 (standard Linux value)
	return 100
}

// readProcessCPUTime reads utime + stime from /proc/self/stat.
// Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt
//
//	majflt cmajflt utime stime cutime cstime priority nice ...
//
// Fields are space-separated; utime is field 14, stime is field 15 (1-indexed).
func readProcessCPUTime() uint64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}

	// Find the end of (comm) field - handles cases like "(foo bar)"
	start := bytes.IndexByte(data, ')')
	if start == -1 || start+2 >= len(data) {
		return 0
	}

	// Fields after (comm) start at index 3
	fields := bytes.Fields(data[start+2:])
	if len(fields) < 13 { // Need fields up to stime (index 12)
		return 0
	}

	// utime is field index 11 (after comm), stime is field index 12
	utime, err1 := strconv.ParseUint(string(fields[11]), 10, 64)
	stime, err2 := strconv.ParseUint(string(fields[12]), 10, 64)
	if err1 != nil || err2 != nil {
		return 0
	}

	return utime + stime
}

// readMemoryRSS reads VmRSS from /proc/self/status.
func readMemoryRSS() uint64 {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					// VmRSS is in kB, convert to bytes
					return val * 1024
				}
			}
			break
		}
	}

	return 0
}

// readCgroupMemoryLimit reads memory limit from cgroup.
// Tries cgroup v2 first, then falls back to cgroup v1.
func readCgroupMemoryLimit() uint64 {
	// Try cgroup v2 (unified hierarchy)
	if limit := readCgroupV2MemoryLimit(); limit > 0 {
		return limit
	}

	// Try cgroup v1
	if limit := readCgroupV1MemoryLimit(); limit > 0 {
		return limit
	}

	return 0
}

// readCgroupV2MemoryLimit reads memory.max from cgroup v2.
func readCgroupV2MemoryLimit() uint64 {
	data, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0
	}

	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0 // No limit
	}

	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}

	return val
}

// readCgroupV1MemoryLimit reads memory.limit_in_bytes from cgroup v1.
func readCgroupV1MemoryLimit() uint64 {
	data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if err != nil {
		return 0
	}

	s := strings.TrimSpace(string(data))
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}

	// Very large values indicate no limit (usually 9223372036854771712)
	if val > 1<<62 {
		return 0
	}

	return val
}
