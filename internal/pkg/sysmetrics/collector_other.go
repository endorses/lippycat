//go:build !linux

package sysmetrics

import (
	"runtime"
)

// platformCollector holds non-Linux state (minimal).
type platformCollector struct{}

// initPlatform initializes non-Linux collection (no-op).
func (c *collector) initPlatform() {}

// collectPlatform gathers metrics using Go runtime (non-Linux fallback).
// CPU is unavailable on non-Linux platforms.
func (c *collector) collectPlatform() Metrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return Metrics{
		CPUPercent:       -1,           // CPU unavailable on non-Linux
		MemoryRSSBytes:   memStats.Sys, // Best approximation of RSS
		MemoryLimitBytes: 0,            // No cgroup on non-Linux
	}
}
