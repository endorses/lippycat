//go:build linux

package admissionintegration

import (
	"golang.org/x/sys/unix"
	"sync/atomic"
	"time"
)

var monotonicFailures atomic.Uint64

func monotonicNow() uint64 { return readMonotonic(unix.ClockGettime) }

func readMonotonic(read func(int32, *unix.Timespec) error) uint64 {
	var ts unix.Timespec
	if err := read(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Aggregate the failure without waiting for logging in a packet path.
		// Zero is invalid evidence and prevents temporal classification.
		monotonicFailures.Add(1)
		return 0
	}
	return uint64(ts.Nano())
}

func monotonicReadErrors() uint64 { return monotonicFailures.Load() }
func monotonicTime(at time.Time) uint64 {
	now := monotonicNow()
	if now == 0 {
		return 0
	}
	delta := time.Since(at)
	if delta < 0 || uint64(delta) > now {
		return 0
	}
	return now - uint64(delta)
}
