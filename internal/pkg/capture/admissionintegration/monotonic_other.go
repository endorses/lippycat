//go:build !linux

package admissionintegration

import "time"

func monotonicNow() uint64           { return 0 }
func monotonicTime(time.Time) uint64 { return 0 }
func monotonicReadErrors() uint64    { return 0 }
