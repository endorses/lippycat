//go:build linux

package admissionintegration

import (
	"errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"testing"
)

func TestMonotonicFailureIsCountedAndCannotSupplyEvidence(t *testing.T) {
	before := monotonicReadErrors()
	now := readMonotonic(func(int32, *unix.Timespec) error { return errors.New("synthetic clock failure") })
	require.Zero(t, now)
	require.Equal(t, before+1, monotonicReadErrors())
	valid := readMonotonic(func(_ int32, ts *unix.Timespec) error { ts.Sec = 1; ts.Nsec = 2; return nil })
	require.Equal(t, uint64(1000000002), valid)
	require.Equal(t, before+1, monotonicReadErrors())
}
