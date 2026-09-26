//go:build linux

package securestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func reservedTestSegment(t *testing.T) (string, *Dir, *FixedSegmentReservation) {
	t.Helper()
	path, d := privateTestDir(t)
	owner, err := d.Lock("output.lsg")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, owner.Close()) })
	r, err := d.ReserveFixedSegment(".offline-stage", "output.lsg")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	return path, d, r
}
func TestReservedFixedSegmentPublishesSameAllocatedInode(t *testing.T) {
	path, d, r := reservedTestSegment(t)
	before, err := d.FileIdentity(".offline-stage")
	require.NoError(t, err)
	require.GreaterOrEqual(t, r.AllocatedBytes(), int64(FixedSegmentBytes))
	_, err = os.Stat(filepath.Join(path, "output.lsg"))
	require.ErrorIs(t, err, os.ErrNotExist)
	r.segment.ops.allocate = func(*os.File, int64) error { t.Fatal("initialization must not allocate after sealing"); return nil }
	bootstrap := bytes.Repeat([]byte{0xa5}, FixedSegmentDataStart)
	out, err := r.Initialize(bootstrap)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	after, err := d.FileIdentity("output.lsg")
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.NoError(t, r.Close())
	s, err := d.OpenFixedSegment("output.lsg")
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	got := make([]byte, FixedSegmentDataStart)
	require.NoError(t, s.ReadAt(got, 0))
	require.Equal(t, bootstrap, got)
	require.NoError(t, s.Activate(FixedSegmentDataStart, 0), "preallocation must leave all payload bytes zero")
	_, err = r.Initialize(bootstrap)
	require.Error(t, err)
}
func TestReservedFixedSegmentDoesNotClobberNewDestination(t *testing.T) {
	path, _, r := reservedTestSegment(t)
	require.NoError(t, os.WriteFile(filepath.Join(path, "output.lsg"), []byte("existing"), 0600))
	out, err := r.Initialize(make([]byte, FixedSegmentDataStart))
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, NotCommitted, out)
	got, err := os.ReadFile(filepath.Join(path, "output.lsg"))
	require.NoError(t, err)
	require.Equal(t, []byte("existing"), got)
}
func TestReservedFixedSegmentPublicationSyncFailureIsUncertain(t *testing.T) {
	_, d, r := reservedTestSegment(t)
	original := d.ops.sync
	failure := errors.New("injected parent sync")
	d.ops.sync = func(f *os.File) error {
		if f == d.file {
			return failure
		}
		return original(f)
	}
	out, err := r.Initialize(make([]byte, FixedSegmentDataStart))
	require.ErrorIs(t, err, failure)
	require.Equal(t, Uncertain, out)
	require.Equal(t, Uncertain, OutcomeOf(err))
	require.NoError(t, r.Close())
}
