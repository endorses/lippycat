//go:build linux

package securestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFixedSegmentAuthenticatedTailRecoveryPreservesSelectedPrefix(t *testing.T) {
	path, d, s := fixedTestSegment(t)
	data := bytes.Repeat([]byte{0x7a}, FixedSegmentBlock)
	out, err := s.Commit(data, bytes.Repeat([]byte{0x31}, FixedSegmentBlock))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	cursor := int64(FixedSegmentDataStart + FixedSegmentBlock)
	require.NoError(t, s.Close())
	f, err := os.OpenFile(filepath.Join(path, fixedTestName), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("unselected interrupted bytes"), cursor)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	s, err = d.OpenFixedSegment(fixedTestName)
	require.NoError(t, err)
	allocation := s.AllocatedBytes()
	out, err = s.DiscardUnselectedTail(cursor)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	require.Equal(t, allocation, s.AllocatedBytes())
	got := make([]byte, len(data))
	require.NoError(t, s.ReadAt(got, FixedSegmentDataStart))
	require.Equal(t, data, got)
	require.NoError(t, s.Activate(cursor, 0))
	_, err = s.DiscardUnselectedTail(cursor)
	require.Error(t, err, "armed handles cannot erase append history")
	require.NoError(t, s.Close())
}
func TestFixedSegmentTailRecoveryFaultLatches(t *testing.T) {
	for _, syncFault := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "sync"}[syncFault], func(t *testing.T) {
			_, d, s := fixedTestSegment(t)
			require.NoError(t, s.Close())
			s, err := d.OpenFixedSegment(fixedTestName)
			require.NoError(t, err)
			if syncFault {
				s.ops.dataSync = func(*os.File) error { return unix.EIO }
			} else {
				s.ops.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
					n, err := f.WriteAt(b[:1], off)
					return n, errors.Join(err, unix.ENOSPC)
				}
			}
			out, err := s.DiscardUnselectedTail(FixedSegmentDataStart)
			require.Error(t, err)
			require.Equal(t, Uncertain, out)
			require.Error(t, s.Activate(FixedSegmentDataStart, 0))
			require.NoError(t, s.Close())
		})
	}
}
