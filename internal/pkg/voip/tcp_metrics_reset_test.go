package voip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResetTCPStreamMetricsStartsNewCaptureSession(t *testing.T) {
	ResetTCPStreamMetrics()
	RecordPostReassemblyDrop(17)
	RecordReassemblyDiscontinuity(9)
	IncrementParserFramingDiscontinuity()
	IncrementStreamRecoveryFailure()

	before := GetTCPStreamMetrics()
	require.Equal(t, int64(1), before.PostReassemblyDroppedChunks)
	require.Equal(t, int64(17), before.PostReassemblyDroppedBytes)
	require.Equal(t, int64(9), before.MissingSequenceBytes)

	ResetTCPStreamMetrics()
	after := GetTCPStreamMetrics()
	require.Zero(t, after.PostReassemblyDroppedChunks)
	require.Zero(t, after.PostReassemblyDroppedBytes)
	require.Zero(t, after.StreamDiscontinuities)
	require.Zero(t, after.MissingSequenceBytes)
	require.Zero(t, after.ParserFramingDiscontinuities)
	require.Zero(t, after.RecoveryFailures)
}
