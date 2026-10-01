package voip

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResetTCPStreamMetricsStartsNewCaptureSession(t *testing.T) {
	ResetTCPStreamMetrics()
	RecordPostReassemblyDrop(17)
	RecordReassemblyDiscontinuity(9)
	IncrementParserFramingDiscontinuity()
	IncrementStreamRecoveryFailure()
	IncrementEstablishedIdleRetention()
	IncrementPreRearmDiscardedChunk()
	IncrementRearmRejectedChunk()
	IncrementRearmKeepaliveChunk()
	factory := &sipStreamFactory{}
	factory.RecordOrphanControl()
	factory.RecordReplacementDrop(31)
	atomic.AddInt64(&tcpStreamMetrics.acceptRejectedControls, 1)

	before := GetTCPStreamMetrics()
	require.Equal(t, int64(1), before.PostReassemblyDroppedChunks)
	require.Equal(t, int64(17), before.PostReassemblyDroppedBytes)
	require.Equal(t, int64(9), before.MissingSequenceBytes)
	require.EqualValues(t, 1, before.RearmKeepaliveChunks)
	require.EqualValues(t, 1, before.OrphanControls)
	require.EqualValues(t, 1, before.AcceptRejectedControls)
	require.EqualValues(t, 31, before.ReplacementDroppedBytes)

	ResetTCPStreamMetrics()
	after := GetTCPStreamMetrics()
	require.Zero(t, after.PostReassemblyDroppedChunks)
	require.Zero(t, after.PostReassemblyDroppedBytes)
	require.Zero(t, after.StreamDiscontinuities)
	require.Zero(t, after.MissingSequenceBytes)
	require.Zero(t, after.ParserFramingDiscontinuities)
	require.Zero(t, after.RecoveryFailures)
	require.Zero(t, after.EstablishedIdleRetentions)
	require.Zero(t, after.PreRearmDiscardedChunks)
	require.Zero(t, after.RearmRejectedChunks)
	require.Zero(t, after.RearmKeepaliveChunks)
	require.Zero(t, after.OrphanControls)
	require.Zero(t, after.AcceptRejectedControls)
	require.Zero(t, after.ReplacementDroppedBytes)
}
