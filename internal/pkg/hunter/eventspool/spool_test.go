package eventspool

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/stretchr/testify/require"
)

func batch(source, session string, batchSequence, first, last uint64) *eventsv1.ProtocolEventBatch {
	return &eventsv1.ProtocolEventBatch{SourceNodeId: source, ProducerSessionId: session, BatchSequence: batchSequence, FirstEventSequence: first, LastEventSequence: last}
}

func TestOpenRetainsExistingRecordsDespiteLimits(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	result, err := s.Enqueue(batch("hunter", "session", 1, 10, 12))
	require.NoError(t, err)
	require.True(t, result.Stored)

	now = now.Add(24 * time.Hour)
	reopened, err := Open(Config{Directory: dir, MaxBytes: 1, MaxAge: time.Second, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1, "startup must not delete over-limit unacknowledged records")
}

func TestChecksumCorruptionIsReportedAndNotDeleted(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 1))
	require.NoError(t, err)
	paths, err := filepath.Glob(filepath.Join(dir, "*"+recordExtension))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	f, err := os.OpenFile(paths[0], os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{0xff}, headerSize)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = Open(Config{Directory: dir})
	require.ErrorContains(t, err, "checksum mismatch")
	_, statErr := os.Stat(paths[0])
	require.NoError(t, statErr, "corrupt records must remain for operator recovery")
}

func TestDropOldestReportsExactRanges(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Policy: DropOldest, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	first, err := s.Enqueue(batch("hunter", "session", 1, 10, 12))
	require.NoError(t, err)
	require.True(t, first.Stored)
	s.config.MaxAge = time.Second
	now = now.Add(2 * time.Second)
	result, err := s.Enqueue(batch("hunter", "session", 2, 20, 21))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.Len(t, result.Losses, 1)
	require.Equal(t, uint64(3), result.Losses[0].Count)
	require.Equal(t, uint64(10), result.Losses[0].EventSequenceRanges[0].First)
	require.Equal(t, uint64(12), result.Losses[0].EventSequenceRanges[0].Last)
	stored := s.Batches()[0]
	require.Equal(t, uint64(2), stored.BatchSequence)
	require.Equal(t, result.Losses, stored.GetStats().GetLosses())
}

func TestDropNewPreservesExistingAndReportsIncomingRange(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, Policy: DropNew})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 2))
	require.NoError(t, err)
	s.config.MaxBytes = s.Bytes()
	result, err := s.Enqueue(batch("hunter", "session", 2, 3, 7))
	require.NoError(t, err)
	require.False(t, result.Stored)
	require.Equal(t, uint64(5), result.Losses[0].Count)
	require.Equal(t, uint64(1), s.Batches()[0].BatchSequence)
}

func TestAgeLimitDropsOnlyCompleteOldBatches(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, MaxAge: time.Minute, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 4))
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	result, err := s.Enqueue(batch("hunter", "session", 2, 5, 6))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.Equal(t, uint64(4), result.Losses[0].Count)
	require.Len(t, s.Batches(), 1)
}

func TestCumulativeAckIsScopedToProducerSession(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	for _, b := range []*eventsv1.ProtocolEventBatch{
		batch("hunter", "one", 1, 1, 1), batch("hunter", "two", 1, 1, 1), batch("hunter", "one", 2, 2, 2),
	} {
		_, err = s.Enqueue(b)
		require.NoError(t, err)
	}
	require.NoError(t, s.Ack("hunter", "one", 1))
	remaining := s.Batches()
	require.Len(t, remaining, 2)
	require.Equal(t, "two", remaining[0].ProducerSessionId)
	require.Equal(t, uint64(2), remaining[1].BatchSequence)

	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 2)
}

func TestRecoveryStateResumesIdentityAndSequences(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "30313233343536373839616263646566", 7, 40, 44))
	require.NoError(t, err)
	source, session, eventSequence, batchSequence, err := s.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "hunter", source)
	require.Equal(t, "30313233343536373839616263646566", session)
	require.Equal(t, uint64(44), eventSequence)
	require.Equal(t, uint64(7), batchSequence)
}

func TestRecoveryStateIncludesLossOnlyEventHighWater(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	lossOnly := batch("hunter", "session", 3, 0, 0)
	lossOnly.Stats = &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{
		Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 4,
		SourceNodeId: "hunter", ProducerSessionId: "session",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 10, Last: 13}},
	}}}
	_, err = s.Enqueue(lossOnly)
	require.NoError(t, err)

	_, _, eventSequence, batchSequence, err := s.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, uint64(13), eventSequence)
	require.Equal(t, uint64(3), batchSequence)
}

func TestRecoveryStateRejectsMixedSessions(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "one", 1, 1, 1))
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "two", 1, 1, 1))
	require.NoError(t, err)
	_, _, _, _, err = s.RecoveryState()
	require.ErrorContains(t, err, "multiple producer sessions")
}

func TestRecoveryOrdersOneSessionByBatchSequence(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 1))
	require.NoError(t, err)
	paths, err := filepath.Glob(filepath.Join(dir, "*"+recordExtension))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	require.NoError(t, os.Rename(paths[0], filepath.Join(dir, "z"+recordExtension)))
	_, err = s.Enqueue(batch("hunter", "session", 2, 2, 2))
	require.NoError(t, err)
	paths, err = filepath.Glob(filepath.Join(dir, "*"+recordExtension))
	require.NoError(t, err)
	for _, path := range paths {
		if filepath.Base(path) != "z"+recordExtension {
			require.NoError(t, os.Rename(path, filepath.Join(dir, "a"+recordExtension)))
		}
	}
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	batches := reopened.Batches()
	require.Equal(t, []uint64{1, 2}, []uint64{batches[0].BatchSequence, batches[1].BatchSequence})
}
