package eventspool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestReadRecordRejectsUntrustedLengthsWithoutRemovingEvidence(t *testing.T) {
	cases := []struct {
		name       string
		declared   uint64
		payload    []byte
		maxPayload uint64
	}{
		{name: "max uint64", declared: ^uint64(0), maxPayload: MaxRecordPayloadBytes},
		{name: "over hard limit", declared: 9, payload: make([]byte, 9), maxPayload: 8},
		{name: "larger than remainder", declared: 2, payload: []byte{1}, maxPayload: 8},
		{name: "smaller than remainder", declared: 1, payload: []byte{1, 2}, maxPayload: 8},
		{name: "header only truncated", declared: 1, maxPayload: 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad"+recordExtension)
			writeRawRecord(t, path, tc.declared, tc.payload)
			_, err := readRecord(path, tc.maxPayload)
			require.Error(t, err)
			_, statErr := os.Stat(path)
			require.NoError(t, statErr)
		})
	}
}

func TestReadRecordAcceptsExactPayloadBoundary(t *testing.T) {
	payload, err := proto.Marshal(batch("node", "session", 1, 0, 0))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "exact"+recordExtension)
	writeRawRecord(t, path, uint64(len(payload)), payload)
	_, err = readRecord(path, uint64(len(payload)))
	require.NoError(t, err)
}

func TestOpenEnforcesExclusiveOwnership(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = Open(Config{Directory: dir})
	require.ErrorContains(t, err, "already owned")
	require.NoError(t, first.Close())
	second, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, second.Close())
}

func TestPublishedBatchesAreImmutableToCallers(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	input := batch("node", "session", 1, 1, 1)
	_, err = s.Enqueue(input)
	require.NoError(t, err)
	input.BatchSequence = 99
	got := s.Batches()
	got[0].BatchSequence = 88
	got, err = s.BatchesAfter("node", "session", 0, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), got[0].GetBatchSequence())
}

func TestPhysicalBytesConsistentlyCountRecordStorage(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Zero(t, s.PhysicalBytes(), "manifest, journal, and lock metadata are not record storage")
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	require.Equal(t, s.Bytes(), s.PhysicalBytes())
	require.NoError(t, s.Close())

	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Equal(t, reopened.Bytes(), reopened.PhysicalBytes())
	require.NoError(t, reopened.Close())
}

func TestDurabilityUncertainBarrierAndRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	failing := defaultFS()
	failing.syncDir = func(string) error { return errors.New("injected sync failure") }
	s.fs = failing
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.ErrorIs(t, err, ErrDurabilityUncertain)
	require.True(t, s.Status().DurabilityUncertain)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.ErrorIs(t, err, ErrDurabilityUncertain)
	_, err = s.BatchesAfter("node", "session", 0, 1)
	require.ErrorIs(t, err, ErrDurabilityUncertain)
	s.fs = defaultFS()
	require.NoError(t, s.Recover())
	require.False(t, s.Status().DurabilityUncertain)
	require.Empty(t, s.Batches(), "record published before failed directory sync was never referenced")
	require.NoError(t, s.Close())
}

func TestCheckpointFailureAfterCommitReportsStored(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir(), CheckpointEvery: 1})
	require.NoError(t, err)
	fs := defaultFS()
	directorySyncs := 0
	fs.syncDir = func(path string) error {
		directorySyncs++
		if directorySyncs == 2 {
			return errors.New("injected checkpoint directory sync failure")
		}
		return syncDirectory(path)
	}
	s.fs = fs
	result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
	require.True(t, result.Stored, "the journal transaction committed before checkpoint maintenance failed")
	require.ErrorIs(t, err, ErrDurabilityUncertain)
	require.True(t, s.Status().DurabilityUncertain)
	s.fs = defaultFS()
	require.NoError(t, s.Close())
}

func TestCommittedCleanupFailureDoesNotReactivateVictim(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(100, 0)
	s, err := Open(Config{Directory: dir, MaxAge: time.Second, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	failing := defaultFS()
	failing.remove = func(path string) error {
		if filepath.Ext(path) == recordExtension {
			return errors.New("injected unlink failure")
		}
		return os.Remove(path)
	}
	s.fs = failing
	result, err := s.Enqueue(batch("node", "session", 2, 2, 2))
	require.True(t, result.Stored)
	var cleanupErr *CleanupError
	require.ErrorAs(t, err, &cleanupErr)
	require.False(t, s.Contains("node", "session", 1))
	require.True(t, s.Contains("node", "session", 2))
	s.fs = defaultFS()
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Equal(t, []uint64{2}, []uint64{reopened.Batches()[0].GetBatchSequence()})
	require.NoError(t, reopened.Close())
}

func TestOversizedRejectionPersistsAndFlushesExactLoss(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, MaxRecordBytes: 256})
	require.NoError(t, err)
	large := batch("node", "session", 1, 0, 0)
	loss := &eventsv1.EventLoss{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, SourceNodeId: "node", ProducerSessionId: "session"}
	for i := uint64(1); i <= 40; i++ {
		sequence := i * 2
		loss.EventSequenceRanges = append(loss.EventSequenceRanges, &eventsv1.SequenceRange{First: sequence, Last: sequence})
		loss.Count++
	}
	large.Stats = &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}}
	result, err := s.Enqueue(large)
	require.ErrorIs(t, err, ErrRecordTooLarge)
	require.Equal(t, RejectionRecordTooLarge, result.Rejection)
	require.True(t, s.HasPendingLosses())
	sequence := uint64(1)
	for s.HasPendingLosses() {
		flush, flushErr := s.FlushPendingLosses("node", "session", sequence, 1)
		require.NoError(t, flushErr)
		require.True(t, flush.Stored)
		sequence++
	}
	require.False(t, s.HasPendingLosses())
	var count uint64
	for _, stored := range s.Batches() {
		for _, reported := range stored.GetStats().GetLosses() {
			count += reported.GetCount()
		}
	}
	require.Equal(t, uint64(40), count)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir, MaxRecordBytes: 256})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 2)
	require.NoError(t, reopened.Close())
}

func TestPendingLossSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, Policy: DropNew, MaxBytes: 1})
	require.NoError(t, err)
	result, err := s.Enqueue(batch("node", "session", 1, 4, 7))
	require.NoError(t, err)
	require.Equal(t, RejectionExhausted, result.Rejection)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir, Policy: DropNew, MaxBytes: 1})
	require.NoError(t, err)
	require.True(t, reopened.HasPendingLosses())
	_, _, lastEvent, lastBatch, err := reopened.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, uint64(7), lastEvent)
	require.Zero(t, lastBatch)
	reopened.config.MaxBytes = 0
	flush, err := reopened.FlushPendingLosses("node", "session", 1, 1)
	require.NoError(t, err)
	require.True(t, flush.Stored)
	require.NoError(t, reopened.Close())
}

func TestPendingLossAPIsRejectInvalidIdentityBeforeCommit(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	valid := func(source, session string, sequence uint64) *eventsv1.EventLoss {
		return &eventsv1.EventLoss{
			Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
			SourceNodeId: source, ProducerSessionId: session,
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: sequence, Last: sequence}},
		}
	}
	_, err = s.RetainLosses([]*eventsv1.EventLoss{valid("node", "one", 1), valid("node", "two", 2)})
	require.ErrorContains(t, err, "producer identity")
	require.False(t, s.HasPending())

	invalid := valid("node", "one", 1)
	invalid.Kind = eventsv1.LossKind_LOSS_KIND_UNSPECIFIED
	_, err = s.RetainLosses([]*eventsv1.EventLoss{invalid})
	require.ErrorContains(t, err, "invalid loss")
	require.False(t, s.HasPending())

	_, err = s.RetainLosses([]*eventsv1.EventLoss{valid("node", "one", 1)})
	require.NoError(t, err)
	_, err = s.FlushPendingLosses("node", "two", 1, 1)
	require.ErrorContains(t, err, "fixed spool session")
	require.True(t, s.HasPendingLosses())
}

func TestFlushPendingLossesHonorsCapacityPolicy(t *testing.T) {
	loss := &eventsv1.EventLoss{
		Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
		SourceNodeId: "node", ProducerSessionId: "session",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}},
	}
	t.Run("drop new remains bounded", func(t *testing.T) {
		s, err := Open(Config{Directory: t.TempDir(), Policy: DropNew, MaxBytes: 1})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		_, err = s.RetainLosses([]*eventsv1.EventLoss{loss})
		require.NoError(t, err)
		result, err := s.FlushPendingLosses("node", "session", 1, 1)
		require.NoError(t, err)
		require.Equal(t, RejectionExhausted, result.Rejection)
		require.Zero(t, s.Bytes())
		require.True(t, s.HasPendingLosses())
	})

	t.Run("drop oldest replaces atomically", func(t *testing.T) {
		s, err := Open(Config{Directory: t.TempDir(), Policy: DropOldest})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		_, err = s.Enqueue(batch("node", "session", 1, 2, 2))
		require.NoError(t, err)
		s.config.MaxBytes = s.Bytes()
		_, err = s.RetainLosses([]*eventsv1.EventLoss{loss})
		require.NoError(t, err)
		result, err := s.FlushPendingLosses("node", "session", 2, 1)
		require.NoError(t, err)
		require.True(t, result.Stored)
		require.LessOrEqual(t, s.Bytes(), s.config.MaxBytes)
		require.False(t, s.Contains("node", "session", 1))
		require.True(t, s.Contains("node", "session", 2))
		require.True(t, s.HasPendingLosses(), "the evicted event remains exact durable coverage")
	})
}

func TestDuplicateBatchIsRejectedBeforeJournalPublication(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 2, 2))
	require.ErrorContains(t, err, "duplicate batch identity")
	require.False(t, s.Status().DurabilityUncertain)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1)
	require.NoError(t, reopened.Close())
}

func TestNormalizeLossesHandlesMaxUint64EndingRange(t *testing.T) {
	losses := normalizeLosses([]*eventsv1.EventLoss{
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: ^uint64(0) - 1, SourceNodeId: "node", ProducerSessionId: "session", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 2, Last: ^uint64(0)}}},
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: "node", ProducerSessionId: "session", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 5, Last: 5}}},
	})
	require.Len(t, losses, 1)
	require.Equal(t, uint64(2), losses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, ^uint64(0), losses[0].GetEventSequenceRanges()[0].GetLast())
	require.Equal(t, ^uint64(0)-1, losses[0].GetCount())
}

func TestRetainLossesRejectsAggregateCountOverflow(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	loss := func(count uint64) *eventsv1.EventLoss {
		return &eventsv1.EventLoss{
			Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: count,
			SourceNodeId: "node", ProducerSessionId: "session",
		}
	}
	_, err = s.RetainLosses([]*eventsv1.EventLoss{loss(^uint64(0)), loss(1)})
	require.ErrorContains(t, err, "overflows exact accounting")
	require.False(t, s.HasPending())
}

func TestJournalIncompleteTailIsIgnoredButInteriorCorruptionFails(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	journal := filepath.Join(dir, journalFileName)
	f, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.Write([]byte{0, 0})
	require.NoError(t, err)
	require.NoError(t, f.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1)
	require.NoError(t, reopened.Close())

	payload, err := os.ReadFile(journal)
	require.NoError(t, err)
	require.Greater(t, len(payload), 25)
	payload[25] ^= 0xff
	require.NoError(t, os.WriteFile(journal, payload, 0o600))
	_, err = Open(Config{Directory: dir})
	require.ErrorContains(t, err, "corrupt frame header")
}

func TestManifestRejectsUnsafeRecordPath(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	m, err := readManifest(filepath.Join(dir, manifestFileName))
	require.NoError(t, err)
	m.Records = []manifestRecord{{Name: "../escape" + recordExtension}}
	payload, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, manifestFileName), payload, 0o600))
	_, err = Open(Config{Directory: dir})
	require.ErrorContains(t, err, "unsafe")
}

func TestAckCleanupFailureAtEachVictimKeepsLogicalCommit(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("victim_%d", failAt), func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			for i := uint64(1); i <= 3; i++ {
				_, err = s.Enqueue(batch("node", "session", i, i, i))
				require.NoError(t, err)
			}
			calls := 0
			failing := defaultFS()
			failing.remove = func(path string) error {
				if filepath.Ext(path) == recordExtension {
					calls++
					if calls == failAt {
						return errors.New("injected unlink failure")
					}
				}
				return os.Remove(path)
			}
			s.fs = failing
			err = s.Ack("node", "session", 3)
			var cleanupErr *CleanupError
			require.ErrorAs(t, err, &cleanupErr)
			require.Empty(t, s.Batches())
			s.fs = defaultFS()
			require.NoError(t, s.Close())
			reopened, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			require.Empty(t, reopened.Batches())
			require.NoError(t, reopened.Close())
		})
	}
}

func TestCheckpointRotationAndIncrementalMetrics(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir(), CheckpointEvery: 2})
	require.NoError(t, err)
	for i := uint64(1); i <= 20; i++ {
		_, err = s.Enqueue(batch("node", "session", i, i, i))
		require.NoError(t, err)
	}
	for after := uint64(0); after < 20; after += 4 {
		got, fetchErr := s.BatchesAfter("node", "session", after, 4)
		require.NoError(t, fetchErr)
		require.NotEmpty(t, got)
	}
	for i := uint64(1); i <= 20; i++ {
		require.NoError(t, s.Ack("node", "session", i))
	}
	metrics := s.SnapshotMetrics()
	require.Equal(t, uint64(20), metrics.RetrievalClones)
	require.Less(t, metrics.RetrievalVisits, uint64(100))
	require.Less(t, metrics.ACKRemovalVisits, uint64(100))
	require.Greater(t, metrics.Rotations, uint64(0))
	require.NoError(t, s.Close())
}

func TestSustainedReplacementBoundsJournalFrames(t *testing.T) {
	now := time.Unix(1, 0)
	s, err := Open(Config{Directory: t.TempDir(), MaxAge: time.Nanosecond, CheckpointEvery: 4, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	for i := uint64(1); i <= 40; i++ {
		now = now.Add(time.Second)
		_, err = s.Enqueue(batch("node", "session", i, i, i))
		require.NoError(t, err)
	}
	metrics := s.SnapshotMetrics()
	require.Greater(t, metrics.Rotations, uint64(0))
	require.LessOrEqual(t, metrics.MaxJournalFrames, uint64(4))
	require.NoError(t, s.Close())
}

func writeRawRecord(t *testing.T, path string, declared uint64, payload []byte) {
	t.Helper()
	header := make([]byte, headerSize)
	copy(header, recordMagic[:])
	binary.BigEndian.PutUint16(header[8:10], recordVersion)
	binary.BigEndian.PutUint64(header[10:18], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(header[18:26], declared)
	binary.BigEndian.PutUint32(header[26:30], crc32.ChecksumIEEE(payload))
	require.NoError(t, os.WriteFile(path, append(header, payload...), 0o600))
}

func FuzzReadRecordHeader(f *testing.F) {
	f.Add(uint64(0), []byte{})
	f.Add(^uint64(0), []byte{1})
	f.Fuzz(func(t *testing.T, declared uint64, payload []byte) {
		if len(payload) > 1024 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "fuzz"+recordExtension)
		writeRawRecord(t, path, declared, payload)
		_, _ = readRecord(path, 1024)
	})
}

func BenchmarkSpoolBuildDrain(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("records_%d", count), func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				s, err := Open(Config{Directory: b.TempDir(), CheckpointEvery: 128})
				if err != nil {
					b.Fatal(err)
				}
				for i := 1; i <= count; i++ {
					if _, err = s.Enqueue(batch("node", "session", uint64(i), uint64(i), uint64(i))); err != nil {
						b.Fatal(err)
					}
				}
				for i := 1; i <= count; i++ {
					if err = s.Ack("node", "session", uint64(i)); err != nil {
						b.Fatal(err)
					}
				}
				if err = s.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSpoolSustainedReplacement(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("records_%d", count), func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				now := time.Unix(1, 0)
				s, err := Open(Config{Directory: b.TempDir(), MaxAge: time.Nanosecond, CheckpointEvery: 128, Clock: func() time.Time { return now }})
				if err != nil {
					b.Fatal(err)
				}
				for i := 1; i <= count; i++ {
					now = now.Add(time.Second)
					if _, err = s.Enqueue(batch("node", "session", uint64(i), uint64(i), uint64(i))); err != nil {
						b.Fatal(err)
					}
				}
				metrics := s.SnapshotMetrics()
				if metrics.Rotations == 0 {
					b.Fatal("expected forced journal rotation")
				}
				b.ReportMetric(float64(metrics.MetadataBytes), "metadata-bytes")
				b.ReportMetric(float64(metrics.Rotations), "rotations")
				if err = s.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
