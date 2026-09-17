package eventspool

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
)

func batch(source, session string, batchSequence, first, last uint64) *eventsv1.ProtocolEventBatch {
	if last < first {
		first, last = last, first
	}
	var input []events.Event
	for sequence := first; sequence != 0 && sequence <= last; sequence++ {
		env := events.Envelope{Timestamp: time.Unix(1, 0).UTC(), EventID: events.DeliveryEventID(source, session, sequence), ProducerSessionID: session, EventSequence: sequence, UID: "uid", NodeID: source, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 53, DestinationPort: 53000}, CaptureScope: events.CaptureScopeFiltered, Provenance: events.SourceProvenance{CaptureSource: "test"}}
		input = append(input, events.NewDNSEvent(env))
	}
	b, err := protoadapter.ToProtoBatch(source, session, batchSequence, input, nil, 1)
	if err != nil {
		panic(err)
	}
	return b
}

func sessionPolicy(session, profile string, headers bool) SessionPolicy {
	return SessionPolicy{Version: 1, SourceNodeID: "hunter", ProducerSessionID: session, DeliveryProfile: profile, IncludeHTTPHeaders: headers, SemanticRevision: 1}
}

func TestSessionPolicyRecoveryRequiresExactMatch(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	policy := sessionPolicy("session", "reliable", false)
	require.NoError(t, s.BindSessionPolicy(policy))
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, reopened.BindSessionPolicy(policy))

	changedDelivery := policy
	changedDelivery.DeliveryProfile = "memory_only"
	require.ErrorContains(t, reopened.BindSessionPolicy(changedDelivery), "pending records use policy")
	changedEnrichment := policy
	changedEnrichment.IncludeHTTPHeaders = true
	require.ErrorContains(t, reopened.BindSessionPolicy(changedEnrichment), "pending records use policy")
}

func TestSessionPolicyLegacyPendingRecordsFailSafe(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "legacy", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.ErrorContains(t, reopened.BindSessionPolicy(sessionPolicy("legacy", "reliable", false)), "pending legacy records")
}

func TestSessionPolicyCanRotateAfterAckDrain(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	require.NoError(t, s.BindSessionPolicy(sessionPolicy("old", "reliable", false)))
	_, err = s.Enqueue(batch("hunter", "old", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Ack("hunter", "old", 1))
	require.NoError(t, s.BindSessionPolicy(sessionPolicy("new", "memory_only", true)))
}

func TestOpenRetainsExistingRecordsDespiteLimits(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	result, err := s.Enqueue(batch("hunter", "session", 1, 10, 12))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.NoError(t, s.Close())

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
	require.NoError(t, s.Close())

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

func TestDropOldestPreservesInheritedLossesAcrossRepeatedEviction(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, MaxAge: time.Second, Policy: DropOldest, Clock: func() time.Time { return now }})
	require.NoError(t, err)

	_, err = s.Enqueue(batch("hunter", "session", 1, 10, 12))
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	_, err = s.Enqueue(batch("hunter", "session", 2, 20, 21))
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	result, err := s.Enqueue(batch("hunter", "session", 3, 30, 30))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.Len(t, result.Losses, 1)
	require.Equal(t, uint64(20), result.Losses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(21), result.Losses[0].GetEventSequenceRanges()[0].GetLast())
	wireLosses := s.Batches()[0].GetStats().GetLosses()
	require.Len(t, wireLosses, 1)
	require.Len(t, wireLosses[0].GetEventSequenceRanges(), 2)
	require.Equal(t, uint64(10), wireLosses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(20), wireLosses[0].GetEventSequenceRanges()[1].GetFirst())
}

func TestDropOldestPreservesLossOnlyBatch(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, MaxAge: time.Second, Policy: DropOldest, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	lossOnly := batch("hunter", "session", 1, 0, 0)
	lossOnly.Stats = &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{
		Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 2,
		SourceNodeId: "hunter", ProducerSessionId: "session",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 4, Last: 5}},
	}}}
	_, err = s.Enqueue(lossOnly)
	require.NoError(t, err)

	now = now.Add(2 * time.Second)
	result, err := s.Enqueue(batch("hunter", "session", 2, 6, 6))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.Empty(t, result.Losses, "inherited losses must not be counted again locally")
	wireLosses := s.Batches()[0].GetStats().GetLosses()
	require.Len(t, wireLosses, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, wireLosses[0].GetKind())
	require.Equal(t, uint64(4), wireLosses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(5), wireLosses[0].GetEventSequenceRanges()[0].GetLast())
}

func TestDropOldestWriteFailurePreservesExistingRecords(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Policy: DropOldest, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 10, 12))
	require.NoError(t, err)

	s.config.MaxAge = time.Second
	now = now.Add(2 * time.Second)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0o700)) })

	_, err = s.Enqueue(batch("hunter", "session", 2, 20, 21))
	require.Error(t, err)
	require.Len(t, s.Batches(), 1)
	require.Equal(t, uint64(1), s.Batches()[0].GetBatchSequence())
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
	for _, b := range []*eventsv1.ProtocolEventBatch{batch("hunter", "one", 1, 1, 1), batch("hunter", "one", 2, 2, 2)} {
		_, err = s.Enqueue(b)
		require.NoError(t, err)
	}
	require.NoError(t, s.Ack("hunter", "two", 99))
	require.Len(t, s.Batches(), 2, "ACK from another session must not remove records")
	require.NoError(t, s.Ack("hunter", "one", 1))
	remaining := s.Batches()
	require.Len(t, remaining, 1)
	require.Equal(t, uint64(2), remaining[0].BatchSequence)
	require.NoError(t, s.Close())

	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1)
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

func TestSpoolRejectsMixedSessions(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "one", 1, 1, 1))
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "two", 1, 1, 1))
	require.ErrorContains(t, err, "fixed spool session")
}

func TestRecoveryOrdersOneSessionByBatchSequence(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	s, err := Open(Config{Directory: dir, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 2, 2, 2))
	require.NoError(t, err)
	_, err = s.Enqueue(batch("hunter", "session", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	batches := reopened.Batches()
	require.Equal(t, []uint64{1, 2}, []uint64{batches[0].BatchSequence, batches[1].BatchSequence})
}
