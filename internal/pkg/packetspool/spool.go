package packetspool

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	data "github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

func cloneState(current state) state {
	current.Records = append([]record(nil), current.Records...)
	current.Losses = append([]LossRange(nil), current.Losses...)
	return current
}
func (s *Spool) available() error {
	if s.closed {
		return ErrClosed
	}
	if s.uncertain {
		return ErrUncertain
	}
	return nil
}
func logicalBytes(records []record) (uint64, error) {
	var total uint64
	for _, r := range records {
		if r.Size > math.MaxUint64-total {
			return 0, errors.New("packet spool byte count overflow")
		}
		total += r.Size
	}
	return total, nil
}
func (s *Spool) validateState(next state) error {
	if next.Version != 1 || !s.matches(next.Identity) || next.AckedSequence > next.LastSequence {
		return ErrIdentity
	}
	if len(next.Records) > s.config.MaxRecords || len(next.Losses) > s.config.MaxLossRanges {
		return errors.New("packet spool checkpoint exceeds configured collection bounds")
	}
	for i, r := range next.Records {
		if r.Sequence <= next.AckedSequence || r.Sequence > next.LastSequence || r.Created <= 0 || r.Size == 0 || r.Size > s.config.MaxRecordBytes+headerBytes+securestore.MaxHeaderBytes+securestore.MaxObjectIDBytes+64 || len(r.Digest) != 64 || i > 0 && next.Records[i-1].Sequence >= r.Sequence {
			return errors.New("packet spool checkpoint record metadata is invalid")
		}
		if _, err := hex.DecodeString(r.Digest); err != nil {
			return err
		}
	}
	bytes, err := logicalBytes(next.Records)
	if err != nil {
		return err
	}
	if s.config.MaxBytes != 0 && bytes > s.config.MaxBytes {
		return errors.New("packet spool checkpoint exceeds configured byte bound")
	}
	for i, loss := range next.Losses {
		if loss.First <= next.AckedSequence || loss.Last < loss.First || loss.Last > next.LastSequence || loss.Reason == "" || len(loss.Reason) > 64 || i > 0 && next.Losses[i-1].Last >= loss.First {
			return errors.New("packet spool checkpoint loss coverage is invalid")
		}
	}
	if len(next.Losses) != 0 && next.LossVersion == 0 {
		return errors.New("packet spool losses have no committed version")
	}
	// Every assigned, unreceipted sequence has exactly one immutable record or
	// exact loss interval. Never accept a checkpoint that hides a coverage hole.
	covered := next.AckedSequence
	i, j := 0, 0
	for i < len(next.Records) || j < len(next.Losses) {
		var first, last uint64
		if j == len(next.Losses) || i < len(next.Records) && next.Records[i].Sequence < next.Losses[j].First {
			first, last = next.Records[i].Sequence, next.Records[i].Sequence
			i++
		} else {
			first, last = next.Losses[j].First, next.Losses[j].Last
			j++
		}
		if covered == math.MaxUint64 || first != covered+1 {
			return errors.New("packet spool checkpoint has a sequence gap or overlapping coverage")
		}
		covered = last
	}
	if covered != next.LastSequence {
		return errors.New("packet spool checkpoint does not account for its sequence frontier")
	}
	return nil
}

func addLoss(next *state, sequence uint64, reason string, limit int) error {
	if next.LossVersion == math.MaxUint64 {
		return errors.New("packet spool loss version exhausted")
	}
	next.Losses = append(next.Losses, LossRange{First: sequence, Last: sequence, Reason: reason})
	sort.Slice(next.Losses, func(i, j int) bool { return next.Losses[i].First < next.Losses[j].First })
	merged := make([]LossRange, 0, len(next.Losses))
	for _, loss := range next.Losses {
		if len(merged) > 0 {
			previous := &merged[len(merged)-1]
			if loss.First <= previous.Last {
				return errors.New("packet spool attempted conflicting loss coverage")
			}
			if previous.Last != math.MaxUint64 && previous.Last+1 == loss.First && previous.Reason == loss.Reason && previous.Confirmed == loss.Confirmed {
				previous.Last = loss.Last
				continue
			}
		}
		merged = append(merged, loss)
	}
	if len(merged) > limit {
		return ErrLossCapacity
	}
	next.Losses = merged
	next.LossVersion++
	return nil
}
func (s *Spool) expire(next *state, now time.Time) error {
	if s.config.MaxAge == 0 {
		return nil
	}
	retained := make([]record, 0, len(next.Records))
	for _, r := range next.Records {
		if !now.Before(time.Unix(0, r.Created).Add(s.config.MaxAge)) {
			if err := addLoss(next, r.Sequence, "expired", s.config.MaxLossRanges); err != nil {
				return err
			}
		} else {
			retained = append(retained, r)
		}
	}
	next.Records = retained
	return nil
}
func coverage(current state) LossCoverage {
	result := LossCoverage{Version: current.LossVersion}
	for _, loss := range current.Losses {
		if !loss.Confirmed {
			result.Ranges = append(result.Ranges, loss)
		}
	}
	return result
}
func (s *Spool) retired(old, next state) {
	active := make(map[uint64]bool, len(next.Records))
	for _, r := range next.Records {
		active[r.Sequence] = true
	}
	for _, r := range old.Records {
		if !active[r.Sequence] {
			s.orphans[recordName(r.Sequence)] = struct{}{}
		}
	}
}

// Enqueue assigns identity and sequence to a copy. Oversize/exhausted input is
// durably accounted as exact loss; metadata exhaustion instead leaves input
// unhandled and returns ErrLossCapacity, permitting the caller to stop admission.
func (s *Spool) Enqueue(batch *data.PacketBatch) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Result{}, err
	}
	if err := s.cleanup(); err != nil {
		return Result{}, err
	}
	if batch == nil {
		return Result{}, errors.New("packet spool batch must not be nil")
	}
	id := s.state.Identity
	if batch.HunterId != "" && batch.HunterId != id.SourceID || batch.ProducerSessionId != "" && batch.ProducerSessionId != id.SessionID || batch.CaptureEpoch != "" && batch.CaptureEpoch != id.CaptureEpoch {
		return Result{}, ErrIdentity
	}
	if s.state.LastSequence == math.MaxUint64 {
		return Result{}, errors.New("packet spool sequence exhausted")
	}
	next := cloneState(s.state)
	now := s.config.Clock()
	if now.UnixNano() <= 0 {
		return Result{}, errors.New("packet spool clock is before its supported epoch")
	}
	if err := s.expire(&next, now); err != nil {
		return Result{}, err
	}
	next.LastSequence++
	result := Result{Sequence: next.LastSequence}
	var encoded []byte
	if uint64(proto.Size(batch)) > s.config.MaxRecordBytes {
		result.Dropped = true
	} else {
		result.Batch = proto.Clone(batch).(*data.PacketBatch)
		result.Batch.HunterId, result.Batch.ProducerSessionId, result.Batch.CaptureEpoch, result.Batch.Sequence = id.SourceID, id.SessionID, id.CaptureEpoch, next.LastSequence
		if uint64(proto.Size(result.Batch)) > s.config.MaxRecordBytes {
			result.Dropped = true
		} else {
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(result.Batch)
			if err != nil {
				return Result{}, err
			}
			encoded, err = s.protect(recordName(result.Sequence), payload, true)
			if err != nil {
				return Result{}, err
			}
		}
	}
	reason := "record_too_large"
	if !result.Dropped {
		total, err := logicalBytes(next.Records)
		if err != nil {
			return Result{}, err
		}
		size := uint64(len(encoded))
		if s.config.MaxBytes != 0 && size > s.config.MaxBytes {
			result.Dropped, reason = true, "exhausted"
		} else {
			for len(next.Records) >= s.config.MaxRecords || s.config.MaxBytes != 0 && size > s.config.MaxBytes-total {
				if s.config.Policy == DropNew {
					result.Dropped, reason = true, "exhausted"
					break
				}
				oldest := next.Records[0]
				if err := addLoss(&next, oldest.Sequence, "exhausted", s.config.MaxLossRanges); err != nil {
					return Result{}, err
				}
				total -= oldest.Size
				next.Records = next.Records[1:]
			}
		}
	}
	name := recordName(result.Sequence)
	if result.Dropped {
		if err := addLoss(&next, result.Sequence, reason, s.config.MaxLossRanges); err != nil {
			return Result{}, err
		}
		result.Batch = nil
	} else {
		digest := sha256.Sum256(encoded)
		next.Records = append(next.Records, record{Sequence: result.Sequence, Created: now.UnixNano(), Size: uint64(len(encoded)), Digest: hex.EncodeToString(digest[:])})
		if err := s.validateState(next); err != nil {
			return Result{}, err
		}
		out, err := s.fs.create(name, encoded)
		if out == securestore.Uncertain {
			s.uncertain = true
			return Result{}, errors.Join(ErrUncertain, err)
		}
		if out == securestore.Committed {
			s.orphans[name] = struct{}{}
		}
		if err != nil || out != securestore.Committed {
			if err == nil {
				err = errors.New("packet spool record was not published")
			}
			return Result{}, &securestore.CommitError{Outcome: securestore.NotCommitted, Op: "publish packet spool record", Err: errors.Join(err, s.cleanup())}
		}
	}
	old := s.state
	committed, err := s.commit(next)
	result.Committed = committed
	if !committed {
		if !s.uncertain {
			err = errors.Join(err, s.cleanup())
		}
		return result, err
	}
	delete(s.orphans, name)
	s.retired(old, next)
	result.Stored = !result.Dropped
	result.Losses = coverage(next)
	return result, errors.Join(err, s.cleanup())
}

// BatchesAfter returns caller-owned copies with stable identities. Retrieval
// applies age retention durably and never retires records as a side effect of
// sending. A batch staged earlier can be evicted later; recheck Contains before
// transmission if the sender can race new admission.
func (s *Spool) BatchesAfter(sequence uint64, limit int) ([]*data.PacketBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.prune(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 128
	}
	limit = min(limit, s.config.MaxRecords)
	var result []*data.PacketBatch
	var bytes uint64
	for _, r := range s.state.Records {
		if r.Sequence <= sequence {
			continue
		}
		if len(result) >= limit || len(result) > 0 && (bytes >= s.config.MaxReadBytes || r.Size > s.config.MaxReadBytes-bytes) {
			break
		}
		batch, err := s.readBatch(r)
		if err != nil {
			return nil, err
		}
		bytes += r.Size
		result = append(result, batch)
	}
	return result, nil
}
func (s *Spool) prune() error {
	if err := s.cleanup(); err != nil {
		return err
	}
	next := cloneState(s.state)
	if err := s.expire(&next, s.config.Clock()); err != nil {
		return err
	}
	if len(next.Records) == len(s.state.Records) {
		return nil
	}
	old := s.state
	committed, err := s.commit(next)
	if !committed {
		return err
	}
	s.retired(old, next)
	return errors.Join(err, s.cleanup())
}

func (s *Spool) receiptMatches(source, session, destination, scope string) bool {
	id := s.state.Identity
	return source == id.SourceID && session == id.SessionID && destination == id.DestinationID && scope == id.AckScope
}

func retireConfirmedPrefix(next *state) {
	for len(next.Losses) > 0 && next.Losses[0].Confirmed && next.AckedSequence != math.MaxUint64 && next.Losses[0].First == next.AckedSequence+1 {
		next.AckedSequence = next.Losses[0].Last
		next.Losses = next.Losses[1:]
	}
}

// Ack applies authenticated cumulative receipt coverage. Unconfirmed losses
// must first be acknowledged through AckLosses, so receipts cannot skip holes.
// The caller must establish contiguous durable coverage for EVERY retained
// record through sequence. A receipt for one later batch alone is insufficient.
func (s *Spool) Ack(source, session, destination, scope string, sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if !s.receiptMatches(source, session, destination, scope) {
		return ErrIdentity
	}
	if sequence > s.state.LastSequence {
		return ErrReceipt
	}
	if sequence <= s.state.AckedSequence {
		return s.cleanup()
	}
	for _, loss := range s.state.Losses {
		if loss.First <= sequence && !loss.Confirmed {
			return ErrReceipt
		}
	}
	next := cloneState(s.state)
	next.AckedSequence = sequence
	next.Records = nil
	for _, r := range s.state.Records {
		if r.Sequence > sequence {
			next.Records = append(next.Records, r)
		}
	}
	next.Losses = nil
	for _, loss := range s.state.Losses {
		if loss.Last > sequence {
			loss.First = max(loss.First, sequence+1)
			next.Losses = append(next.Losses, loss)
		}
	}
	retireConfirmedPrefix(&next)
	old := s.state
	committed, err := s.commit(next)
	if !committed {
		return err
	}
	s.retired(old, next)
	return errors.Join(err, s.cleanup())
}

// PendingLosses returns an independently retransmittable snapshot. The version
// must accompany its acknowledgement; stale snapshots never clear newer loss.
func (s *Spool) PendingLosses() (LossCoverage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return LossCoverage{}, err
	}
	if err := s.prune(); err != nil {
		return LossCoverage{}, err
	}
	return coverage(s.state), nil
}
func (s *Spool) AckLosses(source, session, destination, scope string, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if !s.receiptMatches(source, session, destination, scope) {
		return ErrIdentity
	}
	if version != s.state.LossVersion {
		return ErrReceipt
	}
	return s.ackLossCoverage(coverage(s.state))
}

// AckLossCoverage confirms exactly the authenticated snapshot, even when newer
// loss has been appended or merged meanwhile. It never confirms adjacent newer
// loss merely because the old snapshot's version was once current. Splitting
// consumes the same bounded metadata capacity as new loss; failure is atomic.
func (s *Spool) AckLossCoverage(source, session, destination, scope string, snapshot LossCoverage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if !s.receiptMatches(source, session, destination, scope) {
		return ErrIdentity
	}
	return s.ackLossCoverage(snapshot)
}

func (s *Spool) ackLossCoverage(snapshot LossCoverage) error {
	if snapshot.Version > s.state.LossVersion || len(snapshot.Ranges) > s.config.MaxLossRanges {
		return ErrReceipt
	}
	for i, acknowledged := range snapshot.Ranges {
		if acknowledged.First == 0 || acknowledged.Last < acknowledged.First || acknowledged.Last > s.state.LastSequence || acknowledged.Reason == "" || i > 0 && snapshot.Ranges[i-1].Last >= acknowledged.First {
			return ErrReceipt
		}
		first := max(acknowledged.First, s.state.AckedSequence+1)
		if acknowledged.Last <= s.state.AckedSequence {
			continue
		}
		for _, existing := range s.state.Losses {
			if existing.Last < first {
				continue
			}
			if existing.First > first || existing.Reason != acknowledged.Reason {
				return ErrReceipt
			}
			if existing.Last >= acknowledged.Last {
				first = 0
				break
			}
			first = existing.Last + 1
		}
		if first != 0 {
			return ErrReceipt
		}
	}
	next := cloneState(s.state)
	next.Losses = nil
	appendRange := func(loss LossRange) error {
		if len(next.Losses) > 0 {
			previous := &next.Losses[len(next.Losses)-1]
			if previous.Last != math.MaxUint64 && previous.Last+1 == loss.First && previous.Confirmed == loss.Confirmed && previous.Reason == loss.Reason {
				previous.Last = loss.Last
				return nil
			}
		}
		if len(next.Losses) >= s.config.MaxLossRanges {
			return ErrLossCapacity
		}
		next.Losses = append(next.Losses, loss)
		return nil
	}
	for _, existing := range s.state.Losses {
		cursor := existing.First
		for _, acknowledged := range snapshot.Ranges {
			if acknowledged.Last < cursor || acknowledged.First > existing.Last {
				continue
			}
			first, last := max(cursor, acknowledged.First), min(existing.Last, acknowledged.Last)
			if first > cursor {
				before := existing
				before.First, before.Last = cursor, first-1
				if err := appendRange(before); err != nil {
					return err
				}
			}
			confirmed := existing
			confirmed.First, confirmed.Last, confirmed.Confirmed = first, last, true
			if err := appendRange(confirmed); err != nil {
				return err
			}
			if last == existing.Last {
				cursor = 0
				break
			}
			cursor = last + 1
		}
		if cursor != 0 {
			tail := existing
			tail.First = cursor
			if err := appendRange(tail); err != nil {
				return err
			}
		}
	}
	retireConfirmedPrefix(&next)
	_, err := s.commit(next)
	return err
}

func (s *Spool) Contains(sequence uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return false
	}
	i := sort.Search(len(s.state.Records), func(i int) bool { return s.state.Records[i].Sequence >= sequence })
	return i < len(s.state.Records) && s.state.Records[i].Sequence == sequence && (s.config.MaxAge == 0 || s.config.Clock().Before(time.Unix(0, s.state.Records[i].Created).Add(s.config.MaxAge)))
}
func (s *Spool) Identity() Identity { s.mu.Lock(); defer s.mu.Unlock(); return s.state.Identity }
func (s *Spool) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	bytes, _ := logicalBytes(s.state.Records)
	status := Status{Identity: s.state.Identity, PendingRecords: len(s.state.Records), PendingLosses: len(coverage(s.state).Ranges), LogicalBytes: bytes, LastSequence: s.state.LastSequence, AckedSequence: s.state.AckedSequence, DurabilityUncertain: s.uncertain, Closed: s.closed}
	// addLoss advances this durable version exactly once per lost batch. Receipt
	// compaction never resets it, so confirmed gaps remain visible in diagnostics.
	status.DroppedRecords = s.state.LossVersion
	if s.cleanupErr != nil {
		status.CleanupError = s.cleanupErr.Error()
	}
	if len(s.state.Records) > 0 {
		status.OldestAge = max(time.Duration(0), s.config.Clock().Sub(time.Unix(0, s.state.Records[0].Created)))
	}
	return status
}

// String avoids formatting Config or key material in diagnostics.
func (s *Spool) String() string {
	status := s.Status()
	return fmt.Sprintf("packetspool{pending=%d,bytes=%d,uncertain=%t}", status.PendingRecords, status.LogicalBytes, status.DurabilityUncertain)
}
