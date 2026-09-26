//go:build linux

package securestore

import "errors"

// DiscardUnselectedTail is an explicit recovery operation on an unarmed handle.
// The owning protocol MUST first authenticate both head slots and every byte of
// the selected prefix, and derive cursor from that authenticated selection.
// It cannot repair a head, selected data, or a faulted/active handle. It writes
// only already allocated unselected extents, then synchronizes before activation.
func (s *FixedSegment) DiscardUnselectedTail(cursor int64) (out Outcome, result error) {
	s.lock()
	defer s.unlock()
	out = NotCommitted
	defer func() {
		if result != nil {
			result = &CommitError{Outcome: out, Op: "discard authenticated unselected tail", Err: result}
			s.fault = result
		}
	}()
	if s.fault != nil {
		return out, s.fault
	}
	if s.armed || cursor < FixedSegmentDataStart || cursor > FixedSegmentBytes || cursor%FixedSegmentBlock != 0 {
		return out, errors.New("securestore: fixed tail recovery bounds")
	}
	if err := s.validateLocked(); err != nil {
		return out, err
	}
	zero := make([]byte, 64<<10)
	for offset := cursor; offset < FixedSegmentBytes; {
		n := min(int64(len(zero)), FixedSegmentBytes-offset)
		out = Uncertain
		if err := fixedWriteAll(s.ops, s.file, zero[:n], offset); err != nil {
			return out, err
		}
		offset += n
	}
	if err := s.ops.dataSync(s.file); err != nil {
		return out, contextual("sync discarded fixed tail", err)
	}
	out = Committed
	return out, s.validateLocked()
}
