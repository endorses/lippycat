//go:build li && linux

package delivery

import (
	"crypto/sha256"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const journalIndexMemory = int64(2 << 30)
const journalPendingMemory = int64(64 << 20)
const journalFragmentPlain = 512 << 10

// Every retained or pending record reserves terminal controls independently of
// payload space. Half the control partition remains available for identities,
// checkpoints and compaction coexistence.
const journalTerminalCredit int64 = 1024

func (s *journalSegments) terminalCreditAvailable() bool {
	return s.controlLiability <= s.controlLimit/2-journalTerminalCredit
}

func segmentReservation(n, metadata int64) int64 {
	return n + 2*metadata + (n/journalFragmentPlain+1)*4096 + 4096
}
func (s *journalSegments) reserve(n int64) (*JournalAdmission, error) {
	return s.reserveMetadata(n, journalMetadataMax+32)
}
func (s *journalSegments) reserveMetadata(n, metadata int64) (*JournalAdmission, error) {
	if n <= 0 || n > journalMaxRecord || metadata <= 0 || metadata > journalMetadataMax+32 {
		return nil, ErrJournalFull
	}
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.lastErr != nil {
		return nil, ErrJournalClosed
	}
	credit := segmentReservation(n, metadata)
	// Pending memory includes original immutable payload and metadata. The active
	// extent's unused bytes are part of data capacity, not extra physical capacity.
	free := s.dataFree
	if s.controlMemory+int64(len(j.entries)+s.reservations+1)*32 > journalControlMemory || s.reservations >= j.cfg.MaxPending || len(j.entries)+s.reservations >= j.cfg.MaxRecords || credit > s.pendingAvailable() || credit > free-s.reservedBytes || !s.terminalCreditAvailable() || s.admission >= s.admissionLease || j.next >= s.recordLease {
		j.stats.Rejected++
		return nil, ErrJournalFull
	}
	s.admission++
	admission := s.admission
	s.reservations++
	s.reservedBytes += credit
	s.pendingBytes += credit
	s.controlLiability += journalTerminalCredit
	release := func() { j.mu.Lock(); s.releaseReservationLocked(credit); j.mu.Unlock() }
	return &JournalAdmission{release: release, consume: func(r JournalRecord, cb func(uint64, error)) (uint64, error) {
		if int64(len(r.Data)) != n {
			release()
			return 0, errJournalSchema
		}
		return s.consume(r, cb, admission, credit, metadata, false)
	}}, nil
}
func (s *journalSegments) pendingAvailable() int64 {
	return journalPendingMemory + (8 << 20) - s.pendingBytes
}
func (s *journalSegments) releaseReservationLocked(n int64) {
	s.reservations--
	s.reservedBytes -= n
	s.pendingBytes -= n
	s.controlLiability -= journalTerminalCredit
}
func (s *journalSegments) admit(r JournalRecord, cb func(uint64, error), clone bool) (uint64, error) {
	token, err := s.reserve(int64(len(r.Data)))
	if err != nil {
		return 0, err
	}
	if clone {
		r.Data = append([]byte(nil), r.Data...)
	}
	return token.Admit(r, cb)
}
func (s *journalSegments) consume(r JournalRecord, cb func(uint64, error), admission uint64, credit, metadataLimit int64, clone bool) (uint64, error) {
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	fail := func(err error) (uint64, error) { s.releaseReservationLocked(credit); j.stats.Rejected++; return 0, err }
	if j.closed || j.lastErr != nil {
		return fail(ErrJournalClosed)
	}
	if r.ID != 0 || r.Interface != 0 && r.Interface != j.cfg.Interface || r.JournalUUID != uuid.Nil && r.JournalUUID != j.UUID() || r.StateIncarnation != uuid.Nil && r.StateIncarnation != j.cfg.StateIncarnation {
		return fail(errJournalSchema)
	}
	if _, err := journalPDUCheckpoint(r.Data, j.cfg.Interface, r.XID, j.cfg.PreserveSequences); err != nil {
		return fail(err)
	}
	if j.next >= s.recordLease {
		return fail(ErrJournalFull)
	}
	j.next++
	r.ID = j.next
	r.Interface = j.cfg.Interface
	r.JournalUUID = j.UUID()
	r.StateIncarnation = j.cfg.StateIncarnation
	if r.AdmittedAt.IsZero() {
		r.AdmittedAt = time.Now().UTC()
	} else {
		r.AdmittedAt = r.AdmittedAt.UTC()
	}
	if j.cfg.Interface == PDUTypeX3 && r.Deadline.IsZero() {
		r.Deadline = r.AdmittedAt.Add(j.cfg.MaxAge)
	}
	if j.cfg.Interface == PDUTypeX3 && (r.Deadline.After(r.AdmittedAt.Add(j.cfg.MaxAge)) || !time.Now().Before(r.Deadline)) {
		return fail(errJournalSchema)
	}
	if r.Provenance.Kind == "" && j.cfg.Interface == PDUTypeX2 {
		r.Provenance = li.DeliveryProvenance{Kind: "legacy_x2", CallID: r.CallID, CallGeneration: r.CallGeneration}
	}
	if r.Provenance.Kind == "call" {
		if r.CallIncarnation != uuid.Nil && r.CallIncarnation != r.Provenance.CallIncarnation || r.CallGeneration != 0 && r.CallGeneration != r.Provenance.CallGeneration || r.CallID != "" && r.CallID != r.Provenance.CallID {
			return fail(errJournalSchema)
		}
		r.CallIncarnation = r.Provenance.CallIncarnation
		r.CallGeneration = r.Provenance.CallGeneration
		r.CallID = r.Provenance.CallID
		if c := s.controls[journalCallKey(callForRecord(r))]; c.Kind == "call_close" {
			return fail(ErrJournalClosed)
		}
	}
	if s.terminalReason(r, admission) != "" {
		return fail(ErrJournalClosed)
	}
	meta, err := encodeRecordMetadata(r)
	if err != nil {
		return fail(err)
	}
	if int64(len(meta)) > metadataLimit {
		return fail(errJournalSchema)
	}
	charge := journalLocationCharge(len(meta), len(r.Data))
	if charge > journalIndexMemory-s.indexBytes {
		return fail(ErrJournalFull)
	}
	s.indexBytes += charge
	j.entries[r.ID] = &journalEntry{did: r.DID, payloadBytes: int64(len(r.Data)), size: charge}
	j.stats.Pending++
	select {
	case j.ops <- journalOperation{record: r, callback: cb, admission: admission, reserved: credit, metadata: meta}:
		return r.ID, nil
	default:
		delete(j.entries, r.ID)
		j.stats.Pending--
		s.indexBytes -= charge
		return fail(ErrJournalFull)
	}
}
func (s *journalSegments) callbackLoop() {
	defer close(s.callbacksDone)
	for cb := range s.callbacks {
		if cb.fn != nil {
			cb.fn(cb.id, cb.err)
		}
	}
}
func (s *journalSegments) run() {
	j := s.j
	defer close(j.done)
	defer func() {
		close(s.callbacks)
		<-s.callbacksDone
		s.controlSend.Lock()
		j.mu.Lock()
		s.controlsClosed = true
		j.mu.Unlock()
		close(s.controlsCh)
		s.controlSend.Unlock()
		<-s.controlsDone
		j.purgeMu.Lock()
		defer j.purgeMu.Unlock()
		if err := j.closeStorage(); err != nil {
			j.fault(err)
		}
	}()
	var carry *journalOperation
	for {
		var first journalOperation
		var ok bool
		if carry != nil {
			first = *carry
			carry = nil
			ok = true
		} else {
			first, ok = <-j.ops
		}
		if !ok {
			return
		}
		if first.barrier != nil {
			barrier := first.barrier
			s.callbacks <- journalCallback{fn: func(uint64, error) { close(barrier) }}
			continue
		}
		batch := []journalOperation{first}
		size := len(first.record.Data) + 2*len(first.metadata)
		timer := time.NewTimer(journalBatchDelay)
	collect:
		for size < journalBatchBytes {
			select {
			case op, open := <-j.ops:
				if !open {
					break collect
				}
				if op.barrier != nil || size+len(op.record.Data)+2*len(op.metadata) > journalBatchBytes {
					carry = &op
					break collect
				}
				batch = append(batch, op)
				size += len(op.record.Data) + 2*len(op.metadata)
			case <-timer.C:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		s.ioMu.Lock()
		j.mu.Lock()
		faulted := j.lastErr != nil
		j.mu.Unlock()
		var err error
		if faulted {
			err = ErrJournalClosed
		} else {
			err = s.persistBatch(batch)
		}
		if err == nil {
			j.mu.Lock()
			renew := j.next+journalIDLease/2 >= s.recordLease || s.admission+journalIDLease/2 >= s.admissionLease
			j.mu.Unlock()
			if renew {
				err = s.renewLeases()
			}
		}
		s.ioMu.Unlock()
		if err != nil {
			j.fault(err)
		}
		for _, op := range batch {
			s.ioMu.Lock()
			j.mu.Lock()
			j.stats.Pending--
			s.releaseReservationLocked(op.reserved)
			e := j.entries[op.record.ID]
			callbackErr := err
			if err == nil && e != nil {
				e.persisted = true
				j.stats.Persisted++
				j.stats.Retained++
				s.controlLiability += journalTerminalCredit
				if s.terminalReason(op.record, op.admission) != "" {
					s.removeEntryLocked(op.record.ID, "revoked")
					callbackErr = ErrJournalClosed
				}
			} else if err != nil && securestore.OutcomeOf(err) == securestore.Uncertain {
				j.stats.Uncertain++
			}
			if callbackErr == nil && s.terminalReason(op.record, op.admission) != "" {
				callbackErr = ErrJournalClosed
			}
			j.mu.Unlock()
			s.ioMu.Unlock()
			s.callbacks <- journalCallback{op.record.ID, op.callback, callbackErr}
		}
	}
}
func (s *journalSegments) persistBatch(batch []journalOperation) (result error) {
	outcome := securestore.NotCommitted
	completed := map[uint64]bool{}
	defer func() {
		if result != nil {
			if len(completed) == len(batch) {
				outcome = securestore.Committed
			}
			result = &securestore.CommitError{Outcome: outcome, Op: "persist segmented products", Err: result}
		}
	}()

	controls := make([]journalControl, 0, len(batch)*2)
	seen := map[string]int{}
	for _, op := range batch {
		if s.deferCatalog {
			continue
		}
		cp, err := journalPDUCheckpoint(op.record.Data, s.j.cfg.Interface, op.record.XID, s.j.cfg.PreserveSequences)
		if err != nil {
			return err
		}
		if s.j.cfg.PreserveSequences {
			controls = append(controls, journalControl{Kind: "sequence", Sequence: &cp})
		}
		if op.record.Provenance.Kind == "call" {
			call := callForRecord(op.record)
			call.CoveredAdmissionHighwater = op.admission
			key := journalCallKey(call)
			s.j.mu.Lock()
			old := s.controls[key]
			s.j.mu.Unlock()
			if old.Kind == "call_close" {
				return ErrJournalClosed
			}
			if old.Kind == "" || old.Call.CoveredRecordHighwater < call.CoveredRecordHighwater {
				if pos, ok := seen[key]; ok {
					controls[pos] = journalControl{Kind: "call_open", Call: &call}
				} else {
					seen[key] = len(controls)
					controls = append(controls, journalControl{Kind: "call_open", Call: &call})
				}
			}
		}
	}
	if _, err := s.writeControls(controls); err != nil {
		return err
	}
	var body []byte
	var fragments []segmentFragment
	pending := map[uint64]journalRecordLocation{}
	flush := func() error {
		if len(fragments) == 0 {
			return nil
		}
		e := s.activeData
		// Index JSON duplicates metadata and adds only bounded framing per fragment.
		estimate := int64(segmentFrameHeader + len(body) + 8192)
		for _, f := range fragments {
			estimate += int64(2*len(f.Metadata) + 512)
		}
		if e == nil || e.cursor+estimate > securestore.FixedSegmentBytes {
			var err error
			e, err = s.createExtent("data")
			if err != nil {
				return err
			}
		}
		start := e.cursor
		out, err := s.appendFrame(e, body, fragments, nil)
		if out != securestore.NotCommitted {
			outcome = securestore.Uncertain
		}
		if out == securestore.Committed {
			for _, f := range fragments {
				if f.Part+1 == f.Parts {
					completed[f.ID] = true
				}
				loc := pending[f.ID]
				loc.metadata = f.Metadata
				rec, size, _ := decodeRecordMetadata(f.Metadata)
				_ = rec
				loc.charge = journalLocationCharge(len(f.Metadata), int(size))
				loc.admission = f.Admission
				loc.chunks = append(loc.chunks, journalFragmentLocation{e.ref.ID, start + int64(f.Offset), int(f.Length), f.Hash})
				pending[f.ID] = loc
			}
		}
		clear(body)
		body = nil
		fragments = nil
		return err
	}
	for _, op := range batch {
		purpose := securestore.X2Product
		if s.j.cfg.Interface == PDUTypeX3 {
			purpose = securestore.X3Product
		}
		parts := (len(op.record.Data) + journalFragmentPlain - 1) / journalFragmentPlain
		for part := 0; part < parts; part++ {
			start := part * journalFragmentPlain
			end := min(start+journalFragmentPlain, len(op.record.Data))
			cipher, err := s.j.writer.Seal(purpose, s.productBinding(op.record.ID, part), op.record.Data[start:end])
			if err != nil {
				return err
			}
			cost := len(body) + len(cipher) + 2*len(op.metadata) + 1024
			for _, f := range fragments {
				cost += 2*len(f.Metadata) + 512
			}
			if cost > journalBatchBytes && len(fragments) > 0 {
				if err := flush(); err != nil {
					return err
				}
			}
			fragments = append(fragments, segmentFragment{ID: op.record.ID, Admission: op.admission, Part: uint32(part), Parts: uint32(parts), Total: uint32(len(op.record.Data)), Offset: uint32(segmentFrameHeader + len(body)), Length: uint32(len(cipher)), Hash: sha256.Sum256(cipher), Metadata: op.metadata})
			body = append(body, cipher...)
			clear(cipher)
		}
	}
	if err := flush(); err != nil {
		return err
	}
	for id, loc := range pending {
		rec, _, _ := decodeRecordMetadata(loc.metadata)
		s.observeDeadline(rec)
		s.locations[id] = loc
		for _, chunk := range loc.chunks {
			s.extents[chunk.segment].live++
		}
	}
	s.publishBytes()
	return nil
}
