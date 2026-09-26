//go:build li && linux

package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const journalControlIdentities = 65536
const journalControlMemory = int64(64 << 20)

func validJournalCall(c *li.DeliveryCallIdentity) bool {
	return c != nil && c.StateIncarnation != uuid.Nil && c.CallIncarnation != uuid.Nil && c.XID != uuid.Nil && c.TaskGeneration > 0 && c.CallGeneration > 0 && len(c.CallID) > 0 && len(c.CallID) <= 64<<10
}

type journalCallControl struct {
	Version                   int                `json:"version"`
	JournalUUID               uuid.UUID          `json:"journal_uuid"`
	StateIncarnation          uuid.UUID          `json:"state_incarnation"`
	XID                       uuid.UUID          `json:"xid"`
	TaskGeneration            uint64             `json:"task_generation"`
	DID                       uuid.UUID          `json:"did"`
	DestinationGeneration     uint64             `json:"destination_generation"`
	CallIncarnation           uuid.UUID          `json:"call_incarnation"`
	CallGeneration            uint64             `json:"call_generation"`
	CallID                    string             `json:"call_id"`
	State                     string             `json:"state"`
	CoveredRecordHighwater    uint64             `json:"covered_record_highwater"`
	CoveredAdmissionHighwater uint64             `json:"covered_admission_highwater"`
	ClosedAt                  *li.StateTimestamp `json:"closed_at,omitempty"`
}

func journalCallKey(c journalCallControl) string {
	return fmt.Sprintf("call/%s/%s/%d/%s/%d/%s/%d", c.StateIncarnation, c.XID, c.TaskGeneration, c.DID, c.DestinationGeneration, c.CallIncarnation, c.CallGeneration)
}
func callForRecord(r JournalRecord) journalCallControl {
	return journalCallControl{Version: 1, JournalUUID: r.JournalUUID, StateIncarnation: r.StateIncarnation, XID: r.XID, TaskGeneration: r.TaskGeneration, DID: r.DID, DestinationGeneration: r.DestinationGeneration, CallIncarnation: r.Provenance.CallIncarnation, CallGeneration: r.Provenance.CallGeneration, CallID: r.Provenance.CallID, State: "open", CoveredRecordHighwater: r.ID}
}
func (c journalCallControl) identity() li.DeliveryCallIdentity {
	return li.DeliveryCallIdentity{StateIncarnation: c.StateIncarnation, CallIncarnation: c.CallIncarnation, XID: c.XID, TaskGeneration: c.TaskGeneration, CallGeneration: c.CallGeneration, CallID: c.CallID}
}
func (s *journalSegments) validCallControl(c *journalCallControl) bool {
	if c == nil {
		return false
	}
	identity := c.identity()
	if !validJournalCall(&identity) || c.Version != 1 || c.JournalUUID != s.j.UUID() || c.StateIncarnation != s.j.cfg.StateIncarnation || c.DID == uuid.Nil || c.DestinationGeneration == 0 || c.CoveredRecordHighwater > s.catalog.RecordLease || c.CoveredAdmissionHighwater > s.catalog.AdmissionLease {
		return false
	}
	if c.State == "open" {
		return c.ClosedAt == nil
	}
	return (c.State == "capture_closed" || c.State == "revoked") && c.ClosedAt != nil && c.ClosedAt.Nanos < 1e9 && c.ClosedAt.Seconds >= -62135596800 && c.ClosedAt.Seconds <= 253402300799
}
func (s *journalSegments) validRevocation(r *li.StateRevocation) bool {
	if r == nil || r.Version != 1 || r.ControlID == uuid.Nil || r.JournalUUID != s.j.UUID() || r.StateIncarnation != s.j.cfg.StateIncarnation || r.RevokedAt.Nanos >= 1e9 || r.RevokedAt.Seconds < -62135596800 || r.RevokedAt.Seconds > 253402300799 {
		return false
	}
	task := r.XID != nil && *r.XID != uuid.Nil && r.TaskGeneration != nil && *r.TaskGeneration > 0
	dest := r.DID != nil && *r.DID != uuid.Nil && r.DestinationGeneration != nil && *r.DestinationGeneration > 0
	call := r.CallIncarnation != nil && *r.CallIncarnation != uuid.Nil && r.CallGeneration != nil && *r.CallGeneration > 0
	switch r.Scope {
	case li.StateRevokeTask:
		return task && r.DID == nil && r.DestinationGeneration == nil && r.CallIncarnation == nil && r.CallGeneration == nil
	case li.StateRevokeDestination:
		return dest && r.XID == nil && r.TaskGeneration == nil && r.CallIncarnation == nil && r.CallGeneration == nil
	case li.StateRevokeCall:
		return task && dest && call
	}
	return false
}
func (s *journalSegments) validateControl(c journalControl) error {
	valid := false
	switch c.Kind {
	case "complete", "expired", "purge":
		valid = c.ID > 0 && c.ID <= s.catalog.RecordLease && c.Call == nil && c.Sequence == nil && c.Revocation == nil
	case "sequence":
		valid = c.ID == 0 && c.Sequence != nil && c.Call == nil && c.Revocation == nil
		if valid {
			key, err := productionSequenceKey(c.Sequence.Context)
			valid = err == nil && key != "" && PDUType(c.Sequence.Context.PDUType) == s.j.cfg.Interface
		}
	case "call_open", "call_close":
		valid = c.ID == 0 && s.validCallControl(c.Call) && (c.Kind == "call_open" && c.Call.State == "open" || c.Kind == "call_close" && c.Call.State != "open") && c.Sequence == nil && c.Revocation == nil
	case "revoke":
		valid = c.ID == 0 && c.Call == nil && c.Sequence == nil && s.validRevocation(c.Revocation) && c.Revocation.CoveredRecordHighwater <= s.catalog.RecordLease && c.Revocation.CoveredAdmissionHighwater <= s.catalog.AdmissionLease
	}
	if !valid || c.Record != nil || c.Highwater != 0 {
		return errJournalSchema
	}
	return nil
}
func (s *journalSegments) applyControl(c journalControl, recovery bool) error {
	if err := s.validateControl(c); err != nil {
		return err
	}
	s.j.mu.Lock()
	defer s.j.mu.Unlock()
	encoded, _ := json.Marshal(c)
	switch c.Kind {
	case "sequence":
		key, _ := productionSequenceKey(c.Sequence.Context)
		previous, exists := s.checkpoints[key]
		if !exists || int32(c.Sequence.Next-previous.Next) > 0 {
			charge := int64(len(encoded) + 192)
			if exists {
				old, _ := json.Marshal(journalControl{Kind: "sequence", Sequence: &previous})
				charge -= int64(len(old) + 192)
			}
			if !exists && len(s.checkpoints) >= journalControlIdentities || s.controlMemory+charge > journalControlMemory {
				return ErrJournalFull
			}
			s.controlMemory += charge
			s.checkpoints[key] = *c.Sequence
		}
	case "call_open", "call_close":
		key := journalCallKey(*c.Call)
		old, exists := s.controls[key]
		if exists && old.Call.identity() != c.Call.identity() {
			return errJournalSchema
		}
		charge := int64(len(encoded) + 192)
		if exists {
			previous, _ := json.Marshal(old)
			charge -= int64(len(previous) + 192)
		}
		if !exists && len(s.controls) >= journalControlIdentities || s.controlMemory+charge > journalControlMemory {
			return ErrJournalFull
		}
		if old.Kind == "call_close" && c.Kind == "call_open" {
			return errJournalSchema
		}
		s.controlMemory += charge
		s.controls[key] = c
	case "revoke":
		key := "revoke/" + c.Revocation.ControlID.String()
		old, exists := s.controls[key]
		if exists {
			a, _ := json.Marshal(old)
			b, _ := json.Marshal(c)
			if string(a) != string(b) {
				return errJournalSchema
			}
		}
		if !exists && (len(s.controls) >= journalControlIdentities || s.controlMemory+int64(len(encoded)+192) > journalControlMemory) {
			return ErrJournalFull
		}
		if !exists {
			s.controlMemory += int64(len(encoded) + 192)
		}
		s.controls[key] = c
		if !recovery {
			for id, loc := range s.locations {
				r, _, err := decodeRecordMetadata(loc.metadata)
				if err != nil {
					return err
				}
				if revokeMatches(c.Revocation, r) {
					s.removeEntryLocked(id, "revoked")
					if s.terminals[id] == "" {
						s.controlMemory += 32
					}
					s.terminals[id] = "revoked"
				}
			}
		}
	case "complete", "expired", "purge":
		if s.terminals[c.ID] == "" {
			if s.controlMemory+32 > journalControlMemory {
				return ErrJournalFull
			}
			s.controlMemory += 32
		}
		s.terminals[c.ID] = c.Kind
		if !recovery {
			s.removeEntryLocked(c.ID, c.Kind)
		}
	}
	return nil
}
func revokeMatches(v *li.StateRevocation, r JournalRecord) bool {
	if v.StateIncarnation != r.StateIncarnation {
		return false
	}
	switch v.Scope {
	case li.StateRevokeTask:
		return r.XID == *v.XID && r.TaskGeneration == *v.TaskGeneration
	case li.StateRevokeDestination:
		return r.DID == *v.DID && r.DestinationGeneration == *v.DestinationGeneration
	case li.StateRevokeCall:
		return r.XID == *v.XID && r.TaskGeneration == *v.TaskGeneration && r.DID == *v.DID && r.DestinationGeneration == *v.DestinationGeneration && r.Provenance.CallIncarnation == *v.CallIncarnation && r.Provenance.CallGeneration == *v.CallGeneration
	}
	return false
}

// Caller holds j.mu after startup. Revocations apply to pending admissions too;
// a generation cannot become valid again by allocating a later record ID.
func (s *journalSegments) terminalReason(r JournalRecord, admission uint64) string {
	if reason := s.terminals[r.ID]; reason != "" {
		return reason
	}
	for _, c := range s.controls {
		if c.Revocation != nil && revokeMatches(c.Revocation, r) {
			return "revoked"
		}
	}
	return ""
}
func (s *journalSegments) removeEntryLocked(id uint64, reason string) {
	e := s.j.entries[id]
	if e == nil {
		return
	}
	if e.persisted {
		s.controlLiability -= journalTerminalCredit
		s.j.stats.Persisted--
		s.j.stats.Retained--
	}
	if e.held {
		s.j.stats.Held--
		s.j.decrementHeldLocked(e.did)
	}
	if e.authorized {
		s.j.stats.ReplayPending--
	}
	if reason == "expired" {
		s.j.stats.Expired++
	}
	if reason == "revoked" {
		s.j.stats.Revoked++
	}
	s.forgetDeadline(id)
	delete(s.j.entries, id)
	s.j.replayRevision++
	if loc, ok := s.locations[id]; ok {
		for _, chunk := range loc.chunks {
			if e := s.extents[chunk.segment]; e != nil && e.live > 0 {
				e.live--
			}
		}
	}
}
func (s *journalSegments) requestControl(controls []journalControl) (securestore.Outcome, error) {
	s.controlSend.RLock()
	defer s.controlSend.RUnlock()
	s.j.mu.Lock()
	closed := s.controlsClosed || s.j.lastErr != nil
	s.j.mu.Unlock()
	if closed {
		return securestore.NotCommitted, ErrJournalClosed
	}
	request := journalControlRequest{controls: controls, done: make(chan journalControlResult, 1)}
	select {
	case s.controlsCh <- request:
	default:
		return securestore.NotCommitted, ErrJournalFull
	}
	result := <-request.done
	return result.out, result.err
}
func (s *journalSegments) terminal(id uint64, kind string) error {
	s.j.mu.Lock()
	e := s.j.entries[id]
	pending := e != nil && !e.persisted
	s.j.mu.Unlock()
	if e == nil {
		return nil
	}
	if pending {
		return errors.New("journal persistence is pending")
	}
	_, err := s.requestControl([]journalControl{{Kind: kind, ID: id}})
	return err
}
func (s *journalSegments) revoke(r *li.StateRevocation) (securestore.Outcome, error) {
	if !s.validRevocation(r) {
		return securestore.NotCommitted, errJournalSchema
	}
	// Detach all pointer fields before crossing the asynchronous owner boundary.
	b, _ := json.Marshal(r)
	var copy li.StateRevocation
	if err := strictSegmentJSON(b, &copy); err != nil {
		return securestore.NotCommitted, err
	}
	return s.requestControl([]journalControl{{Kind: "revoke", Revocation: &copy}})
}
func (s *journalSegments) closeCall(c li.DeliveryCallIdentity) (securestore.Outcome, error) {
	if !validJournalCall(&c) {
		return securestore.NotCommitted, errJournalSchema
	}
	s.j.mu.Lock()
	var controls []journalControl
	now := time.Now().UTC()
	closed := li.StateTimestamp{Seconds: now.Unix(), Nanos: uint32(now.Nanosecond())}
	for _, old := range s.controls {
		if old.Call != nil && old.Call.identity() == c && old.Kind == "call_open" {
			copy := *old.Call
			copy.State = "capture_closed"
			copy.ClosedAt = &closed
			copy.CoveredRecordHighwater = s.j.next
			copy.CoveredAdmissionHighwater = s.admission
			controls = append(controls, journalControl{Kind: "call_close", Call: &copy})
		}
	}
	s.j.mu.Unlock()
	if len(controls) == 0 {
		return securestore.Committed, nil
	}
	return s.requestControl(controls)
}
func (s *journalSegments) writeControls(controls []journalControl) (securestore.Outcome, error) {
	if len(controls) == 0 {
		return securestore.Committed, nil
	}
	// Reclaim discharged task controls before accepting a new bounded identity.
	// The selected control replacement must commit before memory is reclaimed.
	s.j.mu.Lock()
	atCapacity := len(s.controls)+len(controls) >= journalControlIdentities
	s.j.mu.Unlock()
	if atCapacity {
		if err := s.pruneTaskControls(); err != nil {
			return securestore.NotCommitted, err
		}
	}
	ordinary := s.deferCatalog
	for _, c := range controls {
		ordinary = ordinary || c.Kind == "sequence" || c.Kind == "call_open"
	}
	previousOrdinary := s.ordinaryControl
	s.ordinaryControl = ordinary
	defer func() { s.ordinaryControl = previousOrdinary }()
	for _, c := range controls {
		if err := s.validateControl(c); err != nil {
			return securestore.NotCommitted, err
		}
	}
	// Frame admission bounds include canonical JSON, before any encryption usage.
	p, err := json.Marshal(controls)
	if err != nil || len(p) > journalBatchBytes-4096 {
		return securestore.NotCommitted, ErrJournalFull
	}
	e := s.activeControl
	if e == nil || e.cursor+int64(len(p))+8192 > securestore.FixedSegmentBytes {
		e, err = s.createExtent("control")
		if errors.Is(err, ErrJournalFull) {
			err = s.compactControls()
			e = s.activeControl
		}
		if err != nil {
			return securestore.NotCommitted, err
		}
	}
	out, err := s.appendFrame(e, nil, nil, controls)
	if out == securestore.Committed {
		for _, c := range controls {
			if applyErr := s.applyControl(c, false); applyErr != nil {
				err = errors.Join(err, applyErr)
			}
		}
	}
	return out, err
}
func (s *journalSegments) controlLoop() {
	defer close(s.controlsDone)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var carry *journalControlRequest
	for {
		var request journalControlRequest
		var ok bool
		if carry != nil {
			request = *carry
			carry = nil
			ok = true
		} else {
			select {
			case request, ok = <-s.controlsCh:
			case <-ticker.C:
				s.ioMu.Lock()
				s.j.mu.Lock()
				faulted := s.j.lastErr != nil
				s.j.mu.Unlock()
				var err error
				if !faulted {
					err = s.expireDue(time.Now())
					if err == nil {
						err = s.reclaimEmpty()
					}
					if err == nil {
						err = s.compactExpiredExtent()
					}
					if err == nil {
						err = s.pruneTaskControls()
					}
				}
				s.ioMu.Unlock()
				if err != nil {
					s.j.fault(err)
				}
				continue
			}
		}
		if !ok {
			return
		}
		requests := []journalControlRequest{request}
		controls := append([]journalControl(nil), request.controls...)
		encoded, _ := json.Marshal(controls)
		size := len(encoded)
		timer := time.NewTimer(journalBatchDelay)
	collect:
		for len(controls) < 4096 && size < journalBatchBytes-8192 {
			select {
			case next, open := <-s.controlsCh:
				if !open {
					break collect
				}
				b, _ := json.Marshal(next.controls)
				if size+len(b) > journalBatchBytes-8192 || len(controls)+len(next.controls) > 4096 {
					carry = &next
					break collect
				}
				requests = append(requests, next)
				controls = append(controls, next.controls...)
				size += len(b)
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
		out, err := s.writeControls(controls)
		s.ioMu.Unlock()
		if err != nil {
			s.j.fault(err)
		}
		for _, r := range requests {
			r.done <- journalControlResult{out, err}
		}
	}
}
func (s *journalSegments) reclaimEmpty() error {
	var retiring []journalSegmentRef
	active := false
	for _, ref := range s.catalog.Selected {
		e := s.extents[ref.ID]
		if ref.Kind == "data" && e.live == 0 && e.cursor > securestore.FixedSegmentDataStart {
			retiring = append(retiring, ref)
			active = active || e == s.activeData
		}
	}
	if len(retiring) == 0 {
		return nil
	}
	var targets []*journalSegmentState
	if active {
		e, err := s.prepareExtent("data")
		if err != nil {
			return err
		}
		targets = append(targets, e)
	}
	if err := s.selectReplacements(retiring, targets); err != nil {
		return err
	}
	if active {
		s.activeData = targets[0]
	}
	return s.retireSelected(retiring)
}
func (s *journalSegments) publishBytes() {
	s.j.mu.Lock()
	s.j.stats.Bytes = s.dataAllocated + s.controlAllocated + s.retainedAllocation
	s.dataFree = s.dataLimit - s.dataAllocated
	if s.activeData != nil {
		s.dataFree += securestore.FixedSegmentBytes - s.activeData.cursor
	}
	s.j.mu.Unlock()
}

func (s *journalSegments) closeRecoveredCalls() error {
	now := time.Now().UTC()
	at := li.StateTimestamp{Seconds: now.Unix(), Nanos: uint32(now.Nanosecond())}
	var batch []journalControl
	size := 0
	for _, c := range s.controls {
		if c.Kind != "call_open" {
			continue
		}
		copy := *c.Call
		copy.State = "capture_closed"
		copy.ClosedAt = &at
		copy.CoveredRecordHighwater = s.catalog.RecordLease
		copy.CoveredAdmissionHighwater = s.catalog.AdmissionLease
		b, _ := json.Marshal(copy)
		if size+len(b) > journalBatchBytes/2 || len(batch) >= 2048 {
			if _, err := s.writeControls(batch); err != nil {
				return err
			}
			batch = nil
			size = 0
		}
		batch = append(batch, journalControl{Kind: "call_close", Call: &copy})
		size += len(b) + 256
	}
	if len(batch) > 0 {
		_, err := s.writeControls(batch)
		return err
	}
	return nil
}
