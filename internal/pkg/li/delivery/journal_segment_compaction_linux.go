//go:build li && linux

package delivery

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"

	"github.com/endorses/lippycat/internal/pkg/li"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// compactData rewrites one bounded extent into the reserved scratch partition.
// Product ciphertext is copied exactly; only index/head metadata is resealed.
// Catalog publication is the sole selection point. Old extents stay selected
// until every replacement byte and head is synchronized.
func (s *journalSegments) compactData(old *journalSegmentState) error {
	target, err := s.prepareExtent("data")
	if err != nil {
		return err
	}
	updates := map[uint64][]journalFragmentLocation{}
	err = s.scanExtentMode(old, func(index segmentIndex) error {
		var body []byte
		var fragments []segmentFragment
		for _, f := range index.Fragments {
			s.j.mu.Lock()
			live := s.j.entries[f.ID] != nil
			s.j.mu.Unlock()
			if !live {
				continue
			}
			data := make([]byte, f.Length)
			if err := old.file.ReadAt(data, index.Start+int64(f.Offset)); err != nil {
				return err
			}
			if sha256.Sum256(data) != f.Hash {
				return errJournalSchema
			}
			f.Offset = uint32(segmentFrameHeader + len(body))
			fragments = append(fragments, f)
			body = append(body, data...)
		}
		if len(fragments) == 0 {
			return nil
		}
		start := target.cursor
		out, err := s.appendFrame(target, body, fragments, nil)
		clear(body)
		if out != securestore.Committed || err != nil {
			return err
		}
		for _, f := range fragments {
			updates[f.ID] = append(updates[f.ID], journalFragmentLocation{target.ref.ID, start + int64(f.Offset), int(f.Length), f.Hash})
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	if err := s.selectReplacements([]journalSegmentRef{old.ref}, []*journalSegmentState{target}); err != nil {
		return err
	}
	for id, chunks := range updates {
		loc := s.locations[id]
		var replacement []journalFragmentLocation
		position := 0
		for _, c := range loc.chunks {
			if c.segment == old.ref.ID {
				replacement = append(replacement, chunks[position])
				position++
				target.live++
			} else {
				replacement = append(replacement, c)
			}
		}
		loc.chunks = replacement
		s.locations[id] = loc
	}
	if s.activeData == old {
		s.activeData = target
	}
	return s.retireSelected([]journalSegmentRef{old.ref})
}
func (s *journalSegments) selectReplacements(old []journalSegmentRef, targets []*journalSegmentState) error {
	remove := map[uuid.UUID]bool{}
	for _, ref := range old {
		remove[ref.ID] = true
	}
	targetIDs := map[uuid.UUID]bool{}
	for _, e := range targets {
		targetIDs[e.ref.ID] = true
	}
	selected := make([]journalSegmentRef, 0, len(s.catalog.Selected)+len(targets))
	inserted := false
	for _, ref := range s.catalog.Selected {
		if remove[ref.ID] {
			if !inserted {
				for _, e := range targets {
					selected = append(selected, e.ref)
				}
				inserted = true
			}
			continue
		}
		selected = append(selected, ref)
	}
	if !inserted {
		return errJournalSchema
	}
	pending := make([]journalSegmentRef, 0, len(s.catalog.Pending)+len(old))
	for _, ref := range s.catalog.Pending {
		if !targetIDs[ref.ID] {
			pending = append(pending, ref)
		}
	}
	pending = append(pending, old...)
	s.catalog.Selected, s.catalog.Pending = selected, pending
	if err := s.persistCatalog(); err != nil {
		return err
	}
	for _, e := range targets {
		if e.ref.Kind == "data" {
			s.dataAllocated += e.file.AllocatedBytes()
		} else {
			s.controlAllocated += e.file.AllocatedBytes()
		}
	}
	return nil
}
func (s *journalSegments) retireSelected(old []journalSegmentRef) error {
	removed := map[uuid.UUID]bool{}
	for _, ref := range old {
		e := s.extents[ref.ID]
		if e == nil || e.file == nil {
			return errJournalSchema
		}
		size := e.file.AllocatedBytes()
		if err := errors.Join(e.file.Close(), e.lock.Close()); err != nil {
			return err
		}
		delete(s.extents, ref.ID)
		removed[ref.ID] = true
		if ref.Kind == "data" {
			s.dataAllocated -= size
		} else {
			s.controlAllocated -= size
		}
	}
	s.j.mu.Lock()
	for id, loc := range s.locations {
		if s.j.entries[id] != nil {
			continue
		}
		contains := false
		remaining := make([]journalFragmentLocation, 0, len(loc.chunks))
		for _, c := range loc.chunks {
			if removed[c.segment] {
				contains = true
			} else {
				remaining = append(remaining, c)
			}
		}
		if contains {
			// A terminal product can span multiple selected extents. Preserve its
			// identity until every fragment has left durable catalog selection.
			if len(remaining) != 0 {
				loc.chunks = remaining
				s.locations[id] = loc
				continue
			}
			s.indexBytes -= loc.charge
			delete(s.locations, id)
			if s.terminals[id] != "" {
				s.controlMemory -= 32
			}
			delete(s.terminals, id)
		}
	}
	s.j.mu.Unlock()
	if err := s.recoverPending(); err != nil {
		return err
	}
	s.publishBytes()
	return s.pruneTaskControls()
}

// Caller holds ioMu. Selected data locations remain obligations even after
// their records become terminal: recovery could encounter those bytes until
// catalog publication retires the extents. Anonymous reservations require the
// conservative condition that every pending producer has drained. Authoritative
// owners prevent later admissions from reopening a withdrawn generation.
func (s *journalSegments) dischargedTaskControlsLocked() (map[string]bool, error) {
	if !s.j.cfg.AuthoritativeTaskAuthorization || s.reservations != 0 || s.j.stats.Pending != 0 {
		return nil, nil
	}
	retained := make(map[x3TaskIdentity]bool)
	for _, loc := range s.locations {
		r, _, err := decodeRecordMetadata(loc.metadata)
		if err != nil {
			return nil, err
		}
		retained[x3TaskIdentity{r.XID, r.TaskGeneration}] = true
	}
	retired := make(map[string]bool)
	for key, c := range s.controls {
		if c.Revocation != nil && c.Revocation.Scope == li.StateRevokeTask && !retained[x3TaskIdentity{*c.Revocation.XID, *c.Revocation.TaskGeneration}] {
			retired[key] = true
		}
	}
	return retired, nil
}

func (s *journalSegments) pruneTaskControls() error {
	if s.compacting || !s.j.cfg.AuthoritativeTaskAuthorization {
		return nil
	}
	s.j.mu.Lock()
	retired, err := s.dischargedTaskControlsLocked()
	s.j.mu.Unlock()
	if err != nil || len(retired) == 0 {
		return err
	}
	return s.compactControls()
}

func (s *journalSegments) compactControls() error {
	if s.compacting {
		return ErrJournalFull
	}
	s.compacting = true
	defer func() { s.compacting = false }()
	s.j.mu.Lock()
	retired, err := s.dischargedTaskControlsLocked()
	if err != nil {
		s.j.mu.Unlock()
		return err
	}
	var controls []journalControl
	for key, c := range s.controls {
		if !retired[key] {
			controls = append(controls, c)
		}
	}
	for _, cp := range s.checkpoints {
		copy := cp
		controls = append(controls, journalControl{Kind: "sequence", Sequence: &copy})
	}
	for id, reason := range s.terminals {
		if _, exists := s.locations[id]; exists && reason != "revoked" {
			controls = append(controls, journalControl{Kind: reason, ID: id})
		}
	}
	s.j.mu.Unlock()
	sort.Slice(controls, func(i, j int) bool {
		a, _ := json.Marshal(controls[i])
		b, _ := json.Marshal(controls[j])
		return string(a) < string(b)
	})
	var old []journalSegmentRef
	for _, ref := range s.catalog.Selected {
		if ref.Kind == "control" {
			old = append(old, ref)
		}
	}
	var targets []*journalSegmentState
	target, err := s.prepareExtent("control")
	if err != nil {
		return err
	}
	targets = append(targets, target)
	var batch []journalControl
	bytes := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if target.cursor+int64(bytes)+8192 > securestore.FixedSegmentBytes {
			if int64(len(targets)+1)*securestore.FixedSegmentBytes > min(s.controlLimit, max(journalSegmentScratch, s.j.cfg.MaxBytes/10)) {
				return ErrJournalFull
			}
			var err error
			target, err = s.prepareExtent("control")
			if err != nil {
				return err
			}
			targets = append(targets, target)
		}
		out, err := s.appendFrame(target, nil, nil, batch)
		batch = nil
		bytes = 0
		if out != securestore.Committed && err == nil {
			return ErrPersistenceUncertain
		}
		return err
	}
	for _, c := range controls {
		b, _ := json.Marshal(c)
		if bytes+len(b) > journalBatchBytes-8192 || len(batch) == 4096 {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, c)
		bytes += len(b) + 1
	}
	if err := flush(); err != nil {
		return err
	}
	if err := s.selectReplacements(old, targets); err != nil {
		return err
	}
	// Memory follows durable catalog selection. On failure the original controls
	// remain authoritative, and a restart selects the original control extents.
	s.j.mu.Lock()
	for key := range retired {
		encoded, err := json.Marshal(s.controls[key])
		if err != nil {
			s.j.mu.Unlock()
			return err
		}
		s.controlMemory -= int64(len(encoded) + 192)
		delete(s.controls, key)
	}
	s.j.mu.Unlock()
	s.activeControl = target
	return s.retireSelected(old)
}
func (s *journalSegments) compactExpiredExtent() error {
	// One extent per tick keeps work and scratch bounded independently of spool
	// length. Prefer the active extent when every product in it is terminal.
	for _, ref := range s.catalog.Selected {
		if ref.Kind != "data" {
			continue
		}
		e := s.extents[ref.ID]
		if e.cursor == securestore.FixedSegmentDataStart {
			continue
		}
		if e.fragments > e.live {
			return s.compactData(e)
		}

	}
	return nil
}
