//go:build li && linux

package delivery

import (
	"errors"

	"github.com/google/uuid"
)

func validateJournalPreparation(cfg JournalConfig) error {
	if cfg.Interface == 0 {
		if cfg.MaxBytes <= journalFaultReserve || cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 || cfg.MaxRecords > 1_000_000 {
			return errors.New("invalid X2 journal capacity")
		}
		return nil
	}
	if cfg.Interface != PDUTypeX2 && cfg.Interface != PDUTypeX3 {
		return errJournalSchema
	}
	if cfg.MaxBytes < journalSegmentMinimum || cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 || cfg.MaxRecords > 2_000_000 || cfg.Interface == PDUTypeX2 && cfg.MaxRecords > 1_000_000 {
		return errors.New("invalid segmented journal capacity")
	}
	if cfg.Interface == PDUTypeX3 && (cfg.StateIncarnation == uuid.Nil || cfg.MaxAge <= 0) {
		return errors.New("X3 journal requires administrative incarnation and positive maximum age")
	}
	return nil
}
func authenticatePreparedProducts(j *Journal) error {
	s, ok := j.segments.(*journalSegments)
	if !ok {
		return nil
	}
	if err := s.inventoryAllocation(); err != nil {
		return err
	}
	// Include selected terminal products too: a corrupt unclaimed product is not
	// silently ignored merely because no live replay entry currently refers to it.
	for id := range s.locations {
		r, err := s.readRecordLocked(id)
		if err != nil {
			return err
		}
		clear(r.Data)
	}
	return nil
}
func activatePreparedJournal(j *Journal) error {
	s, ok := j.segments.(*journalSegments)
	if !ok {
		return startPreparedLegacy(j)
	}
	for _, ref := range s.catalog.Selected {
		if err := s.activateExtent(s.extents[ref.ID]); err != nil {
			return err
		}
	}
	if err := s.recoverPending(); err != nil {
		return err
	}
	if err := startSegmentOwner(s); err != nil {
		return err
	}
	j.cfg.offline = false
	j.cfg.preflight = false
	j.cfg.rewriteDir = nil
	j.cfg.rewriteLock = nil
	j.readOnly = false
	launchSegmentOwner(s)
	return nil
}
