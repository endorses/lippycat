//go:build li && !linux

package delivery

import "errors"

func validateJournalPreparation(cfg JournalConfig) error {
	if cfg.Interface != 0 {
		return errors.New("fixed-segment journal requires Linux private preallocation and atomic publication")
	}
	if cfg.MaxBytes <= journalFaultReserve || cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 || cfg.MaxRecords > 1_000_000 {
		return errors.New("invalid X2 journal capacity")
	}
	return nil
}
func authenticatePreparedProducts(*Journal) error { return nil }
func activatePreparedJournal(j *Journal) error    { return startPreparedLegacy(j) }
