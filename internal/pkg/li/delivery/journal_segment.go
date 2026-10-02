//go:build li

package delivery

import (
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

type journalSegmentBackend interface {
	run()
	reserve(int64) (*JournalAdmission, error)
	reserveMetadata(int64, int64) (*JournalAdmission, error)
	admit(JournalRecord, func(uint64, error), bool) (uint64, error)
	readRecord(uint64) (JournalRecord, error)
	terminal(uint64, string) error
	revoke(*li.StateRevocation) (securestore.Outcome, error)
	closeCall(li.DeliveryCallIdentity) (securestore.Outcome, error)
	highwaters() (uint64, uint64)
	visitSequences(func(x2x3.SequenceCheckpoint) error) error
	close() error
}

func (j *Journal) Revoke(r *li.StateRevocation) (securestore.Outcome, error) {
	if j.segments == nil {
		return j.revokeLegacy(r)
	}
	return j.segments.revoke(r)
}
func (j *Journal) CloseCall(c li.DeliveryCallIdentity) (securestore.Outcome, error) {
	if j.segments == nil {
		return securestore.NotCommitted, ErrJournalMigrationRequired
	}
	return j.segments.closeCall(c)
}
func (j *Journal) Expire(id uint64) error {
	if j.segments == nil {
		return ErrJournalMigrationRequired
	}
	return j.segments.terminal(id, "expired")
}
