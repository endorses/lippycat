//go:build li

package delivery

import "sync"

// JournalAdmission owns bounded pending, metadata and disk credits before a
// producer enters reorder. Release and Admit consume it exactly once.
type JournalAdmission struct {
	mu      sync.Mutex
	consume func(JournalRecord, func(uint64, error)) (uint64, error)
	release func()
}

func (a *JournalAdmission) Release() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.release != nil {
		a.release()
		a.release = nil
		a.consume = nil
	}
}
func (a *JournalAdmission) Admit(r JournalRecord, cb func(uint64, error)) (uint64, error) {
	if a == nil {
		return 0, ErrJournalClosed
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.consume == nil {
		return 0, ErrJournalClosed
	}
	f := a.consume
	a.consume = nil
	a.release = nil
	return f(r, cb)
}
func (j *Journal) ReserveAdmission(bytes int64) (*JournalAdmission, error) {
	if j.segments == nil {
		return nil, ErrJournalMigrationRequired
	}
	return j.segments.reserve(bytes)
}

// SegmentedJournalMemoryBytes is a hard aggregate ceiling for retained indexes,
// pending payloads, one lazy product read, and bounded batch/control scratch.
const SegmentedJournalMemoryBytes = int64(2<<30) + int64(64<<20) + 2*journalMaxRecord + (8 << 20) + (64 << 20)

// ReserveAdmissionWithMetadata reserves the exact canonical logical metadata
// length plus its digest. Admit validates this bound before retaining any entry.
func (j *Journal) ReserveAdmissionWithMetadata(bytes, metadataBytes int64) (*JournalAdmission, error) {
	if j.segments == nil {
		return nil, ErrJournalMigrationRequired
	}
	return j.segments.reserveMetadata(bytes, metadataBytes)
}
