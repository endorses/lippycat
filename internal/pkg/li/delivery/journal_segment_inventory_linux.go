//go:build li && linux

package delivery

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func journalHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}
func journalArtifactName(name string) bool {
	if name == ".lock" || name == ".segments" || name == ".state" || name == ".journal-retired" {
		return true
	}
	for _, prefix := range []string{".rotation-bootstrap-", ".rotation-progress-", ".rotation-candidate-"} {
		if strings.HasPrefix(name, prefix) && journalHex(strings.TrimPrefix(name, prefix), 64) {
			return true
		}
	}
	for _, prefix := range []string{".rotation-prev-bootstrap-", ".rotation-prev-progress-", ".rotation-source-catalog-"} {
		if strings.HasPrefix(name, prefix) && journalHex(strings.TrimPrefix(name, prefix), 64) {
			return true
		}
	}
	for _, prefix := range []string{".segment-", ".segment-stage-"} {
		if strings.HasPrefix(name, prefix) {
			rest := strings.TrimPrefix(name, prefix)
			rest = strings.TrimSuffix(rest, ".reserve")
			rest = strings.TrimSuffix(rest, ".bin")
			id, err := uuid.Parse(rest)
			if err == nil && id != uuid.Nil && id.String() == rest && (name == prefix+rest+".bin" || name == prefix+rest+".bin.reserve") {
				return true
			}
		}
	}
	if strings.HasSuffix(name, ".x2") {
		id, err := strconv.ParseUint(strings.TrimSuffix(name, ".x2"), 10, 64)
		return err == nil && id > 0 && journalRecordName(id) == name
	}
	if strings.HasSuffix(name, ".seq") {
		return journalHex(strings.TrimSuffix(name, ".seq"), 64)
	}
	return false
}
func (s *journalSegments) inventoryAllocation() error {
	var total int64
	count := 0
	err := s.j.store.WalkEntries(func(name string) error {
		count++
		if count > 32768 {
			return errors.New("journal allocation inventory limit exceeded")
		}
		var size int64
		var err error
		switch {
		case strings.HasPrefix(name, ".usage-"), strings.HasPrefix(name, ".securestore-lock-"):
			size, err = s.j.store.MetadataAllocatedSize(name)
		case strings.HasPrefix(name, ".securestore-stage-"), strings.HasPrefix(name, ".securestore-tmp-"):
			size, err = s.j.store.RotationTemporaryAllocatedSize(name)
		case journalArtifactName(name):
			size, err = s.j.store.AllocatedSize(name)
		default:
			return errors.New("unexpected segmented journal file")
		}
		if err != nil {
			return err
		}
		if size > s.j.cfg.MaxBytes-total {
			return ErrJournalFull
		}
		total += size
		return nil
	})
	if err != nil {
		return err
	}
	retained := total - s.dataAllocated - s.controlAllocated
	if retained < 0 {
		return errJournalSchema
	}
	s.retainedAllocation = retained
	// All additional retained artifacts reduce admission capacity, rather than
	// borrowing the fixed control or scratch partitions.
	s.dataLimit = s.j.cfg.MaxBytes - s.controlLimit - max(journalSegmentScratch, s.j.cfg.MaxBytes/10) - max(4<<20, retained)
	if s.dataAllocated > s.dataLimit || s.dataLimit < 0 {
		return ErrJournalFull
	}
	return nil
}
