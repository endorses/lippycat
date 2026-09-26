//go:build li && !linux

package delivery

import (
	"errors"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

var errJournalRewritePlatform = errors.New("offline journal rewrite requires Linux fixed preallocation and atomic publication")

func OpenJournalRewriteSource(JournalConfig, string) (*JournalRewriteSource, error) {
	return nil, errJournalRewritePlatform
}
func OpenJournalRewriteSourceOwned(JournalConfig, string, *securestore.Dir, *securestore.Lock) (*JournalRewriteSource, error) {
	return nil, errJournalRewritePlatform
}
func OpenJournalRewriteSourceCatalogOwned(JournalConfig, string, *securestore.Dir, *securestore.Lock, string) (*JournalRewriteSource, error) {
	return nil, errJournalRewritePlatform
}
func (*JournalRewriteSource) VisitRecords(func(JournalRecord, uint64) error) error {
	return errJournalRewritePlatform
}
func (*JournalRewriteSource) VisitControls(func([]byte) error) error {
	return errJournalRewritePlatform
}
func (*JournalRewriteSource) Plan(*securestore.Keyring) (JournalRewritePlan, error) {
	return JournalRewritePlan{}, errJournalRewritePlatform
}
func OpenJournalRewriteTarget(JournalRewriteTargetOptions) (*JournalRewriteTarget, error) {
	return nil, errJournalRewritePlatform
}
func JournalRewriteSegmentName(id uuid.UUID) string { return ".segment-" + id.String() + ".bin" }
func JournalRewriteSegmentStageName(id uuid.UUID) string {
	return ".segment-stage-" + id.String() + ".bin"
}
