//go:build li

package delivery

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// JournalRewriteMetadata is derived from the complete authenticated source.
// The counters are durable leases; unused portions remain consumed on rewrite.
type JournalRewriteMetadata struct {
	Format                              string
	JournalUUID, StateIncarnation       uuid.UUID
	Interface                           PDUType
	MaxAge                              time.Duration
	RecordHighwater, AdmissionHighwater uint64
	Records                             uint64
	PlaintextBytes, AllocatedBytes      int64
	Digest                              [32]byte
}
type JournalRewriteSource struct {
	j        *Journal
	metadata JournalRewriteMetadata
	once     sync.Once
	closeErr error
}

func (s *JournalRewriteSource) Metadata() JournalRewriteMetadata { return s.metadata }
func (s *JournalRewriteSource) Directory() *securestore.Dir      { return s.j.store }
func (s *JournalRewriteSource) Keys() *securestore.Keyring       { return s.j.keys }
func (s *JournalRewriteSource) Close() error {
	s.once.Do(func() { s.closeErr = s.j.Close() })
	return s.closeErr
}

// JournalRewriteSegment is one physically reserved transaction-owned inode.
// Initialize consumes that same inode. The caller retains its ownership Lock
// and closes its reservation before Initialize returns.
type JournalRewriteSegment struct {
	ID         uuid.UUID
	Kind       string
	Owner      *securestore.Lock
	Initialize func([]byte) (securestore.Outcome, error)
}
type JournalRewriteTargetOptions struct {
	Config    JournalConfig
	Metadata  JournalRewriteMetadata
	Directory *securestore.Dir
	Owner     *securestore.Lock
	Usage     *securestore.Usage
	Segments  []JournalRewriteSegment
}
type JournalRewritePlan struct {
	DataSegments, ControlSegments int
	Seals, Blocks                 uint64
	AllocatedBytes                int64
}

// Target operations have no dynamic create/preallocate/refill path. The caller
// authenticates bootstrap/request authority, reserves every listed inode plus
// metadata/ledger stages, and durably publishes ledger-required before opening.
type JournalRewriteTarget struct{ backend journalRewriteTargetBackend }
type journalRewriteTargetBackend interface {
	importRecord(JournalRecord, uint64) error
	importControl([]byte) error
	finish() ([]byte, error)
	close() error
}

func (t *JournalRewriteTarget) ImportRecord(r JournalRecord, admission uint64) error {
	return t.backend.importRecord(r, admission)
}
func (t *JournalRewriteTarget) ImportControl(control []byte) error {
	return t.backend.importControl(control)
}
func (t *JournalRewriteTarget) Finish() ([]byte, error) { return t.backend.finish() }
func (t *JournalRewriteTarget) Close() error            { return t.backend.close() }
