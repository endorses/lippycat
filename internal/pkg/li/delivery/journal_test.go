//go:build li

package delivery

import (
	"bytes"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func journalTestConfig(t *testing.T) JournalConfig {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0700))
	key := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(key, bytes.Repeat([]byte{42}, 32), 0600))
	return JournalConfig{Dir: dir, KeyFile: key, MaxBytes: 1 << 20, MaxPending: 8, MaxRecords: 32}
}
func journalAdmit(t *testing.T, j *Journal, r JournalRecord) uint64 {
	t.Helper()
	done := make(chan error, 1)
	id, err := j.Admit(r, func(_ uint64, err error) { done <- err })
	require.NoError(t, err)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("persist timeout")
	}
	return id
}
func TestJournalEncryptedImmutableRecoveryAndCheckpoint(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	data := []byte("sensitive immutable IRI product")
	r := JournalRecord{DID: uuid.New(), XID: uuid.New(), TaskGeneration: 8, DestinationGeneration: 9, Data: data, AdmittedAt: time.Now()}
	id := journalAdmit(t, j, r)
	data[0] = 'X'
	b, err := os.ReadFile(j.path(id))
	require.NoError(t, err)
	require.False(t, bytes.Contains(b, []byte("sensitive")))
	require.Equal(t, 1, j.Stats().Persisted)
	require.Zero(t, j.Stats().Pending)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	records, err := journalRecords(j)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "sensitive immutable IRI product", string(records[0].Data))
	require.Equal(t, r.TaskGeneration, records[0].TaskGeneration)
	require.Equal(t, 1, j.Stats().Held)
	require.NoError(t, j.Complete(id))
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Zero(t, j.Stats().Persisted)
	require.NoError(t, j.Close())
}
func TestJournalFullPreservesOldAndPendingIsNotDurable(t *testing.T) {
	cfg := journalTestConfig(t)
	cfg.MaxRecords = 1
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	entered := make(chan struct{})
	release := make(chan struct{})
	_, err = j.Admit(JournalRecord{Data: []byte("first")}, func(_ uint64, err error) { close(entered); <-release })
	require.NoError(t, err)
	<-entered
	_, err = j.Admit(JournalRecord{Data: []byte("second")}, nil)
	require.ErrorIs(t, err, ErrJournalFull)
	require.Equal(t, uint64(1), j.Stats().Rejected)
	close(release)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	records, err := journalRecords(j)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "first", string(records[0].Data))
	require.NoError(t, j.Close())
}
func TestJournalRejectsCorruptionWrongKeyPermissionsAndConcurrentOwner(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	_, err = OpenJournal(cfg)
	require.Error(t, err)
	id := journalAdmit(t, j, JournalRecord{Data: []byte("payload")})
	require.NoError(t, j.Close())
	require.NoError(t, os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{7}, 32), 0600))
	_, err = OpenJournal(cfg)
	require.ErrorContains(t, err, "authentication")
	require.NoError(t, os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{42}, 32), 0600))
	b, err := os.ReadFile(j.path(id))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(j.path(id), b[:len(b)-3], 0600))
	_, err = OpenJournal(cfg)
	require.ErrorContains(t, err, "checksum")
	require.NoError(t, os.Chmod(cfg.Dir, 0755))
	_, err = OpenJournal(cfg)
	require.ErrorContains(t, err, "private")
}
func TestJournalIncompleteAppendDiscardedAndPurgeDurable(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	id := journalAdmit(t, j, JournalRecord{Data: []byte("committed")})
	require.NoError(t, j.Close())
	require.NoError(t, os.WriteFile(j.path(id+1)+".tmp", []byte("torn"), 0600))
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 1, j.Stats().Held)
	require.NoError(t, j.Purge(id))
	require.Zero(t, j.Stats().Bytes)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Zero(t, j.Stats().Held)
	require.NoError(t, j.Close())
}
func TestJournalWriteFaultRejectsFutureAdmissions(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	// Collide with O_EXCL temporary creation to inject a filesystem write failure.
	require.NoError(t, os.WriteFile(j.path(1)+".tmp", nil, 0600))
	done := make(chan error, 1)
	_, err = j.Admit(JournalRecord{Data: []byte("data")}, func(_ uint64, err error) { done <- err })
	require.NoError(t, err)
	require.Error(t, <-done)
	_, err = j.Admit(JournalRecord{}, nil)
	require.ErrorIs(t, err, ErrJournalClosed)
	require.Error(t, j.Close())
}

func journalSequencePDU(t *testing.T, xid uuid.UUID, seq uint32) []byte {
	t.Helper()
	p := x2x3.NewPDU(x2x3.PDUTypeX2, xid, 42)
	e := &x2x3.TLVEncoder{}
	p.AddAttribute(e.EncodeUint32(x2x3.AttrSequenceNumber, seq))
	p.SetPayload([]byte("IRI"))
	b, err := p.MarshalBinary()
	require.NoError(t, err)
	return b
}
func TestJournalSequenceHighwaterSurvivesAcknowledgedProduct(t *testing.T) {
	cfg := journalTestConfig(t)
	cfg.PreserveSequences = true
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	xid := uuid.New()
	id := journalAdmit(t, j, JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 7)})
	require.NoError(t, j.Complete(id))
	require.NoError(t, j.Flush())
	require.Zero(t, j.Stats().Persisted)
	require.Positive(t, j.Stats().Bytes)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	s := x2x3.NewSequencer(8)
	require.NoError(t, j.VisitSequences(s.RestoreCheckpoint))
	next, err := s.Next(x2x3.SequenceContext{PDUType: x2x3.PDUTypeX2, XID: xid, CorrelationID: 42})
	require.NoError(t, err)
	require.Equal(t, uint32(8), next)
	// Older fan-out product cannot move the durable highwater backwards.
	id = journalAdmit(t, j, JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 6)})
	require.NoError(t, j.Complete(id))
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	s = x2x3.NewSequencer(8)
	require.NoError(t, j.VisitSequences(s.RestoreCheckpoint))
	next, err = s.Next(x2x3.SequenceContext{PDUType: x2x3.PDUTypeX2, XID: xid, CorrelationID: 42})
	require.NoError(t, err)
	require.Equal(t, uint32(8), next)
	require.NoError(t, j.Close())
}

func TestJournalRecordIdentityNeverReusedAfterDrain(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	id := journalAdmit(t, j, JournalRecord{Data: []byte("old")})
	require.NoError(t, j.Complete(id))
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	next := journalAdmit(t, j, JournalRecord{Data: []byte("new")})
	require.Greater(t, next, id)
	require.NoError(t, j.Close())
}

func journalRecords(j *Journal) ([]JournalRecord, error) {
	var records []JournalRecord
	err := j.VisitHeld(func(r JournalRecord) error { records = append(records, r); return nil })
	return records, err
}
