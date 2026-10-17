package packetspool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	data "github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Directory: filepath.Join(t.TempDir(), "spool"), SourceID: "edge", DestinationID: "central-domain", AckScope: Central, Protection: Private, Clock: func() time.Time { return time.Unix(1000, 0) }}
}
func createSpool(t *testing.T, config Config) *Spool {
	t.Helper()
	require.NoError(t, Initialize(config))
	s, err := Open(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}
func packet(payload string) *data.PacketBatch {
	return &data.PacketBatch{Packets: []*data.CapturedPacket{{Data: []byte(payload), TimestampNs: 123}}}
}
func ack(t *testing.T, s *Spool, sequence uint64) {
	t.Helper()
	id := s.Identity()
	require.NoError(t, s.Ack(id.SourceID, id.SessionID, id.DestinationID, id.AckScope, sequence))
}
func confirm(t *testing.T, s *Spool, losses LossCoverage) {
	t.Helper()
	id := s.Identity()
	require.NoError(t, s.AckLossCoverage(id.SourceID, id.SessionID, id.DestinationID, id.AckScope, losses))
}

func TestRestartIdentityOwnershipAndReceiptBinding(t *testing.T) {
	cfg := testConfig(t)
	s := createSpool(t, cfg)
	id := s.Identity()
	input := packet("evidence")
	r, err := s.Enqueue(input)
	require.NoError(t, err)
	require.True(t, r.Stored)
	require.True(t, r.Committed)
	require.Equal(t, uint64(1), r.Sequence)
	require.Empty(t, input.HunterId)
	require.Zero(t, input.Sequence)
	input.Packets[0].Data[0] = 'X'
	r.Batch.Packets[0].Data[0] = 'Y'
	batches, err := s.BatchesAfter(0, 1)
	require.NoError(t, err)
	require.Equal(t, "evidence", string(batches[0].Packets[0].Data))
	batches[0].Packets[0].Data[0] = 'Z'
	require.NoError(t, s.Close())
	s, err = Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	require.Equal(t, id, s.Identity())
	batches, err = s.BatchesAfter(0, 2)
	require.NoError(t, err)
	require.Equal(t, "evidence", string(batches[0].Packets[0].Data))
	require.True(t, s.Contains(1))
	require.ErrorIs(t, s.Ack(id.SourceID, id.SessionID, "other", id.AckScope, 1), ErrIdentity)
	require.ErrorIs(t, s.Ack(id.SourceID, "other", id.DestinationID, id.AckScope, 1), ErrIdentity)
	require.ErrorIs(t, s.Ack(id.SourceID, id.SessionID, id.DestinationID, Receiver, 1), ErrIdentity)
	require.ErrorIs(t, s.Ack(id.SourceID, id.SessionID, id.DestinationID, id.AckScope, 2), ErrReceipt)
	ack(t, s, 1)
	require.False(t, s.Contains(1))
	r, err = s.Enqueue(packet("next"))
	require.NoError(t, err)
	require.Equal(t, uint64(2), r.Sequence)
	require.NoError(t, s.Close())
	s, err = Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	require.Equal(t, id, s.Identity())
	require.True(t, s.Contains(2))
	require.False(t, s.Contains(1))
}

func TestExhaustionAndLossOnlyProgress(t *testing.T) {
	for _, policy := range []ExhaustionPolicy{DropOldest, DropNew} {
		t.Run(string(policy), func(t *testing.T) {
			cfg := testConfig(t)
			cfg.MaxRecords = 1
			cfg.Policy = policy
			s := createSpool(t, cfg)
			_, err := s.Enqueue(packet("one"))
			require.NoError(t, err)
			second, err := s.Enqueue(packet("two"))
			require.NoError(t, err)
			losses, err := s.PendingLosses()
			require.NoError(t, err)
			require.Len(t, losses.Ranges, 1)
			if policy == DropOldest {
				require.True(t, second.Stored)
				require.Equal(t, uint64(1), losses.Ranges[0].First)
				require.False(t, s.Contains(1))
				require.True(t, s.Contains(2))
			} else {
				require.True(t, second.Dropped)
				require.Equal(t, uint64(2), losses.Ranges[0].First)
				require.True(t, s.Contains(1))
				require.False(t, s.Contains(2))
			}
			id := s.Identity()
			require.ErrorIs(t, s.Ack(id.SourceID, id.SessionID, id.DestinationID, id.AckScope, 2), ErrReceipt)
			confirm(t, s, losses)
			if policy == DropOldest {
				ack(t, s, 2)
			} else {
				ack(t, s, 1)
			}
			require.Equal(t, uint64(2), s.Status().AckedSequence)
			require.Zero(t, s.Status().PendingRecords)
			require.Zero(t, s.Status().PendingLosses)
			require.NoError(t, s.Close())
			s, err = Open(cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, s.Close()) }()
			require.Equal(t, uint64(2), s.Status().AckedSequence)
		})
	}
}

func TestOldLossSnapshotNeverConfirmsNewAdjacentLoss(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxBytes = 1
	s := createSpool(t, cfg)
	_, err := s.Enqueue(packet("one"))
	require.NoError(t, err)
	first, err := s.PendingLosses()
	require.NoError(t, err)
	_, err = s.Enqueue(packet("two"))
	require.NoError(t, err)
	confirm(t, s, first)
	remaining, err := s.PendingLosses()
	require.NoError(t, err)
	require.Equal(t, []LossRange{{First: 2, Last: 2, Reason: "exhausted"}}, remaining.Ranges)
	require.Equal(t, uint64(1), s.Status().AckedSequence)
	confirm(t, s, remaining)
	require.Equal(t, uint64(2), s.Status().AckedSequence)
	confirm(t, s, first) // already retired exact coverage is idempotent
}

func TestAgeAndOversizeAreExactPersistentLoss(t *testing.T) {
	now := time.Unix(1000, 0)
	cfg := testConfig(t)
	cfg.Clock = func() time.Time { return now }
	cfg.MaxAge = time.Minute
	cfg.MaxRecordBytes = 256
	s := createSpool(t, cfg)
	_, err := s.Enqueue(packet("before blackout"))
	require.NoError(t, err)
	now = now.Add(time.Minute)
	require.False(t, s.Contains(1))
	batches, err := s.BatchesAfter(0, 1)
	require.NoError(t, err)
	require.Empty(t, batches)
	r, err := s.Enqueue(packet(string(bytes.Repeat([]byte{'x'}, 1024))))
	require.NoError(t, err)
	require.True(t, r.Dropped)
	require.Equal(t, uint64(2), r.Sequence)
	losses, err := s.PendingLosses()
	require.NoError(t, err)
	require.Equal(t, []LossRange{{First: 1, Last: 1, Reason: "expired"}, {First: 2, Last: 2, Reason: "record_too_large"}}, losses.Ranges)
	require.NoError(t, s.Close())
	s, err = Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	recovered, err := s.PendingLosses()
	require.NoError(t, err)
	require.Equal(t, losses, recovered)
	confirm(t, s, recovered)
	require.Equal(t, uint64(2), s.Status().AckedSequence)
}

func TestEncryptionAndDirectoryOwnership(t *testing.T) {
	cfg := testConfig(t)
	keyPath := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0600))
	keys, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: "raw-key", File: keyPath}})
	require.NoError(t, err)
	cfg.Protection = Encrypted
	cfg.Keys = keys
	s := createSpool(t, cfg)
	r, err := s.Enqueue(packet("confidential evidence"))
	require.NoError(t, err)
	onDisk, err := os.ReadFile(filepath.Join(cfg.Directory, recordName(r.Sequence)))
	require.NoError(t, err)
	require.NotContains(t, string(onDisk), "confidential evidence")
	_, err = Open(cfg)
	require.ErrorIs(t, err, securestore.ErrLocked)
	require.NoError(t, s.Close())
	s, err = Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	batches, err := s.BatchesAfter(0, 1)
	require.NoError(t, err)
	require.Equal(t, "confidential evidence", string(batches[0].Packets[0].Data))
	require.NoError(t, s.Close())
	require.NoError(t, os.Remove(filepath.Join(cfg.Directory, keys.UsageFileName())))
	_, err = Open(cfg)
	require.Error(t, err)
}

func TestConcurrentAdmissionAndRetrieval(t *testing.T) {
	cfg := testConfig(t)
	s := createSpool(t, cfg)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 10; j++ {
				_, err := s.Enqueue(packet("payload"))
				require.NoError(t, err)
				_, err = s.BatchesAfter(0, 1)
				require.NoError(t, err)
				s.Status()
			}
		}()
	}
	workers.Wait()
	require.Equal(t, uint64(40), s.Status().LastSequence)
}

func TestValidationAndClosedState(t *testing.T) {
	cfg := testConfig(t)
	for _, change := range []func(*Config){func(c *Config) { c.SourceID = "" }, func(c *Config) { c.DestinationID = "" }, func(c *Config) { c.AckScope = "unknown" }, func(c *Config) { c.Protection = "" }, func(c *Config) { c.MaxAge = -1 }, func(c *Config) { c.MaxRecords = -1 }, func(c *Config) { c.MaxRecordBytes = maxPayload + 1 }} {
		bad := cfg
		change(&bad)
		_, err := bad.Validate()
		require.Error(t, err)
	}
	s := createSpool(t, cfg)
	require.NoError(t, s.Close())
	_, err := s.Enqueue(packet("no"))
	require.ErrorIs(t, err, ErrClosed)
	_, err = s.PendingLosses()
	require.ErrorIs(t, err, ErrClosed)
	require.ErrorIs(t, errors.Join(ErrClosed), ErrClosed)
}
