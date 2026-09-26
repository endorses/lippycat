//go:build li && linux

package delivery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func productionJournalConfig(t *testing.T, iface PDUType) JournalConfig {
	t.Helper()
	cfg := journalTestConfig(t)
	cfg.Interface = iface
	cfg.MaxBytes = 512 << 20
	cfg.MaxRecords = 4096
	cfg.MaxPending = 64
	cfg.PreserveSequences = true
	if iface == PDUTypeX3 {
		cfg.StateIncarnation = uuid.New()
		cfg.MaxAge = time.Hour
	}
	return cfg
}
func productionRecord(t *testing.T, cfg JournalConfig, size int) JournalRecord {
	t.Helper()
	xid := uuid.New()
	p := x2x3.NewPDU(x2x3.PDUType(cfg.Interface), xid, 42)
	p.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, 7))
	p.SetPayload(bytes.Repeat([]byte{0x3c}, size))
	data, err := p.MarshalBinary()
	require.NoError(t, err)
	r := JournalRecord{XID: xid, DID: uuid.New(), TaskGeneration: 7, DestinationGeneration: 8, CapturedAt: time.Now().UTC(), Data: data}
	if cfg.Interface == PDUTypeX3 {
		r.StateIncarnation = cfg.StateIncarnation
		r.Provenance = li.DeliveryProvenance{Kind: "call", CallIncarnation: uuid.New(), CallID: "opaque-call", CallGeneration: 9}
	}
	return r
}
func TestProductionJournalRoundtripControlsAndHighwaters(t *testing.T) {
	for _, iface := range []PDUType{PDUTypeX2, PDUTypeX3} {
		t.Run(string(rune('0'+iface)), func(t *testing.T) {
			cfg := productionJournalConfig(t, iface)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			r := productionRecord(t, cfg, 1024)
			id := journalAdmit(t, j, r)
			identity := j.UUID()
			require.NoError(t, j.Close())
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			require.Equal(t, identity, j.UUID())
			require.Equal(t, 1, j.Stats().Held)
			got, err := j.readRecord(id)
			require.NoError(t, err)
			require.Equal(t, r.Data, got.Data)
			require.Equal(t, iface, got.Interface)
			require.NotZero(t, got.ContentSHA256)
			high, admit := j.Highwaters()
			require.Greater(t, high, id)
			require.Positive(t, admit)
			count := 0
			require.NoError(t, j.VisitSequences(func(cp x2x3.SequenceCheckpoint) error { count++; require.Equal(t, uint32(8), cp.Next); return nil }))
			require.Equal(t, 1, count)
			require.NoError(t, j.Complete(id))
			require.Zero(t, j.Stats().Retained)
			require.NoError(t, j.Close())
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			require.Zero(t, j.Stats().Retained)
			require.NoError(t, j.Close())
		})
	}
}
func TestProductionJournalFragmentsAndCallbackTerminal(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 2<<20)
	id := journalAdmit(t, j, r)
	got, err := j.readRecord(id)
	require.NoError(t, err)
	require.Equal(t, r.Data, got.Data)
	done := make(chan error, 1)
	_, err = j.Admit(productionRecord(t, cfg, 100), func(id uint64, err error) {
		if err == nil {
			err = j.Complete(id)
		}
		done <- err
	})
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NoError(t, j.Flush())
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	got, err = j.readRecord(id)
	require.NoError(t, err)
	require.Equal(t, r.Data, got.Data)
	require.NoError(t, j.Close())
}
func TestProductionJournalRevocationExpiryAndStrictInterface(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 100)
	id := journalAdmit(t, j, r)
	bad := r
	bad.Data = append([]byte(nil), r.Data...)
	binary.BigEndian.PutUint16(bad.Data[2:4], uint16(PDUTypeX2))
	_, err = j.Admit(bad, nil)
	require.Error(t, err)
	high, admit := j.Highwaters()
	rev := &li.StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: j.UUID(), StateIncarnation: cfg.StateIncarnation, Scope: li.StateRevokeTask, XID: &r.XID, TaskGeneration: &r.TaskGeneration, CoveredRecordHighwater: high, CoveredAdmissionHighwater: admit, RevokedAt: li.StateTimestamp{Seconds: time.Now().Unix()}}
	out, err := j.Revoke(rev)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	require.Zero(t, j.Stats().Retained)
	_, err = j.Admit(r, nil)
	require.Error(t, err)
	r2 := productionRecord(t, cfg, 100)
	r2.AdmittedAt = time.Now().UTC()
	r2.Deadline = r2.AdmittedAt.Add(100 * time.Millisecond)
	journalAdmit(t, j, r2)
	require.Eventually(t, func() bool { return j.Stats().Retained == 0 }, 3*time.Second, 20*time.Millisecond)
	require.Equal(t, uint64(1), j.Stats().Expired)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Zero(t, j.Stats().Retained)
	_, err = j.Admit(r, nil)
	require.Error(t, err)
	require.NoError(t, j.Close())
	_ = id
}
func TestProductionJournalCorruptSelectedHeadFailsClosed(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	journalAdmit(t, j, productionRecord(t, cfg, 100))
	s := j.segments.(*journalSegments)
	name := segmentName(s.activeData.ref.ID)
	require.NoError(t, j.Close())
	f, err := os.OpenFile(filepath.Join(cfg.Dir, name), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{0xff}, securestore.FixedSegmentBlock+20)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	j, err = OpenJournal(cfg)
	require.Error(t, err)
	require.Nil(t, j)
}

func TestProductionJournalCompactionPreservesLiveCiphertextAndControls(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	a := productionRecord(t, cfg, 2000)
	b := productionRecord(t, cfg, 3000)
	idA := journalAdmit(t, j, a)
	idB := journalAdmit(t, j, b)
	require.NoError(t, j.Complete(idA))
	s := j.segments.(*journalSegments)
	s.ioMu.Lock()
	old := s.activeData.ref.ID
	require.NoError(t, s.compactData(s.activeData))
	require.NotEqual(t, old, s.activeData.ref.ID)
	require.NoError(t, s.compactControls())
	s.ioMu.Unlock()
	got, err := j.readRecord(idB)
	require.NoError(t, err)
	require.Equal(t, b.Data, got.Data)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 1, j.Stats().Held)
	got, err = j.readRecord(idB)
	require.NoError(t, err)
	require.Equal(t, b.Data, got.Data)
	require.NoError(t, j.Close())
}
func TestProductionJournalMetadataReservationAndRecoveryCharge(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 100)
	r.ID = 1
	r.Interface = PDUTypeX3
	r.JournalUUID = j.UUID()
	r.AdmittedAt = time.Now().UTC()
	r.Deadline = r.AdmittedAt.Add(cfg.MaxAge)
	prefix, err := recordPrefix(r, uint64(len(r.Data)))
	require.NoError(t, err)
	r.ID = 0
	token, err := j.ReserveAdmissionWithMetadata(int64(len(r.Data)), int64(len(prefix)+32))
	require.NoError(t, err)
	done := make(chan error, 1)
	_, err = token.Admit(r, func(_ uint64, e error) { done <- e })
	require.NoError(t, err)
	require.NoError(t, <-done)
	s := j.segments.(*journalSegments)
	j.mu.Lock()
	charged := s.indexBytes
	j.mu.Unlock()
	require.Positive(t, charged)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	s = j.segments.(*journalSegments)
	require.Equal(t, charged, s.indexBytes)
	require.NoError(t, j.Close())
}
func TestProductionJournalOfflineOwnersConsumePreallocatedSegments(t *testing.T) {
	sourceCfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(sourceCfg)
	require.NoError(t, err)
	r := productionRecord(t, sourceCfg, 2<<20)
	id := journalAdmit(t, j, r)
	require.NoError(t, j.Close())
	source, err := OpenJournalRewriteSource(sourceCfg, "segments")
	require.NoError(t, err)
	defer source.Close()
	cfg := productionJournalConfig(t, PDUTypeX3)
	cfg.StateIncarnation = source.Metadata().StateIncarnation
	require.NoError(t, os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{0x55}, 32), 0600))
	ring, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: "fresh", File: cfg.KeyFile}})
	require.NoError(t, err)
	cfg.Keys = ring
	plan, err := source.Plan(ring)
	require.NoError(t, err)
	dir, err := securestore.OpenDir(cfg.Dir)
	require.NoError(t, err)
	defer dir.Close()
	owner, err := dir.Lock(".lock")
	require.NoError(t, err)
	defer owner.Close()
	_, err = dir.Create(".lock", nil)
	require.NoError(t, err)
	var slots []JournalRewriteSegment
	var locks []*securestore.Lock
	defer func() {
		for _, l := range locks {
			require.NoError(t, l.Close())
		}
	}()
	for _, kind := range []string{"data", "control"} {
		count := plan.DataSegments
		if kind == "control" {
			count = plan.ControlSegments
		}
		for range count {
			id := uuid.New()
			lock, err := dir.Lock(segmentName(id))
			require.NoError(t, err)
			locks = append(locks, lock)
			reservation, err := dir.ReserveFixedSegment(segmentStageName(id), segmentName(id))
			require.NoError(t, err)
			slots = append(slots, JournalRewriteSegment{ID: id, Kind: kind, Owner: lock, Initialize: func(b []byte) (securestore.Outcome, error) {
				out, err := reservation.Initialize(b)
				return out, errors.Join(err, reservation.Close())
			}})
		}
	}
	_, err = securestore.InitializeUsage(dir, ring, [16]byte(source.Metadata().JournalUUID))
	require.NoError(t, err)
	usage, err := securestore.OpenUsage(dir, ring, [16]byte(source.Metadata().JournalUUID))
	require.NoError(t, err)
	defer usage.Close()
	require.NoError(t, usage.ReserveAttempt(plan.Seals, plan.Blocks, dir.Replace))
	target, err := OpenJournalRewriteTarget(JournalRewriteTargetOptions{Config: cfg, Metadata: source.Metadata(), Directory: dir, Owner: owner, Usage: usage, Segments: slots})
	require.NoError(t, err)
	require.NoError(t, source.VisitRecords(target.ImportRecord))
	require.NoError(t, source.VisitControls(target.ImportControl))
	catalog, err := target.Finish()
	require.NoError(t, err)
	_, err = dir.Create(".segments", catalog)
	require.NoError(t, err)
	require.NoError(t, target.Close())
	require.NoError(t, usage.Close())
	for _, l := range locks {
		require.NoError(t, l.Close())
	}
	locks = nil
	require.NoError(t, owner.Close())
	require.NoError(t, dir.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	got, err := j.readRecord(id)
	require.NoError(t, err)
	require.Equal(t, r.Data, got.Data)
	require.Equal(t, source.Metadata().JournalUUID, j.UUID())
	require.NoError(t, j.Close())
}

func TestProductionJournalInterruptedTailReadOnlyExportAndRuntimeRecovery(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	id := journalAdmit(t, j, productionRecord(t, cfg, 300))
	s := j.segments.(*journalSegments)
	path := filepath.Join(cfg.Dir, segmentName(s.activeData.ref.ID))
	cursor := s.activeData.cursor
	require.NoError(t, j.Close())
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("incomplete unselected append"), cursor)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	source, err := OpenJournalRewriteSource(cfg, "segments")
	require.NoError(t, err)
	require.NoError(t, source.Close())
	f, err = os.Open(path)
	require.NoError(t, err)
	b := make([]byte, 10)
	_, err = f.ReadAt(b, cursor)
	require.NoError(t, err)
	require.NotEqual(t, make([]byte, 10), b)
	require.NoError(t, f.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	_, err = j.readRecord(id)
	require.NoError(t, err)
	require.NoError(t, j.Close())
	f, err = os.Open(path)
	require.NoError(t, err)
	_, err = f.ReadAt(b, cursor)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 10), b)
	require.NoError(t, f.Close())
}
func TestProductionJournalRecoveryClosesCaptureWithoutRevokingHistory(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 100)
	id := journalAdmit(t, j, r)
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 1, j.Stats().Retained)
	_, err = j.Admit(r, nil)
	require.Error(t, err)
	_, err = j.readRecord(id)
	require.NoError(t, err)
	require.NoError(t, j.Close())
}

func TestProductionJournalCommitOutcomesAndFaultLatch(t *testing.T) {
	for _, which := range []string{"before-data", "uncertain", "committed-cleanup"} {
		t.Run(which, func(t *testing.T) {
			cfg := productionJournalConfig(t, PDUTypeX3)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			s := j.segments.(*journalSegments)
			s.commitFrame = func(f *securestore.FixedSegment, data, head []byte) (securestore.Outcome, error) {
				if binary.BigEndian.Uint32(data[8:]) == segmentFrameHeader {
					return f.Commit(data, head)
				}
				if which == "before-data" {
					return securestore.NotCommitted, unix.ENOSPC
				}
				out, err := f.Commit(data, head)
				if err != nil {
					return out, err
				}
				if which == "uncertain" {
					return securestore.Uncertain, unix.EIO
				}
				return securestore.Committed, unix.EIO
			}
			done := make(chan error, 1)
			_, err = j.Admit(productionRecord(t, cfg, 100), func(_ uint64, e error) { done <- e })
			require.NoError(t, err)
			err = <-done
			require.Error(t, err)
			expected := securestore.NotCommitted
			if which == "uncertain" {
				expected = securestore.Uncertain
			}
			if which == "committed-cleanup" {
				expected = securestore.Committed
			}
			require.Equal(t, expected, securestore.OutcomeOf(err))
			_, err = j.Admit(productionRecord(t, cfg, 100), nil)
			require.Error(t, err)
			require.Error(t, j.Close())
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			count := 1
			if which == "before-data" {
				count = 0
			}
			require.Equal(t, count, j.Stats().Retained)
			require.NoError(t, j.Close())
		})
	}
}
func TestProductionJournalCrashChild(t *testing.T) {
	cut := os.Getenv("LC_JOURNAL_CRASH_CUT")
	if cut == "" {
		t.Skip("subprocess only")
	}
	incarnation, err := uuid.Parse(os.Getenv("LC_JOURNAL_CRASH_STATE"))
	require.NoError(t, err)
	cfg := JournalConfig{Dir: os.Getenv("LC_JOURNAL_CRASH_DIR"), KeyFile: os.Getenv("LC_JOURNAL_CRASH_KEY"), Interface: PDUTypeX3, StateIncarnation: incarnation, MaxAge: time.Hour, MaxBytes: 512 << 20, MaxPending: 64, MaxRecords: 4096, PreserveSequences: true}
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	s := j.segments.(*journalSegments)
	s.commitFrame = func(f *securestore.FixedSegment, data, head []byte) (securestore.Outcome, error) {
		if binary.BigEndian.Uint32(data[8:]) == segmentFrameHeader {
			return f.Commit(data, head)
		}
		if cut == "after-sync" {
			out, err := f.Commit(data, head)
			if err != nil {
				return out, err
			}
			os.Exit(73)
		}
		raw, err := os.OpenFile(filepath.Join(cfg.Dir, segmentName(s.activeData.ref.ID)), os.O_RDWR, 0)
		if err != nil {
			return securestore.NotCommitted, err
		}
		if _, err = raw.WriteAt(data, s.activeData.cursor); err != nil {
			return securestore.NotCommitted, err
		}
		if cut == "torn-head" {
			_, err = raw.WriteAt(head[:37], int64((s.activeData.active^1)+1)*securestore.FixedSegmentBlock)
			if err != nil {
				return securestore.Uncertain, err
			}
		}
		if err := raw.Sync(); err != nil {
			return securestore.Uncertain, err
		}
		os.Exit(73)
		return securestore.Uncertain, nil
	}
	_, err = j.Admit(productionRecord(t, cfg, 100), nil)
	require.NoError(t, err)
	select {}
}
func TestProductionJournalSubprocessCrashBoundaries(t *testing.T) {
	for _, cut := range []string{"data-only", "torn-head", "after-sync"} {
		t.Run(cut, func(t *testing.T) {
			cfg := productionJournalConfig(t, PDUTypeX3)
			command := exec.Command(os.Args[0], "-test.run=^TestProductionJournalCrashChild$")
			command.Env = append(os.Environ(), "LC_JOURNAL_CRASH_CUT="+cut, "LC_JOURNAL_CRASH_DIR="+cfg.Dir, "LC_JOURNAL_CRASH_KEY="+cfg.KeyFile, "LC_JOURNAL_CRASH_STATE="+cfg.StateIncarnation.String())
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, string(output))
			require.Equal(t, 73, exit.ExitCode(), string(output))
			j, err := OpenJournal(cfg)
			if cut == "torn-head" {
				require.Error(t, err)
				require.Nil(t, j)
				return
			}
			require.NoError(t, err)
			count := 0
			if cut == "after-sync" {
				count = 1
			}
			require.Equal(t, count, j.Stats().Held)
			high, _ := j.Highwaters()
			require.Greater(t, high, uint64(1))
			require.NoError(t, j.Close())
		})
	}
}
func TestProductionJournalTypedBatchRejectsCrossTypeAndJournal(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	s := j.segments.(*journalSegments)
	r := productionRecord(t, cfg, 100)
	id := journalAdmit(t, j, r)
	got, err := j.readRecord(id)
	require.NoError(t, err)
	call := callForRecord(got)
	call.CoveredAdmissionHighwater = 1
	c := journalControl{Kind: "call_open", Call: &call}
	require.NoError(t, s.validateControl(c))
	c.Kind = "revoke"
	require.Error(t, s.validateControl(c))
	c.Kind = "call_open"
	call.JournalUUID = uuid.New()
	require.Error(t, s.validateControl(c))
	require.NoError(t, j.Close())
}

func TestProductionJournalTerminalCreditSupportsPrimaryOutage(t *testing.T) {
	const records = 1_200_000
	for _, tc := range []struct {
		bytes      int64
		sufficient bool
	}{{4 << 30, false}, {24 << 30, true}} {
		s := &journalSegments{controlLimit: max(2*securestore.FixedSegmentBytes, tc.bytes/10)}
		// Exercise the exact admission predicate without allocating product buffers
		// or writing a synthetic million-record spool.
		for i := 0; i < records; i++ {
			if !s.terminalCreditAvailable() {
				break
			}
			s.controlLiability += journalTerminalCredit
		}
		require.Equal(t, tc.sufficient, s.controlLiability == records*journalTerminalCredit)
	}
}
func TestProductionJournalControlMemoryCensusAfterClosure(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 100)
	id := journalAdmit(t, j, r)
	got, err := j.readRecord(id)
	require.NoError(t, err)
	_, err = j.CloseCall(callForRecord(got).identity())
	require.NoError(t, err)
	require.NoError(t, j.Complete(id))
	s := j.segments.(*journalSegments)
	s.ioMu.Lock()
	j.mu.Lock()
	census := int64(len(s.terminals)) * 32
	for _, c := range s.controls {
		b, e := json.Marshal(c)
		require.NoError(t, e)
		census += int64(len(b) + 192)
	}
	for _, cp := range s.checkpoints {
		b, e := json.Marshal(journalControl{Kind: "sequence", Sequence: &cp})
		require.NoError(t, e)
		census += int64(len(b) + 192)
	}
	require.Equal(t, census, s.controlMemory)
	j.mu.Unlock()
	s.ioMu.Unlock()
	require.NoError(t, j.Close())
}
func TestProductionJournalRetirementCheckedUnderOwnerLock(t *testing.T) {
	for _, iface := range []PDUType{0, PDUTypeX3} {
		t.Run(string(rune('0'+iface)), func(t *testing.T) {
			cfg := productionJournalConfig(t, iface)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			// Competing startup must settle ownership before inspecting this marker.
			out, err := j.store.Create(".journal-retired", []byte("retired"))
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			_, err = OpenJournal(cfg)
			require.ErrorIs(t, err, securestore.ErrLocked)
			require.NoError(t, j.Close())
			_, err = OpenJournal(cfg)
			require.ErrorContains(t, err, "retired")
		})
	}
}
func TestProductionJournalReceiptInventoryUsesWorkspaceToken(t *testing.T) {
	for _, prefix := range []string{".rotation-prev-bootstrap-", ".rotation-prev-progress-"} {
		require.True(t, journalArtifactName(prefix+strings.Repeat("a", 64)))
		require.False(t, journalArtifactName(prefix+strings.Repeat("a", 32)))
		require.False(t, journalArtifactName(prefix+strings.Repeat("A", 64)))
	}
}
