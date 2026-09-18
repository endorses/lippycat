package eventspool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"google.golang.org/protobuf/proto"
)

// resolveJournal applies journal metadata before opening record files. This is
// what permits post-commit garbage collection even while an older checkpoint
// still names the retired immutable files.
func (s *Spool) resolveJournal(base manifest) (manifest, uint64, error) {
	path := journalPath(s.config.Directory, base.Generation)
	f, err := openRegularNoFollow(path, os.O_RDWR)
	if errors.Is(err, os.ErrNotExist) {
		return manifest{}, 0, errors.New("open event spool: manifest exists without journal")
	}
	if err != nil {
		return manifest{}, 0, fmt.Errorf("open event spool journal: %w", err)
	}
	defer f.Close()
	header := make([]byte, 20)
	if _, err = io.ReadFull(f, header); err != nil {
		return manifest{}, 0, fmt.Errorf("read event spool journal header: %w", err)
	}
	if string(header[:8]) != string(journalMagic[:]) || binary.BigEndian.Uint32(header[8:12]) != manifestVersion || binary.BigEndian.Uint64(header[12:20]) != base.Generation {
		return manifest{}, 0, errors.New("read event spool journal: invalid format or generation")
	}
	records := append([]manifestRecord(nil), base.Records...)
	pending := cloneLosses(base.PendingLosses)
	sequence := base.AppliedTransactions
	offset := int64(20)
	var replayed uint64
	for {
		header := make([]byte, journalFrameHeaderSize)
		_, readErr := io.ReadFull(f, header)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			if err = f.Truncate(offset); err != nil {
				return manifest{}, 0, fmt.Errorf("truncate journal tail: %w", err)
			}
			break
		}
		if readErr != nil {
			return manifest{}, 0, fmt.Errorf("read journal frame header: %w", readErr)
		}
		if string(header[:8]) != string(journalMagic[:]) || binary.BigEndian.Uint32(header[8:12]) != manifestVersion || binary.BigEndian.Uint64(header[12:20]) != base.Generation || crc32.ChecksumIEEE(header[:32]) != binary.BigEndian.Uint32(header[32:36]) {
			return manifest{}, 0, fmt.Errorf("read event spool journal: corrupt frame header at offset %d", offset)
		}
		frameSequence := binary.BigEndian.Uint64(header[20:28])
		length := binary.BigEndian.Uint32(header[28:32])
		if length == 0 || length > maxJournalFramePayload {
			return manifest{}, 0, fmt.Errorf("read event spool journal: invalid frame length %d", length)
		}
		frame := make([]byte, int(length)+4)
		if _, readErr = io.ReadFull(f, frame); readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				if err = f.Truncate(offset); err != nil {
					return manifest{}, 0, fmt.Errorf("truncate journal tail: %w", err)
				}
				break
			}
			return manifest{}, 0, fmt.Errorf("read journal frame: %w", readErr)
		}
		if crc32.ChecksumIEEE(frame[:length]) != binary.BigEndian.Uint32(frame[length:]) {
			return manifest{}, 0, fmt.Errorf("read event spool journal: checksum mismatch at offset %d", offset)
		}
		var tx transaction
		if err = json.Unmarshal(frame[:length], &tx); err != nil {
			return manifest{}, 0, fmt.Errorf("read event spool journal transaction: %w", err)
		}
		if tx.Version != manifestVersion || tx.Generation != base.Generation {
			return manifest{}, 0, errors.New("read event spool journal: transaction format mismatch")
		}
		if tx.Sequence != frameSequence {
			return manifest{}, 0, fmt.Errorf("read event spool journal: frame transaction mismatch at offset %d", offset)
		}
		if tx.Sequence > sequence {
			if tx.Sequence != sequence+1 {
				return manifest{}, 0, fmt.Errorf("read event spool journal: sequence gap at %d", tx.Sequence)
			}
			remove := map[string]bool{}
			active := make(map[string]bool, len(records))
			for _, record := range records {
				active[record.Name] = true
			}
			for _, name := range tx.Remove {
				if !safeBasename(name) {
					return manifest{}, 0, fmt.Errorf("journal contains unsafe path %q", name)
				}
				if remove[name] {
					return manifest{}, 0, fmt.Errorf("journal transaction contains duplicate removal %q", name)
				}
				if !active[name] {
					return manifest{}, 0, fmt.Errorf("journal transaction removes inactive record %q", name)
				}
				remove[name] = true
			}
			kept := records[:0]
			for _, mr := range records {
				if !remove[mr.Name] {
					kept = append(kept, mr)
				}
			}
			records = kept
			records = append(records, tx.Add...)
			pending = cloneLosses(tx.PendingLosses)
			sequence = tx.Sequence
			base.SourceNodeID, base.ProducerSessionID = tx.SourceNodeID, tx.ProducerSessionID
			base.LastEventSequence, base.LastBatchSequence = tx.LastEventSequence, tx.LastBatchSequence
			base.RetiredBatchSequence = tx.RetiredBatchSequence
			base.SessionPolicy = tx.SessionPolicy
			replayed++
		}
		offset += int64(journalFrameHeaderSize+4) + int64(length)
	}
	var logical uint64
	for _, mr := range records {
		if logical > ^uint64(0)-mr.Size {
			return manifest{}, 0, errors.New("journal logical bytes overflow")
		}
		logical += mr.Size
	}
	base.Records = records
	base.PendingLosses = pending
	base.AppliedTransactions = sequence
	base.LogicalBytes = logical
	return base, replayed, nil
}

func (s *Spool) commit(tx transaction) error {
	if s.txSequence == ^uint64(0) || tx.Sequence == 0 {
		return errors.New("commit event spool transaction: journal transaction sequence is exhausted")
	}
	if tx.Generation != s.generation || tx.Sequence != s.txSequence+1 {
		return errors.New("commit event spool transaction: invalid generation or transaction sequence")
	}
	if !tx.ResetSession {
		tx.SourceNodeID, tx.ProducerSessionID = s.singleSource, s.singleProducer
		tx.LastEventSequence, tx.LastBatchSequence = s.lastEventSequence, s.lastBatchSequence
		tx.RetiredBatchSequence = max(tx.RetiredBatchSequence, s.retiredBatchSequence)
		if s.sessionPolicy != nil {
			copyPolicy := *s.sessionPolicy
			tx.SessionPolicy = &copyPolicy
		}
	}
	for _, mr := range tx.Add {
		r, readErr := readRecord(filepath.Join(s.config.Directory, mr.Name), s.config.MaxRecordBytes)
		if readErr != nil {
			return readErr
		}
		b := r.batch
		if tx.SourceNodeID == "" {
			tx.SourceNodeID, tx.ProducerSessionID = b.GetSourceNodeId(), b.GetProducerSessionId()
		}
		tx.LastBatchSequence = max(tx.LastBatchSequence, b.GetBatchSequence())
		tx.LastEventSequence = max(tx.LastEventSequence, b.GetLastEventSequence())
		for _, loss := range b.GetStats().GetLosses() {
			for _, eventRange := range loss.GetEventSequenceRanges() {
				tx.LastEventSequence = max(tx.LastEventSequence, eventRange.GetLast())
			}
		}
	}
	for _, loss := range tx.PendingLosses {
		if tx.SourceNodeID == "" {
			tx.SourceNodeID, tx.ProducerSessionID = loss.GetSourceNodeId(), loss.GetProducerSessionId()
		}
		for _, eventRange := range loss.GetEventSequenceRanges() {
			tx.LastEventSequence = max(tx.LastEventSequence, eventRange.GetLast())
		}
	}
	payload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("commit event spool transaction: marshal: %w", err)
	}
	if len(payload) > s.config.journalFrameLimit {
		return s.commitLargeTransaction(tx)
	}
	frame := make([]byte, journalFrameHeaderSize+len(payload)+4)
	copy(frame[:8], journalMagic[:])
	binary.BigEndian.PutUint32(frame[8:12], manifestVersion)
	binary.BigEndian.PutUint64(frame[12:20], tx.Generation)
	binary.BigEndian.PutUint64(frame[20:28], tx.Sequence)
	binary.BigEndian.PutUint32(frame[28:32], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[32:36], crc32.ChecksumIEEE(frame[:32]))
	copy(frame[journalFrameHeaderSize:], payload)
	binary.BigEndian.PutUint32(frame[journalFrameHeaderSize+len(payload):], crc32.ChecksumIEEE(payload))
	f, err := s.fs.openFile(journalPath(s.config.Directory, s.generation), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("commit event spool transaction: open journal: %w", err)
	}
	written, writeErr := f.Write(frame)
	if writeErr == nil && written != len(frame) {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if writeErr == nil {
		syncErr = f.Sync()
		s.metrics.Syncs++
	}
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		s.uncertain = true
		return fmt.Errorf("%w: journal publication failed: %v %v %v", ErrDurabilityUncertain, writeErr, syncErr, closeErr)
	}
	s.metrics.MetadataBytes += uint64(len(frame))
	if err = s.applyTransaction(tx); err != nil {
		s.uncertain = true
		return fmt.Errorf("%w: apply transaction: %v", ErrDurabilityUncertain, err)
	}
	s.transactionsSinceCheckpoint++
	s.metrics.JournalFrames++
	s.metrics.MaxJournalFrames = max(s.metrics.MaxJournalFrames, s.metrics.JournalFrames)
	if s.shouldCheckpoint() {
		generation := s.generation
		if err = s.rotateCheckpoint(); err != nil {
			if s.generation != generation {
				return err
			}
			if !errors.Is(err, ErrDurabilityUncertain) {
				s.checkpointRequired = true
				s.checkpointErr = err
				return errors.Join(ErrCheckpointRequired, err)
			}
			return err
		}
	}
	return nil
}

// commitLargeTransaction publishes an oversized logical mutation as the first
// checkpoint of a fresh journal generation. This keeps cumulative ACK and
// replacement atomic without permitting an unbounded journal frame. The old
// checkpoint/journal remain authoritative until the replacement checkpoint is
// renamed and its directory entry is synced.
func (s *Spool) commitLargeTransaction(tx transaction) error {
	if s.generation == ^uint64(0) {
		return errors.New("commit event spool transaction: journal generation is exhausted")
	}
	oldGeneration := s.generation
	newGeneration := oldGeneration + 1
	if err := s.createJournal(newGeneration); err != nil {
		return err
	}

	type stateSnapshot struct {
		records                                                    []record
		bytes, generation, txSequence                              uint64
		transactionsSinceCheckpoint, commitCount                   uint64
		pendingLosses                                              []*eventsv1.EventLoss
		identitySet, homogeneous                                   bool
		singleSource, singleProducer                               string
		lastEventSequence, lastBatchSequence, retiredBatchSequence uint64
		checkpointRecordBase                                       int
		sessionPolicy                                              *SessionPolicy
	}
	snapshot := stateSnapshot{
		records: append([]record(nil), s.records...), bytes: s.bytes,
		generation: s.generation, txSequence: s.txSequence,
		transactionsSinceCheckpoint: s.transactionsSinceCheckpoint, commitCount: s.commitCount,
		pendingLosses: cloneLosses(s.pendingLosses), identitySet: s.identitySet, homogeneous: s.homogeneous,
		singleSource: s.singleSource, singleProducer: s.singleProducer,
		lastEventSequence: s.lastEventSequence, lastBatchSequence: s.lastBatchSequence,
		retiredBatchSequence: s.retiredBatchSequence,
		checkpointRecordBase: s.checkpointRecordBase,
	}
	if s.sessionPolicy != nil {
		copyPolicy := *s.sessionPolicy
		snapshot.sessionPolicy = &copyPolicy
	}
	restore := func() {
		s.records, s.bytes = snapshot.records, snapshot.bytes
		s.rebuildIndex()
		s.generation, s.txSequence = snapshot.generation, snapshot.txSequence
		s.transactionsSinceCheckpoint, s.commitCount = snapshot.transactionsSinceCheckpoint, snapshot.commitCount
		s.pendingLosses = snapshot.pendingLosses
		s.identitySet, s.homogeneous = snapshot.identitySet, snapshot.homogeneous
		s.singleSource, s.singleProducer = snapshot.singleSource, snapshot.singleProducer
		s.lastEventSequence, s.lastBatchSequence = snapshot.lastEventSequence, snapshot.lastBatchSequence
		s.retiredBatchSequence = snapshot.retiredBatchSequence
		s.checkpointRecordBase, s.sessionPolicy = snapshot.checkpointRecordBase, snapshot.sessionPolicy
	}

	if err := s.applyTransaction(tx); err != nil {
		restore()
		cleanupErr := s.retryCleanup([]string{filepath.Base(journalPath(s.config.Directory, newGeneration))})
		return errors.Join(fmt.Errorf("commit event spool transaction: apply oversized mutation: %w", err), cleanupErr)
	}
	s.generation, s.txSequence = newGeneration, 0
	if err := s.publishCheckpoint(); err != nil {
		if !errors.Is(err, ErrDurabilityUncertain) {
			restore()
			cleanupErr := s.retryCleanup([]string{filepath.Base(journalPath(s.config.Directory, newGeneration))})
			return errors.Join(err, cleanupErr)
		}
		return err
	}
	s.transactionsSinceCheckpoint = 0
	s.metrics.JournalFrames = 0
	s.checkpointRecordBase = len(s.records)
	s.metrics.Rotations++
	return s.retryCleanup([]string{filepath.Base(journalPath(s.config.Directory, oldGeneration))})
}

func (s *Spool) shouldCheckpoint() bool {
	threshold := s.config.CheckpointEvery
	if uint64(s.checkpointRecordBase) > threshold {
		threshold = uint64(s.checkpointRecordBase)
	}
	if s.transactionsSinceCheckpoint >= threshold {
		return true
	}
	// A checkpoint taken with a large active set must not leave nearly that
	// many retirement frames to replay after the set has drained. This second
	// trigger keeps outstanding replay work bounded by the records still active
	// plus the configured threshold, while the base trigger preserves geometric
	// checkpointing during growth and replacement.
	activeBound := uint64(len(s.records))
	if activeBound > ^uint64(0)-s.config.CheckpointEvery {
		activeBound = ^uint64(0)
	} else {
		activeBound += s.config.CheckpointEvery
	}
	return s.transactionsSinceCheckpoint >= activeBound
}

func (s *Spool) applyTransaction(tx transaction) error {
	remove := map[string]bool{}
	active := make(map[string]bool, len(s.records))
	for _, record := range s.records {
		active[record.name] = true
	}
	for _, name := range tx.Remove {
		if !safeBasename(name) {
			return fmt.Errorf("event spool transaction contains unsafe path %q", name)
		}
		if remove[name] {
			return fmt.Errorf("event spool transaction contains duplicate removal %q", name)
		}
		if !active[name] {
			return fmt.Errorf("event spool transaction removes inactive record %q", name)
		}
		remove[name] = true
	}
	total := s.bytes
	prefix := 0
	for prefix < len(s.records) && remove[s.records[prefix].name] {
		total -= s.records[prefix].size
		prefix++
	}
	if prefix == len(remove) {
		for _, r := range s.records[:prefix] {
			delete(s.index, identityKey(r.batch.GetSourceNodeId(), r.batch.GetProducerSessionId(), r.batch.GetBatchSequence()))
		}
		s.records = s.records[prefix:]
	} else {
		total = s.bytes
		kept := s.records[:0]
		for _, r := range s.records {
			if remove[r.name] {
				delete(s.index, identityKey(r.batch.GetSourceNodeId(), r.batch.GetProducerSessionId(), r.batch.GetBatchSequence()))
				total -= r.size
				continue
			}
			kept = append(kept, r)
		}
		s.records = kept
	}
	if len(s.records) == 0 {
		s.identitySet = false
		s.homogeneous = true
		s.singleSource = ""
		s.singleProducer = ""
	}
	needsSort := false
	for _, mr := range tx.Add {
		if !safeBasename(mr.Name) {
			return fmt.Errorf("event spool transaction contains unsafe path %q", mr.Name)
		}
		key := identityKey(mr.SourceNodeID, mr.ProducerSessionID, mr.BatchSequence)
		if _, exists := s.index[key]; exists {
			return fmt.Errorf("event spool transaction duplicates identity %s", key)
		}
		r, err := readRecord(filepath.Join(s.config.Directory, mr.Name), s.config.MaxRecordBytes)
		if err != nil {
			return err
		}
		if r.size != mr.Size || r.batch.GetSourceNodeId() != mr.SourceNodeID || r.batch.GetProducerSessionId() != mr.ProducerSessionID || r.batch.GetBatchSequence() != mr.BatchSequence {
			return fmt.Errorf("event spool transaction: metadata mismatch for %q", mr.Name)
		}
		if len(s.records) > 0 {
			previous := s.records[len(s.records)-1].batch
			if previous.GetSourceNodeId() == r.batch.GetSourceNodeId() && previous.GetProducerSessionId() == r.batch.GetProducerSessionId() && previous.GetBatchSequence() > r.batch.GetBatchSequence() {
				needsSort = true
			}
		}
		s.records = append(s.records, r)
		total += r.size
		s.index[key] = len(s.records) - 1
		if !s.identitySet {
			s.identitySet = true
			s.homogeneous = true
			s.singleSource = mr.SourceNodeID
			s.singleProducer = mr.ProducerSessionID
		} else if mr.SourceNodeID != s.singleSource || mr.ProducerSessionID != s.singleProducer {
			s.homogeneous = false
		}
	}
	if len(tx.Add) > 0 {
		if needsSort {
			sortRecords(s.records)
			s.rebuildIndex()
		}
	}
	s.bytes = total
	s.pendingLosses = normalizeLosses(tx.PendingLosses)
	s.txSequence = tx.Sequence
	s.commitCount++
	s.singleSource, s.singleProducer = tx.SourceNodeID, tx.ProducerSessionID
	s.lastEventSequence, s.lastBatchSequence = tx.LastEventSequence, tx.LastBatchSequence
	s.retiredBatchSequence = tx.RetiredBatchSequence
	if tx.SessionPolicy != nil {
		copyPolicy := *tx.SessionPolicy
		s.sessionPolicy = &copyPolicy
	} else {
		s.sessionPolicy = nil
	}
	if s.singleSource != "" {
		s.identitySet = true
	}
	return nil
}

func (s *Spool) rotateCheckpoint() error {
	if s.generation == ^uint64(0) {
		return errors.New("rotate event spool checkpoint: journal generation is exhausted")
	}
	oldGeneration, oldSequence := s.generation, s.txSequence
	newGeneration := oldGeneration + 1
	if err := s.createJournal(newGeneration); err != nil {
		return err
	}
	s.generation, s.txSequence = newGeneration, 0
	if err := s.publishCheckpoint(); err != nil {
		if !errors.Is(err, ErrDurabilityUncertain) {
			s.generation, s.txSequence = oldGeneration, oldSequence
			cleanupErr := s.retryCleanup([]string{filepath.Base(journalPath(s.config.Directory, newGeneration))})
			return errors.Join(err, cleanupErr)
		}
		return err
	}
	s.transactionsSinceCheckpoint = 0
	s.metrics.JournalFrames = 0
	s.checkpointRecordBase = len(s.records)
	s.metrics.Rotations++
	return s.retryCleanup([]string{filepath.Base(journalPath(s.config.Directory, oldGeneration))})
}
func (s *Spool) publishCheckpoint() error {
	m := manifest{Version: manifestVersion, Generation: s.generation, AppliedTransactions: s.txSequence, LogicalBytes: s.bytes, PendingLosses: cloneLosses(s.pendingLosses), SourceNodeID: s.singleSource, ProducerSessionID: s.singleProducer, LastEventSequence: s.lastEventSequence, LastBatchSequence: s.lastBatchSequence, RetiredBatchSequence: s.retiredBatchSequence, SessionPolicy: s.sessionPolicy}
	for _, r := range s.records {
		m.Records = append(m.Records, toManifestRecord(r))
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.metrics.MetadataBytes += uint64(len(payload))
	tmp, err := s.fs.createTemp(s.config.Directory, ".manifest-*")
	if err != nil {
		return fmt.Errorf("publish event spool manifest: create: %w", err)
	}
	name := tmp.Name()
	cleanup := func() error { return s.retryCleanup([]string{filepath.Base(name)}) }
	if err = writeSpoolFile(tmp, payload); err == nil {
		err = tmp.Sync()
		s.metrics.Syncs++
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return errors.Join(fmt.Errorf("publish event spool manifest: write: %v %v", err, closeErr), cleanup())
	}
	if err = s.fs.rename(name, filepath.Join(s.config.Directory, manifestFileName)); err != nil {
		return errors.Join(fmt.Errorf("publish event spool manifest: rename: %w", err), cleanup())
	}
	if err = s.fs.syncDir(s.config.Directory); err != nil {
		s.uncertain = true
		return fmt.Errorf("%w: manifest directory sync: %v", ErrDurabilityUncertain, err)
	}
	s.metrics.Syncs++
	s.metrics.Checkpoints++
	return nil
}
func (s *Spool) createJournal(generation uint64) error {
	tmp, err := s.fs.createTemp(s.config.Directory, ".journal-*")
	if err != nil {
		return fmt.Errorf("create event spool journal: %w", err)
	}
	name := tmp.Name()
	cleanup := func() error { return s.retryCleanup([]string{filepath.Base(name)}) }
	header := make([]byte, 20)
	copy(header, journalMagic[:])
	binary.BigEndian.PutUint32(header[8:12], manifestVersion)
	binary.BigEndian.PutUint64(header[12:20], generation)
	if err = writeSpoolFile(tmp, header); err == nil {
		err = tmp.Sync()
		s.metrics.Syncs++
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return errors.Join(fmt.Errorf("create event spool journal: write: %v %v", err, closeErr), cleanup())
	}
	if err = s.fs.rename(name, journalPath(s.config.Directory, generation)); err != nil {
		return errors.Join(fmt.Errorf("create event spool journal: rename: %w", err), cleanup())
	}
	if err = s.fs.syncDir(s.config.Directory); err != nil {
		s.uncertain = true
		return fmt.Errorf("%w: journal directory sync: %v", ErrDurabilityUncertain, err)
	}
	s.metrics.Syncs++
	return nil
}

func (s *Spool) writeRecord(created time.Time, b *eventsv1.ProtocolEventBatch, payload []byte) (record, error) {
	createdNano := created.UnixNano()
	tmp, err := s.fs.createTemp(s.config.Directory, ".eventbatch-*")
	if err != nil {
		return record{}, fmt.Errorf("enqueue event batch: create temporary record: %w", err)
	}
	name := tmp.Name()
	cleanup := func() error { return s.retryCleanup([]string{filepath.Base(name)}) }
	header := make([]byte, headerSize)
	copy(header, recordMagic[:])
	binary.BigEndian.PutUint16(header[8:10], recordVersion)
	binary.BigEndian.PutUint64(header[10:18], uint64(createdNano))
	binary.BigEndian.PutUint64(header[18:26], uint64(len(payload)))
	binary.BigEndian.PutUint32(header[26:30], crc32.ChecksumIEEE(payload))
	if err = writeSpoolFile(tmp, header); err == nil {
		err = writeSpoolFile(tmp, payload)
	}
	if err == nil {
		err = tmp.Sync()
		s.metrics.Syncs++
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		accountingErr := s.accountTemporaryRecord(name)
		cleanupErr := cleanup()
		return record{}, errors.Join(fmt.Errorf("enqueue event batch: write record: %v %v", err, closeErr), accountingErr, cleanupErr, s.reconcileFailedPhysicalAccounting(accountingErr))
	}
	finalName := fmt.Sprintf("%020d-%s%s", createdNano, filepath.Base(name), recordExtension)
	final := filepath.Join(s.config.Directory, finalName)
	if err = s.fs.rename(name, final); err != nil {
		// A failed rename leaves the fully written temporary record behind. Count
		// it before cleanup so a cleanup failure remains visible in physical-byte
		// status and a later successful retry can subtract it exactly once.
		accountingErr := s.accountTemporaryRecord(name)
		cleanupErr := cleanup()
		return record{}, errors.Join(fmt.Errorf("enqueue event batch: publish record: %w", err), accountingErr, cleanupErr, s.reconcileFailedPhysicalAccounting(accountingErr))
	}
	recordSize := uint64(headerSize + len(payload))
	// The rename makes the record visible to this process even if the following
	// directory sync leaves power-loss durability uncertain. Status must account
	// for that physical orphan throughout the uncertainty barrier.
	if recordSize > ^uint64(0)-s.physicalBytes {
		s.uncertain = true
		return record{}, fmt.Errorf("%w: published record physical bytes overflow", ErrDurabilityUncertain)
	}
	s.physicalBytes += recordSize
	if err = s.fs.syncDir(s.config.Directory); err != nil {
		s.uncertain = true
		return record{}, fmt.Errorf("%w: record directory sync: %v", ErrDurabilityUncertain, err)
	}
	s.metrics.Syncs++
	return record{name: finalName, path: final, created: created, size: recordSize, payloadSize: uint64(len(payload)), batch: proto.Clone(b).(*eventsv1.ProtocolEventBatch)}, nil
}

func (s *Spool) accountTemporaryRecord(path string) error {
	name := filepath.Base(path)
	if s.unaccountedPhysical == nil {
		s.unaccountedPhysical = make(map[string]bool)
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		delete(s.unaccountedPhysical, name)
		return nil
	}
	if err != nil {
		s.unaccountedPhysical[name] = true
		return fmt.Errorf("enqueue event batch: stat failed temporary record %q: %w", path, err)
	}
	if info.Size() <= 0 {
		delete(s.unaccountedPhysical, name)
		return nil
	}
	visibleBytes := uint64(info.Size())
	if visibleBytes > ^uint64(0)-s.physicalBytes {
		s.unaccountedPhysical[name] = true
		return errors.New("enqueue event batch: physical bytes overflow")
	}
	s.physicalBytes += visibleBytes
	delete(s.unaccountedPhysical, name)
	return nil
}

func (s *Spool) reconcileFailedPhysicalAccounting(accountingErr error) error {
	if accountingErr == nil {
		return nil
	}
	if err := s.refreshPhysical(); err != nil {
		s.uncertain = true
		return fmt.Errorf("%w: reconcile event spool physical bytes: %v", ErrDurabilityUncertain, err)
	}
	return nil
}

func (s *Spool) retryCleanup(names []string) error {
	if s.orphanFailures == nil {
		s.orphanFailures = make(map[string]error)
	}
	var first error
	refreshPhysical := false
	for _, name := range names {
		path := filepath.Join(s.config.Directory, name)
		var removedBytes uint64
		if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 {
			removedBytes = uint64(info.Size())
		}
		removeErr := s.fs.remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			s.orphanFailures[name] = removeErr
			if first == nil {
				first = &CleanupError{Operation: "remove", Path: path, Err: removeErr}
			}
		} else if removeErr == nil {
			if countsAsPhysicalRecord(name) && !s.unaccountedPhysical[name] && removedBytes <= s.physicalBytes {
				s.physicalBytes -= removedBytes
			}
			delete(s.unaccountedPhysical, name)
			delete(s.orphanFailures, name)
		} else if errors.Is(removeErr, os.ErrNotExist) {
			refreshPhysical = true
			delete(s.unaccountedPhysical, name)
			delete(s.orphanFailures, name)
		}
	}
	if refreshPhysical {
		if err := s.refreshPhysical(); err != nil && first == nil {
			first = &CleanupError{Operation: "reconcile physical bytes", Path: s.config.Directory, Err: err}
		}
	}
	if len(names) > 0 {
		if err := s.fs.syncDir(s.config.Directory); err != nil {
			s.orphanFailures[".directory-sync"] = err
			if first == nil {
				first = &CleanupError{Operation: "sync directory", Path: s.config.Directory, Err: err}
			}
		} else {
			s.metrics.Syncs++
			delete(s.orphanFailures, ".directory-sync")
		}
	}
	if len(s.orphanFailures) > 0 {
		for name, err := range s.orphanFailures {
			s.cleanupErr = &CleanupError{Operation: "retry cleanup", Path: filepath.Join(s.config.Directory, name), Err: err}
			break
		}
	} else {
		s.cleanupErr = nil
	}
	if first != nil {
		return first
	}
	return s.cleanupErr
}

func (s *Spool) retryKnownCleanup() {
	if len(s.orphanFailures) == 0 {
		return
	}
	var names []string
	needSync := false
	for name := range s.orphanFailures {
		if name == ".directory-sync" {
			needSync = true
		} else {
			names = append(names, name)
		}
	}
	_ = s.retryCleanup(names)
	if needSync && len(names) == 0 {
		if err := s.fs.syncDir(s.config.Directory); err == nil {
			delete(s.orphanFailures, ".directory-sync")
			s.metrics.Syncs++
			if len(s.orphanFailures) == 0 {
				s.cleanupErr = nil
			}
		}
	}
}
func (s *Spool) cleanupOrphans() error {
	entries, err := os.ReadDir(s.config.Directory)
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for _, r := range s.records {
		active[r.name] = true
	}
	var names []string
	activeJournal := filepath.Base(journalPath(s.config.Directory, s.generation))
	for _, e := range entries {
		orphanRecord := strings.HasSuffix(e.Name(), recordExtension) && !active[e.Name()]
		temporary := strings.HasPrefix(e.Name(), ".eventbatch-") || strings.HasPrefix(e.Name(), ".manifest-") || strings.HasPrefix(e.Name(), ".journal-")
		journalCandidate := (e.Name() == journalFileName) || (strings.HasPrefix(e.Name(), "journal-") && strings.HasSuffix(e.Name(), ".log"))
		orphanJournal := journalCandidate && e.Name() != activeJournal
		if !e.IsDir() && (orphanRecord || orphanJournal || temporary) {
			names = append(names, e.Name())
		}
	}
	return s.retryCleanup(names)
}

func writeSpoolFile(file spoolFile, payload []byte) error {
	for len(payload) > 0 {
		n, err := file.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
func (s *Spool) refreshPhysical() error {
	entries, err := os.ReadDir(s.config.Directory)
	if err != nil {
		return err
	}
	var total uint64
	for _, e := range entries {
		if e.IsDir() || !countsAsPhysicalRecord(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 {
			if uint64(info.Size()) > ^uint64(0)-total {
				return errors.New("refresh event spool physical bytes: overflow")
			}
			total += uint64(info.Size())
		}
	}
	s.physicalBytes = total
	s.unaccountedPhysical = nil
	return nil
}

func countsAsPhysicalRecord(name string) bool {
	return strings.HasSuffix(name, recordExtension) || strings.HasPrefix(name, ".eventbatch-")
}

func openRegularNoFollow(path string, flags int) (*os.File, error) {
	entryInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !entryInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("open event spool metadata %q: file is not regular", path)
	}
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(entryInfo, info) {
		_ = f.Close()
		return nil, fmt.Errorf("open event spool metadata %q: file changed while opening", path)
	}
	return f, nil
}
