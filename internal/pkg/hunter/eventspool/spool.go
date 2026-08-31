// Package eventspool provides a crash-recoverable, bounded spool for event batches.
package eventspool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"google.golang.org/protobuf/proto"
)

const (
	recordExtension = ".eventbatch"
	recordVersion   = uint16(1)
	headerSize      = 8 + 2 + 8 + 8 + 4
)

var recordMagic = [8]byte{'L', 'C', 'E', 'V', 'S', 'P', 'L', '1'}

// ExhaustionPolicy selects which complete batches are lost when a limit is hit.
type ExhaustionPolicy string

const (
	DropOldest ExhaustionPolicy = "drop_oldest"
	DropNew    ExhaustionPolicy = "drop_new"
)

type Config struct {
	Directory string
	MaxBytes  uint64
	MaxAge    time.Duration
	Policy    ExhaustionPolicy
	Clock     func() time.Time
}

type record struct {
	path    string
	created time.Time
	size    uint64
	batch   *eventsv1.ProtocolEventBatch
}

// EnqueueResult reports whether the new batch was persisted and every exact
// event sequence range discarded while enforcing limits.
type EnqueueResult struct {
	Stored bool
	Losses []*eventsv1.EventLoss
}

type Spool struct {
	mu      sync.Mutex
	config  Config
	records []record
	bytes   uint64
}

// Open loads and validates all existing records. It deliberately performs no
// age or byte-limit cleanup: unacknowledged data must survive process startup.
func Open(config Config) (*Spool, error) {
	if config.Directory == "" {
		return nil, errors.New("open event spool: directory is required")
	}
	if config.Policy == "" {
		config.Policy = DropOldest
	}
	if config.Policy != DropOldest && config.Policy != DropNew {
		return nil, fmt.Errorf("open event spool: invalid exhaustion policy %q", config.Policy)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if err := os.MkdirAll(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("open event spool: create directory: %w", err)
	}
	entries, err := os.ReadDir(config.Directory)
	if err != nil {
		return nil, fmt.Errorf("open event spool: read directory: %w", err)
	}
	s := &Spool{config: config}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), recordExtension) {
			continue
		}
		r, err := readRecord(filepath.Join(config.Directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		s.records = append(s.records, r)
		s.bytes += r.size
	}
	sort.Slice(s.records, func(i, j int) bool {
		left, right := s.records[i].batch, s.records[j].batch
		if left.GetSourceNodeId() == right.GetSourceNodeId() && left.GetProducerSessionId() == right.GetProducerSessionId() && left.GetBatchSequence() != right.GetBatchSequence() {
			return left.GetBatchSequence() < right.GetBatchSequence()
		}
		if s.records[i].created.Equal(s.records[j].created) {
			return s.records[i].path < s.records[j].path
		}
		return s.records[i].created.Before(s.records[j].created)
	})
	return s, nil
}

// Enqueue durably writes a complete batch. DropNew never mutates existing
// records when admission would exceed a limit. DropOldest removes complete
// records, returning their exact logical event ranges.
func (s *Spool) Enqueue(batch *eventsv1.ProtocolEventBatch) (EnqueueResult, error) {
	if batch == nil {
		return EnqueueResult{}, errors.New("enqueue event batch: nil batch")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: marshal: %w", err)
	}
	recordBytes := uint64(headerSize + len(payload))
	now := s.config.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.config.Policy == DropNew && (s.overByteLimit(s.bytes+recordBytes) || s.hasExpired(now)) {
		return EnqueueResult{Losses: lossesFor(batch)}, nil
	}
	result := EnqueueResult{}
	storedBatch := batch
	if s.config.Policy == DropOldest {
		storedBatch = proto.Clone(batch).(*eventsv1.ProtocolEventBatch)
		for len(s.records) > 0 && (s.recordExpired(s.records[0], now) || s.overByteLimit(s.bytes+recordBytes)) {
			removed := s.records[0]
			if err := os.Remove(removed.path); err != nil {
				return result, fmt.Errorf("enqueue event batch: remove oldest %q: %w", removed.path, err)
			}
			s.records = s.records[1:]
			s.bytes -= removed.size
			result.Losses = append(result.Losses, lossesFor(removed.batch)...)
			storedBatch.Stats = appendLosses(storedBatch.GetStats(), lossesFor(removed.batch))
			payload, err = proto.MarshalOptions{Deterministic: true}.Marshal(storedBatch)
			if err != nil {
				return result, fmt.Errorf("enqueue event batch: marshal with loss report: %w", err)
			}
			recordBytes = uint64(headerSize + len(payload))
		}
		if s.overByteLimit(recordBytes) {
			result.Losses = append(result.Losses, lossesFor(batch)...)
			if err := syncDirectory(s.config.Directory); err != nil {
				return result, err
			}
			return result, nil
		}
		batch = storedBatch
	}

	r, err := s.writeRecord(now, batch, payload)
	if err != nil {
		return result, err
	}
	s.records = append(s.records, r)
	s.bytes += r.size
	result.Stored = true
	return result, nil
}

func appendLosses(stats *eventsv1.EventBatchStats, losses []*eventsv1.EventLoss) *eventsv1.EventBatchStats {
	if stats == nil {
		stats = &eventsv1.EventBatchStats{}
	} else {
		stats = proto.Clone(stats).(*eventsv1.EventBatchStats)
	}
	for _, loss := range losses {
		if loss != nil {
			stats.Losses = append(stats.Losses, proto.Clone(loss).(*eventsv1.EventLoss))
		}
	}
	return stats
}

// Ack deletes complete records cumulatively for one producer session. Records
// from other sessions are untouched even when their batch sequence is lower.
func (s *Spool) Ack(sourceNodeID, producerSessionID string, batchSequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.records[:0]
	changed := false
	for _, r := range s.records {
		b := r.batch
		if b.GetSourceNodeId() == sourceNodeID && b.GetProducerSessionId() == producerSessionID && b.GetBatchSequence() <= batchSequence {
			if err := os.Remove(r.path); err != nil {
				return fmt.Errorf("ack event spool: remove %q: %w", r.path, err)
			}
			s.bytes -= r.size
			changed = true
			continue
		}
		kept = append(kept, r)
	}
	s.records = kept
	if changed {
		return syncDirectory(s.config.Directory)
	}
	return nil
}

// Batches returns cloned, oldest-first batches for sending or retrying.
func (s *Spool) Batches() []*eventsv1.ProtocolEventBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*eventsv1.ProtocolEventBatch, len(s.records))
	for i := range s.records {
		out[i] = proto.Clone(s.records[i].batch).(*eventsv1.ProtocolEventBatch)
	}
	return out
}

func (s *Spool) Bytes() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// RecoveryState returns the sole producer session and its highest persisted
// event and batch sequences. Mixed sessions require operator intervention so a
// new stream cannot accidentally open under one identity and send another.
func (s *Spool) RecoveryState() (sourceNodeID, producerSessionID string, lastEventSequence, lastBatchSequence uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		b := r.batch
		if producerSessionID == "" {
			sourceNodeID, producerSessionID = b.GetSourceNodeId(), b.GetProducerSessionId()
		} else if sourceNodeID != b.GetSourceNodeId() || producerSessionID != b.GetProducerSessionId() {
			return "", "", 0, 0, fmt.Errorf("event spool contains multiple producer sessions")
		}
		lastEventSequence = max(lastEventSequence, b.GetLastEventSequence())
		lastBatchSequence = max(lastBatchSequence, b.GetBatchSequence())
	}
	return sourceNodeID, producerSessionID, lastEventSequence, lastBatchSequence, nil
}

func (s *Spool) overByteLimit(n uint64) bool { return s.config.MaxBytes > 0 && n > s.config.MaxBytes }
func (s *Spool) recordExpired(r record, now time.Time) bool {
	return s.config.MaxAge > 0 && now.Sub(r.created) > s.config.MaxAge
}
func (s *Spool) hasExpired(now time.Time) bool {
	return len(s.records) > 0 && s.recordExpired(s.records[0], now)
}

func (s *Spool) writeRecord(created time.Time, batch *eventsv1.ProtocolEventBatch, payload []byte) (record, error) {
	tmp, err := os.CreateTemp(s.config.Directory, ".eventbatch-*")
	if err != nil {
		return record{}, fmt.Errorf("enqueue event batch: create temporary record: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	header := make([]byte, headerSize)
	copy(header, recordMagic[:])
	binary.BigEndian.PutUint16(header[8:10], recordVersion)
	binary.BigEndian.PutUint64(header[10:18], uint64(created.UnixNano()))
	binary.BigEndian.PutUint64(header[18:26], uint64(len(payload)))
	binary.BigEndian.PutUint32(header[26:30], crc32.ChecksumIEEE(payload))
	if _, err = tmp.Write(header); err == nil {
		_, err = tmp.Write(payload)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		cleanup()
		return record{}, fmt.Errorf("enqueue event batch: write record: %w", err)
	}
	if closeErr != nil {
		cleanup()
		return record{}, fmt.Errorf("enqueue event batch: close record: %w", closeErr)
	}
	// The temporary name contributes a random suffix, so independent producer
	// sessions with the same timestamp and batch sequence cannot overwrite one
	// another.
	final := filepath.Join(s.config.Directory, fmt.Sprintf("%020d-%s%s", created.UnixNano(), filepath.Base(tmpName), recordExtension))
	if err = os.Rename(tmpName, final); err != nil {
		cleanup()
		return record{}, fmt.Errorf("enqueue event batch: publish record: %w", err)
	}
	if err = syncDirectory(s.config.Directory); err != nil {
		return record{}, err
	}
	return record{path: final, created: created, size: uint64(headerSize + len(payload)), batch: proto.Clone(batch).(*eventsv1.ProtocolEventBatch)}, nil
}

func readRecord(path string) (record, error) {
	f, err := os.Open(path)
	if err != nil {
		return record{}, fmt.Errorf("open event spool record %q: %w", path, err)
	}
	defer f.Close()
	header := make([]byte, headerSize)
	if _, err = io.ReadFull(f, header); err != nil {
		return record{}, fmt.Errorf("read event spool record %q header: %w", path, err)
	}
	if string(header[:8]) != string(recordMagic[:]) || binary.BigEndian.Uint16(header[8:10]) != recordVersion {
		return record{}, fmt.Errorf("read event spool record %q: invalid format", path)
	}
	length := binary.BigEndian.Uint64(header[18:26])
	if length > uint64(^uint(0)>>1) {
		return record{}, fmt.Errorf("read event spool record %q: payload too large", path)
	}
	payload := make([]byte, int(length))
	if _, err = io.ReadFull(f, payload); err != nil {
		return record{}, fmt.Errorf("read event spool record %q payload: %w", path, err)
	}
	var extra [1]byte
	if n, readErr := f.Read(extra[:]); n != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return record{}, fmt.Errorf("read event spool record %q: trailing data", path)
	}
	if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(header[26:30]) {
		return record{}, fmt.Errorf("read event spool record %q: checksum mismatch", path)
	}
	b := new(eventsv1.ProtocolEventBatch)
	if err = proto.Unmarshal(payload, b); err != nil {
		return record{}, fmt.Errorf("read event spool record %q protobuf: %w", path, err)
	}
	return record{path: path, created: time.Unix(0, int64(binary.BigEndian.Uint64(header[10:18]))), size: uint64(headerSize) + length, batch: b}, nil
}

func lossesFor(batch *eventsv1.ProtocolEventBatch) []*eventsv1.EventLoss {
	first, last := batch.GetFirstEventSequence(), batch.GetLastEventSequence()
	if first == 0 && last == 0 {
		return nil
	}
	if last < first {
		first, last = last, first
	}
	return []*eventsv1.EventLoss{{
		Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: last - first + 1,
		SourceNodeId: batch.GetSourceNodeId(), ProducerSessionId: batch.GetProducerSessionId(),
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: first, Last: last}},
	}}
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sync event spool directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync event spool directory: %w", err)
	}
	return nil
}
