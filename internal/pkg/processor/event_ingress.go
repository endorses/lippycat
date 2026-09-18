//go:build processor || tap || all

package processor

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const defaultIngressMaxBatchBytes = protoadapter.MaxEncodedBatchBytes

type EventIngressPolicy struct {
	Dispatcher    *events.Dispatcher
	Profile       string
	WALDirectory  string
	WALMaxBytes   int64
	MaxBatchBytes int
}

type ingressSession struct{ batch, event uint64 }
type ingressSessionKey struct {
	sourceNodeID      string
	producerSessionID string
}

func ingressKey(sourceNodeID, producerSessionID string) ingressSessionKey {
	return ingressSessionKey{sourceNodeID: sourceNodeID, producerSessionID: producerSessionID}
}

type eventIngress struct {
	dispatcher    *events.Dispatcher
	profile       eventsv1.IngressProfile
	maxBatchBytes int
	wal           *eventWAL
	mu            sync.Mutex
	sessions      map[ingressSessionKey]ingressSession
	delivered     map[ingressSessionKey]ingressSession
	authorize     func(*eventsv1.EventIngressOpen) bool
	flowControl   func() int32
}

func newEventIngress(p EventIngressPolicy) (*eventIngress, error) {
	profile := eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY
	if p.Profile != "" && p.Profile != "memory_only" && p.Profile != "reliable" {
		return nil, fmt.Errorf("invalid event ingress profile %q", p.Profile)
	}
	if p.Profile == "reliable" {
		profile = eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
	}
	if p.MaxBatchBytes <= 0 {
		p.MaxBatchBytes = defaultIngressMaxBatchBytes
	}
	if p.MaxBatchBytes < protoadapter.MaxEncodedBatchBytes {
		return nil, fmt.Errorf("event ingress maximum batch bytes %d is below the durable forwarding contract %d", p.MaxBatchBytes, protoadapter.MaxEncodedBatchBytes)
	}
	i := &eventIngress{
		dispatcher: p.Dispatcher, profile: profile, maxBatchBytes: p.MaxBatchBytes,
		sessions: make(map[ingressSessionKey]ingressSession), delivered: make(map[ingressSessionKey]ingressSession),
	}
	if profile == eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE {
		if p.WALDirectory == "" {
			return nil, errors.New("reliable event ingress requires a WAL directory")
		}
		wal, err := openEventWAL(p.WALDirectory, p.WALMaxBytes)
		if err != nil {
			return nil, err
		}
		wal.maxRecordBytes = p.MaxBatchBytes
		i.wal = wal
	}
	return i, nil
}

func (s *EventService) StreamEvents(stream eventsv1.EventService_StreamEventsServer) error {
	if s.ingress == nil || s.ingress.dispatcher == nil {
		return status.Error(codes.FailedPrecondition, "event ingress is unavailable")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "first event ingress message must open a producer session")
	}
	if open.SourceNodeId == "" || open.ProducerSessionId == "" || open.EventApiMajor != 1 || open.SemanticProfileRevision != supportedEventSemanticProfile {
		return status.Error(codes.FailedPrecondition, "unsupported or incomplete event producer profile")
	}
	if open.Profile != s.ingress.profile {
		return status.Errorf(codes.FailedPrecondition, "requested ingress profile %s is unavailable; configured profile is %s", open.Profile, s.ingress.profile)
	}
	allowedKinds := make(map[events.Kind]struct{}, len(open.EventKinds))
	for _, kind := range open.EventKinds {
		domain, ok := ingressEventKind(kind)
		if !ok {
			return status.Errorf(codes.FailedPrecondition, "unsupported ingress event kind %s", kind)
		}
		allowedKinds[domain] = struct{}{}
	}
	if len(allowedKinds) == 0 {
		return status.Error(codes.FailedPrecondition, "producer profile has no event kinds")
	}
	if s.ingress.authorize != nil && !s.ingress.authorize(open) {
		return status.Error(codes.PermissionDenied, "event producer or relay is not registered")
	}
	if err := stream.Send(&eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: s.ingress.profile}); err != nil {
		return err
	}
	key := ingressKey(open.SourceNodeId, open.ProducerSessionId)
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := msg.GetBatch()
		if batch == nil {
			return status.Error(codes.InvalidArgument, "producer session is already open")
		}
		if s.ingress.authorize != nil && !s.ingress.authorize(open) {
			return status.Error(codes.PermissionDenied, "event producer or relay registration no longer authorizes this session")
		}
		ctrl, err := s.ingress.admit(stream.Context(), key, open, allowedKinds, batch)
		if err != nil {
			return err
		}
		if err := stream.Send(ctrl); err != nil {
			return err
		}
	}
}

func (i *eventIngress) admit(_ context.Context, key ingressSessionKey, open *eventsv1.EventIngressOpen, allowedKinds map[events.Kind]struct{}, batch *eventsv1.ProtocolEventBatch) (*eventsv1.EventIngressControl, error) {
	if proto.Size(batch) > i.maxBatchBytes {
		return nil, status.Error(codes.ResourceExhausted, "event batch exceeds processor ingress limit")
	}
	if batch.SourceNodeId != open.SourceNodeId || batch.ProducerSessionId != open.ProducerSessionId || batch.SemanticProfileRevision != open.SemanticProfileRevision {
		return nil, status.Error(codes.InvalidArgument, "event batch does not match the opened producer session")
	}
	decoded, _, err := protoadapter.DecodeBatch(batch)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid event batch: %v", err)
	}
	for _, event := range decoded {
		if len(allowedKinds) != 0 {
			if _, ok := allowedKinds[event.Kind()]; !ok {
				return nil, status.Errorf(codes.PermissionDenied, "event kind %s was not negotiated", event.Kind())
			}
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	state, knownSession := i.sessions[key]
	previousAdmittedEvent := state.event
	// Memory-only ingress deliberately loses its admitted high-water marks when
	// the processor restarts. The producer has already deleted cumulatively
	// ACKed batches, so a fresh processor must treat the first retained batch as
	// the new baseline. Otherwise it NACKs an unrecoverable prefix forever and
	// wedges the producer session. Once a session is known, normal gap detection
	// remains strict. Reliable ingress restores its baseline from the WAL.
	if !knownSession && i.wal == nil {
		if batch.BatchSequence > 0 {
			state.batch = batch.BatchSequence - 1
		}
		if batch.FirstEventSequence > 0 {
			state.event = batch.FirstEventSequence - 1
		}
	}
	if batch.BatchSequence <= state.batch {
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch, FlowControl: i.currentFlowControl()}, nil
	}
	for _, loss := range batch.GetStats().GetLosses() {
		for _, eventRange := range loss.GetEventSequenceRanges() {
			if eventRange.GetFirst() <= previousAdmittedEvent {
				return nil, status.Error(codes.InvalidArgument, "event loss range overlaps previously admitted event coverage")
			}
		}
	}
	eventGapFirst := state.event
	if eventGapFirst != ^uint64(0) {
		eventGapFirst++
	}
	hasEventGap := batch.FirstEventSequence > eventGapFirst
	gapLast := uint64(0)
	if hasEventGap {
		gapLast = batch.FirstEventSequence - 1
	} else if batch.FirstEventSequence == 0 {
		// A loss-only replacement may retire older unsent batches. Its exact
		// ranges are the proof that lets the receiver advance across that batch
		// gap without NACKing a sequence the sender has durably retired.
		gapLast = admittedEventHighWater(batch, state.event)
	}
	gapCovered := gapLast >= eventGapFirst && lossRangeCovered(batch.GetStats().GetLosses(), open.SourceNodeId, open.ProducerSessionId, eventGapFirst, gapLast)
	if batch.BatchSequence != state.batch+1 && !gapCovered {
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK, CumulativeAckSequence: state.batch, NackBatchRanges: []*eventsv1.SequenceRange{{First: state.batch + 1, Last: batch.BatchSequence - 1}}, FlowControl: i.currentFlowControl()}, nil
	}
	if batch.FirstEventSequence != 0 && batch.FirstEventSequence <= state.event {
		return nil, status.Error(codes.InvalidArgument, "event sequence overlaps previously admitted events")
	}
	if hasEventGap && !gapCovered {
		return nil, status.Error(codes.InvalidArgument, "event sequence leaves a gap after previously admitted events")
	}
	if i.wal != nil {
		if err := i.wal.append(batch); err != nil {
			return nil, status.Errorf(codes.ResourceExhausted, "recoverable event admission failed: %v", err)
		}
	}
	// Reliable admission is complete once the checksummed record is synced. A
	// retry must not append it again even if the volatile dispatcher is full.
	if i.wal != nil {
		state.batch = batch.BatchSequence
		state.event = admittedEventHighWater(batch, state.event)
		i.sessions[key] = state
		// Once a durable session has an undispatched batch, preserve ordering by
		// leaving subsequent batches in the WAL for recovery as well.
		delivered := i.delivered[key]
		if delivered.batch+1 == batch.BatchSequence && i.dispatcher.EnqueueBatch(decoded) {
			i.delivered[key] = state
		}
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch, FlowControl: i.currentFlowControl()}, nil
	}
	if !i.dispatcher.EnqueueBatch(decoded) {
		return nil, status.Error(codes.ResourceExhausted, "event ingress queue is full")
	}
	state.batch = batch.BatchSequence
	state.event = admittedEventHighWater(batch, state.event)
	i.sessions[key] = state
	return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch, FlowControl: i.currentFlowControl()}, nil
}

func admittedEventHighWater(batch *eventsv1.ProtocolEventBatch, current uint64) uint64 {
	high := max(current, batch.GetLastEventSequence())
	for _, loss := range batch.GetStats().GetLosses() {
		for _, r := range loss.GetEventSequenceRanges() {
			high = max(high, r.GetLast())
		}
	}
	return high
}

func lossRangeCovered(losses []*eventsv1.EventLoss, sourceNodeID, producerSessionID string, first, last uint64) bool {
	if first == 0 || last < first {
		return false
	}
	ranges := make([]*eventsv1.SequenceRange, 0)
	for _, loss := range losses {
		if loss.GetSourceNodeId() != sourceNodeID || loss.GetProducerSessionId() != producerSessionID {
			continue
		}
		for _, r := range loss.GetEventSequenceRanges() {
			ranges = append(ranges, r)
		}
	}
	sort.Slice(ranges, func(a, b int) bool { return ranges[a].GetFirst() < ranges[b].GetFirst() })
	next := first
	for _, r := range ranges {
		if r.GetFirst() > next || r.GetLast() < next {
			continue
		}
		if r.GetLast() >= last {
			return true
		}
		next = r.GetLast() + 1
	}
	return false
}

func ingressEventKind(kind eventsv1.EventKind) (events.Kind, bool) {
	switch kind {
	case eventsv1.EventKind_EVENT_KIND_CONN:
		return events.KindConn, true
	case eventsv1.EventKind_EVENT_KIND_DNS:
		return events.KindDNS, true
	case eventsv1.EventKind_EVENT_KIND_TLS:
		return events.KindTLS, true
	case eventsv1.EventKind_EVENT_KIND_HTTP:
		return events.KindHTTP, true
	case eventsv1.EventKind_EVENT_KIND_SMTP:
		return events.KindSMTP, true
	case eventsv1.EventKind_EVENT_KIND_RADIUS:
		return events.KindRADIUS, true
	case eventsv1.EventKind_EVENT_KIND_FILE_METADATA:
		return events.KindFileMetadata, true
	default:
		return "", false
	}
}

func (i *eventIngress) currentFlowControl() int32 {
	if i.flowControl == nil {
		return 0
	}
	return i.flowControl()
}

func (i *eventIngress) recover() error {
	if i == nil || i.wal == nil {
		return nil
	}
	checkpoint, err := i.wal.loadCheckpoint()
	if err != nil {
		return err
	}
	i.sessions = checkpoint
	i.delivered = make(map[ingressSessionKey]ingressSession, len(checkpoint))
	for key, state := range checkpoint {
		i.delivered[key] = state
	}
	return i.wal.replay(func(batch *eventsv1.ProtocolEventBatch) error {
		decoded, _, err := protoadapter.DecodeBatch(batch)
		if err != nil {
			return fmt.Errorf("decode recovered event batch: %w", err)
		}
		key := ingressKey(batch.SourceNodeId, batch.ProducerSessionId)
		if state := i.sessions[key]; batch.BatchSequence <= state.batch {
			return nil
		}
		if !i.dispatcher.EnqueueBatch(decoded) {
			return errors.New("event queue full during WAL recovery")
		}
		i.mu.Lock()
		state := i.sessions[key]
		if batch.BatchSequence > state.batch {
			state.batch = batch.BatchSequence
			state.event = admittedEventHighWater(batch, state.event)
			i.sessions[key] = state
			i.delivered[key] = state
		}
		i.mu.Unlock()
		return nil
	})
}

type eventWAL struct {
	mu       sync.Mutex
	file     *os.File
	maxBytes int64
	// maxRecordBytes mirrors the configured ingress batch limit so every
	// batch accepted before a crash is also valid during recovery.
	maxRecordBytes int
	size           int64
	dir            string
}

func openEventWAL(dir string, max int64) (*eventWAL, error) {
	if max <= 0 {
		max = 1 << 30
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create event ingress WAL directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "processor-events.wal"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open event ingress WAL: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &eventWAL{file: f, maxBytes: max, maxRecordBytes: defaultIngressMaxBatchBytes, size: info.Size(), dir: dir}, nil
}

func (w *eventWAL) checkpoint(sessions map[ingressSessionKey]ingressSession) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	durable := durableIngressCheckpoint{Version: 1, Sessions: make([]durableIngressSession, 0, len(sessions))}
	for key, state := range sessions {
		durable.Sessions = append(durable.Sessions, durableIngressSession{SourceNodeID: key.sourceNodeID, ProducerSessionID: key.producerSessionID, Batch: state.batch, Event: state.event})
	}
	sort.Slice(durable.Sessions, func(a, b int) bool {
		if durable.Sessions[a].SourceNodeID == durable.Sessions[b].SourceNodeID {
			return durable.Sessions[a].ProducerSessionID < durable.Sessions[b].ProducerSessionID
		}
		return durable.Sessions[a].SourceNodeID < durable.Sessions[b].SourceNodeID
	})
	payload, err := json.Marshal(durable)
	if err != nil {
		return fmt.Errorf("marshal event ingress checkpoint: %w", err)
	}
	tmp, err := os.CreateTemp(w.dir, ".event-ingress-checkpoint-*")
	if err != nil {
		return fmt.Errorf("create event ingress checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(payload); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write event ingress checkpoint: %w", err)
	}
	if err = os.Rename(tmpName, filepath.Join(w.dir, "processor-events.checkpoint")); err != nil {
		return fmt.Errorf("publish event ingress checkpoint: %w", err)
	}
	return syncIngressDirectory(w.dir)
}

func (w *eventWAL) loadCheckpoint() (map[ingressSessionKey]ingressSession, error) {
	path := filepath.Join(w.dir, "processor-events.checkpoint")
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[ingressSessionKey]ingressSession), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read event ingress checkpoint: %w", err)
	}
	var durable durableIngressCheckpoint
	if err := json.Unmarshal(payload, &durable); err != nil {
		return nil, fmt.Errorf("decode event ingress checkpoint: %w", err)
	}
	if durable.Version == 0 {
		return loadLegacyIngressCheckpoint(payload)
	}
	if durable.Version != 1 {
		return nil, fmt.Errorf("decode event ingress checkpoint: unsupported version %d", durable.Version)
	}
	result := make(map[ingressSessionKey]ingressSession, len(durable.Sessions))
	for _, state := range durable.Sessions {
		key := ingressKey(state.SourceNodeID, state.ProducerSessionID)
		if key.sourceNodeID == "" || key.producerSessionID == "" {
			return nil, errors.New("decode event ingress checkpoint: session identity is required")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("decode event ingress checkpoint: duplicate session identity")
		}
		result[key] = ingressSession{batch: state.Batch, event: state.Event}
	}
	return result, nil
}

func loadLegacyIngressCheckpoint(payload []byte) (map[ingressSessionKey]ingressSession, error) {
	legacy := make(map[string]durableIngressSession)
	if err := json.Unmarshal(payload, &legacy); err != nil {
		return nil, fmt.Errorf("decode legacy event ingress checkpoint: %w", err)
	}
	result := make(map[ingressSessionKey]ingressSession, len(legacy))
	for encoded, state := range legacy {
		parts := strings.SplitN(encoded, "\x00", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, errors.New("decode legacy event ingress checkpoint: invalid session identity")
		}
		result[ingressKey(parts[0], parts[1])] = ingressSession{batch: state.Batch, event: state.Event}
	}
	return result, nil
}

type durableIngressCheckpoint struct {
	Version  uint32                  `json:"version"`
	Sessions []durableIngressSession `json:"sessions"`
}

type durableIngressSession struct {
	SourceNodeID      string `json:"source_node_id"`
	ProducerSessionID string `json:"producer_session_id"`
	Batch             uint64 `json:"batch"`
	Event             uint64 `json:"event"`
}

func syncIngressDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (w *eventWAL) append(batch *eventsv1.ProtocolEventBatch) error {
	payload, err := proto.Marshal(batch)
	if err != nil {
		return err
	}
	recordSize := int64(8 + len(payload))
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+recordSize > w.maxBytes {
		return fmt.Errorf("WAL byte limit exceeded")
	}
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[4:], crc32.ChecksumIEEE(payload))
	if _, err = w.file.Write(header[:]); err == nil {
		_, err = w.file.Write(payload)
	}
	if err != nil {
		return errors.Join(err, w.rollbackAppend())
	}
	if err = w.file.Sync(); err != nil {
		return errors.Join(err, w.rollbackAppend())
	}
	w.size += recordSize
	return nil
}

func (w *eventWAL) rollbackAppend() error {
	if err := w.file.Truncate(w.size); err != nil {
		return fmt.Errorf("truncate failed WAL append: %w", err)
	}
	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek after failed WAL append: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync failed WAL rollback: %w", err)
	}
	return nil
}

func (w *eventWAL) replay(fn func(*eventsv1.ProtocolEventBatch) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReader(w.file)
	var validSize int64
	for {
		var h [8]byte
		_, err := io.ReadFull(r, h[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			if err = w.truncateTornTail(validSize); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return fmt.Errorf("read WAL header: %w", err)
		}
		n := binary.BigEndian.Uint32(h[:4])
		if n == 0 || uint64(n) > uint64(w.maxRecordBytes) {
			return errors.New("invalid WAL record length")
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(r, b); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if err = w.truncateTornTail(validSize); err != nil {
					return err
				}
				break
			}
			return err
		}
		if crc32.ChecksumIEEE(b) != binary.BigEndian.Uint32(h[4:]) {
			return errors.New("event ingress WAL checksum mismatch")
		}
		batch := new(eventsv1.ProtocolEventBatch)
		if err = proto.Unmarshal(b, batch); err != nil {
			return err
		}
		if err = fn(batch); err != nil {
			return err
		}
		validSize += int64(len(h) + len(b))
	}
	_, err := w.file.Seek(0, io.SeekEnd)
	return err
}

func (w *eventWAL) truncateTornTail(validSize int64) error {
	if err := w.file.Truncate(validSize); err != nil {
		return fmt.Errorf("truncate torn event ingress WAL tail: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync truncated event ingress WAL: %w", err)
	}
	w.size = validSize
	return nil
}
func (w *eventWAL) close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

func (w *eventWAL) reset() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.file.Truncate(0); err != nil {
		return err
	}
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	w.size = 0
	return nil
}
