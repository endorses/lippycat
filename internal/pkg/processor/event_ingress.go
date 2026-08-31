//go:build processor || tap || all

package processor

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const defaultIngressMaxBatchBytes = 4 << 20

type EventIngressPolicy struct {
	Dispatcher    *events.Dispatcher
	Profile       string
	WALDirectory  string
	WALMaxBytes   int64
	MaxBatchBytes int
}

type ingressSession struct{ batch, event uint64 }
type eventIngress struct {
	dispatcher    *events.Dispatcher
	profile       eventsv1.IngressProfile
	maxBatchBytes int
	wal           *eventWAL
	mu            sync.Mutex
	sessions      map[string]ingressSession
	authorize     func(string, string) bool
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
	i := &eventIngress{dispatcher: p.Dispatcher, profile: profile, maxBatchBytes: p.MaxBatchBytes, sessions: make(map[string]ingressSession)}
	if profile == eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE {
		if p.WALDirectory == "" {
			return nil, errors.New("reliable event ingress requires a WAL directory")
		}
		wal, err := openEventWAL(p.WALDirectory, p.WALMaxBytes)
		if err != nil {
			return nil, err
		}
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
	if s.ingress.authorize != nil && !s.ingress.authorize(open.SourceNodeId, open.RelayNodeId) {
		return status.Error(codes.PermissionDenied, "event producer or relay is not registered")
	}
	if err := stream.Send(&eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: s.ingress.profile}); err != nil {
		return err
	}
	key := open.SourceNodeId + "\x00" + open.ProducerSessionId
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := msg.GetBatch()
		if batch == nil {
			return status.Error(codes.InvalidArgument, "producer session is already open")
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

func (i *eventIngress) admit(_ context.Context, key string, open *eventsv1.EventIngressOpen, allowedKinds map[events.Kind]struct{}, batch *eventsv1.ProtocolEventBatch) (*eventsv1.EventIngressControl, error) {
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
	state := i.sessions[key]
	if batch.BatchSequence <= state.batch {
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch}, nil
	}
	if batch.BatchSequence != state.batch+1 {
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK, CumulativeAckSequence: state.batch, NackBatchRanges: []*eventsv1.SequenceRange{{First: state.batch + 1, Last: batch.BatchSequence - 1}}}, nil
	}
	if state.event != 0 && batch.LastEventSequence <= state.event {
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch}, nil
	}
	if state.event != 0 && batch.FirstEventSequence > state.event+1 {
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
		state.event = batch.LastEventSequence
		i.sessions[key] = state
		for _, event := range decoded {
			if !i.dispatcher.Enqueue(event) {
				// The durable record remains available for recovery. ACK still
				// reflects recoverable admission, independently of volatile pressure.
				break
			}
		}
		return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch, FlowControl: i.currentFlowControl()}, nil
	}
	if !i.dispatcher.EnqueueBatch(decoded) {
		return nil, status.Error(codes.ResourceExhausted, "event ingress queue is full")
	}
	state.batch = batch.BatchSequence
	state.event = batch.LastEventSequence
	i.sessions[key] = state
	return &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: state.batch, FlowControl: i.currentFlowControl()}, nil
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
	return i.wal.replay(func(batch *eventsv1.ProtocolEventBatch) error {
		decoded, _, err := protoadapter.DecodeBatch(batch)
		if err != nil {
			return fmt.Errorf("decode recovered event batch: %w", err)
		}
		key := batch.SourceNodeId + "\x00" + batch.ProducerSessionId
		if !i.dispatcher.EnqueueBatch(decoded) {
			return errors.New("event queue full during WAL recovery")
		}
		i.mu.Lock()
		state := i.sessions[key]
		if batch.BatchSequence > state.batch {
			state.batch = batch.BatchSequence
			if batch.LastEventSequence > state.event {
				state.event = batch.LastEventSequence
			}
			i.sessions[key] = state
		}
		i.mu.Unlock()
		return nil
	})
}

type eventWAL struct {
	mu       sync.Mutex
	file     *os.File
	maxBytes int64
	size     int64
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
	return &eventWAL{file: f, maxBytes: max, size: info.Size()}, nil
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
		return err
	}
	if err = w.file.Sync(); err != nil {
		return err
	}
	w.size += recordSize
	return nil
}
func (w *eventWAL) replay(fn func(*eventsv1.ProtocolEventBatch) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReader(w.file)
	for {
		var h [8]byte
		_, err := io.ReadFull(r, h[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read WAL header: %w", err)
		}
		n := binary.BigEndian.Uint32(h[:4])
		if n == 0 || int(n) > defaultIngressMaxBatchBytes {
			return errors.New("invalid WAL record length")
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(r, b); err != nil {
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
	}
	_, err := w.file.Seek(0, io.SeekEnd)
	return err
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
