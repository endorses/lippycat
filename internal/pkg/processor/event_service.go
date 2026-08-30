//go:build processor || tap || all

package processor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	EventSubscriptionVersion        = 1
	defaultEventSubscriberQueueSize = 256
	defaultEventMaxBatchEvents      = 128
	defaultEventMaxMessageBytes     = 4 << 20
	minimumEventMaxMessageBytes     = 1024
	eventLossReportInterval         = 100 * time.Millisecond
)

// EventSubscriptionPolicy is the processor-side authorization and resource
// policy for normalized event subscriptions. File content is never eligible.
type EventSubscriptionPolicy struct {
	ProcessorNodeID      string
	QueueSize            int
	MaxBatchEvents       uint32
	MaxMessageBytes      uint32
	AllowSensitiveFields bool
	AllowFileMetadata    bool
	subscriptionLimit    *subscriptionLimiter
}

type subscriptionLimiter struct {
	mu     sync.Mutex
	active int
	max    int
}

func newSubscriptionLimiter(max int) *subscriptionLimiter { return &subscriptionLimiter{max: max} }

func (l *subscriptionLimiter) acquire() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.active >= l.max {
		return false
	}
	l.active++
	return true
}

func (l *subscriptionLimiter) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.active--
	l.mu.Unlock()
}

// EventService serves the live-only v1 normalized event subscription API.
type EventService struct {
	eventsv1.UnimplementedEventServiceServer
	broadcaster *broadcast.Broadcaster
	policy      EventSubscriptionPolicy
}

func NewEventService(broadcaster *broadcast.Broadcaster, policy EventSubscriptionPolicy) (*EventService, error) {
	if broadcaster == nil {
		return nil, errors.New("event broadcaster is required")
	}
	if policy.QueueSize <= 0 {
		policy.QueueSize = defaultEventSubscriberQueueSize
	}
	if policy.MaxBatchEvents == 0 || policy.MaxBatchEvents > protoadapter.MaxBatchEvents {
		policy.MaxBatchEvents = defaultEventMaxBatchEvents
	}
	if policy.MaxMessageBytes == 0 {
		policy.MaxMessageBytes = defaultEventMaxMessageBytes
	}
	return &EventService{broadcaster: broadcaster, policy: policy}, nil
}

func (s *EventService) SubscribeEvents(req *eventsv1.EventSubscribeRequest, stream eventsv1.EventService_SubscribeEventsServer) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "event subscription request is required")
	}
	if req.SubscriptionVersion != EventSubscriptionVersion {
		return status.Errorf(codes.FailedPrecondition, "unsupported event subscription version %d (supported: %d)", req.SubscriptionVersion, EventSubscriptionVersion)
	}
	if req.IncludeSensitiveFields && !s.policy.AllowSensitiveFields {
		return status.Error(codes.PermissionDenied, "sensitive event fields are not authorized")
	}
	if req.IncludeFileMetadata && !s.policy.AllowFileMetadata {
		return status.Error(codes.PermissionDenied, "file metadata events are not authorized")
	}
	if err := validateEventSelectors("node_ids", req.NodeIds); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validateEventSelectors("processor_node_ids", req.ProcessorNodeIds); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if len(req.PreviousStreamId) > protoadapter.MaxStringBytes {
		return status.Errorf(codes.InvalidArgument, "previous_stream_id exceeds %d bytes", protoadapter.MaxStringBytes)
	}
	if len(req.EventKinds) > protoadapter.MaxCollectionEntries {
		return status.Errorf(codes.InvalidArgument, "event_kinds exceeds %d entries", protoadapter.MaxCollectionEntries)
	}
	kinds, err := requestedEventKinds(req.EventKinds, req.IncludeFileMetadata)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	maxBatchEvents := req.MaxBatchEvents
	if maxBatchEvents == 0 || maxBatchEvents > s.policy.MaxBatchEvents {
		maxBatchEvents = s.policy.MaxBatchEvents
	}
	maxMessageBytes := req.MaxMessageBytes
	if maxMessageBytes == 0 || maxMessageBytes > s.policy.MaxMessageBytes {
		maxMessageBytes = s.policy.MaxMessageBytes
	}
	if maxMessageBytes < minimumEventMaxMessageBytes {
		return status.Errorf(codes.InvalidArgument, "max_message_bytes must be at least %d", minimumEventMaxMessageBytes)
	}
	if !s.policy.subscriptionLimit.acquire() {
		return status.Error(codes.ResourceExhausted, "maximum number of subscribers reached")
	}
	defer s.policy.subscriptionLimit.release()

	project := safeEventProjector(req.IncludeSensitiveFields, req.IncludeFileMetadata)
	sub, err := s.broadcaster.Subscribe(broadcast.Options{
		QueueSize: s.policy.QueueSize, Kinds: kinds, NodeIDs: req.NodeIds,
		ProcessorNodeIDs: req.ProcessorNodeIds, Project: project,
	})
	if err != nil {
		return status.Errorf(codes.Unavailable, "subscribe to processor events: %v", err)
	}
	defer sub.Close()
	liveBoundary := timestamppb.New(sub.AdmittedAt())

	streamID, err := newEventStreamID()
	if err != nil {
		return status.Errorf(codes.Internal, "create event stream ID: %v", err)
	}
	deliverySequence := uint64(1)
	started := &eventsv1.EventSubscriptionControl{
		Kind:     eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED,
		StreamId: streamID, LiveBoundary: liveBoundary, DeliverySequence: deliverySequence,
		SupportedEventKinds: supportedEventKinds(s.policy.AllowFileMetadata),
	}
	if err := sendEventMessage(stream, controlMessage(deliverySequence, started), maxMessageBytes); err != nil {
		return err
	}
	if req.PreviousStreamId != "" {
		deliverySequence++
		gap := &eventsv1.EventSubscriptionControl{
			Kind:     eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP,
			StreamId: streamID, DeliverySequence: deliverySequence,
			Losses:                   []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_RECONNECT, SourceNodeId: s.policy.ProcessorNodeID}},
			PreviousStreamId:         req.PreviousStreamId,
			PreviousDeliverySequence: req.PreviousDeliverySequence,
		}
		// The prior stream ID is diagnostic metadata. Keep the mandatory,
		// explicit reconnect loss report even when that metadata cannot fit the
		// subscriber's negotiated receive limit.
		if proto.Size(controlMessage(deliverySequence, gap)) > int(maxMessageBytes) {
			gap.PreviousStreamId = ""
		}
		if proto.Size(controlMessage(deliverySequence, gap)) > int(maxMessageBytes) {
			gap.Losses[0].SourceNodeId = ""
		}
		if err := sendEventMessage(stream, controlMessage(deliverySequence, gap), maxMessageBytes); err != nil {
			return err
		}
	}

	batchSequence := uint64(0)
	var pending events.Event
	lossTicker := time.NewTicker(eventLossReportInterval)
	defer lossTicker.Stop()
	for {
		if pending != nil {
			losses := sub.ConsumeLosses()
			if len(losses) > 0 {
				deliverySequence, err = sendLossGaps(stream, streamID, deliverySequence, subscriberLosses(losses), maxMessageBytes)
				if err != nil {
					return err
				}
			}
			event := pending
			pending = nil
			deliverySequence, batchSequence, pending, err = s.sendEventBatch(stream, sub, event, maxBatchEvents, maxMessageBytes, streamID, deliverySequence, batchSequence)
			if err != nil {
				return err
			}
			continue
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-lossTicker.C:
			losses := sub.ConsumeLosses()
			if len(losses) == 0 {
				continue
			}
			deliverySequence, err = sendLossGaps(stream, streamID, deliverySequence, subscriberLosses(losses), maxMessageBytes)
			if err != nil {
				return err
			}
		case event, ok := <-sub.Events():
			if !ok {
				return nil
			}
			deliverySequence, batchSequence, pending, err = s.sendEventBatch(stream, sub, event, maxBatchEvents, maxMessageBytes, streamID, deliverySequence, batchSequence)
			if err != nil {
				return err
			}
		}
	}
}

func sendLossGaps(stream eventsv1.EventService_SubscribeEventsServer, streamID string, deliverySequence uint64, losses []*eventsv1.EventLoss, maxMessageBytes uint32) (uint64, error) {
	for len(losses) > 0 {
		count := 1
		for count <= len(losses) {
			sequence := deliverySequence + 1
			gap := &eventsv1.EventSubscriptionControl{
				Kind:             eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP,
				StreamId:         streamID,
				DeliverySequence: sequence,
				Losses:           losses[:count],
			}
			if proto.Size(controlMessage(sequence, gap)) > int(maxMessageBytes) {
				break
			}
			count++
		}
		count--
		if count == 0 {
			// Preserve an explicit loss count even when one detailed record cannot
			// fit the subscriber's negotiated receive limit.
			losses[0] = &eventsv1.EventLoss{Kind: losses[0].Kind, Count: losses[0].Count}
			continue
		}
		deliverySequence++
		gap := &eventsv1.EventSubscriptionControl{
			Kind:             eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP,
			StreamId:         streamID,
			DeliverySequence: deliverySequence,
			Losses:           losses[:count],
		}
		if err := sendEventMessage(stream, controlMessage(deliverySequence, gap), maxMessageBytes); err != nil {
			return deliverySequence, err
		}
		losses = losses[count:]
	}
	return deliverySequence, nil
}

func validateEventSelectors(name string, values []string) error {
	if len(values) > protoadapter.MaxCollectionEntries {
		return fmt.Errorf("%s exceeds %d entries", name, protoadapter.MaxCollectionEntries)
	}
	for index, value := range values {
		if value == "" {
			return fmt.Errorf("%s[%d] is empty", name, index)
		}
		if len(value) > protoadapter.MaxStringBytes {
			return fmt.Errorf("%s[%d] exceeds %d bytes", name, index, protoadapter.MaxStringBytes)
		}
	}
	return nil
}

func (s *EventService) sendEventBatch(stream eventsv1.EventService_SubscribeEventsServer, sub *broadcast.Subscription, first events.Event, maxBatchEvents, maxMessageBytes uint32, streamID string, deliverySequence, batchSequence uint64) (uint64, uint64, events.Event, error) {
	batchEvents := []events.Event{first}
	var pending events.Event
drain:
	for uint32(len(batchEvents)) < maxBatchEvents {
		select {
		case next, ok := <-sub.Events():
			if !ok {
				break drain
			}
			firstEnvelope, nextEnvelope := first.Envelope(), next.Envelope()
			if nextEnvelope.NodeID != firstEnvelope.NodeID || nextEnvelope.ProducerSessionID != firstEnvelope.ProducerSessionID {
				pending = next
				break drain
			}
			previousEnvelope := batchEvents[len(batchEvents)-1].Envelope()
			if nextEnvelope.EventSequence != previousEnvelope.EventSequence+1 {
				pending = next
				break drain
			}
			candidate := append(append([]events.Event(nil), batchEvents...), next)
			wire, err := protoadapter.ToProtoBatch(firstEnvelope.NodeID, firstEnvelope.ProducerSessionID, batchSequence+1, candidate, nil, 1)
			if err != nil {
				return deliverySequence, batchSequence, pending, status.Errorf(codes.Internal, "encode subscribed event batch: %v", err)
			}
			candidateMessage := &eventsv1.EventSubscriptionMessage{DeliverySequence: deliverySequence + 1, Message: &eventsv1.EventSubscriptionMessage_Batch{Batch: wire}}
			if proto.Size(candidateMessage) > int(maxMessageBytes) {
				pending = next
				break drain
			}
			batchEvents = append(batchEvents, next)
		default:
			break drain
		}
	}
	batchSequence++
	batch, err := protoadapter.ToProtoBatch(first.Envelope().NodeID, first.Envelope().ProducerSessionID, batchSequence, batchEvents, nil, 1)
	if err != nil {
		return deliverySequence, batchSequence, pending, status.Errorf(codes.Internal, "encode subscribed event: %v", err)
	}
	message := &eventsv1.EventSubscriptionMessage{DeliverySequence: deliverySequence + 1, Message: &eventsv1.EventSubscriptionMessage_Batch{Batch: batch}}
	if proto.Size(message) <= int(maxMessageBytes) {
		deliverySequence++
		return deliverySequence, batchSequence, pending, sendEventMessage(stream, message, maxMessageBytes)
	}
	loss := &eventsv1.EventLoss{
		Kind:              eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION,
		Count:             uint64(len(batchEvents)),
		SourceNodeId:      first.Envelope().NodeID,
		ProducerSessionId: first.Envelope().ProducerSessionID,
	}
	for _, event := range batchEvents {
		sequence := event.Envelope().EventSequence
		loss.EventSequenceRanges = append(loss.EventSequenceRanges, &eventsv1.SequenceRange{First: sequence, Last: sequence})
	}
	deliverySequence, err = sendLossGaps(stream, streamID, deliverySequence, []*eventsv1.EventLoss{loss}, maxMessageBytes)
	return deliverySequence, batchSequence, pending, err
}

func sendEventMessage(stream eventsv1.EventService_SubscribeEventsServer, message *eventsv1.EventSubscriptionMessage, maxMessageBytes uint32) error {
	if proto.Size(message) > int(maxMessageBytes) {
		return status.Errorf(codes.ResourceExhausted, "event subscription message exceeds max_message_bytes (%d)", maxMessageBytes)
	}
	return stream.Send(message)
}

func controlMessage(sequence uint64, control *eventsv1.EventSubscriptionControl) *eventsv1.EventSubscriptionMessage {
	return &eventsv1.EventSubscriptionMessage{DeliverySequence: sequence, Message: &eventsv1.EventSubscriptionMessage_Control{Control: control}}
}

func requestedEventKinds(input []eventsv1.EventKind, includeFileMetadata bool) ([]events.Kind, error) {
	if len(input) == 0 {
		kinds := []events.Kind{events.KindConn, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP}
		if includeFileMetadata {
			kinds = append(kinds, events.KindFileMetadata)
		}
		return kinds, nil
	}
	kinds := make([]events.Kind, 0, len(input))
	for _, kind := range input {
		var mapped events.Kind
		switch kind {
		case eventsv1.EventKind_EVENT_KIND_CONN:
			mapped = events.KindConn
		case eventsv1.EventKind_EVENT_KIND_DNS:
			mapped = events.KindDNS
		case eventsv1.EventKind_EVENT_KIND_TLS:
			mapped = events.KindTLS
		case eventsv1.EventKind_EVENT_KIND_HTTP:
			mapped = events.KindHTTP
		case eventsv1.EventKind_EVENT_KIND_SMTP:
			mapped = events.KindSMTP
		case eventsv1.EventKind_EVENT_KIND_FILE_METADATA:
			if !includeFileMetadata {
				return nil, fmt.Errorf("file metadata kind requires include_file_metadata")
			}
			mapped = events.KindFileMetadata
		default:
			return nil, fmt.Errorf("unsupported event kind %s", kind)
		}
		kinds = append(kinds, mapped)
	}
	return kinds, nil
}

func supportedEventKinds(includeFileMetadata bool) []eventsv1.EventKind {
	kinds := []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_CONN, eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_TLS, eventsv1.EventKind_EVENT_KIND_HTTP, eventsv1.EventKind_EVENT_KIND_SMTP}
	if includeFileMetadata {
		kinds = append(kinds, eventsv1.EventKind_EVENT_KIND_FILE_METADATA)
	}
	return kinds
}

func subscriberLosses(losses []broadcast.Loss) []*eventsv1.EventLoss {
	result := make([]*eventsv1.EventLoss, 0, len(losses))
	for _, loss := range losses {
		kind := eventsv1.LossKind_LOSS_KIND_SUBSCRIBER
		if loss.Cause == broadcast.LossCauseDispatcherOverflow {
			kind = eventsv1.LossKind_LOSS_KIND_DISPATCH
		}
		wire := &eventsv1.EventLoss{Kind: kind, Count: loss.Count, SourceNodeId: loss.SourceNodeID, ProducerSessionId: loss.ProducerSessionID}
		for _, sequenceRange := range loss.Ranges {
			wire.EventSequenceRanges = append(wire.EventSequenceRanges, &eventsv1.SequenceRange{First: sequenceRange.First, Last: sequenceRange.Last})
		}
		result = append(result, wire)
	}
	return result
}

func safeEventProjector(includeSensitiveFields, includeFileMetadata bool) broadcast.Projector {
	return func(event events.Event) (events.Event, bool, error) {
		if event == nil || event.Kind() == events.KindFileContent {
			return nil, false, nil
		}
		if event.Kind() == events.KindFileMetadata && !includeFileMetadata {
			return nil, false, nil
		}
		if includeSensitiveFields {
			return event, true, nil
		}
		switch value := event.(type) {
		case events.HTTPEvent:
			value.Headers, value.Username = nil, ""
			value.RequestFilenames, value.ResponseFilenames = nil, nil
			value.URI, value.Referrer, value.Origin = "", "", ""
			return value, true, nil
		case *events.HTTPEvent:
			copy := *value
			copy.Headers, copy.Username = nil, ""
			copy.RequestFilenames, copy.ResponseFilenames = nil, nil
			copy.URI, copy.Referrer, copy.Origin = "", "", ""
			return copy, true, nil
		case events.SMTPEvent:
			value.MailFrom, value.Recipients, value.From, value.To, value.CC = "", nil, "", nil, nil
			value.ReplyTo, value.MessageID, value.InReplyTo, value.Subject = "", "", "", ""
			value.OriginatingIP, value.Received, value.Path = netip.Addr{}, nil, nil
			return value, true, nil
		case *events.SMTPEvent:
			copy := *value
			copy.MailFrom, copy.Recipients, copy.From, copy.To, copy.CC = "", nil, "", nil, nil
			copy.ReplyTo, copy.MessageID, copy.InReplyTo, copy.Subject = "", "", "", ""
			copy.OriginatingIP, copy.Received, copy.Path = netip.Addr{}, nil, nil
			return copy, true, nil
		case events.FileMetadataEvent:
			value.Filename, value.ExtractedPath = "", ""
			return value, true, nil
		case *events.FileMetadataEvent:
			copy := *value
			copy.Filename, copy.ExtractedPath = "", ""
			return copy, true, nil
		default:
			return event, true, nil
		}
	}
}

func newEventStreamID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
