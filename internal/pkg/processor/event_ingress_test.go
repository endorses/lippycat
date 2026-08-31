//go:build processor || tap || all

package processor

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ingressBatch(t *testing.T, batch, sequence uint64) *eventsv1.ProtocolEventBatch {
	t.Helper()
	producer, err := events.NewOfflineProducer("node-a", events.OfflineSession{InputIdentity: "fixture", AnalysisProfile: "profile-1", SourceOrdering: []string{"fixture"}})
	require.NoError(t, err)
	envelope := events.Envelope{Timestamp: time.Unix(1, 0), NodeID: "node-a", CaptureScope: events.CaptureScopeFull, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53}}
	ev := producer.Assign(events.NewDNSEvent(envelope))
	// Advance the deterministic producer when a later event sequence is needed.
	for ev.Envelope().EventSequence < sequence {
		ev = producer.Assign(events.NewDNSEvent(envelope))
	}
	wire, err := protoadapter.ToProtoBatch("node-a", ev.Envelope().ProducerSessionID, batch, []events.Event{ev}, nil, 1)
	require.NoError(t, err)
	return wire
}

func TestNegotiateEventForwardingRejectsAndExplicitlyFallsBack(t *testing.T) {
	bad := &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, EventApiMajors: []uint32{2}, SemanticProfileRevision: 1, EventKinds: []int32{1}, StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"}}
	_, _, _, _, _, err := negotiateEventForwarding(bad)
	require.Error(t, err)
	bad.AllowPacketFallback = true
	mode, _, _, _, notice, err := negotiateEventForwarding(bad)
	require.NoError(t, err)
	assert.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, mode)
	assert.Contains(t, notice, "explicit packet fallback")
}

func TestNegotiateEventForwardingRejectsInsufficientStatefulAnalysis(t *testing.T) {
	capabilities := &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, EventApiMajors: []uint32{1}, SemanticProfileRevision: 1, EventKinds: []int32{1}, StatefulAnalysisFeatures: []string{"tcp_reassembly"}}
	_, _, _, _, _, err := negotiateEventForwarding(capabilities)
	require.ErrorContains(t, err, "stateful features")
	capabilities.StatefulAnalysisFeatures = []string{"relay"}
	mode, _, _, _, _, err := negotiateEventForwarding(capabilities)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
}

func TestRegisterHunterAcceptsMixedPacketAndEventModes(t *testing.T) {
	p, err := New(Config{ProcessorID: "processor-a", ListenAddr: "127.0.0.1:0", MaxHunters: 2})
	require.NoError(t, err)

	packetResponse, err := p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "packet-hunter",
		EventForwarding: &management.EventForwardingCapabilities{
			RequestedMode: management.ForwardingMode_FORWARDING_MODE_PACKETS,
		},
	})
	require.NoError(t, err)
	require.True(t, packetResponse.GetAccepted())
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, packetResponse.GetAcceptedForwardingMode())

	eventResponse, err := p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "event-hunter",
		EventForwarding: &management.EventForwardingCapabilities{
			RequestedMode:            management.ForwardingMode_FORWARDING_MODE_EVENTS,
			EventApiMajors:           []uint32{1},
			EventKinds:               []int32{1, 2, 3, 4, 5, 6},
			SemanticProfileRevision:  1,
			StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"},
		},
	})
	require.NoError(t, err)
	require.True(t, eventResponse.GetAccepted())
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, eventResponse.GetAcceptedForwardingMode())

	require.Len(t, p.hunterManager.GetAll(""), 2)
}

func eventForwardingCapabilities(kinds ...int32) *management.EventForwardingCapabilities {
	return &management.EventForwardingCapabilities{
		RequestedMode:            management.ForwardingMode_FORWARDING_MODE_EVENTS,
		EventApiMajors:           []uint32{1},
		EventKinds:               kinds,
		SemanticProfileRevision:  1,
		StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"},
	}
}

func eventIngressOpen(nodeID string, kinds ...eventsv1.EventKind) *eventsv1.EventIngressOpen {
	return &eventsv1.EventIngressOpen{
		SourceNodeId:            nodeID,
		ProducerSessionId:       "session-a",
		EventApiMajor:           1,
		SemanticProfileRevision: 1,
		EventKinds:              kinds,
	}
}

func TestEventIngressAuthorizationRejectsPacketAndFallbackRegistrations(t *testing.T) {
	p, err := New(Config{ProcessorID: "processor-a", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)

	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "packet-hunter",
		EventForwarding: &management.EventForwardingCapabilities{
			RequestedMode: management.ForwardingMode_FORWARDING_MODE_PACKETS,
		},
	})
	require.NoError(t, err)
	require.False(t, p.eventIngress.authorize(eventIngressOpen("packet-hunter", eventsv1.EventKind_EVENT_KIND_DNS)))

	fallback := eventForwardingCapabilities(int32(eventsv1.EventKind_EVENT_KIND_DNS))
	fallback.EventApiMajors = []uint32{2}
	fallback.AllowPacketFallback = true
	response, err := p.RegisterHunter(context.Background(), &management.HunterRegistration{HunterId: "fallback-hunter", EventForwarding: fallback})
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.AcceptedForwardingMode)
	require.False(t, p.eventIngress.authorize(eventIngressOpen("fallback-hunter", eventsv1.EventKind_EVENT_KIND_DNS)))
}

func TestEventIngressAuthorizationEnforcesAcceptedKinds(t *testing.T) {
	p, err := New(Config{ProcessorID: "processor-a", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId:        "event-hunter",
		EventForwarding: eventForwardingCapabilities(int32(eventsv1.EventKind_EVENT_KIND_DNS)),
	})
	require.NoError(t, err)

	require.True(t, p.eventIngress.authorize(eventIngressOpen("event-hunter", eventsv1.EventKind_EVENT_KIND_DNS)))
	require.False(t, p.eventIngress.authorize(eventIngressOpen("event-hunter", eventsv1.EventKind_EVENT_KIND_HTTP)))
	require.False(t, p.eventIngress.authorize(eventIngressOpen("event-hunter", eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_HTTP)))
}

func TestEventIngressAuthorizationUsesLatestRegistration(t *testing.T) {
	p, err := New(Config{ProcessorID: "processor-a", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId:        "hunter-a",
		EventForwarding: eventForwardingCapabilities(int32(eventsv1.EventKind_EVENT_KIND_DNS)),
	})
	require.NoError(t, err)
	open := eventIngressOpen("hunter-a", eventsv1.EventKind_EVENT_KIND_DNS)
	require.True(t, p.eventIngress.authorize(open))

	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{
		HunterId: "hunter-a",
		EventForwarding: &management.EventForwardingCapabilities{
			RequestedMode: management.ForwardingMode_FORWARDING_MODE_PACKETS,
		},
	})
	require.NoError(t, err)
	require.False(t, p.eventIngress.authorize(open))
}

func TestEventIngressDeduplicatesAndNACKsGaps(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 8})
	require.NoError(t, err)
	broadcaster := broadcast.New()
	require.NoError(t, d.Register(broadcaster))
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "memory_only"})
	require.NoError(t, err)
	b := ingressBatch(t, 1, 1)
	open := &eventsv1.EventIngressOpen{SourceNodeId: b.SourceNodeId, ProducerSessionId: b.ProducerSessionId, SemanticProfileRevision: 1}
	ack, err := i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, b)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ack.CumulativeAckSequence)
	ack, err = i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, b)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ack.CumulativeAckSequence)
	i.flowControl = func() int32 { return int32(data.FlowControl_FLOW_PAUSE) }
	ack, err = i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, b)
	require.NoError(t, err)
	assert.Equal(t, int32(data.FlowControl_FLOW_PAUSE), ack.FlowControl)
	gap := ingressBatch(t, 3, 2)
	ctrl, err := i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, gap)
	require.NoError(t, err)
	assert.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK, ctrl.Kind)
	assert.Equal(t, uint64(2), ctrl.NackBatchRanges[0].First)
	assert.Equal(t, int32(data.FlowControl_FLOW_PAUSE), ctrl.FlowControl)
}

func TestEventIngressAcceptsExplicitlyReportedSpoolGap(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 8})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "memory_only"})
	require.NoError(t, err)
	b := ingressBatch(t, 2, 2)
	b.Stats = &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: b.SourceNodeId, ProducerSessionId: b.ProducerSessionId, EventSequenceRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}}}}}
	open := &eventsv1.EventIngressOpen{SourceNodeId: b.SourceNodeId, ProducerSessionId: b.ProducerSessionId, SemanticProfileRevision: 1}
	ack, err := i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, b)
	require.NoError(t, err)
	require.Equal(t, uint64(2), ack.CumulativeAckSequence)
}

func TestEventIngressLossOnlyBatchAdvancesEventHighWater(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 8})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "memory_only"})
	require.NoError(t, err)
	next := ingressBatch(t, 2, 2)
	lossOnly := &eventsv1.ProtocolEventBatch{SourceNodeId: next.SourceNodeId, ProducerSessionId: next.ProducerSessionId, BatchSequence: 1, SemanticProfileRevision: 1, Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 1, SourceNodeId: next.SourceNodeId, ProducerSessionId: next.ProducerSessionId, EventSequenceRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}}}}}}
	open := &eventsv1.EventIngressOpen{SourceNodeId: next.SourceNodeId, ProducerSessionId: next.ProducerSessionId, SemanticProfileRevision: 1}
	key := next.SourceNodeId + "\x00" + next.ProducerSessionId
	ack, err := i.admit(context.Background(), key, open, nil, lossOnly)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ack.CumulativeAckSequence)
	ack, err = i.admit(context.Background(), key, open, nil, next)
	require.NoError(t, err)
	require.Equal(t, uint64(2), ack.CumulativeAckSequence)
}

func TestEventIngressRejectsPartialCrossBatchOverlap(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 8})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "memory_only"})
	require.NoError(t, err)
	first := ingressBatch(t, 1, 1)
	open := &eventsv1.EventIngressOpen{SourceNodeId: first.SourceNodeId, ProducerSessionId: first.ProducerSessionId, SemanticProfileRevision: 1}
	_, err = i.admit(context.Background(), first.SourceNodeId+"\x00"+first.ProducerSessionId, open, nil, first)
	require.NoError(t, err)
	overlap := ingressBatch(t, 2, 2)
	overlap.Events = append([]*eventsv1.ProtocolEvent{first.Events[0]}, overlap.Events...)
	overlap.FirstEventSequence = 1
	require.ErrorContains(t, func() error {
		_, admitErr := i.admit(context.Background(), first.SourceNodeId+"\x00"+first.ProducerSessionId, open, nil, overlap)
		return admitErr
	}(), "overlaps")
}

func TestReliableEventIngressWALSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	wal, err := openEventWAL(dir, 1<<20)
	require.NoError(t, err)
	b := ingressBatch(t, 1, 1)
	require.NoError(t, wal.append(b))
	require.NoError(t, wal.close())
	reopened, err := openEventWAL(dir, 1<<20)
	require.NoError(t, err)
	defer reopened.close()
	count := 0
	require.NoError(t, reopened.replay(func(got *eventsv1.ProtocolEventBatch) error {
		count++
		assert.Equal(t, b.SourceNodeId, got.SourceNodeId)
		return nil
	}))
	assert.Equal(t, 1, count)
}

func TestEventWALReplayTruncatesTornFinalRecord(t *testing.T) {
	for _, test := range []struct {
		name string
		tail []byte
	}{
		{name: "partial header", tail: []byte{0, 0, 0}},
		{name: "partial payload", tail: []byte{0, 0, 0, 10, 0, 0, 0, 0, 1, 2, 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			wal, err := openEventWAL(dir, 1<<20)
			require.NoError(t, err)
			require.NoError(t, wal.append(ingressBatch(t, 1, 1)))
			validSize := wal.size
			_, err = wal.file.Write(test.tail)
			require.NoError(t, err)
			require.NoError(t, wal.file.Sync())
			require.NoError(t, wal.close())

			reopened, err := openEventWAL(dir, 1<<20)
			require.NoError(t, err)
			count := 0
			require.NoError(t, reopened.replay(func(*eventsv1.ProtocolEventBatch) error {
				count++
				return nil
			}))
			require.Equal(t, 1, count)
			require.Equal(t, validSize, reopened.size)
			info, err := reopened.file.Stat()
			require.NoError(t, err)
			require.Equal(t, validSize, info.Size())
			require.NoError(t, reopened.close())
		})
	}
}

func TestReliableEventIngressDispatchesAfterDurableAdmission(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 8})
	require.NoError(t, err)
	broadcaster := broadcast.New()
	require.NoError(t, d.Register(broadcaster))
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "reliable", WALDirectory: t.TempDir()})
	require.NoError(t, err)
	defer i.wal.close()
	b := ingressBatch(t, 1, 1)
	open := &eventsv1.EventIngressOpen{SourceNodeId: b.SourceNodeId, ProducerSessionId: b.ProducerSessionId, SemanticProfileRevision: 1}
	ack, err := i.admit(context.Background(), b.SourceNodeId+"\x00"+b.ProducerSessionId, open, nil, b)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ack.CumulativeAckSequence)
	require.Eventually(t, func() bool { return broadcaster.Stats().Published == 1 }, time.Second, time.Millisecond)
}

func TestReliableEventIngressRetainsAckedUndispatchedBatchForRecovery(t *testing.T) {
	dir := t.TempDir()
	stopped, err := events.NewDispatcher(events.Config{QueueSize: 1})
	require.NoError(t, err)
	ingress, err := newEventIngress(EventIngressPolicy{Dispatcher: stopped, Profile: "reliable", WALDirectory: dir})
	require.NoError(t, err)
	b := ingressBatch(t, 1, 1)
	open := &eventsv1.EventIngressOpen{SourceNodeId: b.SourceNodeId, ProducerSessionId: b.ProducerSessionId, SemanticProfileRevision: 1}
	key := b.SourceNodeId + "\x00" + b.ProducerSessionId
	ack, err := ingress.admit(context.Background(), key, open, nil, b)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ack.CumulativeAckSequence)
	require.Equal(t, ingressSession{batch: 1, event: 1}, ingress.sessions[key])
	require.Empty(t, ingress.delivered)
	require.False(t, ingressSessionsEqual(ingress.sessions, ingress.delivered))
	require.NoError(t, ingress.wal.checkpoint(ingress.delivered))
	require.NoError(t, ingress.wal.close())

	recoveredDispatcher, err := events.NewDispatcher(events.Config{QueueSize: 2})
	require.NoError(t, err)
	require.NoError(t, recoveredDispatcher.Start(context.Background()))
	defer recoveredDispatcher.Close(context.Background())
	recovered, err := newEventIngress(EventIngressPolicy{Dispatcher: recoveredDispatcher, Profile: "reliable", WALDirectory: dir})
	require.NoError(t, err)
	defer recovered.wal.close()
	require.NoError(t, recovered.recover())
	require.Equal(t, ingressSession{batch: 1, event: 1}, recovered.sessions[key])
	require.Equal(t, recovered.sessions, recovered.delivered)
}

func TestWALRecoveryDoesNotAdvanceDedupBeforeQueueAdmission(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 1})
	require.NoError(t, err)
	dir := t.TempDir()
	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "reliable", WALDirectory: dir})
	require.NoError(t, err)
	b := ingressBatch(t, 1, 1)
	require.NoError(t, i.wal.append(b))

	require.ErrorContains(t, i.recover(), "queue full")
	require.Empty(t, i.sessions)
	require.NoError(t, i.wal.close())
}

func TestWALRecoveryRestoresLossOnlyEventHighWater(t *testing.T) {
	d, err := events.NewDispatcher(events.Config{QueueSize: 1})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer d.Close(context.Background())

	i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "reliable", WALDirectory: t.TempDir()})
	require.NoError(t, err)
	defer i.wal.close()
	lossOnly := &eventsv1.ProtocolEventBatch{
		SourceNodeId: "node-a", ProducerSessionId: "session-a", BatchSequence: 1,
		SemanticProfileRevision: 1,
		Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{
			Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 7,
			SourceNodeId: "node-a", ProducerSessionId: "session-a",
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: 1, Last: 7}},
		}}},
	}
	require.NoError(t, i.wal.append(lossOnly))
	require.NoError(t, i.recover())
	require.Equal(t, ingressSession{batch: 1, event: 7}, i.sessions["node-a\x00session-a"])
}

func TestEventWALReplayHonorsConfiguredRecordLimit(t *testing.T) {
	dir := t.TempDir()
	w, err := openEventWAL(dir, 16<<20)
	require.NoError(t, err)
	w.maxRecordBytes = 5 << 20
	large := &eventsv1.ProtocolEventBatch{SourceNodeId: string(make([]byte, defaultIngressMaxBatchBytes+1))}
	require.NoError(t, w.append(large))
	require.NoError(t, w.close())

	reopened, err := openEventWAL(dir, 16<<20)
	require.NoError(t, err)
	defer reopened.close()
	reopened.maxRecordBytes = 5 << 20
	require.NoError(t, reopened.replay(func(*eventsv1.ProtocolEventBatch) error { return nil }))
}

func TestEventWALResetCheckpointsDrainedRecords(t *testing.T) {
	dir := t.TempDir()
	wal, err := openEventWAL(dir, 1<<20)
	require.NoError(t, err)
	require.NoError(t, wal.append(ingressBatch(t, 1, 1)))
	require.NoError(t, wal.reset())
	require.Zero(t, wal.size)
	count := 0
	require.NoError(t, wal.replay(func(*eventsv1.ProtocolEventBatch) error { count++; return nil }))
	require.Zero(t, count)
	require.NoError(t, wal.close())
}

func TestEventWALCheckpointPreservesDedupAfterReset(t *testing.T) {
	dir := t.TempDir()
	wal, err := openEventWAL(dir, 1<<20)
	require.NoError(t, err)
	sessions := map[string]ingressSession{"node\x00session": {batch: 3, event: 7}}
	require.NoError(t, wal.checkpoint(sessions))
	require.NoError(t, wal.reset())
	require.NoError(t, wal.close())
	reopened, err := openEventWAL(dir, 1<<20)
	require.NoError(t, err)
	got, err := reopened.loadCheckpoint()
	require.NoError(t, err)
	require.Equal(t, sessions, got)
	require.NoError(t, reopened.close())
}
