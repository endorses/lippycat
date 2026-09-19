//go:build hunter || all

package hunter

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests the hunter constructor
func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:55555",
				BatchSize:     100,
				BufferSize:    8192,
			},
			wantErr: false,
		},
		{
			name: "empty hunter ID",
			config: Config{
				HunterID:      "",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:55555",
			},
			wantErr:     true,
			errContains: "hunter ID is required",
		},
		{
			name: "empty processor address",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "",
			},
			wantErr:     true,
			errContains: "processor address is required",
		},
		{
			name: "default flow control settings",
			config: Config{
				HunterID:      "test-hunter-1",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:55555",
				// MaxBufferedBatches and SendTimeout not set - should use defaults
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hunter, err := New(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, hunter)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, hunter)
				assert.Equal(t, tt.config.HunterID, hunter.config.HunterID)
				assert.Equal(t, tt.config.ProcessorAddr, hunter.config.ProcessorAddr)

				// Verify defaults were applied
				if tt.config.MaxBufferedBatches == 0 {
					assert.Equal(t, 10, hunter.config.MaxBufferedBatches, "default MaxBufferedBatches should be 10")
				}
				if tt.config.SendTimeout == 0 {
					assert.Equal(t, 5*time.Second, hunter.config.SendTimeout, "default SendTimeout should be 5s")
				}

				// Verify batch queue was created with correct capacity
				// Batch queue is now managed by forwarding manager
			}
		})
	}
}

// TestCapturedPacket tests packet structure
func TestCapturedPacket(t *testing.T) {
	// Test basic packet creation
	packet := &data.CapturedPacket{
		Data:           []byte{0x01, 0x02, 0x03},
		TimestampNs:    1234567890,
		CaptureLength:  3,
		OriginalLength: 3,
	}

	assert.Equal(t, []byte{0x01, 0x02, 0x03}, packet.Data)
	assert.Equal(t, int64(1234567890), packet.TimestampNs)
	assert.Equal(t, uint32(3), packet.CaptureLength)
	assert.Equal(t, uint32(3), packet.OriginalLength)
}

// TestGetStatsCollector tests statistics collector retrieval
func TestGetStatsCollector(t *testing.T) {
	hunter, err := New(Config{
		ProcessorAddr: "localhost:55555",
		HunterID:      "test-hunter",
		Interfaces:    []string{"eth0"},
		BatchSize:     10,
		BufferSize:    100,
	})
	require.NoError(t, err)

	statsCollector := hunter.GetStatsCollector()
	assert.NotNil(t, statsCollector)

	// Initially all stats should be zero
	assert.Equal(t, uint64(0), statsCollector.GetCaptured())
	assert.Equal(t, uint64(0), statsCollector.GetMatched())
	assert.Equal(t, uint64(0), statsCollector.GetForwarded())
	assert.Equal(t, uint64(0), statsCollector.GetDropped())
	assert.Equal(t, uint64(0), statsCollector.GetBufferBytes())
}

func TestCaptureLossStatsSampleBufferOverflowOnce(t *testing.T) {
	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: "hunter-loss", BufferSize: 1})
	require.NoError(t, err)
	require.NoError(t, hunter.captureManager.Start(nil))
	defer hunter.captureManager.Stop()
	buffer := hunter.captureManager.GetPacketBuffer()
	require.NotNil(t, buffer)
	for range 100 {
		buffer.Send(capture.PacketInfo{})
	}
	previous := int64(0)
	hunter.updateCaptureLossStats(&previous)
	first := hunter.statsCollector.ToProto(0).GetCaptureLosses()
	require.Positive(t, first)
	hunter.updateCaptureLossStats(&previous)
	require.Equal(t, first, hunter.statsCollector.ToProto(0).GetCaptureLosses())
}

func TestEventPolicyChangeRotatesProducerSession(t *testing.T) {
	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: "hunter-rotate", ForwardMode: "events", EventSpoolDir: t.TempDir(), EventDeliveryProfile: "memory_only"})
	require.NoError(t, err)
	hunter.ctx, hunter.cancel = context.WithCancel(context.Background())
	defer hunter.cancel()
	require.NoError(t, hunter.initializeEventForwarding())
	oldSession := hunter.eventForwarder.ProducerSessionID()
	applied := false
	require.NoError(t, hunter.ApplyPolicyChange(func() error { applied = true; return nil }))
	require.True(t, applied)
	require.NotEqual(t, oldSession, hunter.eventForwarder.ProducerSessionID())
	hunter.eventRuntime.Close()
	require.NoError(t, hunter.eventDispatcher.Close(context.Background()))
}

func TestInitializeEventForwardingAllowsRecoveredFinalSequenceToDrain(t *testing.T) {
	const session = "30313233343536373839616263646566"
	dir := t.TempDir()
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	policy := eventspool.SessionPolicy{Version: 1, SourceNodeID: "hunter-final", ProducerSessionID: session, DeliveryProfile: "reliable", SemanticRevision: 1}
	require.NoError(t, spool.BindSessionPolicy(policy))
	event := events.NewDNSEvent(events.Envelope{Timestamp: time.Unix(1, 0), EventID: events.DeliveryEventID("hunter-final", session, ^uint64(0)), ProducerSessionID: session, EventSequence: ^uint64(0), UID: "uid", NodeID: "hunter-final", Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 53, DestinationPort: 53000}, CaptureScope: events.CaptureScopeFiltered})
	batch, err := protoadapter.ToProtoBatch("hunter-final", session, ^uint64(0), []events.Event{event}, nil, 1)
	require.NoError(t, err)
	result, err := spool.Enqueue(batch)
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.NoError(t, spool.Close())

	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: "hunter-final", ForwardMode: "events", EventSpoolDir: dir, EventDeliveryProfile: "reliable"})
	require.NoError(t, err)
	hunter.ctx = context.Background()
	require.NoError(t, hunter.initializeEventForwarding())
	require.NotNil(t, hunter.eventForwarder)
	require.Nil(t, hunter.eventRuntime, "an exhausted recovered session must remain drain-only until its final batch is ACKed")
	require.Equal(t, session, hunter.eventForwarder.ProducerSessionID())
	applied := false
	err = hunter.ApplyPolicyChange(func() error { applied = true; return nil })
	require.ErrorContains(t, err, "still draining")
	require.False(t, applied, "policy authority must not change while pre-change durable events are draining")
	require.NoError(t, hunter.eventSpool.Close())
}

func TestInitializeEventForwardingStagesRecoveredTerminalLosses(t *testing.T) {
	const session = "30313233343536373839616263646566"
	dir := t.TempDir()
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	policy := eventspool.SessionPolicy{Version: 1, SourceNodeID: "hunter-loss-final", ProducerSessionID: session, DeliveryProfile: "reliable", SemanticRevision: 1}
	require.NoError(t, spool.BindSessionPolicy(policy))
	retention, err := spool.RetainLosses([]*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: "hunter-loss-final", ProducerSessionId: session, EventSequenceRanges: []*eventsv1.SequenceRange{{First: ^uint64(0), Last: ^uint64(0)}}}})
	require.NoError(t, err)
	require.True(t, retention.Committed)
	require.NoError(t, spool.Close())

	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: "hunter-loss-final", ForwardMode: "events", EventSpoolDir: dir, EventDeliveryProfile: "reliable"})
	require.NoError(t, err)
	hunter.ctx = context.Background()
	require.NoError(t, hunter.initializeEventForwarding())
	require.True(t, hunter.eventSpool.HasPendingLosses())
	require.Empty(t, hunter.eventSpool.Batches(), "terminal loss publication waits until forwarding has started")
	result, err := hunter.eventForwarder.FlushPendingLosses(1, 1)
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.False(t, hunter.eventSpool.HasPendingLosses())
	batches := hunter.eventSpool.Batches()
	require.Len(t, batches, 1)
	require.Equal(t, uint64(1), batches[0].GetBatchSequence())
	require.Equal(t, ^uint64(0), batches[0].GetStats().GetLosses()[0].GetEventSequenceRanges()[0].GetFirst())
	require.Nil(t, hunter.eventRuntime)
	require.NoError(t, hunter.eventSpool.Close())
}

func TestInitializeEventForwardingDrainsFinalCarrierBeforeTerminalResidualLoss(t *testing.T) {
	const session = "30313233343536373839616263646566"
	dir := t.TempDir()
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	policy := eventspool.SessionPolicy{Version: 1, SourceNodeID: "hunter-fragmented-final", ProducerSessionID: session, DeliveryProfile: "reliable", SemanticRevision: 1}
	require.NoError(t, spool.BindSessionPolicy(policy))
	seed := &eventsv1.ProtocolEventBatch{SourceNodeId: policy.SourceNodeID, ProducerSessionId: session, BatchSequence: ^uint64(0) - 1, SemanticProfileRevision: 1}
	result, err := spool.Enqueue(seed)
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.NoError(t, spool.Ack(policy.SourceNodeID, session, seed.BatchSequence))

	ranges := make([]*eventsv1.SequenceRange, 5000)
	for i := range ranges {
		sequence := ^uint64(0) - uint64(2*(len(ranges)-1-i))
		ranges[i] = &eventsv1.SequenceRange{First: sequence, Last: sequence}
	}
	losses := []*eventsv1.EventLoss{
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 2500, SourceNodeId: policy.SourceNodeID, ProducerSessionId: session, EventSequenceRanges: ranges[:2500]},
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 2500, SourceNodeId: policy.SourceNodeID, ProducerSessionId: session, EventSequenceRanges: ranges[2500:]},
	}
	retention, err := spool.RetainLosses(losses)
	require.NoError(t, err)
	require.True(t, retention.Committed)
	require.NoError(t, spool.Close())

	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: policy.SourceNodeID, ForwardMode: "events", EventSpoolDir: dir, EventDeliveryProfile: "reliable"})
	require.NoError(t, err)
	hunter.ctx = context.Background()
	require.NoError(t, hunter.initializeEventForwarding(), "the committed final carrier must remain forwardable even when residual exact loss cannot receive another sequence")
	result, err = hunter.eventForwarder.FlushPendingLosses(^uint64(0), 1)
	require.NoError(t, err)
	require.True(t, result.Stored)
	batches := hunter.eventSpool.Batches()
	require.Len(t, batches, 1)
	require.Equal(t, ^uint64(0), batches[0].GetBatchSequence())
	require.True(t, hunter.eventSpool.HasPendingLosses(), "coverage beyond the final carrier remains durable and triggers terminal fail-stop after that carrier drains")
	require.Nil(t, hunter.eventRuntime)
	require.NoError(t, hunter.eventSpool.Close())
}

func TestInitializeEventForwardingStartsDrainBeforeTerminalLossOnFullDropNewSpool(t *testing.T) {
	const session = "30313233343536373839616263646566"
	dir := t.TempDir()
	policy := eventspool.SessionPolicy{Version: 1, SourceNodeID: "hunter-full-final", ProducerSessionID: session, DeliveryProfile: "reliable", SemanticRevision: 1}
	spool, err := eventspool.Open(eventspool.Config{Directory: dir, Policy: eventspool.DropNew})
	require.NoError(t, err)
	require.NoError(t, spool.BindSessionPolicy(policy))
	event := events.NewDNSEvent(events.Envelope{Timestamp: time.Unix(1, 0), EventID: events.DeliveryEventID(policy.SourceNodeID, session, ^uint64(0)-1), ProducerSessionID: session, EventSequence: ^uint64(0) - 1, UID: "uid", NodeID: policy.SourceNodeID, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 53, DestinationPort: 53000}, CaptureScope: events.CaptureScopeFiltered})
	batch, err := protoadapter.ToProtoBatch(policy.SourceNodeID, session, 1, []events.Event{event}, nil, 1)
	require.NoError(t, err)
	result, err := spool.Enqueue(batch)
	require.NoError(t, err)
	require.True(t, result.Stored)
	maxBytes := spool.Bytes()
	retention, err := spool.RetainLosses([]*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: policy.SourceNodeID, ProducerSessionId: session, EventSequenceRanges: []*eventsv1.SequenceRange{{First: ^uint64(0), Last: ^uint64(0)}}}})
	require.NoError(t, err)
	require.True(t, retention.Committed)
	require.NoError(t, spool.Close())

	hunter, err := New(Config{ProcessorAddr: "processor:55555", HunterID: policy.SourceNodeID, ForwardMode: "events", EventSpoolDir: dir, EventSpoolMaxBytes: maxBytes, EventSpoolExhaustionPolicy: string(eventspool.DropNew), EventDeliveryProfile: "reliable"})
	require.NoError(t, err)
	hunter.ctx = context.Background()
	require.NoError(t, hunter.initializeEventForwarding(), "recovery must start the forwarder before a full spool has capacity for the terminal loss carrier")
	require.Len(t, hunter.eventSpool.Batches(), 1)
	require.True(t, hunter.eventSpool.HasPendingLosses())

	result, err = hunter.eventForwarder.FlushPendingLosses(2, 1)
	require.NoError(t, err)
	require.False(t, result.Stored)
	require.Equal(t, eventspool.RejectionExhausted, result.Rejection)
	require.NoError(t, hunter.eventSpool.Ack(policy.SourceNodeID, session, 1))
	result, err = hunter.eventForwarder.FlushPendingLosses(2, 1)
	require.NoError(t, err)
	require.True(t, result.Stored, "the staged terminal carrier must commit once ACK drain frees capacity")
	require.False(t, hunter.eventSpool.HasPendingLosses())
	require.NoError(t, hunter.eventSpool.Close())
}

func TestExhaustedRecoveryFailsClosedOnSpoolRecoveryBarrier(t *testing.T) {
	require.ErrorIs(t, exhaustedRecoveryStatusError(eventspool.Status{DurabilityUncertain: true}), eventspool.ErrDurabilityUncertain)
	require.ErrorIs(t, exhaustedRecoveryStatusError(eventspool.Status{CheckpointRequired: true}), eventspool.ErrCheckpointRequired)
	require.NoError(t, exhaustedRecoveryStatusError(eventspool.Status{}))

	committed := eventspool.EnqueueResult{Stored: true}
	require.ErrorIs(t, exhaustedRecoveryPublicationError(committed, eventspool.ErrDurabilityUncertain), eventspool.ErrDurabilityUncertain)
	cleanupErr := &eventspool.CleanupError{Operation: "remove", Path: "record", Err: errors.New("injected cleanup failure")}
	require.NoError(t, exhaustedRecoveryPublicationError(committed, cleanupErr), "committed cleanup-only failures remain forwardable")
	require.Error(t, exhaustedRecoveryPublicationError(eventspool.EnqueueResult{}, cleanupErr), "pre-commit errors must fail closed")
}

// TestStatsAtomic tests that stats can be safely updated from multiple goroutines
func TestStatsAtomic(t *testing.T) {
	hunter, err := New(Config{
		ProcessorAddr: "localhost:55555",
		HunterID:      "test-hunter",
		Interfaces:    []string{"eth0"},
		BatchSize:     10,
		BufferSize:    100,
	})
	require.NoError(t, err)

	// Increment stats from multiple goroutines
	const numGoroutines = 10
	const incrementsPerGoroutine = 100

	done := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < incrementsPerGoroutine; j++ {
				hunter.statsCollector.IncrementCaptured()
				hunter.statsCollector.IncrementMatched()
				hunter.statsCollector.IncrementForwarded(1)
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	expected := uint64(numGoroutines * incrementsPerGoroutine)
	assert.Equal(t, expected, hunter.statsCollector.GetCaptured())
	assert.Equal(t, expected, hunter.statsCollector.GetMatched())
	assert.Equal(t, expected, hunter.statsCollector.GetForwarded())
}

// TestMin tests the min helper function
func TestMin(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a < b", 5, 10, 5},
		{"a > b", 10, 5, 5},
		{"a == b", 7, 7, 7},
		{"negative numbers", -5, -10, -10},
		{"zero", 0, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := min(tt.a, tt.b)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestFlowControlStateTransitions tests flow control state machine
func TestFlowControlStateTransitions_Extended(t *testing.T) {
	tests := []struct {
		name          string
		initialState  data.FlowControl
		signal        data.FlowControl
		expectedState data.FlowControl
	}{
		{
			name:          "CONTINUE to PAUSE",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectedState: data.FlowControl_FLOW_PAUSE,
		},
		{
			name:          "PAUSE to RESUME",
			initialState:  data.FlowControl_FLOW_PAUSE,
			signal:        data.FlowControl_FLOW_RESUME,
			expectedState: data.FlowControl_FLOW_RESUME,
		},
		{
			name:          "RESUME to CONTINUE",
			initialState:  data.FlowControl_FLOW_RESUME,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
		},
		{
			name:          "CONTINUE to SLOW",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_SLOW,
			expectedState: data.FlowControl_FLOW_SLOW,
		},
		{
			name:          "SLOW to CONTINUE",
			initialState:  data.FlowControl_FLOW_SLOW,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
		},
	}
	_ = tests // Keep test cases for documentation

	// Flow control is now managed by forwarding.Manager
	// TODO: Create tests in forwarding/manager_test.go
	t.Skip("Flow control logic moved to forwarding.Manager")
}

// TestBatchSizeConfiguration tests batch size limits
func TestBatchSizeConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		batchSize     int
		expectedBatch int
	}{
		{
			name:          "zero batch size",
			batchSize:     0,
			expectedBatch: 0,
		},
		{
			name:          "custom batch size",
			batchSize:     500,
			expectedBatch: 500,
		},
		{
			name:          "small batch size",
			batchSize:     10,
			expectedBatch: 10,
		},
		{
			name:          "large batch size",
			batchSize:     10000,
			expectedBatch: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hunter, err := New(Config{
				HunterID:      "test-hunter",
				Interfaces:    []string{"eth0"},
				ProcessorAddr: "localhost:55555",
				BatchSize:     tt.batchSize,
			})

			require.NoError(t, err)
			assert.NotNil(t, hunter)
			assert.Equal(t, tt.expectedBatch, hunter.config.BatchSize)
		})
	}
}

// TestContextCancellation tests proper cleanup on context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Start a goroutine that should exit on context cancellation
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()

	// Cancel context
	cancel()

	// Wait for goroutine to exit with timeout
	select {
	case <-done:
		// Success - goroutine exited
	case <-time.After(1 * time.Second):
		t.Fatal("goroutine did not exit on context cancellation")
	}
}
