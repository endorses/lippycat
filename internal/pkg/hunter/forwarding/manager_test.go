//go:build hunter || all

package forwarding

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

type flowStats struct{ forwarded, dropped atomic.Uint64 }

func (*flowStats) IncrementCaptured()            {}
func (*flowStats) IncrementMatched()             {}
func (s *flowStats) IncrementForwarded(n uint64) { s.forwarded.Add(n) }
func (s *flowStats) IncrementDropped(n uint64)   { s.dropped.Add(n) }
func (*flowStats) GetCaptured() uint64           { return 0 }
func (*flowStats) GetMatched() uint64            { return 0 }
func (s *flowStats) GetDropped() uint64          { return s.dropped.Load() }

type recordingStream struct {
	ctx       context.Context
	mu        sync.Mutex
	sequences []uint64
	sent      chan struct{}
}

type fakeTicker struct{ ch chan time.Time }

func (t *fakeTicker) Chan() <-chan time.Time { return t.ch }
func (*fakeTicker) Stop()                    {}

type fakeClock struct{ ticker *fakeTicker }

func (c *fakeClock) NewTicker(time.Duration) Ticker { return c.ticker }

func (s *recordingStream) Send(batch *data.PacketBatch) error {
	s.mu.Lock()
	s.sequences = append(s.sequences, batch.Sequence)
	s.mu.Unlock()
	select {
	case s.sent <- struct{}{}:
	default:
	}
	return nil
}
func (*recordingStream) Recv() (*data.StreamControl, error) { return nil, context.Canceled }
func (*recordingStream) Header() (metadata.MD, error)       { return nil, nil }
func (*recordingStream) Trailer() metadata.MD               { return nil }
func (*recordingStream) CloseSend() error                   { return nil }
func (s *recordingStream) Context() context.Context         { return s.ctx }
func (*recordingStream) SendMsg(any) error                  { return nil }
func (*recordingStream) RecvMsg(any) error                  { return nil }

func packet() *pipeline.PacketEnvelope { return &pipeline.PacketEnvelope{Data: []byte{1}} }

type testPacketBufferProvider struct{ buffer *capture.PacketBuffer }

func (p testPacketBufferProvider) GetPacketBuffer() *capture.PacketBuffer { return p.buffer }

func TestSendBatchReconcilesNamedLossCounters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	packetBuffer := capture.NewPacketBuffer(ctx, 1)
	defer packetBuffer.Close()
	for i := 0; i < 100; i++ {
		packetBuffer.Send(capture.PacketInfo{})
	}
	require.Positive(t, packetBuffer.GetDropped())

	stats := &flowStats{}
	stats.dropped.Store(3)
	queue := make(chan *pipeline.PacketBatch, 1)
	m := New(Config{BatchSize: 1}, stats, testPacketBufferProvider{buffer: packetBuffer}, ctx, queue)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})
	require.True(t, m.AddPacketToBatch(packet()))
	m.SendBatch()

	batch := <-queue
	require.Equal(t, uint64(packetBuffer.GetDropped()), batch.Stats.CaptureBufferRegularDrops)
	require.Zero(t, batch.Stats.CaptureBufferSIPDrops)
	require.Equal(t, uint64(3), batch.Stats.BatchChannelDrops)
	require.Equal(t, batch.Stats.CaptureBufferRegularDrops+batch.Stats.CaptureBufferSIPDrops+batch.Stats.BatchChannelDrops, batch.Stats.Dropped)

	cancel()
	m.Wait()
}

func TestHandleFlowControl_PauseAndResume(t *testing.T) {
	m := &Manager{}

	// Initially not paused
	assert.False(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())

	// PAUSE
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_PAUSE,
	})
	assert.True(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_PAUSE, m.GetFlowControlState())

	// RESUME
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_RESUME,
	})
	assert.False(t, m.IsPaused())
	assert.Equal(t, data.FlowControl_FLOW_RESUME, m.GetFlowControlState())
}

func TestHandleFlowControl_SlowAndContinue(t *testing.T) {
	m := &Manager{}

	// SLOW
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_SLOW,
	})
	assert.Equal(t, data.FlowControl_FLOW_SLOW, m.GetFlowControlState())
	assert.False(t, m.IsPaused()) // SLOW does not pause

	// CONTINUE
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_CONTINUE,
	})
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())
}

func TestHandleFlowControl_StateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  data.FlowControl
		initialPaused bool
		signal        data.FlowControl
		expectedState data.FlowControl
		expectedPause bool
	}{
		{
			name:          "CONTINUE to PAUSE",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_PAUSE,
			expectedState: data.FlowControl_FLOW_PAUSE,
			expectedPause: true,
		},
		{
			name:          "PAUSE to RESUME",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_RESUME,
			expectedState: data.FlowControl_FLOW_RESUME,
			expectedPause: false,
		},
		{
			name:          "CONTINUE to SLOW",
			initialState:  data.FlowControl_FLOW_CONTINUE,
			signal:        data.FlowControl_FLOW_SLOW,
			expectedState: data.FlowControl_FLOW_SLOW,
			expectedPause: false,
		},
		{
			name:          "SLOW to CONTINUE",
			initialState:  data.FlowControl_FLOW_SLOW,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
			expectedPause: false,
		},
		{
			name:          "PAUSE to CONTINUE releases sender",
			initialState:  data.FlowControl_FLOW_PAUSE,
			initialPaused: true,
			signal:        data.FlowControl_FLOW_CONTINUE,
			expectedState: data.FlowControl_FLOW_CONTINUE,
			expectedPause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{}
			m.flowControlState.Store(int32(tt.initialState))
			m.paused.Store(tt.initialPaused)

			m.HandleFlowControl(&data.StreamControl{
				FlowControl: tt.signal,
			})

			assert.Equal(t, tt.expectedState, m.GetFlowControlState())
			assert.Equal(t, tt.expectedPause, m.IsPaused())
		})
	}
}

func TestPauseKeepsCurrentBatchBoundedAndAccountsDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan *pipeline.PacketBatch, 2)
	stats := &flowStats{}
	m := New(Config{BatchSize: 2}, stats, nil, ctx, queue)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})

	for i := 0; i < 7; i++ {
		if m.AddPacketToBatch(packet()) {
			m.SendBatch()
		}
	}

	m.batchMu.Lock()
	currentLen := len(m.currentBatch)
	m.batchMu.Unlock()
	require.Less(t, currentLen, 2)
	require.Len(t, queue, 2)
	require.Equal(t, uint64(2), stats.dropped.Load(), "one full batch should be dropped")

	cancel()
	m.Wait()
}

func TestPauseAccountsDropsWhenMemoryAndDiskAreFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan *pipeline.PacketBatch, 1)
	stats := &flowStats{}
	m := New(Config{
		BatchSize:         1,
		DiskBufferEnabled: true,
		DiskBufferDir:     t.TempDir(),
		DiskBufferMaxSize: 1, // smaller than every serialized batch
	}, stats, nil, ctx, queue)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})

	for i := 0; i < 3; i++ {
		m.AddPacketToBatch(packet())
		m.SendBatch()
	}
	require.Len(t, queue, 1)
	require.Equal(t, uint64(2), stats.dropped.Load())
	require.Equal(t, uint64(2), m.GetDiskBufferMetrics().TotalDropped)

	cancel()
	m.Wait()
	require.NoError(t, m.Close())
}

func TestResumeDrainsPausedBatchesInOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan *pipeline.PacketBatch, 4)
	m := New(Config{BatchSize: 1}, &flowStats{}, nil, ctx, queue)
	stream := &recordingStream{ctx: ctx, sent: make(chan struct{}, 4)}
	m.SetStream(stream)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})
	for i := 0; i < 3; i++ {
		m.AddPacketToBatch(packet())
		m.SendBatch()
	}
	time.Sleep(10 * time.Millisecond)
	require.Empty(t, stream.sequences)

	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_RESUME})
	for i := 0; i < 3; i++ {
		select {
		case <-stream.sent:
		case <-time.After(time.Second):
			t.Fatal("queued batch was not sent")
		}
	}
	stream.mu.Lock()
	require.Equal(t, []uint64{1, 2, 3}, stream.sequences)
	stream.mu.Unlock()
	cancel()
	m.Wait()
}

func TestResumePreservesOrderAcrossMemoryAndDiskOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan *pipeline.PacketBatch, 2)
	m := New(Config{
		BatchSize:         1,
		DiskBufferEnabled: true,
		DiskBufferDir:     t.TempDir(),
		DiskBufferMaxSize: 1 << 20,
	}, &flowStats{}, nil, ctx, queue)
	stream := &recordingStream{ctx: ctx, sent: make(chan struct{}, 4)}
	m.SetStream(stream)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})

	for i := 0; i < 4; i++ {
		m.AddPacketToBatch(packet())
		m.SendBatch()
	}
	require.Len(t, queue, 2)
	require.Equal(t, uint64(2), m.GetDiskBufferMetrics().PendingBatches)

	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_RESUME})
	for i := 0; i < 4; i++ {
		select {
		case <-stream.sent:
		case <-time.After(2 * time.Second):
			t.Fatalf("queued batch %d was not sent", i+1)
		}
	}
	stream.mu.Lock()
	require.Equal(t, []uint64{1, 2, 3, 4}, stream.sequences)
	stream.mu.Unlock()

	cancel()
	m.Wait()
	require.NoError(t, m.Close())
}

func TestSlowPacesSenderWithoutBlockingBatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan *pipeline.PacketBatch, 8)
	m := New(Config{BatchSize: 1, SlowSendInterval: 30 * time.Millisecond}, &flowStats{}, nil, ctx, queue)
	stream := &recordingStream{ctx: ctx, sent: make(chan struct{}, 8)}
	m.SetStream(stream)
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_SLOW})
	start := time.Now()
	for i := 0; i < 3; i++ {
		m.AddPacketToBatch(packet())
		m.SendBatch()
	}
	require.LessOrEqual(t, time.Since(start), 20*time.Millisecond, "capture-side batching blocked")
	for i := 0; i < 3; i++ {
		select {
		case <-stream.sent:
		case <-time.After(time.Second):
			t.Fatal("paced batch was not sent")
		}
	}
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	cancel()
	m.Wait()
}

func TestLongDurationFlowTransitionsWithFakeClock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticker := &fakeTicker{ch: make(chan time.Time, 8)}
	clock := &fakeClock{ticker: ticker}
	queue := make(chan *pipeline.PacketBatch, 8)
	m := New(Config{BatchSize: 1, SlowSendInterval: time.Second, Clock: clock}, &flowStats{}, nil, ctx, queue)
	stream := &recordingStream{ctx: ctx, sent: make(chan struct{}, 8)}
	m.SetStream(stream)

	// A day-long PAUSE is represented by advancing the fake time without any
	// wall-clock wait. Capture batching remains bounded and nothing is sent.
	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_PAUSE})
	for i := 0; i < 3; i++ {
		m.AddPacketToBatch(packet())
		m.SendBatch()
	}
	select {
	case <-stream.sent:
		t.Fatal("batch sent while paused")
	default:
	}

	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_SLOW})
	base := time.Unix(0, 0)
	for day := 1; day <= 3; day++ {
		ticker.ch <- base.Add(time.Duration(day) * 24 * time.Hour)
		select {
		case <-stream.sent:
		case <-time.After(time.Second):
			t.Fatalf("batch %d was not released by fake-clock tick", day)
		}
	}
	stream.mu.Lock()
	require.Equal(t, []uint64{1, 2, 3}, stream.sequences)
	stream.mu.Unlock()

	m.HandleFlowControl(&data.StreamControl{FlowControl: data.FlowControl_FLOW_CONTINUE})
	m.AddPacketToBatch(packet())
	m.SendBatch()
	select {
	case <-stream.sent:
	case <-time.After(time.Second):
		t.Fatal("CONTINUE did not remove pacing")
	}
	cancel()
	m.Wait()
}

func TestHandleFlowControl_AckSequence(t *testing.T) {
	m := &Manager{}

	// Verify no panic with ack sequence
	m.HandleFlowControl(&data.StreamControl{
		AckSequence: 42,
		FlowControl: data.FlowControl_FLOW_CONTINUE,
	})
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, m.GetFlowControlState())
}

func TestHandleFlowControl_ErrorMessage(t *testing.T) {
	m := &Manager{}

	// Verify no panic with error message
	m.HandleFlowControl(&data.StreamControl{
		FlowControl: data.FlowControl_FLOW_PAUSE,
		Error:       "processor overloaded",
	})
	assert.True(t, m.IsPaused())
}
