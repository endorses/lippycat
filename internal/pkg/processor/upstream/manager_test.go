package upstream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/stretchr/testify/require"
)

type detectingStream struct {
	inSend     atomic.Int32
	overlapped atomic.Bool
	sends      atomic.Uint64
	closed     atomic.Bool
	release    chan struct{}
}

type failingStream struct {
	detectingStream
	err error
}

func (s *failingStream) Send(*data.PacketBatch) error {
	s.sends.Add(1)
	return s.err
}

func (s *detectingStream) Send(*data.PacketBatch) error {
	if s.inSend.Add(1) != 1 {
		s.overlapped.Store(true)
	}
	defer s.inSend.Add(-1)
	if s.release != nil {
		<-s.release
	}
	time.Sleep(time.Microsecond)
	s.sends.Add(1)
	return nil
}

func (s *detectingStream) Recv() (*data.StreamControl, error) {
	return nil, errors.New("not used")
}

func (s *detectingStream) CloseSend() error {
	if s.inSend.Load() != 0 {
		s.overlapped.Store(true)
	}
	s.closed.Store(true)
	return nil
}

func startTestGeneration(m *Manager, stream upstreamStream, queueSize int) *connection {
	ctx, cancel := context.WithCancel(context.Background())
	generation := &connection{
		stream: stream,
		queue:  make(chan *data.PacketBatch, queueSize),
		ctx:    ctx,
		cancel: cancel,
	}
	generation.accepting.Store(true)
	m.mu.Lock()
	m.generation = generation
	m.mu.Unlock()
	generation.wg.Add(1)
	go m.sendBatches(generation)
	return generation
}

func stopTestGeneration(generation *connection) {
	generation.accepting.Store(false)
	generation.cancel()
	generation.wg.Wait()
}

func TestForwardSerializesConcurrentCallers(t *testing.T) {
	var forwarded atomic.Uint64
	m := NewManager(Config{OutboundQueueSize: 4096}, &forwarded)
	stream := &detectingStream{}
	generation := startTestGeneration(m, stream, 4096)

	const callers = 32
	const batchesPerCaller = 50
	var callersWG sync.WaitGroup
	callersWG.Add(callers)
	for caller := 0; caller < callers; caller++ {
		go func() {
			defer callersWG.Done()
			for i := 0; i < batchesPerCaller; i++ {
				m.Forward(&data.PacketBatch{Packets: []*data.CapturedPacket{{}}})
			}
		}()
	}
	callersWG.Wait()

	require.Eventually(t, func() bool {
		return stream.sends.Load() == callers*batchesPerCaller
	}, 5*time.Second, time.Millisecond)
	stopTestGeneration(generation)
	require.False(t, stream.overlapped.Load())
	require.Equal(t, uint64(callers*batchesPerCaller), forwarded.Load())
	require.True(t, stream.closed.Load())
}

func TestCleanupCloseSendNeverOverlapsBlockedSend(t *testing.T) {
	m := NewManager(Config{OutboundQueueSize: 1}, nil)
	stream := &detectingStream{release: make(chan struct{})}
	generation := startTestGeneration(m, stream, 1)
	m.Forward(&data.PacketBatch{})
	require.Eventually(t, func() bool { return stream.inSend.Load() == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 1, m.QueueDepth(), "an in-flight send must contribute to upstream pressure")

	stopped := make(chan struct{})
	go func() {
		stopTestGeneration(generation)
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("sender stopped before its active Send returned")
	case <-time.After(20 * time.Millisecond):
	}
	require.False(t, stream.closed.Load())
	close(stream.release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("sender did not stop after Send returned")
	}
	require.True(t, stream.closed.Load())
	require.False(t, stream.overlapped.Load())
}

func TestSendFailureTerminatesGenerationAndRequestsReconnect(t *testing.T) {
	m := NewManager(Config{OutboundQueueSize: 1}, nil)
	stream := &failingStream{err: errors.New("send failed")}
	generation := startTestGeneration(m, stream, 1)

	m.Forward(&data.PacketBatch{})
	require.Eventually(t, func() bool {
		m.reconnectMu.Lock()
		defer m.reconnectMu.Unlock()
		return m.reconnecting
	}, time.Second, time.Millisecond)
	require.ErrorIs(t, generation.ctx.Err(), context.Canceled)
	require.False(t, generation.accepting.Load())
	require.Equal(t, 0, m.QueueDepth())
	stopTestGeneration(generation)
	require.Equal(t, uint64(1), stream.sends.Load())
	require.Equal(t, int32(1), m.consecutiveFailures.Load())
	require.True(t, stream.closed.Load())
}

func TestSendFailureAccountingSpansGenerationsUntilSuccessfulSend(t *testing.T) {
	m := NewManager(Config{OutboundQueueSize: 1}, nil)

	for want := int32(1); want <= constants.MaxConsecutiveSendFailures; want++ {
		stream := &failingStream{err: errors.New("send failed")}
		generation := startTestGeneration(m, stream, 1)
		m.Forward(&data.PacketBatch{})
		require.Eventually(t, func() bool {
			return generation.ctx.Err() != nil
		}, time.Second, time.Millisecond)
		stopTestGeneration(generation)
		require.Equal(t, want, m.consecutiveFailures.Load(),
			"creating a replacement stream must not count as recovered delivery")
	}

	stream := &detectingStream{}
	generation := startTestGeneration(m, stream, 1)
	m.Forward(&data.PacketBatch{})
	require.Eventually(t, func() bool {
		return stream.sends.Load() == 1
	}, time.Second, time.Millisecond)
	stopTestGeneration(generation)
	require.Zero(t, m.consecutiveFailures.Load(),
		"only a successful Send proves upstream packet delivery recovered")
}

func TestOldGenerationCannotSendOnSuccessor(t *testing.T) {
	m := NewManager(Config{OutboundQueueSize: 4}, nil)
	oldStream := &detectingStream{}
	oldGeneration := startTestGeneration(m, oldStream, 4)
	stopTestGeneration(oldGeneration)

	newStream := &detectingStream{}
	newGeneration := startTestGeneration(m, newStream, 4)
	m.Forward(&data.PacketBatch{})
	require.Eventually(t, func() bool { return newStream.sends.Load() == 1 }, time.Second, time.Millisecond)
	stopTestGeneration(newGeneration)

	require.Equal(t, uint64(0), oldStream.sends.Load())
	require.Equal(t, uint64(1), newStream.sends.Load())
}

func TestForwardDropsWhenOutboundQueueIsFull(t *testing.T) {
	m := NewManager(Config{OutboundQueueSize: 1}, nil)
	stream := &detectingStream{release: make(chan struct{})}
	generation := startTestGeneration(m, stream, 1)
	m.Forward(&data.PacketBatch{})
	require.Eventually(t, func() bool { return stream.inSend.Load() == 1 }, time.Second, time.Millisecond)
	m.Forward(&data.PacketBatch{})
	m.Forward(&data.PacketBatch{})
	require.Equal(t, uint64(1), m.droppedBatches.Load())
	close(stream.release)
	stopTestGeneration(generation)
}
