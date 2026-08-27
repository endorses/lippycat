//go:build hunter || all

package forwarding

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

type ownershipStats struct{ forwarded, dropped atomic.Uint64 }

func (*ownershipStats) IncrementCaptured()            {}
func (*ownershipStats) IncrementMatched()             {}
func (s *ownershipStats) IncrementForwarded(n uint64) { s.forwarded.Add(n) }
func (s *ownershipStats) IncrementDropped(n uint64)   { s.dropped.Add(n) }
func (*ownershipStats) GetCaptured() uint64           { return 0 }
func (*ownershipStats) GetMatched() uint64            { return 0 }
func (s *ownershipStats) GetDropped() uint64          { return s.dropped.Load() }

type blockingStream struct {
	ctx          context.Context
	started      chan struct{}
	startOnce    sync.Once
	active       atomic.Int32
	maxActive    atomic.Int32
	sends        atomic.Int32
	closeOverlap atomic.Bool
	closed       atomic.Int32
}

func (s *blockingStream) Send(*data.PacketBatch) error {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	s.sends.Add(1)
	for {
		old := s.maxActive.Load()
		if active <= old || s.maxActive.CompareAndSwap(old, active) {
			break
		}
	}
	s.startOnce.Do(func() { close(s.started) })
	<-s.ctx.Done()
	return s.ctx.Err()
}
func (*blockingStream) Recv() (*data.StreamControl, error) { return nil, context.Canceled }
func (*blockingStream) Header() (metadata.MD, error)       { return nil, nil }
func (*blockingStream) Trailer() metadata.MD               { return nil }
func (s *blockingStream) CloseSend() error {
	if s.active.Load() != 0 {
		s.closeOverlap.Store(true)
	}
	s.closed.Add(1)
	return nil
}
func (s *blockingStream) Context() context.Context { return s.ctx }
func (*blockingStream) SendMsg(any) error          { return nil }
func (*blockingStream) RecvMsg(any) error          { return nil }

func TestBlockedSendTimeoutStopsOwnerBeforeClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stream := &blockingStream{ctx: ctx, started: make(chan struct{})}
	queue := make(chan *data.PacketBatch, 2)
	stats := &ownershipStats{}
	m := New(Config{BatchSize: 1}, stats, nil, ctx, queue)
	m.SetStream(stream)
	m.SetDisconnectCallback(cancel)
	queue <- &data.PacketBatch{Sequence: 1, Packets: []*data.CapturedPacket{{}}}
	queue <- &data.PacketBatch{Sequence: 2, Packets: []*data.CapturedPacket{{}}}

	select {
	case <-stream.started:
	case <-time.After(time.Second):
		t.Fatal("send did not start")
	}

	done := make(chan struct{})
	go func() { m.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(constants.DefaultSendTimeout + time.Second):
		t.Fatal("stream owner survived send timeout")
	}

	require.Equal(t, int32(1), stream.sends.Load(), "a second send started on the blocked stream")
	require.Equal(t, int32(1), stream.maxActive.Load())
	require.Equal(t, int32(1), stream.closed.Load())
	require.False(t, stream.closeOverlap.Load())
}

func TestOldSenderCannotCloseSuccessorStream(t *testing.T) {
	oldCtx, cancelOld := context.WithCancel(context.Background())
	oldStream := &blockingStream{ctx: oldCtx, started: make(chan struct{})}
	old := New(Config{BatchSize: 1}, &ownershipStats{}, nil, oldCtx, make(chan *data.PacketBatch, 1))
	old.SetStream(oldStream)

	newCtx, cancelNew := context.WithCancel(context.Background())
	newStream := &blockingStream{ctx: newCtx, started: make(chan struct{})}
	newManager := New(Config{BatchSize: 1}, &ownershipStats{}, nil, newCtx, make(chan *data.PacketBatch, 1))
	newManager.SetStream(newStream)

	cancelOld()
	old.Wait()
	require.Equal(t, int32(1), oldStream.closed.Load())
	require.Zero(t, newStream.closed.Load())

	cancelNew()
	newManager.Wait()
	require.Equal(t, int32(1), newStream.closed.Load())
}
