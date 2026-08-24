package events

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testSink struct {
	mu      sync.Mutex
	events  []Event
	handle  func(Event) error
	flushes int
	closes  int
}

func (s *testSink) HandleEvent(_ context.Context, event Event) error {
	if s.handle != nil {
		if err := s.handle(event); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (s *testSink) Flush(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushes++
	return nil
}
func (s *testSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return nil
}

func newTestDispatcher(t *testing.T, queueSize, sinkQueueSize int) *Dispatcher {
	t.Helper()
	d, err := NewDispatcher(Config{
		QueueSize: queueSize, SinkQueueSize: sinkQueueSize, WarningInterval: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	return d
}

func TestDispatcherDispatchAndKindFiltering(t *testing.T) {
	all, dns := &testSink{}, &testSink{}
	d := newTestDispatcher(t, 8, 8)
	require.NoError(t, d.Register(all))
	require.NoError(t, d.Register(dns, KindDNS))
	require.NoError(t, d.Start(context.Background()))
	require.True(t, d.Enqueue(NewDNSEvent(Envelope{})))
	require.True(t, d.Enqueue(NewHTTPEvent(Envelope{})))
	require.NoError(t, d.Flush(context.Background()))

	all.mu.Lock()
	require.Equal(t, []Kind{KindDNS, KindHTTP}, []Kind{all.events[0].Kind(), all.events[1].Kind()})
	all.mu.Unlock()
	dns.mu.Lock()
	require.Len(t, dns.events, 1)
	require.Equal(t, KindDNS, dns.events[0].Kind())
	dns.mu.Unlock()
	require.NoError(t, d.Close(context.Background()))
}

func TestDispatcherCloseDrainsFlushesAndCloses(t *testing.T) {
	sink := &testSink{}
	d := newTestDispatcher(t, 8, 8)
	require.NoError(t, d.Register(sink))
	require.NoError(t, d.Start(context.Background()))
	for range 4 {
		require.True(t, d.Enqueue(NewConnEvent(Envelope{})))
	}
	require.NoError(t, d.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 4)
	require.Equal(t, 1, sink.flushes)
	require.Equal(t, 1, sink.closes)
}

func TestDispatcherDropsForFullSlowSinkWithoutBlocking(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	sink := &testSink{handle: func(Event) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}}
	d := newTestDispatcher(t, 32, 1)
	require.NoError(t, d.Register(sink))
	require.NoError(t, d.Start(context.Background()))
	require.True(t, d.Enqueue(NewDNSEvent(Envelope{})))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("sink did not receive first event")
	}
	for range 20 {
		d.Enqueue(NewDNSEvent(Envelope{}))
	}
	require.Eventually(t, func() bool { return d.Stats().SinkDropped > 0 }, time.Second, time.Millisecond)
	close(release)
	require.NoError(t, d.Close(context.Background()))
}

func TestDispatcherCountsSinkErrorsAndContinues(t *testing.T) {
	wantErr := errors.New("sink failure")
	sink := &testSink{handle: func(Event) error { return wantErr }}
	d := newTestDispatcher(t, 4, 4)
	require.NoError(t, d.Register(sink))
	require.NoError(t, d.Start(context.Background()))
	require.True(t, d.Enqueue(NewSMTPEvent(Envelope{})))
	require.NoError(t, d.Flush(context.Background()))
	require.Equal(t, uint64(1), d.Stats().SinkErrors)
	require.NoError(t, d.Close(context.Background()))
}

func TestDispatcherQueueFullAndLifecycleValidation(t *testing.T) {
	_, err := NewDispatcher(Config{})
	require.Error(t, err)
	d := newTestDispatcher(t, 1, 1)
	require.False(t, d.Enqueue(NewDNSEvent(Envelope{})))
	require.Equal(t, uint64(1), d.Stats().Dropped)
	require.NoError(t, d.Start(context.Background()))
	require.ErrorIs(t, d.Register(&testSink{}), ErrDispatcherStarted)
	require.ErrorIs(t, d.Start(context.Background()), ErrDispatcherStarted)
	require.NoError(t, d.Close(context.Background()))
	require.False(t, d.Enqueue(NewDNSEvent(Envelope{})))
}

func TestTypedContentSeparation(t *testing.T) {
	metadata := NewFileMetadataEvent(Envelope{UID: "metadata"})
	content := NewFileContentEvent(Envelope{UID: "content"})
	content.Content = []byte("payload")
	require.Equal(t, KindFileMetadata, metadata.Kind())
	require.Equal(t, KindFileContent, content.Kind())
	require.Equal(t, "metadata", metadata.Envelope().UID)
	require.Equal(t, "content", content.Envelope().UID)
}
