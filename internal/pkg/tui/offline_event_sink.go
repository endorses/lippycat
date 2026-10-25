//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

// offlineEventSink persists directly from the dispatcher's bounded lossless
// queue. It owns no additional queue or detached worker. Every accepted metadata
// snapshot reaches disk before the compatibility ring; errors cancel indexing
// and remain observable through Err, Flush and Close.
type offlineEventSink struct {
	mu      sync.Mutex
	builder *offline.EventBuilder
	store   *store.EventStore
	cancel  context.CancelCauseFunc
	failure error
	closed  bool
}

type offlineEventPersistenceError struct{ cause error }

func (e *offlineEventPersistenceError) Error() string {
	return fmt.Sprintf("persist offline event history: %v", e.cause)
}
func (e *offlineEventPersistenceError) Unwrap() error           { return e.cause }
func (e *offlineEventPersistenceError) TerminalSinkError() bool { return true }

func newOfflineEventSink(builder *offline.EventBuilder, retained *store.EventStore, cancel context.CancelCauseFunc) *offlineEventSink {
	return &offlineEventSink{builder: builder, store: retained, cancel: cancel}
}

func (s *offlineEventSink) HandleEvent(ctx context.Context, event events.Event) error {
	if event == nil || (reflect.ValueOf(event).Kind() == reflect.Pointer && reflect.ValueOf(event).IsNil()) {
		return nil
	}
	if event.Kind() == events.KindFileContent {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	if s.closed {
		return errors.New("offline event sink is closed")
	}
	if s.builder == nil {
		return s.fail(errors.New("offline event builder is unavailable"))
	}
	if err := s.builder.Append(ctx, event); err != nil {
		return s.fail(err)
	}
	if s.store != nil {
		s.store.AddBatch([]events.Event{event})
	}
	return nil
}

// fail is called with mu held. The first failure is the index cancellation cause;
// subsequent queued events cannot replace it or turn the prefix into success.
func (s *offlineEventSink) fail(err error) error {
	if s.failure == nil {
		s.failure = &offlineEventPersistenceError{cause: err}
		if s.cancel != nil {
			s.cancel(s.failure)
		}
	}
	return s.failure
}

func (s *offlineEventSink) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

func (s *offlineEventSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.failure, ctx.Err())
}

func (s *offlineEventSink) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return errors.Join(s.failure, ctx.Err())
}

var _ events.Sink = (*offlineEventSink)(nil)
