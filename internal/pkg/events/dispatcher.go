package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

var ErrDispatcherStarted = errors.New("event dispatcher already started")

type Config struct {
	QueueSize       int
	SinkQueueSize   int
	WarningInterval time.Duration
	Logger          *slog.Logger
}

type Stats struct{ Enqueued, Dispatched, Dropped, SinkDropped, SinkErrors uint64 }

type dispatchItem struct {
	event   Event
	barrier chan struct{}
}
type sinkItem struct {
	event   Event
	barrier chan struct{}
}
type registration struct {
	sink  Sink
	kinds map[Kind]struct{}
	queue chan sinkItem
}

type Dispatcher struct {
	cfg                                                    Config
	queue                                                  chan dispatchItem
	mu                                                     sync.RWMutex
	registrations                                          []*registration
	started, stopped                                       bool
	ctx                                                    context.Context
	cancel                                                 context.CancelFunc
	dispatchWG, sinkWG                                     sync.WaitGroup
	enqueued, dispatched, dropped, sinkDropped, sinkErrors atomic.Uint64
}

func NewDispatcher(cfg Config) (*Dispatcher, error) {
	if cfg.QueueSize <= 0 {
		return nil, fmt.Errorf("event queue size must be positive")
	}
	if cfg.SinkQueueSize <= 0 {
		cfg.SinkQueueSize = cfg.QueueSize
	}
	if cfg.WarningInterval <= 0 {
		cfg.WarningInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Get()
	}
	return &Dispatcher{cfg: cfg, queue: make(chan dispatchItem, cfg.QueueSize)}, nil
}

// Register subscribes sink to kinds. An empty kind list subscribes to all events.
// Registration is restricted to before Start so routing remains race-free.
func (d *Dispatcher) Register(sink Sink, kinds ...Kind) error {
	if sink == nil {
		return fmt.Errorf("register event sink: nil sink")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return ErrDispatcherStarted
	}
	set := make(map[Kind]struct{}, len(kinds))
	for _, kind := range kinds {
		set[kind] = struct{}{}
	}
	d.registrations = append(d.registrations, &registration{sink: sink, kinds: set, queue: make(chan sinkItem, d.cfg.SinkQueueSize)})
	return nil
}

func (d *Dispatcher) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return ErrDispatcherStarted
	}
	if d.stopped {
		return fmt.Errorf("event dispatcher cannot be restarted after stop")
	}
	d.started = true
	d.ctx, d.cancel = context.WithCancel(ctx)
	for _, reg := range d.registrations {
		d.sinkWG.Add(1)
		go d.runSink(reg)
	}
	d.dispatchWG.Add(1)
	go d.runDispatcher()
	return nil
}

// Enqueue never waits for a sink or for queue space.
func (d *Dispatcher) Enqueue(ev Event) bool {
	if ev == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.started || d.stopped {
		d.dropped.Add(1)
		return false
	}
	select {
	case d.queue <- dispatchItem{event: ev}:
		d.enqueued.Add(1)
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}

func (d *Dispatcher) runDispatcher() {
	defer d.dispatchWG.Done()
	ticker := time.NewTicker(d.cfg.WarningInterval)
	defer ticker.Stop()
	var previousDropped, previousSinkDropped uint64
	for {
		select {
		case item, ok := <-d.queue:
			if !ok {
				for _, reg := range d.registrations {
					close(reg.queue)
				}
				return
			}
			if item.barrier != nil {
				for _, reg := range d.registrations {
					reg.queue <- sinkItem{barrier: item.barrier}
				}
				continue
			}
			ev := item.event
			for _, reg := range d.registrations {
				if len(reg.kinds) > 0 {
					if _, ok := reg.kinds[ev.Kind()]; !ok {
						continue
					}
				}
				select {
				case reg.queue <- sinkItem{event: ev}:
					d.dispatched.Add(1)
				default:
					d.sinkDropped.Add(1)
				}
			}
		case <-ticker.C:
			dropped, sinkDropped := d.dropped.Load(), d.sinkDropped.Load()
			if dropped > previousDropped || sinkDropped > previousSinkDropped {
				d.cfg.Logger.Warn("normalized protocol events dropped", "dispatcher_dropped", dropped-previousDropped, "sink_dropped", sinkDropped-previousSinkDropped)
			}
			previousDropped, previousSinkDropped = dropped, sinkDropped
		}
	}
}

func (d *Dispatcher) runSink(reg *registration) {
	defer d.sinkWG.Done()
	for item := range reg.queue {
		if item.barrier != nil {
			item.barrier <- struct{}{}
			continue
		}
		if err := reg.sink.HandleEvent(d.ctx, item.event); err != nil {
			d.sinkErrors.Add(1)
			d.cfg.Logger.Error("normalized event sink failed", "kind", item.event.Kind(), "error", err)
		}
	}
}

// Stop drains accepted events, then flushes every sink. It does not close sinks.
func (d *Dispatcher) Stop(ctx context.Context) error {
	d.mu.Lock()
	if !d.started {
		d.stopped = true
		d.mu.Unlock()
		return nil
	}
	if d.stopped {
		d.mu.Unlock()
		return nil
	}
	d.stopped = true
	close(d.queue)
	d.mu.Unlock()
	if err := waitGroup(ctx, &d.dispatchWG); err != nil {
		d.cancel()
		return fmt.Errorf("drain event dispatcher: %w", err)
	}
	if err := waitGroup(ctx, &d.sinkWG); err != nil {
		d.cancel()
		return fmt.Errorf("drain event sinks: %w", err)
	}
	var result error
	for _, reg := range d.registrations {
		if err := reg.sink.Flush(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("flush event sink: %w", err))
		}
	}
	d.cancel()
	return result
}

// Flush waits for all events accepted before the call, then flushes sinks.
func (d *Dispatcher) Flush(ctx context.Context) error {
	d.mu.RLock()
	if !d.started || d.stopped {
		d.mu.RUnlock()
		return nil
	}
	barrier := make(chan struct{}, len(d.registrations))
	select {
	case d.queue <- dispatchItem{barrier: barrier}:
		d.mu.RUnlock()
	case <-ctx.Done():
		d.mu.RUnlock()
		return fmt.Errorf("queue event flush barrier: %w", ctx.Err())
	}
	for range d.registrations {
		select {
		case <-barrier:
		case <-ctx.Done():
			return fmt.Errorf("wait for event flush barrier: %w", ctx.Err())
		}
	}
	var result error
	for _, reg := range d.registrations {
		if err := reg.sink.Flush(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("flush event sink: %w", err))
		}
	}
	return result
}

func (d *Dispatcher) Close(ctx context.Context) error {
	result := d.Stop(ctx)
	for _, reg := range d.registrations {
		if err := reg.sink.Close(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("close event sink: %w", err))
		}
	}
	return result
}

func (d *Dispatcher) QueueDepth() int    { return len(d.queue) }
func (d *Dispatcher) QueueCapacity() int { return cap(d.queue) }
func (d *Dispatcher) Stats() Stats {
	return Stats{d.enqueued.Load(), d.dispatched.Load(), d.dropped.Load(), d.sinkDropped.Load(), d.sinkErrors.Load()}
}

func waitGroup(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
