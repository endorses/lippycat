package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// PacketSink consumes normalized packets. Close must drain accepted work and
// be idempotent.
type PacketSink interface {
	HandlePacket(context.Context, *PacketEnvelope) Result
	Close(context.Context) error
}

// SinkResult attributes a delivery outcome to one configured sink.
type SinkResult struct {
	Name   string
	Result Result
}

// PacketFanout delivers each envelope to sinks in registration order.
// Delivery is synchronous; a sink that needs independent backpressure owns its
// queue and reports queue pressure through Result.
type PacketFanout struct {
	mu     sync.RWMutex
	sinks  []namedPacketSink
	closed bool
	once   sync.Once
	err    error
}

type namedPacketSink struct {
	name string
	sink PacketSink
}

// NewPacketFanout creates a fanout. Sink names must be non-empty and unique.
func NewPacketFanout(sinks ...SinkRegistration) (*PacketFanout, error) {
	f := &PacketFanout{}
	seen := make(map[string]struct{}, len(sinks))
	for _, registration := range sinks {
		if registration.Name == "" {
			return nil, errors.New("packet sink name is empty")
		}
		if registration.Sink == nil {
			return nil, fmt.Errorf("packet sink %q is nil", registration.Name)
		}
		if _, exists := seen[registration.Name]; exists {
			return nil, fmt.Errorf("packet sink name %q is duplicated", registration.Name)
		}
		seen[registration.Name] = struct{}{}
		f.sinks = append(f.sinks, namedPacketSink{name: registration.Name, sink: registration.Sink})
	}
	return f, nil
}

// SinkRegistration gives a sink a stable name for outcome attribution.
type SinkRegistration struct {
	Name string
	Sink PacketSink
}

// Dispatch offers an envelope to every sink and returns outcomes in
// registration order.
func (f *PacketFanout) Dispatch(ctx context.Context, envelope *PacketEnvelope) []SinkResult {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return []SinkResult{{Name: "fanout", Result: Result{Outcome: OutcomeShutdown, DropReason: DropShutdown, Err: context.Canceled}}}
	}
	results := make([]SinkResult, 0, len(f.sinks))
	for _, configured := range f.sinks {
		if err := ctx.Err(); err != nil {
			results = append(results, SinkResult{Name: configured.name, Result: Result{Outcome: OutcomeShutdown, DropReason: DropShutdown, Err: err}})
			continue
		}
		results = append(results, SinkResult{Name: configured.name, Result: configured.sink.HandlePacket(ctx, envelope)})
	}
	return results
}

// Close closes sinks in reverse registration order and joins all close errors.
func (f *PacketFanout) Close(ctx context.Context) error {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		sinks := append([]namedPacketSink(nil), f.sinks...)
		f.mu.Unlock()
		for i := len(sinks) - 1; i >= 0; i-- {
			if err := sinks[i].sink.Close(ctx); err != nil {
				f.err = errors.Join(f.err, fmt.Errorf("close packet sink %q: %w", sinks[i].name, err))
			}
		}
	})
	return f.err
}

// EnvelopeRunner dispatches an ordered envelope stream. Outcome receives every
// dispatch result before the next envelope is read.
type EnvelopeRunner struct {
	Fanout  *PacketFanout
	Outcome func(*PacketEnvelope, []SinkResult)
}

// Run blocks until input closes or the context is cancelled. The first
// actionable sink error is retained and returned after the input has drained;
// sinks own detailed failure metrics, so repeated failures cannot grow runner
// memory without bound.
func (r EnvelopeRunner) Run(ctx context.Context, input <-chan *PacketEnvelope) error {
	if r.Fanout == nil {
		return errors.New("packet fanout is nil")
	}
	var runErr error
	for {
		select {
		case <-ctx.Done():
			return errors.Join(runErr, ctx.Err())
		case envelope, ok := <-input:
			if !ok {
				return runErr
			}
			results := r.Fanout.Dispatch(ctx, envelope)
			if r.Outcome != nil {
				r.Outcome(envelope, results)
			}
			for _, result := range results {
				if runErr == nil && result.Result.Err != nil && result.Result.Outcome != OutcomeShutdown {
					runErr = fmt.Errorf("packet sink %q: %w", result.Name, result.Result.Err)
				}
			}
		}
	}
}
