package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
	name    string
	sink    PacketSink
	metrics sinkMetrics
}

const outcomeCount = int(OutcomeShutdown) + 1
const dropReasonCount = int(DropShutdown) + 1

type sinkMetrics struct {
	outcomes [outcomeCount]atomic.Uint64
	drops    [dropReasonCount]atomic.Uint64
}

// SinkMetrics is a point-in-time snapshot of outcomes attributed to one sink.
type SinkMetrics struct {
	Outcomes map[Outcome]uint64
	Drops    map[DropReason]uint64
}

func (m *sinkMetrics) record(result Result) {
	if int(result.Outcome) < len(m.outcomes) {
		m.outcomes[result.Outcome].Add(1)
	}
	if result.DropReason != DropNone && int(result.DropReason) < len(m.drops) {
		m.drops[result.DropReason].Add(1)
	}
}

func (m *sinkMetrics) snapshot() SinkMetrics {
	snapshot := SinkMetrics{Outcomes: make(map[Outcome]uint64), Drops: make(map[DropReason]uint64)}
	for outcome := OutcomeAccepted; int(outcome) < len(m.outcomes); outcome++ {
		if count := m.outcomes[outcome].Load(); count != 0 {
			snapshot.Outcomes[outcome] = count
		}
	}
	for reason := DropNone; int(reason) < len(m.drops); reason++ {
		if count := m.drops[reason].Load(); count != 0 {
			snapshot.Drops[reason] = count
		}
	}
	return snapshot
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
	for i := range f.sinks {
		configured := &f.sinks[i]
		if err := ctx.Err(); err != nil {
			result := Result{Outcome: OutcomeShutdown, DropReason: DropShutdown, Err: err}
			configured.metrics.record(result)
			results = append(results, SinkResult{Name: configured.name, Result: result})
			continue
		}
		result := configured.sink.HandlePacket(ctx, envelope)
		configured.metrics.record(result)
		results = append(results, SinkResult{Name: configured.name, Result: result})
	}
	return results
}

// Metrics returns point-in-time outcome and drop counters keyed by sink name.
func (f *PacketFanout) Metrics() map[string]SinkMetrics {
	f.mu.RLock()
	defer f.mu.RUnlock()
	metrics := make(map[string]SinkMetrics, len(f.sinks))
	for i := range f.sinks {
		metrics[f.sinks[i].name] = f.sinks[i].metrics.snapshot()
	}
	return metrics
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
