// Package sipflow composes output-neutral SIP parsing, dialog selection, call
// registry updates, and independently buffered sinks.
package sipflow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

var (
	ErrStarted    = errors.New("SIP orchestrator already started")
	ErrNotStarted = errors.New("SIP orchestrator not started")
	ErrClosed     = errors.New("SIP orchestrator closed")
)

// Message is exactly one framed SIP message and its selection context.
type Message struct {
	Payload []byte
	// Event carries a parser result produced by an ingress/framing layer. When
	// present Analyze uses it directly and does not parse Payload again.
	Event *sharedsip.Event
	// ExpectedCallID, when set by a framing layer, must match the parsed value
	// before selection or registry mutation.
	ExpectedCallID   string
	Envelope         *pipeline.PacketEnvelope
	ParseOptions     sharedsip.ParseOptions
	FilterConfigured bool
	DirectMatch      bool
	// Match evaluates topology-specific filters against the already parsed
	// message. It avoids forcing adapters to parse SIP a second time.
	Match func(sharedsip.Event) bool
	// Validate applies topology security policy after the single shared parse and
	// before selection or registry mutation.
	Validate func(sharedsip.Event) error
}

// Registry owns call state. Observe runs for selected messages before they are
// published. Complete runs after every sink has handled or dropped a terminal
// result, preserving final-message ordering.
type Registry interface {
	Observe(pipeline.SIPResult) (RegistryObservation, error)
	Complete(callID string, at time.Time) ([]pipeline.CallLifecycleObservation, error)
}

// RegistryObservation enriches a domain result and may carry an adapter-owned
// value to its sinks. Attachment is deliberately opaque: protobuf conversion
// and other topology details remain outside this package.
type RegistryObservation struct {
	Lifecycle        []pipeline.CallLifecycleObservation
	MatchedFilterIDs []string
	Attachment       any
}

// SelectionStore retains the sticky selection decision for a dialog. Its
// implementation is topology-owned so its lifetime and bounds are explicit.
type SelectionStore interface {
	Selected(callID string) bool
	MarkSelected(callID string)
	Forget(callID string)
}

// Sink consumes selected SIP results. It must describe delivery using the
// pipeline's typed result contract.
type Sink interface {
	HandleSIP(context.Context, SinkInput) pipeline.Result
}

type SinkInput struct {
	Result     pipeline.SIPResult
	Attachment any
}

// CompletionPolicy identifies messages that end a dialog. Completion occurs
// after sink delivery, never before the terminal message is visible to sinks.
type CompletionPolicy interface {
	Completes(sharedsip.Event) bool
}

// DialogCompletionPolicy completes on BYE/CANCEL requests and their final
// responses. Deployments needing time-wait can supply a different policy.
type DialogCompletionPolicy struct{}

func (DialogCompletionPolicy) Completes(event sharedsip.Event) bool {
	if event.Method == "BYE" || event.Method == "CANCEL" {
		return true
	}
	return event.ResponseCode >= 200 && (event.CSeqMethod == "BYE" || event.CSeqMethod == "CANCEL")
}

type Config struct {
	SelectionPolicy callregistry.SelectionPolicy
	SelectionStore  SelectionStore
	Registry        Registry
	Completion      CompletionPolicy
}

// ProcessResult reports orchestration acceptance separately from asynchronous
// sink delivery. Sink enqueue outcomes are attributable by sink name.
type ProcessResult struct {
	SIP        pipeline.SIPResult
	Stage      pipeline.Result
	Sinks      map[string]pipeline.Result
	Attachment any
	Terminal   bool
}

type sinkRegistration struct {
	name  string
	sink  Sink
	queue chan delivery
	stats sinkCounters
}

type delivery struct {
	input SinkInput
	done  func()
}

type sinkCounters struct {
	accepted, filtered, dropped, retryable, permanent, shutdown atomic.Uint64
	queueFull, bufferFull, rateLimited, expired, shutdownDrop   atomic.Uint64
}

type SinkStats struct {
	Accepted, Filtered, Dropped                 uint64
	RetryableFailures, PermanentFailures        uint64
	Shutdown                                    uint64
	QueueFull, BufferFull, RateLimited, Expired uint64
	ShutdownDrops                               uint64
}

type Orchestrator struct {
	cfg Config

	mu      sync.RWMutex
	sinks   []*sinkRegistration
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func New(cfg Config) (*Orchestrator, error) {
	if cfg.SelectionPolicy == nil {
		cfg.SelectionPolicy = callregistry.StickySelectionPolicy{}
	}
	if cfg.SelectionStore == nil {
		return nil, fmt.Errorf("selection store is required")
	}
	if cfg.Completion == nil {
		cfg.Completion = DialogCompletionPolicy{}
	}
	return &Orchestrator{cfg: cfg}, nil
}

// RegisterSink adds a named, independently buffered sink before Start.
func (o *Orchestrator) RegisterSink(name string, sink Sink, queueSize int) error {
	if name == "" || sink == nil || queueSize <= 0 {
		return fmt.Errorf("sink name, implementation, and positive queue size are required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.started || o.closed {
		if o.closed {
			return ErrClosed
		}
		return ErrStarted
	}
	for _, existing := range o.sinks {
		if existing.name == name {
			return fmt.Errorf("duplicate SIP sink %q", name)
		}
	}
	o.sinks = append(o.sinks, &sinkRegistration{name: name, sink: sink, queue: make(chan delivery, queueSize)})
	return nil
}

func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.started {
		return ErrStarted
	}
	if o.closed {
		return ErrClosed
	}
	o.started = true
	o.ctx, o.cancel = context.WithCancel(ctx)
	for _, registered := range o.sinks {
		o.wg.Add(1)
		go o.runSink(registered)
	}
	return nil
}

// Analyze synchronously parses and selects a message and updates call state.
// It does not publish to sinks, allowing topology adapters to buffer selected
// messages while preserving their parsed result and registry observation.
func (o *Orchestrator) Analyze(message Message) ProcessResult {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.started {
		return ProcessResult{Stage: pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: ErrNotStarted}}
	}
	if o.closed || o.ctx.Err() != nil {
		return ProcessResult{Stage: pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: ErrClosed}}
	}

	var event sharedsip.Event
	var err error
	if message.Event != nil {
		event = *message.Event
	} else {
		event, err = sharedsip.Parse(message.Payload, message.ParseOptions)
	}
	if err != nil {
		outcome := pipeline.OutcomePermanentFailure
		if errors.Is(err, sharedsip.ErrNotSIP) {
			outcome = pipeline.OutcomeFiltered
		}
		return ProcessResult{Stage: pipeline.Result{Outcome: outcome, Err: err}}
	}
	if event.CallID == "" {
		return ProcessResult{Stage: pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("SIP message has no Call-ID")}}
	}
	result := pipeline.SIPResultFromEvent(event, message.Envelope)
	if message.Envelope != nil {
		result.MatchedFilterIDs = append([]string(nil), message.Envelope.MatchedFilterIDs...)
	}
	if message.ExpectedCallID != "" && event.CallID != message.ExpectedCallID {
		return ProcessResult{
			SIP: pipeline.SIPResultFromEvent(event, message.Envelope),
			Stage: pipeline.Result{Outcome: pipeline.OutcomePermanentFailure,
				Err: fmt.Errorf("parsed SIP Call-ID does not match framed Call-ID")},
		}
	}
	if message.Validate != nil {
		if err := message.Validate(event); err != nil {
			return ProcessResult{SIP: pipeline.SIPResultFromEvent(event, message.Envelope), Stage: pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: err}}
		}
	}
	previouslySelected := o.cfg.SelectionStore.Selected(event.CallID)
	directMatch := message.DirectMatch
	if message.Match != nil {
		directMatch = directMatch || message.Match(event)
	}
	if !o.cfg.SelectionPolicy.Select(callregistry.SelectionInput{
		FilterConfigured:   message.FilterConfigured,
		DirectMatch:        directMatch,
		PreviouslySelected: previouslySelected,
	}) {
		return ProcessResult{SIP: result, Stage: pipeline.Result{Outcome: pipeline.OutcomeFiltered}}
	}
	o.cfg.SelectionStore.MarkSelected(event.CallID)
	if o.cfg.Registry != nil {
		observation, observeErr := o.cfg.Registry.Observe(result)
		if observeErr != nil {
			if !previouslySelected {
				o.cfg.SelectionStore.Forget(event.CallID)
			}
			return ProcessResult{SIP: result, Stage: pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("observe SIP call: %w", observeErr)}}
		}
		result.Lifecycle = append(result.Lifecycle, observation.Lifecycle...)
		if len(observation.MatchedFilterIDs) > 0 {
			result.MatchedFilterIDs = append([]string(nil), observation.MatchedFilterIDs...)
		}
		return ProcessResult{SIP: result, Stage: pipeline.Result{Outcome: pipeline.OutcomeAccepted}, Attachment: observation.Attachment, Terminal: o.cfg.Completion.Completes(event)}
	}
	return ProcessResult{SIP: result, Stage: pipeline.Result{Outcome: pipeline.OutcomeAccepted}, Terminal: o.cfg.Completion.Completes(event)}
}

// Dispatch offers an accepted analysis to every sink. A full sink queue does
// not block any other sink. Non-accepted analyses are returned unchanged.
func (o *Orchestrator) Dispatch(analysis ProcessResult) ProcessResult {
	if analysis.Stage.Outcome != pipeline.OutcomeAccepted {
		return analysis
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.started {
		analysis.Stage = pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: ErrNotStarted}
		return analysis
	}
	if o.closed || o.ctx.Err() != nil {
		analysis.Stage = pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: ErrClosed}
		return analysis
	}

	var pending atomic.Int64
	completion := func() {
		if pending.Add(-1) != 0 {
			return
		}
		if o.cfg.Registry != nil {
			if _, err := o.cfg.Registry.Complete(analysis.SIP.CallID, analysis.SIP.Timestamp); err != nil {
				logger.Error("Failed to complete SIP dialog",
					"operation", "post_sink_completion",
					"error", err)
			}
		}
		o.cfg.SelectionStore.Forget(analysis.SIP.CallID)
	}
	responses := make(map[string]pipeline.Result, len(o.sinks))
	if analysis.Terminal {
		pending.Store(int64(len(o.sinks)))
	}
	for _, registered := range o.sinks {
		item := delivery{input: SinkInput{Result: analysis.SIP, Attachment: analysis.Attachment}}
		if analysis.Terminal {
			item.done = completion
		}
		select {
		case registered.queue <- item:
			responses[registered.name] = pipeline.Result{Outcome: pipeline.OutcomeAccepted}
		default:
			dropped := pipeline.Result{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropQueueFull}
			registered.stats.record(dropped)
			responses[registered.name] = dropped
			if item.done != nil {
				item.done()
			}
		}
	}
	if analysis.Terminal && len(o.sinks) == 0 {
		if o.cfg.Registry != nil {
			if _, err := o.cfg.Registry.Complete(analysis.SIP.CallID, analysis.SIP.Timestamp); err != nil {
				logger.Error("Failed to complete SIP dialog",
					"operation", "no_sink_completion",
					"error", err)
			}
		}
		o.cfg.SelectionStore.Forget(analysis.SIP.CallID)
	}
	analysis.Sinks = responses
	return analysis
}

// Process composes Analyze and Dispatch for modes that do not need an
// intermediate buffer.
func (o *Orchestrator) Process(message Message) ProcessResult {
	return o.Dispatch(o.Analyze(message))
}

func (o *Orchestrator) runSink(registered *sinkRegistration) {
	defer o.wg.Done()
	for item := range registered.queue {
		result := registered.sink.HandleSIP(o.ctx, item.input)
		registered.stats.record(result)
		if item.done != nil {
			item.done()
		}
	}
}

// Close stops admission, drains all accepted sink work, and is idempotent.
func (o *Orchestrator) Close() {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		o.wg.Wait()
		return
	}
	o.closed = true
	for _, registered := range o.sinks {
		close(registered.queue)
	}
	o.mu.Unlock()
	o.wg.Wait()
	if o.cancel != nil {
		o.cancel()
	}
}

func (o *Orchestrator) Stats() map[string]SinkStats {
	o.mu.RLock()
	defer o.mu.RUnlock()
	stats := make(map[string]SinkStats, len(o.sinks))
	for _, registered := range o.sinks {
		stats[registered.name] = registered.stats.snapshot()
	}
	return stats
}

func (s *sinkCounters) record(result pipeline.Result) {
	switch result.Outcome {
	case pipeline.OutcomeAccepted:
		s.accepted.Add(1)
	case pipeline.OutcomeFiltered:
		s.filtered.Add(1)
	case pipeline.OutcomeDropped:
		s.dropped.Add(1)
	case pipeline.OutcomeRetryableFailure:
		s.retryable.Add(1)
	case pipeline.OutcomePermanentFailure:
		s.permanent.Add(1)
	case pipeline.OutcomeShutdown:
		s.shutdown.Add(1)
	}
	switch result.DropReason {
	case pipeline.DropQueueFull:
		s.queueFull.Add(1)
	case pipeline.DropBufferFull:
		s.bufferFull.Add(1)
	case pipeline.DropRateLimited:
		s.rateLimited.Add(1)
	case pipeline.DropExpired:
		s.expired.Add(1)
	case pipeline.DropShutdown:
		s.shutdownDrop.Add(1)
	}
}

func (s *sinkCounters) snapshot() SinkStats {
	return SinkStats{
		Accepted: s.accepted.Load(), Filtered: s.filtered.Load(), Dropped: s.dropped.Load(),
		RetryableFailures: s.retryable.Load(), PermanentFailures: s.permanent.Load(), Shutdown: s.shutdown.Load(),
		QueueFull: s.queueFull.Load(), BufferFull: s.bufferFull.Load(), RateLimited: s.rateLimited.Load(),
		Expired: s.expired.Load(), ShutdownDrops: s.shutdownDrop.Load(),
	}
}
