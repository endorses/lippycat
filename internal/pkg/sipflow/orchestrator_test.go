package sipflow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memorySelections struct {
	mu       sync.Mutex
	selected map[string]bool
}

func newMemorySelections() *memorySelections {
	return &memorySelections{selected: make(map[string]bool)}
}
func (s *memorySelections) Selected(callID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selected[callID]
}
func (s *memorySelections) MarkSelected(callID string) {
	s.mu.Lock()
	s.selected[callID] = true
	s.mu.Unlock()
}
func (s *memorySelections) Forget(callID string) {
	s.mu.Lock()
	delete(s.selected, callID)
	s.mu.Unlock()
}

type recordingRegistry struct {
	mu           sync.Mutex
	observed     []pipeline.SIPResult
	completed    []string
	observeError error
	completeErr  error
}

func (r *recordingRegistry) Observe(result pipeline.SIPResult) (RegistryObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.observeError != nil {
		return RegistryObservation{}, r.observeError
	}
	r.observed = append(r.observed, result)
	return RegistryObservation{
		Lifecycle:        []pipeline.CallLifecycleObservation{{State: pipeline.CallLifecycleUpdated, Timestamp: result.Timestamp}},
		MatchedFilterIDs: []string{"registry-filter"},
		Attachment:       "registry-attachment",
	}, nil
}
func (r *recordingRegistry) Complete(callID string, _ time.Time) ([]pipeline.CallLifecycleObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completed = append(r.completed, callID)
	return nil, r.completeErr
}

type sinkFunc func(context.Context, SinkInput) pipeline.Result

func (f sinkFunc) HandleSIP(ctx context.Context, input SinkInput) pipeline.Result {
	return f(ctx, input)
}

func sipMessage(startLine, callID, extra string) []byte {
	return []byte(startLine + "\r\nCall-ID: " + callID + "\r\nFrom: <sip:alice@example.test>;tag=a\r\nTo: <sip:bob@example.test>;tag=b\r\n" + extra + "Content-Length: 0\r\n\r\n")
}

func newStarted(t *testing.T, cfg Config) *Orchestrator {
	t.Helper()
	o, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, o.Start(context.Background()))
	t.Cleanup(o.Close)
	return o
}

func TestProcessParsesTypedSIPResultAndPreservesEnvelope(t *testing.T) {
	selections := newMemorySelections()
	registry := &recordingRegistry{}
	o := newStarted(t, Config{SelectionStore: selections, Registry: registry})
	at := time.Unix(123, 456)
	envelope := &pipeline.PacketEnvelope{CaptureTime: at, MatchedFilterIDs: []string{"f-1"}}

	got := o.Process(Message{
		Payload:      sipMessage("INVITE sip:bob@example.test SIP/2.0", "call-1", "CSeq: 1 INVITE\r\n"),
		Envelope:     envelope,
		ParseOptions: sharedsip.ParseOptions{Timestamp: at, SourceIP: "192.0.2.1", DestinationIP: "192.0.2.2", SourcePort: 5060, DestinationPort: 5061},
	})

	require.Equal(t, pipeline.OutcomeAccepted, got.Stage.Outcome)
	assert.Equal(t, "call-1", got.SIP.CallID)
	assert.Equal(t, "INVITE", got.SIP.Method)
	assert.Equal(t, "INVITE", got.SIP.CSeqMethod)
	assert.Equal(t, "alice", got.SIP.FromUser)
	assert.Equal(t, "bob", got.SIP.ToUser)
	assert.Equal(t, "192.0.2.1", got.SIP.SourceIP)
	assert.Equal(t, uint16(5061), got.SIP.DestinationPort)
	assert.Same(t, envelope, got.SIP.Packet)
	assert.Equal(t, []string{"registry-filter"}, got.SIP.MatchedFilterIDs)
	assert.Equal(t, "registry-attachment", got.Attachment)
	assert.Len(t, got.SIP.Lifecycle, 1)
	assert.True(t, selections.Selected("call-1"))
}

func TestProcessParseAndRegistryOutcomes(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		regErr  error
		outcome pipeline.Outcome
	}{
		{name: "not SIP is filtered", payload: []byte("hello"), outcome: pipeline.OutcomeFiltered},
		{name: "malformed content length fails", payload: []byte("INVITE sip:b SIP/2.0\r\nCall-ID: x\r\nContent-Length: nope\r\n\r\n"), outcome: pipeline.OutcomePermanentFailure},
		{name: "missing call ID fails", payload: []byte("OPTIONS sip:b SIP/2.0\r\nContent-Length: 0\r\n\r\n"), outcome: pipeline.OutcomePermanentFailure},
		{name: "registry failure fails", payload: sipMessage("INVITE sip:b SIP/2.0", "x", ""), regErr: errors.New("registry unavailable"), outcome: pipeline.OutcomePermanentFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := newStarted(t, Config{SelectionStore: newMemorySelections(), Registry: &recordingRegistry{observeError: test.regErr}})
			got := o.Process(Message{Payload: test.payload})
			assert.Equal(t, test.outcome, got.Stage.Outcome)
			if test.outcome == pipeline.OutcomePermanentFailure {
				assert.Error(t, got.Stage.Err)
			}
		})
	}
}

func TestExpectedCallIDRejectsBeforeSelectionAndRegistry(t *testing.T) {
	selections := newMemorySelections()
	registry := &recordingRegistry{}
	o := newStarted(t, Config{SelectionStore: selections, Registry: registry})

	got := o.Analyze(Message{
		Payload:        sipMessage("INVITE sip:b SIP/2.0", "parsed", ""),
		ExpectedCallID: "framed", FilterConfigured: true, DirectMatch: true,
	})

	assert.Equal(t, pipeline.OutcomePermanentFailure, got.Stage.Outcome)
	assert.Error(t, got.Stage.Err)
	assert.False(t, selections.Selected("parsed"))
	registry.mu.Lock()
	assert.Empty(t, registry.observed)
	registry.mu.Unlock()
}

func TestStickySelectionPreservesInDialogMessages(t *testing.T) {
	selections := newMemorySelections()
	o := newStarted(t, Config{SelectionStore: selections})

	first := o.Process(Message{Payload: sipMessage("INVITE sip:b SIP/2.0", "sticky", "CSeq: 1 INVITE\r\n"), FilterConfigured: true, DirectMatch: true})
	second := o.Process(Message{Payload: sipMessage("ACK sip:b SIP/2.0", "sticky", "CSeq: 1 ACK\r\n"), FilterConfigured: true})
	unmatched := o.Process(Message{Payload: sipMessage("ACK sip:b SIP/2.0", "other", "CSeq: 1 ACK\r\n"), FilterConfigured: true})

	assert.Equal(t, pipeline.OutcomeAccepted, first.Stage.Outcome)
	assert.Equal(t, pipeline.OutcomeAccepted, second.Stage.Outcome)
	assert.Equal(t, pipeline.OutcomeFiltered, unmatched.Stage.Outcome)
}

func TestNoFilterSelectsMessage(t *testing.T) {
	o := newStarted(t, Config{SelectionStore: newMemorySelections()})
	got := o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "all", "CSeq: 1 OPTIONS\r\n")})
	assert.Equal(t, pipeline.OutcomeAccepted, got.Stage.Outcome)
}

func TestDialogCompletionPolicy(t *testing.T) {
	policy := DialogCompletionPolicy{}
	cases := []struct {
		line, cseq string
		want       bool
	}{
		{"BYE sip:b SIP/2.0", "2 BYE", true},
		{"CANCEL sip:b SIP/2.0", "1 CANCEL", true},
		{"SIP/2.0 200 OK", "2 BYE", true},
		{"SIP/2.0 487 Request Terminated", "1 CANCEL", true},
		{"SIP/2.0 180 Ringing", "1 INVITE", false},
		{"ACK sip:b SIP/2.0", "1 ACK", false},
	}
	for _, tc := range cases {
		event, err := sharedsip.Parse(sipMessage(tc.line, "complete", "CSeq: "+tc.cseq+"\r\n"), sharedsip.ParseOptions{})
		require.NoError(t, err)
		assert.Equal(t, tc.want, policy.Completes(event), tc.line)
	}
}

func TestCompletionRunsAfterEverySinkAndForQueueDrop(t *testing.T) {
	selections := newMemorySelections()
	registry := &recordingRegistry{}
	o, err := New(Config{SelectionStore: selections, Registry: registry})
	require.NoError(t, err)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	require.NoError(t, o.RegisterSink("blocked", sinkFunc(func(context.Context, SinkInput) pipeline.Result {
		started <- struct{}{}
		<-release
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	}), 1))
	require.NoError(t, o.Start(context.Background()))
	t.Cleanup(o.Close)

	// Occupy the worker and its queue, then make the terminal delivery drop.
	o.Process(Message{Payload: sipMessage("INVITE sip:b SIP/2.0", "occupy", "")})
	<-started
	o.Process(Message{Payload: sipMessage("INVITE sip:b SIP/2.0", "queued", "")})
	terminal := o.Process(Message{Payload: sipMessage("BYE sip:b SIP/2.0", "terminal", "CSeq: 2 BYE\r\n")})
	require.Equal(t, pipeline.OutcomeDropped, terminal.Sinks["blocked"].Outcome)
	require.Eventually(t, func() bool {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		return assert.ObjectsAreEqual([]string{"terminal"}, registry.completed)
	}, time.Second, time.Millisecond)
	assert.False(t, selections.Selected("terminal"))
	close(release)
}

func TestTerminalCompletionWaitsForSuccessfulSink(t *testing.T) {
	selections := newMemorySelections()
	registry := &recordingRegistry{}
	o, err := New(Config{SelectionStore: selections, Registry: registry})
	require.NoError(t, err)
	release := make(chan struct{})
	seen := make(chan struct{})
	require.NoError(t, o.RegisterSink("output", sinkFunc(func(context.Context, SinkInput) pipeline.Result {
		close(seen)
		<-release
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	}), 1))
	require.NoError(t, o.Start(context.Background()))
	t.Cleanup(o.Close)

	o.Process(Message{Payload: sipMessage("BYE sip:b SIP/2.0", "ordered", "CSeq: 2 BYE\r\n")})
	<-seen
	registry.mu.Lock()
	assert.Empty(t, registry.completed)
	registry.mu.Unlock()
	close(release)
	require.Eventually(t, func() bool {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		return len(registry.completed) == 1
	}, time.Second, time.Millisecond)
}

func TestSinkFanoutIsIndependentAndMetricsArePerSink(t *testing.T) {
	o, err := New(Config{SelectionStore: newMemorySelections()})
	require.NoError(t, err)
	release := make(chan struct{})
	slowStarted := make(chan struct{}, 1)
	fastCount := make(chan struct{}, 3)
	require.NoError(t, o.RegisterSink("slow", sinkFunc(func(context.Context, SinkInput) pipeline.Result {
		slowStarted <- struct{}{}
		<-release
		return pipeline.Result{Outcome: pipeline.OutcomeRetryableFailure, Err: errors.New("retry")}
	}), 1))
	require.NoError(t, o.RegisterSink("fast", sinkFunc(func(context.Context, SinkInput) pipeline.Result {
		fastCount <- struct{}{}
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	}), 4))
	require.NoError(t, o.Start(context.Background()))
	t.Cleanup(o.Close)

	o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "one", "")})
	<-slowStarted
	o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "two", "")})
	third := o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "three", "")})
	require.Equal(t, pipeline.OutcomeDropped, third.Sinks["slow"].Outcome)
	require.Equal(t, pipeline.DropQueueFull, third.Sinks["slow"].DropReason)
	require.Equal(t, pipeline.OutcomeAccepted, third.Sinks["fast"].Outcome)
	for range 3 {
		select {
		case <-fastCount:
		case <-time.After(time.Second):
			t.Fatal("fast sink was controlled by slow sink")
		}
	}
	close(release)
	require.Eventually(t, func() bool {
		stats := o.Stats()
		return stats["slow"].Dropped == 1 && stats["slow"].RetryableFailures == 2 && stats["fast"].Accepted == 3
	}, time.Second, time.Millisecond)
	stats := o.Stats()
	assert.Equal(t, uint64(1), stats["slow"].QueueFull)
	assert.Zero(t, stats["fast"].Dropped)
}

func TestSinkTypedOutcomesAndDropReasonsAreCounted(t *testing.T) {
	outcomes := []pipeline.Result{
		{Outcome: pipeline.OutcomeFiltered},
		{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropBufferFull},
		{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropRateLimited},
		{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropExpired},
		{Outcome: pipeline.OutcomePermanentFailure},
		{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown},
	}
	var mu sync.Mutex
	o, err := New(Config{SelectionStore: newMemorySelections()})
	require.NoError(t, err)
	require.NoError(t, o.RegisterSink("typed", sinkFunc(func(context.Context, SinkInput) pipeline.Result {
		mu.Lock()
		defer mu.Unlock()
		result := outcomes[0]
		outcomes = outcomes[1:]
		return result
	}), 8))
	require.NoError(t, o.Start(context.Background()))
	for i := 0; i < 6; i++ {
		o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", string(rune('a'+i)), "")})
	}
	o.Close()
	stats := o.Stats()["typed"]
	assert.Equal(t, uint64(1), stats.Filtered)
	assert.Equal(t, uint64(3), stats.Dropped)
	assert.Equal(t, uint64(1), stats.PermanentFailures)
	assert.Equal(t, uint64(1), stats.Shutdown)
	assert.Equal(t, uint64(1), stats.BufferFull)
	assert.Equal(t, uint64(1), stats.RateLimited)
	assert.Equal(t, uint64(1), stats.Expired)
	assert.Equal(t, uint64(1), stats.ShutdownDrops)
}

func TestLifecycleAndConfigurationErrors(t *testing.T) {
	_, err := New(Config{})
	require.Error(t, err)
	o, err := New(Config{SelectionStore: newMemorySelections()})
	require.NoError(t, err)
	assert.Error(t, o.RegisterSink("", sinkFunc(func(context.Context, SinkInput) pipeline.Result { return pipeline.Result{} }), 1))
	before := o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "x", "")})
	assert.ErrorIs(t, before.Stage.Err, ErrNotStarted)
	require.NoError(t, o.Start(context.Background()))
	assert.ErrorIs(t, o.Start(context.Background()), ErrStarted)
	o.Close()
	o.Close()
	after := o.Process(Message{Payload: sipMessage("OPTIONS sip:b SIP/2.0", "x", "")})
	assert.Equal(t, pipeline.OutcomeShutdown, after.Stage.Outcome)
}

func TestAnalyzeUsesProvidedParsedEventWithoutReparsingPayload(t *testing.T) {
	o := newStarted(t, Config{SelectionStore: newMemorySelections()})
	event, err := sharedsip.Parse(sipMessage("INVITE sip:b SIP/2.0", "parsed-once", ""), sharedsip.ParseOptions{})
	require.NoError(t, err)

	result := o.Analyze(Message{
		Payload:          []byte("this payload is deliberately not SIP"),
		Event:            &event,
		ExpectedCallID:   event.CallID,
		FilterConfigured: false,
	})
	assert.Equal(t, pipeline.OutcomeAccepted, result.Stage.Outcome)
	assert.Equal(t, event.CallID, result.SIP.CallID)
}
