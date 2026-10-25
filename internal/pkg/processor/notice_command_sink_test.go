//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func commandSinkNotice(sequence uint64) events.NoticeEvent {
	env := events.Envelope{NodeID: "hunter-a", ProducerSessionID: "origin-session", EventSequence: sequence, Timestamp: time.Unix(1700000000, 0)}
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, sequence)
	notice := events.NewNoticeEvent(env)
	notice.Detector, notice.DetectorVersion, notice.Category = events.NoticeDetectorDNSTunneling, "1", events.NoticeCategorySecurity
	notice.Severity = events.NoticeWarning
	notice.DetectorNodeID, notice.DetectorGeneration = "controller", "local-generation"
	notice.DNS = &events.DNSNoticeEvidence{Domain: fmt.Sprintf("domain-%d.example", sequence), Score: 0.95, Threshold: 0.7, Entropy: 4.5, Queries: 10, UniqueSubdomains: 3, SourceIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	return notice
}

func commandSinkConfig() NoticeCommandSinkConfig {
	return NoticeCommandSinkConfig{AuthorityNodeID: "controller", AuthorityGeneration: "local-generation", QueueSize: 4, MaxIdentities: 8, MaxOutputBytes: 128}
}

func newCommandSink(t *testing.T, command string, config NoticeCommandSinkConfig) *NoticeCommandSink {
	t.Helper()
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: command, Timeout: 5 * time.Second, Concurrency: 1})
	sink, err := NewNoticeCommandSink(executor, config)
	require.NoError(t, err)
	require.NoError(t, sink.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, sink.Close(ctx))
	})
	return sink
}

func TestNoticeCommandSinkValidatesLifecycleAndAvoidsGenericIngress(t *testing.T) {
	_, err := NewNoticeCommandSink(nil, commandSinkConfig())
	require.Error(t, err)
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "true", DryRun: true})
	for _, invalid := range []NoticeCommandSinkConfig{
		{}, {AuthorityNodeID: "local", AuthorityGeneration: "generation", QueueSize: 1, MaxIdentities: 1},
		{AuthorityNodeID: "local", AuthorityGeneration: "generation", QueueSize: 2, MaxIdentities: 1, MaxOutputBytes: 128},
	} {
		_, err := NewNoticeCommandSink(executor, invalid)
		require.Error(t, err)
	}
	sink, err := NewNoticeCommandSink(executor, commandSinkConfig())
	require.NoError(t, err)
	_, globallyRegistrable := any(sink).(events.Sink)
	require.False(t, globallyRegistrable, "wire/WAL/relay ingress cannot accidentally register the local action API")
	require.ErrorIs(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)), ErrNoticeCommandNotReady)
	require.NoError(t, sink.Close(context.Background()))
	require.NoError(t, sink.Close(context.Background()))
	require.ErrorIs(t, sink.Start(context.Background()), ErrNoticeCommandClosed)
	require.ErrorIs(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)), ErrNoticeCommandClosed)
}

func TestNoticeCommandSinkRequiresCurrentLocalAuthorityAndIdentity(t *testing.T) {
	sink := newCommandSink(t, "true", commandSinkConfig())
	for _, change := range []func(*events.NoticeEvent){
		func(e *events.NoticeEvent) { e.DetectorNodeID = "relay" },
		func(e *events.NoticeEvent) { e.DetectorGeneration = "previous-generation" },
		func(e *events.NoticeEvent) { e.Detector = "unrelated.detector" },
	} {
		e := commandSinkNotice(1)
		change(&e)
		require.NoError(t, sink.HandleLocalNotice(context.Background(), e))
	}
	for _, change := range []func(*events.NoticeEvent){
		func(e *events.NoticeEvent) { e.EventEnvelope.EventID = "forged" },
		func(e *events.NoticeEvent) { e.EventEnvelope.ProducerSessionID = "" },
		func(e *events.NoticeEvent) { e.DNS = nil },
		func(e *events.NoticeEvent) { e.DNS.Queries = math.MaxUint64 },
		func(e *events.NoticeEvent) { e.DNS.Score = math.NaN() },
	} {
		e := commandSinkNotice(1)
		change(&e)
		require.Error(t, sink.HandleLocalNotice(context.Background(), e))
	}
	require.NoError(t, sink.Flush(context.Background()))
	stats := sink.Stats()
	require.EqualValues(t, 3, stats.Ignored)
	require.EqualValues(t, 5, stats.Dropped)
	require.Zero(t, stats.Completed)
	require.Zero(t, stats.Identities)
}

func TestNoticeCommandSinkDeduplicatesAndDrainsLocalActions(t *testing.T) {
	output := filepath.Join(t.TempDir(), "commands")
	sink := newCommandSink(t, "printf '%s\\n' %domain% >> "+shellEscape(output), commandSinkConfig())
	first, second := commandSinkNotice(1), commandSinkNotice(2)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), first))
	require.NoError(t, sink.HandleLocalNotice(context.Background(), first))
	require.NoError(t, sink.HandleLocalNotice(context.Background(), second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, sink.Close(ctx), "graceful close must drain all previously admitted commands")
	require.NoError(t, sink.Flush(ctx))
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, first.DNS.Domain+"\n"+second.DNS.Domain+"\n", string(content))
	stats := sink.Stats()
	require.EqualValues(t, 2, stats.Completed)
	require.EqualValues(t, 1, stats.Duplicate)
	require.Zero(t, stats.Failed)
	require.Zero(t, stats.Dropped)
	require.Zero(t, stats.Queued)
	require.Equal(t, 2, stats.Identities)
}

func TestNoticeCommandSinkNeverEvictsActionHistory(t *testing.T) {
	config := commandSinkConfig()
	config.QueueSize, config.MaxIdentities = 1, 1
	sink := newCommandSink(t, "true", config)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
	require.NoError(t, sink.Flush(context.Background()))
	require.ErrorIs(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(2)), ErrNoticeCommandHistory)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
	require.EqualValues(t, 1, sink.Stats().Completed)
	require.EqualValues(t, 1, sink.Stats().Dropped)
	require.EqualValues(t, 1, sink.Stats().Duplicate)
	require.Equal(t, 1, sink.Stats().Identities)
}

func TestNoticeCommandSinkQueuePressureAndCanceledCloseJoinWorker(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "running")
	config := commandSinkConfig()
	config.QueueSize = 1
	sink := newCommandSink(t, "printf ready > "+shellEscape(ready)+"; exec sleep 30", config)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
	require.Eventually(t, func() bool { _, err := os.Stat(ready); return err == nil }, 5*time.Second, time.Millisecond)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(2)))
	require.ErrorIs(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(3)), ErrNoticeCommandFull)
	require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(3)), "overflow identity remains attempted rather than becoming replay eligible")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, sink.Flush(ctx), context.Canceled)
	require.ErrorIs(t, sink.Close(ctx), context.Canceled)
	select {
	case <-sink.done:
	default:
		t.Fatal("canceled close returned without joining its worker")
	}
	stats := sink.Stats()
	require.EqualValues(t, 3, stats.Dropped)
	require.EqualValues(t, 1, stats.Duplicate)
	require.Zero(t, stats.Queued)
	require.Zero(t, stats.Completed)
	require.Zero(t, stats.Failed)
}

func TestNoticeCommandSinkRecordsCommandFailureAndTimeout(t *testing.T) {
	for _, command := range []string{"exit 7", "exec sleep 30"} {
		t.Run(command, func(t *testing.T) {
			executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: command, Timeout: 25 * time.Millisecond, Concurrency: 1})
			sink, err := NewNoticeCommandSink(executor, commandSinkConfig())
			require.NoError(t, err)
			require.NoError(t, sink.Start(context.Background()))
			t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
			require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, sink.Flush(ctx))
			require.EqualValues(t, 1, sink.Stats().Failed)
			require.Zero(t, sink.Stats().Completed)
		})
	}
}

func TestNoticeCommandSinkParentCancellationAndExecutorPressure(t *testing.T) {
	t.Run("parent cancellation", func(t *testing.T) {
		ready := filepath.Join(t.TempDir(), "running")
		executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "printf ready > " + shellEscape(ready) + "; exec sleep 30"})
		sink, err := NewNoticeCommandSink(executor, commandSinkConfig())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, sink.Start(ctx))
		t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
		require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
		require.Eventually(t, func() bool { _, err := os.Stat(ready); return err == nil }, 5*time.Second, time.Millisecond)
		cancel()
		select {
		case <-sink.done:
		case <-time.After(5 * time.Second):
			t.Fatal("parent cancellation did not join the notice worker")
		}
		require.EqualValues(t, 1, sink.Stats().Dropped)
		require.ErrorIs(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(2)), ErrNoticeCommandClosed)
	})
	t.Run("shared executor pressure", func(t *testing.T) {
		executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "true", Concurrency: 1})
		executor.sem <- struct{}{}
		sink, err := NewNoticeCommandSink(executor, commandSinkConfig())
		require.NoError(t, err)
		require.NoError(t, sink.Start(context.Background()))
		t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
		require.NoError(t, sink.HandleLocalNotice(context.Background(), commandSinkNotice(1)))
		require.NoError(t, sink.Flush(context.Background()))
		<-executor.sem
		require.EqualValues(t, 1, sink.Stats().Dropped)
		require.Zero(t, sink.Stats().Failed)
		require.Zero(t, sink.Stats().Completed)
	})
}

func TestExecuteTunnelingCommandContextPreservesEscapedSubstitutions(t *testing.T) {
	dir := t.TempDir()
	output, injected := filepath.Join(dir, "literal"), filepath.Join(dir, "must-not-exist")
	meta := TunnelingMetadata{Domain: "a'$(touch " + injected + ").example", Score: 0.9123, Entropy: 4.567, Queries: 123, SrcIPs: []string{"192.0.2.1", "192.0.2.2"}, HunterID: "hunter'$(false)", Timestamp: time.Unix(1700000000, 0).UTC()}
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "printf '%s|%s|%s|%s|%s|%s|%s' %domain% %score% %entropy% %queries% %srcips% %hunter% %timestamp% > " + shellEscape(output)})
	require.NoError(t, executor.ExecuteTunnelingCommandContext(context.Background(), meta, 64))
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, strings.Join([]string{meta.Domain, "0.91", "4.57", "123", "192.0.2.1,192.0.2.2", meta.HunterID, "2023-11-14T22:13:20Z"}, "|"), string(content))
	_, err = os.Stat(injected)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestExecuteTunnelingCommandContextBoundsDiagnosticsAndSharesConcurrency(t *testing.T) {
	output := &boundedCommandOutput{limit: 13}
	input := strings.Repeat("x", 1<<20)
	n, err := output.Write([]byte(input))
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	require.Equal(t, strings.Repeat("x", 13), string(output.bytes))
	require.True(t, output.truncated)
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "printf '%010000d' 0; printf '%010000d' 0 >&2", Concurrency: 1})
	require.NoError(t, executor.ExecuteTunnelingCommandContext(context.Background(), TunnelingMetadata{}, 13))
	executor.sem <- struct{}{}
	require.ErrorIs(t, executor.ExecuteTunnelingCommandContext(context.Background(), TunnelingMetadata{}, 13), ErrCommandConcurrencyLimit)
	<-executor.sem
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, executor.ExecuteTunnelingCommandContext(ctx, TunnelingMetadata{}, 13), context.Canceled)
	failing := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "exit 7"})
	err = failing.ExecuteTunnelingCommandContext(context.Background(), TunnelingMetadata{}, 13)
	var exit *exec.ExitError
	require.True(t, errors.As(err, &exit))
	require.Equal(t, 7, exit.ExitCode())
}

func TestTunnelingCommandPlaceholderDataIsNeverReexpanded(t *testing.T) {
	dir := t.TempDir()
	output, injected := filepath.Join(dir, "literal"), filepath.Join(dir, "must-not-exist")
	meta := TunnelingMetadata{Domain: "%hunter%", HunterID: "$(touch " + injected + ")"}
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "printf '%s' %domain% > " + shellEscape(output)})
	require.NoError(t, executor.ExecuteTunnelingCommandContext(context.Background(), meta, 64))
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "%hunter%", string(content))
	_, err = os.Stat(injected)
	require.ErrorIs(t, err, os.ErrNotExist)
}
