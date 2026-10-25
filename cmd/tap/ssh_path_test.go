//go:build tap || all

package tap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type sshTapSink struct{ observations chan events.SSHEvent }

func (s *sshTapSink) HandleEvent(ctx context.Context, event events.Event) error {
	select {
	case s.observations <- event.(events.SSHEvent):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*sshTapSink) Flush(context.Context) error { return nil }
func (*sshTapSink) Close(context.Context) error { return nil }

func TestSSHActualTapRuntimeProducesControlledHandshakeLog(t *testing.T) {
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	flag := TapCmd.PersistentFlags().Lookup("no-filter-policy")
	previousPolicy, changed := flag.Value.String(), flag.Changed
	require.NoError(t, TapCmd.PersistentFlags().Set("no-filter-policy", "allow"))
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(previousPolicy)); flag.Changed = changed })
	policy := eventconfig.Default()
	directory := t.TempDir()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	closeWriter := sync.OnceFunc(func() { require.NoError(t, writer.Close()) })
	t.Cleanup(closeWriter)
	fixture := &mixedTapInterface{reader: reader}
	frames := pcapgo.NewWriterNanos(writer)
	require.NoError(t, frames.WriteFileHeader(65535, layers.LinkTypeEthernet))
	runtime, err := newTapRuntime(processor.Config{
		ProcessorID: "tap-ssh", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(t.TempDir(), "managed", "filters.yaml"), EventAnalysis: &policy,
		EventQueueSize: 64, GracefulShutdownTimeout: 100 * time.Millisecond,
		LogConfig: &processor.StructuredLogConfig{Enabled: true, Directory: directory, Format: "json", Streams: []string{"ssh"}, QueueSize: 32},
	}, "tcp port 2222", protocolcatalog.MustLookup("generic"), tapRuntimeHooks{ConfigureSourceConfig: func(config *source.LocalSourceConfig) {
		config.Interfaces, config.BatchSize, config.BatchTimeout, config.BufferSize = []string{"capture0"}, 1, time.Millisecond, 128
		config.CaptureInterfaces = func() []pcaptypes.PcapInterface { return []pcaptypes.PcapInterface{fixture} }
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.processor.Shutdown()) })
	t.Cleanup(runtime.appFilter.Close)
	sink := &sshTapSink{observations: make(chan events.SSHEvent, 8)}
	require.NoError(t, runtime.processor.RegisterEventSink(sink, events.KindSSH))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.processor.Start(ctx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		closeWriter()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("SSH tap did not join its local source and processor")
		}
	})
	t.Cleanup(stop)
	require.Eventually(t, runtime.localSource.IsStarted, 5*time.Second, time.Millisecond)
	for _, packet := range packets {
		require.True(t, runtime.appFilter.MatchPacket(packet.Packet), "generic tap capture must admit the SSH fixture on a custom port")
		require.NoError(t, frames.WritePacket(packet.Packet.Metadata().CaptureInfo, packet.Packet.Data()))
	}
	observations := make(map[string]events.SSHEvent)
	for range 4 {
		select {
		case observation := <-sink.observations:
			require.True(t, events.HasValidDeliveryIdentity(observation.Envelope()))
			require.Equal(t, "tap-ssh", observation.Envelope().NodeID)
			require.Equal(t, "tap-ssh-local", observation.Envelope().Provenance.CaptureSource)
			observations[observation.Envelope().EventID] = observation
		case <-time.After(10 * time.Second):
			t.Fatalf("actual tap local capture did not produce four SSH observations: source=%+v processor=%+v", runtime.localSource.Stats(), runtime.processor.GetStats())
		}
	}
	stop() // Production shutdown drains the configured structured-log writer.
	content, err := os.ReadFile(filepath.Join(directory, "ssh.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Len(t, lines, 4)
	complete := make(map[string]bool)
	for _, line := range lines {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		observation, ok := observations[record["event_id"].(string)]
		require.True(t, ok)
		require.Equal(t, string(observation.Role), record["role"])
		require.Equal(t, string(observation.Status), record["status"])
		require.Equal(t, "tap-ssh", record["node_id"])
		if observation.Status == events.SSHStatusComplete {
			require.Equal(t, observation.HASSH, record["hassh"])
			require.NotEmpty(t, record["hassh_algorithms"])
			complete[string(observation.Role)] = true
		} else {
			require.Nil(t, record["hassh"])
		}
	}
	require.Equal(t, map[string]bool{"client": true, "server": true}, complete)
	require.Empty(t, sink.observations, "shutdown must not repeat terminal SSH observations")
}
