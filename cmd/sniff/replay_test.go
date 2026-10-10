//go:build cli || all

package sniff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestReplayValidation(t *testing.T) {
	oldFile := readFile
	t.Cleanup(func() {
		readFile = oldFile
		viper.Set("sniff.replay_loop", 1)
		viper.Set("sniff.replay_loop_delay", time.Duration(0))
	})
	readFile = ""
	for _, tc := range []struct {
		count     int
		delay     time.Duration
		files     []string
		wantError bool
	}{
		{1, 0, nil, false}, {0, 0, nil, true}, {-1, 0, []string{"input.pcap"}, true},
		{1, -time.Second, []string{"input.pcap"}, true}, {0, time.Second, []string{"input.pcap"}, false},
	} {
		viper.Set("sniff.replay_loop", tc.count)
		viper.Set("sniff.replay_loop_delay", tc.delay)
		if tc.wantError {
			require.Error(t, validateReplayOptions(SniffCmd, tc.files))
		} else {
			require.NoError(t, validateReplayOptions(SniffCmd, tc.files))
		}
	}
	for _, cmd := range SniffCmd.Commands() {
		require.NotNil(t, cmd.InheritedFlags().Lookup("replay-loop"), cmd.Name())
	}
}

func TestRepeatedLocalPipelinePreservesPCAPAndResetsTiming(t *testing.T) {
	env := testEnvelope(t)
	input := filepath.Join(t.TempDir(), "input.pcap")
	f, err := os.Create(input)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, env.LinkType))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: env.CaptureTime, CaptureLength: len(env.Data), Length: len(env.Data)}, env.Data))
	require.NoError(t, f.Close())
	output := filepath.Join(t.TempDir(), "output.pcap")
	sink, err := newPCAPEnvelopeSink(output)
	require.NoError(t, err)
	timing := vinterface.NewTimingReplayer(true)
	vif := &virtualInterfaceEnvelopeSink{manager: &stubVIFManager{}, timing: timing}
	fanout, err := pipeline.NewPacketFanout(pipeline.SinkRegistration{Name: "pcap", Sink: sink}, pipeline.SinkRegistration{Name: "vif", Sink: vif})
	require.NoError(t, err)
	p := &localEnvelopePipeline{fanout: fanout}
	var replayErr error
	passes := 0
	err = capture.StartOfflineSnifferOrdered([]string{input}, "", func(devices []pcaptypes.PcapInterface, filter string) {
		replayErr = capture.RunOfflineOrderedRepeated(context.Background(), devices, filter, capture.OfflineReplayOptions{Count: 2, BeforePass: func(uint64) error { passes++; timing.Reset(); return nil }}, func(ctx context.Context, packets <-chan capture.PacketInfo) error {
			return p.processContext(ctx, packets, pipeline.SourcePCAPReplay)
		})
	})
	require.NoError(t, err)
	require.NoError(t, replayErr)
	require.NoError(t, fanout.Close(context.Background()))
	require.Equal(t, 2, passes)
	require.Equal(t, 2, p.count)
	f, err = os.Open(output)
	require.NoError(t, err)
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for range 2 {
		data, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, env.Data, data)
		require.Equal(t, env.CaptureTime, ci.Timestamp)
	}
	_, _, err = r.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}

func TestLocalReplayCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, waitReplayStartup(ctx, time.Hour), context.Canceled)
	manager := &stubVIFManager{injectErr: io.ErrUnexpectedEOF}
	sink := &virtualInterfaceEnvelopeSink{manager: manager, timing: vinterface.NewTimingReplayer(true)}
	env := testEnvelope(t)
	require.ErrorIs(t, sink.HandlePacket(ctx, env).Err, context.Canceled)
	packets := make(chan capture.PacketInfo, 1)
	packets <- captureadapter.ToPacketInfo(env)
	p := &localEnvelopePipeline{}
	require.ErrorIs(t, p.processContext(ctx, packets, pipeline.SourcePCAPReplay), context.Canceled)
	require.Zero(t, p.count)
}

func TestRepeatedReplayResetsNormalizedAnalysis(t *testing.T) {
	input := filepath.Join(t.TempDir(), "identity.pcap")
	require.NoError(t, os.WriteFile(input, []byte("identity"), 0o600))
	sink := &sniffEventSink{}
	session, err := newSniffEventSession("", []string{input}, "replay-test", sink)
	require.NoError(t, err)
	defer session.analysis.Close()
	opts := replayOptionsForSession(capture.OfflineReplayOptions{Count: 2}, session)
	info := captureadapter.ToPacketInfo(testEnvelope(t))
	require.NoError(t, opts.BeforePass(1))
	session.observe(&info)
	require.NoError(t, opts.BeforePass(2))
	session.observe(&info)
	session.analysis.EOF()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, session.dispatcher.Close(ctx))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	connections := 0
	for _, event := range sink.events {
		if event.Kind() == events.KindConn {
			connections++
		}
	}
	require.Equal(t, 2, connections, "each pass must flush its own connection observation")
}

func TestReplayInterruptPreservesOtherFailures(t *testing.T) {
	require.True(t, onlyReplayCancellation(fmt.Errorf("pass: %w", errors.Join(context.Canceled, context.Canceled))))
	require.False(t, onlyReplayCancellation(errors.Join(context.Canceled, io.ErrUnexpectedEOF)))
	require.False(t, onlyReplayCancellation(nil))
}
