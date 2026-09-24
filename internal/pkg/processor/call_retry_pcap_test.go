//go:build processor || tap || all

package processor

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestMatched503RetryRetainsSinglePcapWriter(t *testing.T) {
	start := time.Now().Add(-100 * time.Second)
	clock := start
	dir := t.TempDir()
	aggregator := voip.NewCallAggregator()
	aggregator.SetBYETimewait(time.Nanosecond)
	var mu sync.Mutex
	var completions []CallMetadata
	manager, err := NewSessionOutputManager(&PcapWriterConfig{
		Enabled: true, OutputDir: dir, FilePattern: "{timestamp}_{callid}.pcap", SyncInterval: time.Hour, MaxIdle: 30 * time.Second,
		OnCallComplete: func(meta CallMetadata) {
			mu.Lock()
			completions = append(completions, meta)
			mu.Unlock()
		},
	}, &CallCompletionMonitorConfig{GracePeriod: time.Nanosecond, RetryWindow: 2 * time.Minute, Now: func() time.Time { return clock }}, aggregator)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	monitor := manager.monitor.(*CallCompletionMonitor)
	packet := func(method, cseqMethod string, code uint32, number uint64, branch string, at time.Time) *data.CapturedPacket {
		return &data.CapturedPacket{TimestampNs: at.UnixNano(), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{
			CallId: "synthetic-pcap-retry", FromUser: "caller", ToUser: "callee",
			Method: method, CseqMethod: cseqMethod, CseqNumber: number, ViaBranch: branch, ResponseCode: code,
		}}}
	}
	write := func(payload string, at time.Time, media bool) {
		require.NoError(t, manager.WritePacket("synthetic-pcap-retry", "caller", "callee", at, []byte(payload), layers.LinkTypeEthernet, media))
	}
	require.True(t, monitor.ProcessPacket(packet("INVITE", "INVITE", 0, 1, "z9hG4bK-one", start), "hunter"))
	write("invite-one", start, false)
	manager.writer.mu.RLock()
	firstWriter := manager.writer.writers["synthetic-pcap-retry"]
	manager.writer.mu.RUnlock()
	require.NotNil(t, firstWriter)
	clock = start.Add(time.Second)
	require.True(t, monitor.ProcessPacket(packet("RESPONSE", "INVITE", 503, 1, "z9hG4bK-one", clock), "hunter"))
	write("503", start.Add(time.Second), false)
	monitor.checkEndedCalls()
	require.False(t, manager.lifecycle.IsFinalized("synthetic-pcap-retry"))
	firstWriter.mu.Lock()
	firstWriter.lastWrite = time.Now().Add(-time.Minute)
	firstWriter.mu.Unlock()
	monitor.sweepIdleWriters()
	require.False(t, manager.lifecycle.IsFinalized("synthetic-pcap-retry"), "idle sweep must not beat the retry window")
	clock = start.Add(89 * time.Second) // 88 seconds after the 503.
	monitor.checkEndedCalls()
	monitor.processPendingClose()
	require.False(t, manager.lifecycle.IsFinalized("synthetic-pcap-retry"))
	require.True(t, monitor.ProcessPacket(packet("INVITE", "INVITE", 0, 2, "z9hG4bK-two", clock), "hunter"))
	write("invite-two", clock, false)
	earlyMedia := packet("", "", 0, 0, "", clock)
	earlyMedia.Metadata.Rtp = &data.RTPMetadata{Ssrc: 123, Sequence: 0}
	require.True(t, monitor.ProcessPacket(earlyMedia, "hunter"))
	write("early-media", clock, true)
	manager.writer.mu.RLock()
	require.Same(t, firstWriter, manager.writer.writers["synthetic-pcap-retry"])
	manager.writer.mu.RUnlock()
	clock = start.Add(90 * time.Second)
	require.True(t, monitor.ProcessPacket(packet("RESPONSE", "INVITE", 200, 2, "z9hG4bK-two", clock), "hunter"))
	write("200", clock, false)
	clock = start.Add(90*time.Second + 500*time.Millisecond)
	require.True(t, monitor.ProcessPacket(packet("ACK", "INVITE", 0, 2, "z9hG4bK-ack", clock), "hunter"))
	write("ack", clock, false)
	clock = start.Add(91 * time.Second)
	media := packet("", "", 0, 0, "", clock)
	media.Metadata.Rtp = &data.RTPMetadata{Ssrc: 123, Sequence: 1}
	require.True(t, monitor.ProcessPacket(media, "hunter"))
	write("answered-media", clock, true)
	clock = start.Add(92 * time.Second)
	require.True(t, monitor.ProcessPacket(packet("BYE", "BYE", 0, 3, "z9hG4bK-bye", clock), "hunter"))
	write("bye", clock, false)
	clock = start.Add(93 * time.Second)
	monitor.checkEndedCalls()
	clock = start.Add(94 * time.Second)
	monitor.processPendingClose()
	require.True(t, manager.lifecycle.IsFinalized("synthetic-pcap-retry"))
	countPackets := func(suffix string) int {
		paths, globErr := filepath.Glob(filepath.Join(dir, "*"+suffix+".pcap"))
		require.NoError(t, globErr)
		require.Len(t, paths, 1)
		file, openErr := os.Open(paths[0])
		require.NoError(t, openErr)
		defer file.Close()
		reader, readErr := pcapgo.NewReader(file)
		require.NoError(t, readErr)
		count := 0
		for {
			_, _, nextErr := reader.ReadPacketData()
			if nextErr == io.EOF {
				break
			}
			require.NoError(t, nextErr)
			count++
		}
		return count
	}
	require.Equal(t, 6, countPackets("_sip"))
	require.Equal(t, 2, countPackets("_rtp"))
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, completions, 1)
	require.Equal(t, "caller", completions[0].Caller)
	require.Equal(t, "callee", completions[0].Called)
}

func TestVerifiedCallIDRestartCreatesDistinctPcapAndCompletionMetadata(t *testing.T) {
	dir := t.TempDir()
	aggregator := voip.NewCallAggregator()
	var mu sync.Mutex
	var completions []CallMetadata
	manager, err := NewSessionOutputManager(&PcapWriterConfig{
		Enabled: true, OutputDir: dir, FilePattern: "same_{callid}.pcap", SyncInterval: time.Hour,
		OnCallComplete: func(meta CallMetadata) {
			mu.Lock()
			completions = append(completions, meta)
			mu.Unlock()
		},
	}, DefaultCallCompletionMonitorConfig(), aggregator)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	monitor := manager.monitor.(*CallCompletionMonitor)
	packet := func(method string, code uint32, cseq uint64, branch, fromTag, toTag string) *data.CapturedPacket {
		return &data.CapturedPacket{TimestampNs: time.Now().UnixNano(), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{
			CallId: "synthetic-reused-id", Method: method, CseqMethod: "INVITE", ResponseCode: code,
			CseqNumber: cseq, ViaBranch: branch, FromTag: fromTag, ToTag: toTag,
		}}}
	}
	require.True(t, monitor.ProcessPacket(packet("INVITE", 0, 1, "z9hG4bK-first", "caller-first", ""), "hunter"))
	require.NoError(t, manager.WritePacket("synthetic-reused-id", "caller-first", "callee-first", time.Now(), []byte("first invite"), layers.LinkTypeEthernet, false))
	first := manager.writer.writers["synthetic-reused-id"]
	require.NotNil(t, first)
	require.True(t, manager.lifecycle.Finalize("synthetic-reused-id", CallFinalizationProtocolComplete).Finalized)

	require.True(t, monitor.ProcessPacket(packet("INVITE", 0, 2, "z9hG4bK-second", "caller-second", ""), "hunter"))
	require.True(t, monitor.ProcessPacket(packet("RESPONSE", 200, 2, "z9hG4bK-second", "caller-second", "callee-second"), "hunter"))
	require.NoError(t, manager.WritePacket("synthetic-reused-id", "caller-second", "callee-second", time.Now(), []byte("second answer"), layers.LinkTypeEthernet, false))
	second := manager.writer.writers["synthetic-reused-id"]
	require.NotNil(t, second)
	require.NotSame(t, first, second)
	require.NotEqual(t, first.generation, second.generation)
	require.True(t, manager.lifecycle.Finalize("synthetic-reused-id", CallFinalizationProtocolComplete).Finalized)

	paths, err := filepath.Glob(filepath.Join(dir, "*.pcap"))
	require.NoError(t, err)
	require.Len(t, paths, 2, "same-name generations must retain separate PCAP artifacts")
	require.NotEqual(t, paths[0], paths[1])
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, completions, 2)
	require.Equal(t, "caller-first", completions[0].Caller)
	require.Equal(t, "callee-first", completions[0].Called)
	require.Equal(t, "caller-second", completions[1].Caller)
	require.Equal(t, "callee-second", completions[1].Called)
}
