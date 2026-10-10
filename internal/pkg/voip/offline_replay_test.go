//go:build cli || all

package voip

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func writeVoIPReplayFixture(t *testing.T, path string, packet gopacket.Packet) {
	t.Helper()
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, layers.LinkTypeEthernet))
	require.NoError(t, writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()))
	require.NoError(t, file.Close())
}

func voIPReplayInvite(t *testing.T, callID string) capture.PacketInfo {
	t.Helper()
	body := "v=0\r\nc=IN IP4 192.168.1.100\r\nm=audio 8000 RTP/AVP 0\r\n"
	message := fmt.Sprintf("INVITE sip:peer@example.com SIP/2.0\r\nCall-ID: %s\r\nFrom: <sip:caller@example.com>;tag=123\r\nTo: <sip:peer@example.com>\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", callID, len(body), body)
	return createUdpPacketInfo(t, 5060, 5060, []byte(message))
}

func TestOfflineVoIPReplayRetainsEachPass(t *testing.T) {
	previous := GetConfig()
	t.Cleanup(func() { SetConfig(previous) })
	sipusers.ClearAll()
	t.Cleanup(sipusers.ClearAll)
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			dir := t.TempDir()
			cfg := DefaultConfig()
			cfg.WriteVoIP = true
			cfg.OutputFile = filepath.Join(dir, "output.pcap")
			SetConfig(cfg)
			packet := voIPReplayInvite(t, "replayed-call").Packet
			if transport == "tcp" {
				packet = createTCPSIPPacket(t, tcpSIPMsg("INVITE sip:peer@example.com SIP/2.0", "replayed-call", "<sip:caller@example.com>", ""), "192.0.2.1", "192.0.2.2")
			}
			packet.Metadata().Timestamp = time.Unix(1700000000, 123000)
			input := filepath.Join(dir, "input.pcap")
			writeVoIPReplayFixture(t, input, packet)
			require.NoError(t, StartOfflineVoipSnifferWithReplay(context.Background(), []string{input}, "", capture.OfflineReplayOptions{Count: 2}))
			output, err := os.Open(filepath.Join(dir, "output_sip_replayed-call.pcap"))
			require.NoError(t, err)
			defer func() { require.NoError(t, output.Close()) }()
			reader, err := pcapgo.NewReader(output)
			require.NoError(t, err)
			for range 2 {
				data, info, err := reader.ReadPacketData()
				require.NoError(t, err)
				if transport == "udp" {
					require.Equal(t, packet.Data(), data)
				} else {
					// Existing TCP SIP output reconstructs a complete-message
					// frame. Verify its payload and source capture time.
					decoded := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
					require.Equal(t, packet.ApplicationLayer().Payload(), decoded.ApplicationLayer().Payload())
				}
				require.True(t, packet.Metadata().Timestamp.Equal(info.Timestamp), "source capture timestamp must be preserved")
			}
			_, _, err = reader.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

type replayRecordingCallOutput struct {
	opened, closed, written int
}

func (o *replayRecordingCallOutput) OpenSession(string, layers.LinkType) error {
	o.opened++
	return nil
}
func (o *replayRecordingCallOutput) WritePacket(string, gopacket.Packet, PacketType) error {
	o.written++
	return nil
}
func (o *replayRecordingCallOutput) CloseSession(string) error { o.closed++; return nil }
func (*replayRecordingCallOutput) Shutdown() error             { return nil }

func TestVoIPReplayPassResetsCallTracking(t *testing.T) {
	sipusers.ClearAll()
	t.Cleanup(sipusers.ClearAll)
	cfg := DefaultConfig()
	cfg.WriteVoIP = true
	output := &replayRecordingCallOutput{}
	packet := voIPReplayInvite(t, "same-call")
	for range 2 {
		input := make(chan capture.PacketInfo, 1)
		input <- packet
		close(input)
		require.NoError(t, runVoipPass(context.Background(), input, cfg, output, nil, true))
	}
	// The same call is admitted and closed once per pass. A tracker carried
	// over from the previous pass would suppress the second admission.
	require.Equal(t, 2, output.opened)
	require.Equal(t, 2, output.closed)
	require.Equal(t, 2, output.written)
}

func TestOfflineVoIPReplayContinuousCancellation(t *testing.T) {
	previous := GetConfig()
	SetConfig(DefaultConfig())
	t.Cleanup(func() { SetConfig(previous) })
	sipusers.ClearAll()
	t.Cleanup(sipusers.ClearAll)
	input := filepath.Join(t.TempDir(), "input.pcap")
	writeVoIPReplayFixture(t, input, voIPReplayInvite(t, "cancel-call").Packet)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var completed uint64
	err := StartOfflineVoipSnifferWithReplay(ctx, []string{input}, "", capture.OfflineReplayOptions{
		Count: 0,
		AfterPass: func(pass uint64) error {
			completed = pass
			if pass == 2 {
				cancel()
			}
			return nil
		},
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, uint64(2), completed)
}

func TestVoIPVirtualInterfacePacingHonorsReplayContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	manager := &recordingVIFManager{}
	sink := &virtualInterfacePacketSink{manager: manager, timing: vinterface.NewTimingReplayer(true), replayContext: ctx}
	first := &pipeline.PacketEnvelope{CaptureTime: time.Unix(1700000000, 0)}
	require.Equal(t, pipeline.OutcomeAccepted, sink.HandlePacket(context.Background(), first).Outcome)
	second := &pipeline.PacketEnvelope{CaptureTime: first.CaptureTime.Add(5 * time.Second)}
	result := sink.HandlePacket(context.Background(), second)
	require.ErrorIs(t, result.Err, context.DeadlineExceeded)
	require.Len(t, manager.packets, 1)
}

func TestVoIPReplayStartupDelayCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, waitVoIPReplayStartup(ctx, time.Hour), context.DeadlineExceeded)
}
