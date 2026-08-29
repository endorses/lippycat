package captureadapter

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestStreamPreservesOrderCaptureTimeAndSource(t *testing.T) {
	input := make(chan capture.PacketInfo, 3)
	for i := 0; i < 3; i++ {
		packet := gopacket.NewPacket([]byte{byte(i + 1)}, gopacket.LayerTypePayload, gopacket.Default)
		packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i+1), 0),
			CaptureLength: 1,
			Length:        1,
		}
		input <- capture.PacketInfo{Packet: packet, Interface: "fixture.pcap", LinkType: layers.LinkTypeRaw}
	}
	close(input)
	output := make(chan *pipeline.PacketEnvelope, 3)
	require.NoError(t, Stream(context.Background(), input, output, pipeline.SourcePCAPReplay))
	close(output)

	for i := 0; i < 3; i++ {
		envelope := <-output
		require.Equal(t, []byte{byte(i + 1)}, envelope.Data)
		require.Equal(t, time.Unix(int64(i+1), 0), envelope.CaptureTime)
		require.Equal(t, pipeline.SourcePCAPReplay, envelope.Source.Kind)
		require.Equal(t, "fixture.pcap", envelope.Source.InterfaceName)
	}
}

func TestStreamCancellationDoesNotBlockOnOutput(t *testing.T) {
	input := make(chan capture.PacketInfo, 1)
	input <- capture.PacketInfo{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, Stream(ctx, input, make(chan *pipeline.PacketEnvelope), pipeline.SourceLiveCapture), context.Canceled)
}
