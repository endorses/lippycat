package pcapsink

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestSinkPreservesNormalizedEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packets.pcap")
	sink, err := New(path)
	require.NoError(t, err)

	wantTime := time.Unix(123, 456000).UTC()
	result := sink.HandlePacket(context.Background(), &pipeline.PacketEnvelope{
		Data:           []byte{1, 2, 3, 4},
		LinkType:       layers.LinkTypeRaw,
		CaptureTime:    wantTime,
		CaptureLength:  4,
		OriginalLength: 8,
	})
	require.Equal(t, pipeline.OutcomeAccepted, result.Outcome)
	require.NoError(t, sink.Close(context.Background()))
	require.NoError(t, sink.Close(context.Background()))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	require.Equal(t, layers.LinkTypeRaw, reader.LinkType())
	data, info, err := reader.ReadPacketData()
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, 4}, data)
	require.Equal(t, wantTime, info.Timestamp)
	require.Equal(t, 4, info.CaptureLength)
	require.Equal(t, 8, info.Length)
}

func TestSinkRejectsPacketsAfterClose(t *testing.T) {
	sink, err := New(filepath.Join(t.TempDir(), "packets.pcap"))
	require.NoError(t, err)
	require.NoError(t, sink.Close(context.Background()))
	result := sink.HandlePacket(context.Background(), &pipeline.PacketEnvelope{})
	require.Equal(t, pipeline.OutcomeShutdown, result.Outcome)
	require.Error(t, result.Err)
}
