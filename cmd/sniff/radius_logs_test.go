//go:build cli || all

package sniff

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestRADIUSFixtureSniffStructuredLogs(t *testing.T) {
	viper.Set("logs.streams", []string{"radius"})
	viper.Set("logs.format", "json")
	t.Cleanup(func() { viper.Set("logs.streams", nil); viper.Set("logs.format", nil) })
	dir := t.TempDir()
	session, err := newSniffLogSession(dir)
	require.NoError(t, err)
	session.radius.Close()
	session.radius, err = radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "local"}, 1812, 1813, 19120)
	require.NoError(t, err)
	file, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	for {
		raw, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		require.NoError(t, readErr)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		session.observe(&capture.PacketInfo{Packet: packet, LinkType: reader.LinkType(), Interface: "fixture"})
	}
	session.radius.Close()
	require.NoError(t, session.dispatcher.Close(context.Background()))
	contents, err := os.ReadFile(filepath.Join(dir, "radius.log"))
	require.NoError(t, err)
	codes := map[float64]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		var row map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &row))
		codes[row["code"].(float64)] = true
		require.NotEmpty(t, row["observation_id"])
		require.Equal(t, "fixture", row["source_id"])
	}
	for _, code := range []float64{1, 2, 3, 4, 5, 11} {
		require.True(t, codes[code], "missing code %v", code)
	}
}

func TestConfiguredRADIUSPipelineOwnsLogObservation(t *testing.T) {
	viper.Set("logs.streams", []string{"radius"})
	viper.Set("logs.format", "json")
	t.Cleanup(func() { viper.Set("logs.streams", nil); viper.Set("logs.format", nil) })
	dir := t.TempDir()
	session, err := newSniffLogSessionMode(dir, true)
	require.NoError(t, err)
	require.Nil(t, session.radius)
	config := radiusconfig.Config{Ports: []uint16{19120}, Scope: radius.CaptureScope{OperatorScope: "test-operator", ProfileRevision: "mapping-v2"}}
	fanout, err := pipeline.NewPacketFanout(pipeline.SinkRegistration{Name: "discard", Sink: newCLIEnvelopeSink(io.Discard, "json", false)})
	require.NoError(t, err)
	p := &localEnvelopePipeline{fanout: fanout, radiusConfig: &config, logSession: session}
	defer p.close()
	file, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	packets := make(chan capture.PacketInfo, 32)
	for {
		raw, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		require.NoError(t, readErr)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		packets <- capture.PacketInfo{Packet: packet, LinkType: reader.LinkType(), Interface: "fixture"}
	}
	close(packets)
	p.process(packets, pipeline.SourcePCAPReplay)
	require.NoError(t, session.dispatcher.Close(context.Background()))
	contents, err := os.ReadFile(filepath.Join(dir, "radius.log"))
	require.NoError(t, err)
	custom := 0
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		var row map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &row))
		require.Equal(t, "sniff", row["origin_node_id"])
		require.Equal(t, "fixture", row["source_id"])
		if row["id.orig_p"] == float64(19120) || row["id.resp_p"] == float64(19120) {
			custom++
		}
	}
	require.Equal(t, 4, custom, "custom-port logs must use the configured observer")
}
