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
	"github.com/endorses/lippycat/internal/pkg/radius"
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
	file, err := os.Open("../../testdata/radius/acceptance.pcap")
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
