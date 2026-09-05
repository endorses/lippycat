package capture

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestOfflineESPSnapshotSurvivesGlobalConfigurationChange(t *testing.T) {
	viper.Reset()
	resetESPNullConfig()
	t.Cleanup(func() { viper.Reset(); resetESPNullConfig() })
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 12)
	frozen := FreezeOfflineESPConfig()
	frame := buildESPNullIPv6Packet(0x11223344, buildMinimalTCPHeader(5060, 5060, []byte("INVITE sip:a@example.com SIP/2.0\r\n\r\n")), 6, 2, 12)
	path := filepath.Join(t.TempDir(), "source.pcap")
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(frame), Length: len(frame)}, frame))
	require.NoError(t, file.Close())
	file, err = os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	viper.Set("esp_null", false)
	viper.Set("esp_icv_size", 8)
	resetESPNullConfig()
	for _, tc := range []struct {
		name    string
		cfg     OfflineESPConfig
		decoded bool
	}{
		{"frozen enabled", frozen, true},
		{"frozen disabled", OfflineESPConfig{ICVSize: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithOfflineESPConfig(context.Background(), tc.cfg)
			cursor, err := newOfflineCursor(ctx, pcaptypes.CreateOfflineInterface(file), "", 0)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, cursor.Close()) })
			packet, err := cursor.Next(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.decoded, packet.Packet.Layer(layers.LayerTypeTCP) != nil)
		})
	}
}
