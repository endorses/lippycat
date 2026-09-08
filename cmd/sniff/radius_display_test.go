//go:build cli || all

package sniff

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestRADIUSRoutineOutputRedactsCredentials(t *testing.T) {
	for _, code := range []byte{1, 12} {
		raw := make([]byte, 20)
		raw[0], raw[1] = code, 7
		raw = append(raw, 1, 7, 'a', 'l', 'i', 'c', 'e')
		raw = append(raw, 2, 18)
		raw = append(raw, []byte("SECRET-PASSWORD!")...)
		raw[3] = byte(len(raw))
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("198.51.100.1")}
		udp := &layers.UDP{SrcPort: 40000, DstPort: 1812}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		b := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(raw)))
		env := &pipeline.PacketEnvelope{Data: b.Bytes(), LinkType: layers.LinkTypeRaw, CaptureTime: time.Now(), CaptureLength: len(b.Bytes()), OriginalLength: len(b.Bytes())}
		observer, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "sniff"})
		require.NoError(t, err)
		if code == 1 {
			_, _, decodeErr := radius.DecodePacket(env.Data, env.LinkType, env.Packet().Metadata().CaptureInfo, radius.CaptureScope{}, radius.Identity{})
			require.NoError(t, decodeErr)
		}
		env.RADIUS = observer.Process(env.Packet(), env.LinkType, "fixture", nil)
		observer.Close()
		for _, format := range []string{"text", "json"} {
			var output bytes.Buffer
			result := newCLIEnvelopeSink(&output, format, false).HandlePacket(context.Background(), env)
			require.NoError(t, result.Err)
			require.NotContains(t, output.String(), "SECRET")
			require.NotContains(t, output.String(), "534543524554")
			if code == 1 && format == "json" {
				var display types.PacketDisplay
				require.NoError(t, json.Unmarshal(output.Bytes(), &display))
				require.Empty(t, display.RawData)
				require.NotNil(t, display.RADIUSData)
				require.Equal(t, "request", display.RADIUSData.Association)
				require.Equal(t, []string{"1:hex:616c696365"}, display.RADIUSData.Attributes)
			}
		}
	}
}
