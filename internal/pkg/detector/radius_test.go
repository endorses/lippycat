package detector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestRADIUSCommittedDetectionFixtures(t *testing.T) {
	manifest, err := os.ReadFile("../../../testdata/radius/expected.json")
	require.NoError(t, err)
	var expected struct {
		Observations []struct {
			Name, Outcome   string
			SourcePort      uint16 `json:"source_port"`
			DestinationPort uint16 `json:"destination_port"`
		}
	}
	require.NoError(t, json.Unmarshal(manifest, &expected))
	file, err := os.Open("../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	detector := New()
	defer detector.Shutdown()
	for _, want := range expected.Observations {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		t.Run(want.Name, func(t *testing.T) {
			packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
			packet.Metadata().CaptureInfo = ci
			result := detectRADIUS(packet)
			supported := want.SourcePort == 1812 || want.SourcePort == 1813 || want.DestinationPort == 1812 || want.DestinationPort == 1813
			if want.Outcome != "valid" || !supported {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			require.Equal(t, "RADIUS", result.Protocol)
			require.Equal(t, "RADIUS", detector.Detect(packet).Protocol)
			require.Equal(t, "RADIUS", detector.DetectWithoutCache(packet).Protocol)
			if ip, ok := packet.NetworkLayer().(*layers.IPv6); ok && ip.NextHeader == layers.IPProtocolUDP {
				// Insert a valid eight-byte hop-by-hop header into the committed frame.
				offset := len(raw) - len(ip.LayerContents()) - len(ip.LayerPayload())
				extended := append([]byte(nil), raw[:offset+40]...)
				extended = append(extended, 17, 0, 0, 0, 0, 0, 0, 0)
				extended = append(extended, raw[offset+40:]...)
				extended[offset+6] = 0
				payloadLength := int(ip.Length) + 8
				extended[offset+4], extended[offset+5] = byte(payloadLength>>8), byte(payloadLength)
				withOptions := gopacket.NewPacket(extended, reader.LinkType(), gopacket.Default)
				ci.CaptureLength += 8
				ci.Length += 8
				withOptions.Metadata().CaptureInfo = ci
				require.NotNil(t, detectRADIUS(withOptions), "IPv6 hop-by-hop bytes must remain present during validation")
			}
		})
	}
}
