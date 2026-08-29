//go:build hunter || all

package forwarding

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/capture"
)

func TestConvertPacketPreservesCaptureTimestamp(t *testing.T) {
	capturedAt := time.Date(2026, time.August, 24, 12, 34, 56, 789123456, time.UTC)
	packet := gopacket.NewPacket([]byte{0x01, 0x02}, layers.LayerTypeEthernet, gopacket.NoCopy)
	packet.Metadata().Timestamp = capturedAt
	packet.Metadata().CaptureLength = 2
	packet.Metadata().Length = 2

	converted := convertPacket(capture.PacketInfo{
		Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "fixture0",
	}, []string{"li-filter"})

	require.Equal(t, capturedAt, converted.CaptureTime)
}
