package capture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestRADIUSDisplayUsesDecodedPortsAndIngressObservation(t *testing.T) {
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		raw, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		info := PacketInfo{Packet: packet, LinkType: r.LinkType()}
		if i == 4 { // The fifth fixture uses the configured service port 19120.
			require.Nil(t, RADIUSDisplay(info))
			info.RADIUS, _, err = radius.DecodePacket(raw, r.LinkType(), ci, radius.CaptureScope{}, radius.Identity{}, 19120)
			require.NoError(t, err)
		}
		require.NotNil(t, RADIUSDisplay(info))
	}
}
