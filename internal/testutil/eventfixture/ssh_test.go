package eventfixture

import (
	"testing"
	"time"

	sshparser "github.com/endorses/lippycat/internal/pkg/ssh"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestSSHMessagesUsesRealControlledBidirectionalHandshake(t *testing.T) {
	packets, err := SSHMessages()
	require.NoError(t, err)
	var parsers [2]sshparser.Stream
	var banners, kex [2]int
	for i, packet := range packets {
		require.Nil(t, packet.Packet.ErrorLayer())
		require.Equal(t, BaseTime.Add(time.Duration(i)*time.Millisecond), packet.Packet.Metadata().Timestamp)
		tcp := packet.Packet.TransportLayer().(*layers.TCP)
		direction := 0
		if tcp.SrcPort == SSHServerPort {
			direction = 1
		}
		if i == 0 {
			require.True(t, tcp.SYN)
			require.False(t, tcp.ACK)
		}
		require.NoError(t, parsers[direction].Feed(tcp.Payload, func(observation sshparser.Observation) {
			if observation.Identification != nil {
				banners[direction]++
			}
			if observation.KEXINIT != nil {
				kex[direction]++
			}
		}))
	}
	require.Equal(t, [2]int{1, 1}, banners)
	require.Equal(t, [2]int{1, 1}, kex)
}
