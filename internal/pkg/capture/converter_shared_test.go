package capture

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestTCPFlagPresentationParity(t *testing.T) {
	for mask := 0; mask < 64; mask++ {
		tcp := layers.TCP{SYN: mask&1 != 0, ACK: mask&2 != 0, FIN: mask&4 != 0, RST: mask&8 != 0, PSH: mask&16 != 0, URG: mask&32 != 0, ECE: true, CWR: true}
		var names []string
		for bit, name := range []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"} {
			if mask&(1<<bit) != 0 {
				names = append(names, name)
			}
		}
		want := strings.Join(names, " ")
		if want == "" {
			want = "NONE"
		}
		require.Equal(t, want, FormatTCPFlags(&tcp))
	}
	for _, tcp := range []bool{false, true} {
		raw := offlineDecoderFixture(t, false, tcp, 40001, nil, []byte("payload"))
		packet := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.Default)
		fields := ExtractPacketFields(packet)
		want := fmt.Sprintf("%s -> %s", fields.SrcPort, fields.DstPort)
		if tcp {
			want += " [ACK]"
		}
		require.Equal(t, want, fields.Info)
	}
}
