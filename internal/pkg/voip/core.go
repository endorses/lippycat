package voip

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func StartProcessor(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	defer CloseWriters()
	fmt.Println("Starting Processor")
	for pkt := range ch {
		packet := pkt.Packet
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			continue
		}
		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			HandleTCPPackets(pkt, layer, assembler)
		case *layers.UDP:
			HandleUDPPackets(pkt, layer)
		}
	}
}

func containsUserInHeaders(headers map[string]string) bool {
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		for _, u := range SIPUsers.usernames {
			if strings.Contains(val, u) {
				// fmt.Println("true", val)
				return true
			}
		}
	}
	return false
}
