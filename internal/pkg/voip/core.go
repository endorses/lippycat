package voip

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func StartVoipSniffer(interfaces, filter string) {
	fmt.Println("Starting VOIP Sniffer")
	streamFactory := NewSipStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	capture.Init(strings.Split(interfaces, ","), filter, StartProcessor, assembler)
}

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
			// fmt.Println("TCP")
			HandleTcpPackets(pkt, layer, assembler)
		case *layers.UDP:
			// fmt.Println("UDP")
			HandleUdpPackets(pkt, layer)
		}
	}
}

func containsUserInHeaders(headers map[string]string) bool {
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		for _, u := range SipUsers.usernames {
			if strings.Contains(val, u) {
				// fmt.Println("true", val)
				return true
			}
		}
	}
	return false
}
