package voip

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	fmt.Println("Starting VOIP Sniffer")
	streamFactory := NewSipStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	capture.Init(devices, filter, startProcessor, assembler)
}

func StartLiveVoipSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartVoipSniffer)
}

func StartOfflineVoipSniffer(interfaces, filter string) {
	capture.StartOfflineSniffer(interfaces, filter, StartVoipSniffer)
}

func startProcessor(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	defer CloseWriters()
	// fmt.Println("Starting Processor")
	for pkt := range ch {
		packet := pkt.Packet
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			// fmt.Println("startProcessor nil")
			continue
		}
		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			// fmt.Println("TCP")
			handleTcpPackets(pkt, layer, assembler)
		case *layers.UDP:
			// fmt.Println("UDP")
			handleUdpPackets(pkt, layer)
		}
	}
}

func containsUserInHeaders(headers map[string]string) bool {
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		if sipusers.IsSurveiled(val) {
			return true
		}
	}
	return false
}
