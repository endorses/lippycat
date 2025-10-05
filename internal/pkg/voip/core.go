package voip

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	ctx := context.Background()
	logger.InfoContext(ctx, "Starting VoIP sniffer",
		"device_count", len(devices),
		"filter", filter)

	streamFactory := NewSipStreamFactory(ctx)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Use common signal handler pattern (like hunt and sniff do)
	capture.RunWithSignalHandler(devices, filter, startProcessor, assembler)
}

func StartLiveVoipSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartVoipSniffer)
}

func StartOfflineVoipSniffer(interfaces, filter string) {
	capture.StartOfflineSniffer(interfaces, filter, StartVoipSniffer)
}

func startProcessor(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	defer CloseWriters()
	for pkt := range ch {
		packet := pkt.Packet
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			continue
		}
		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			handleTcpPackets(pkt, layer, assembler)
		case *layers.UDP:
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
