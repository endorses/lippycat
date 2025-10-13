package voip

import (
	"context"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

var (
	globalBufferMgr *BufferManager
	bufferOnce      sync.Once
)

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	ctx := context.Background()
	logger.InfoContext(ctx, "Starting VoIP sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Create handler for local file writing
	handler := NewLocalFileHandler()
	streamFactory := NewSipStreamFactory(ctx, handler)
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

	// Initialize buffer manager (5 second timeout, 200 packet max per call)
	bufferOnce.Do(func() {
		globalBufferMgr = NewBufferManager(5*time.Second, 200)
		logger.Info("Initialized VoIP buffer manager", "max_age", "5s", "max_size", 200)
	})
	defer func() {
		if globalBufferMgr != nil {
			globalBufferMgr.Close()
		}
	}()

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
