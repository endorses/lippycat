package voip

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type tcpPacketAssembler interface {
	AssembleTCP(gopacket.Flow, *layers.TCP, time.Time) error
}

// handleTcpPackets processes TCP packets and feeds them to the assembler
func handleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler tcpPacketAssembler, offlineMode ...bool) {
	handleTcpPacketsWithConfig(pkt, layer, assembler, DefaultConfig(), offlineMode...)
}

func handleTcpPacketsWithConfig(pkt capture.PacketInfo, layer *layers.TCP, assembler tcpPacketAssembler, config *Config, offlineMode ...bool) {
	// Set the current link type for TCP stream processing
	if linkLayer := pkt.Packet.LinkLayer(); linkLayer != nil {
		setCurrentLinkType(layers.LinkTypeEthernet) // Default to ethernet
	}

	// Process through plugin system if enabled
	if err := ProcessPacketWithPlugins(context.Background(), pkt.Packet); err != nil {
		logger.Debug("Plugin processing error for TCP packet", "error", err)
	}

	// Buffer the packet for potential PCAP writing
	flow := pkt.Packet.NetworkLayer().NetworkFlow()
	transportFlow := layer.TransportFlow()
	BufferTCPPacketWithConfig(flow, transportFlow, pkt, config)

	// Feed the packet to the TCP assembler for stream reconstruction
	offline := len(offlineMode) > 0 && offlineMode[0]
	kind := pipeline.SourceLiveCapture
	if offline {
		kind = pipeline.SourcePCAPReplay
	}
	var err error
	if engine, ok := assembler.(*pipeline.ReassemblyEngine); ok {
		err = engine.Assemble(captureadapter.FromPacketInfo(pkt, kind))
	} else {
		err = assembler.AssembleTCP(pkt.Packet.NetworkLayer().NetworkFlow(), layer, pkt.Packet.Metadata().Timestamp)
	}
	if err != nil {
		logger.Error("Failed to assemble VoIP TCP packet", "error", err)
	}
}
