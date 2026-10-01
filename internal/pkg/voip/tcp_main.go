package voip

import (
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

	// Reassembly supplies each message's capture timestamp and handlers write
	// a synthesized packet containing exactly that message. Raw tuple-keyed
	// buffering is unnecessary here and would let an old generation's delayed
	// cleanup erase packets captured for a new connection on the same tuple.

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
