//go:build cli || hunter || processor || tap || tui || all

// Package protocolmeta converts packet-level analyzer output to the protobuf
// metadata transported between capture and processor nodes.
package protocolmeta

import (
	"github.com/endorses/lippycat/api/gen/data"
	httpparser "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Enrich adds flow, TLS, and HTTP metadata without replacing metadata already
// produced by protocol-specific handlers.
func Enrich(packet gopacket.Packet, metadata *data.PacketMetadata, includeHTTPHeaders bool) *data.PacketMetadata {
	if packet == nil {
		return metadata
	}
	if metadata == nil {
		metadata = &data.PacketMetadata{}
	}
	populateFlow(packet, metadata)
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && len(tcp.Payload) > 0 {
		if metadata.Tls == nil {
			metadata.Tls = TLSToProto(tls.NewParser().ParsePayload(tcp.Payload))
		}
		if metadata.Http == nil {
			metadata.Http = HTTPToProto(httpparser.NewParser().ParsePayload(tcp.Payload), includeHTTPHeaders)
		}
	}
	return metadata
}

func populateFlow(packet gopacket.Packet, metadata *data.PacketMetadata) {
	if network := packet.NetworkLayer(); network != nil {
		metadata.SrcIp = network.NetworkFlow().Src().String()
		metadata.DstIp = network.NetworkFlow().Dst().String()
	}
	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "tcp", uint32(transport.SrcPort), uint32(transport.DstPort)
	case *layers.UDP:
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "udp", uint32(transport.SrcPort), uint32(transport.DstPort)
	}
}
