// Package captureadapter adapts local capture records to pipeline envelopes.
package captureadapter

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FromPacketInfo converts a local capture record with explicit source
// provenance. Callers replaying a PCAP must pass SourcePCAPReplay so replay and
// live packets do not become indistinguishable after normalization.
func FromPacketInfo(info capture.PacketInfo, kind ...pipeline.SourceKind) *pipeline.PacketEnvelope {
	sourceKind := pipeline.SourceLiveCapture
	if len(kind) != 0 {
		sourceKind = kind[0]
	}
	linkType := info.LinkType
	if linkType == 0 && info.Packet != nil {
		switch {
		case info.Packet.Layer(layers.LayerTypeEthernet) != nil:
			linkType = layers.LinkTypeEthernet
		case info.Packet.Layer(layers.LayerTypeLinuxSLL) != nil:
			linkType = layers.LinkTypeLinuxSLL
		case info.Packet.Layer(layers.LayerTypeIPv4) != nil || info.Packet.Layer(layers.LayerTypeIPv6) != nil:
			linkType = layers.LinkTypeRaw
		}
	}
	e := &pipeline.PacketEnvelope{LinkType: linkType, Source: pipeline.SourceProvenance{Kind: sourceKind, InterfaceName: info.Interface}}
	if info.Packet == nil {
		return e
	}
	e.Data = append([]byte(nil), info.Packet.Data()...)
	if m := info.Packet.Metadata(); m != nil {
		e.CaptureTime, e.CaptureLength, e.OriginalLength = m.Timestamp, m.CaptureLength, m.Length
	}
	return e
}

// ToPacketInfo converts an envelope back to the existing local capture record.
// Capture metadata is restored on the decoded packet rather than replaced with
// processing time.
func ToPacketInfo(e *pipeline.PacketEnvelope) capture.PacketInfo {
	if e == nil {
		return capture.PacketInfo{}
	}
	p := gopacket.NewPacket(append([]byte(nil), e.Data...), e.LinkType, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     e.CaptureTime,
		CaptureLength: e.CaptureLength,
		Length:        e.OriginalLength,
	}
	return capture.PacketInfo{Packet: p, LinkType: e.LinkType, Interface: e.Source.InterfaceName}
}

// ForEach normalizes a local capture stream at its ingress boundary and invokes
// consume synchronously, preserving channel order and backpressure semantics.
func ForEach(in <-chan capture.PacketInfo, kind pipeline.SourceKind, consume func(*pipeline.PacketEnvelope)) {
	for info := range in {
		consume(FromPacketInfo(info, kind))
	}
}
