package detector

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// detectRADIUS validates each complete datagram before any cached flow result.
// A reused UDP tuple cannot turn malformed messages into RADIUS observations.
func detectRADIUS(packet gopacket.Packet) *signatures.DetectionResult {
	if packet == nil || packet.NetworkLayer() == nil {
		return nil
	}
	ci := packet.Metadata().CaptureInfo
	if ci.CaptureLength != ci.Length || (ci.CaptureLength != 0 && ci.CaptureLength != len(packet.Data())) {
		return nil
	}
	network := packet.NetworkLayer()
	var link layers.LinkType
	switch network.(type) {
	case *layers.IPv4:
		link = layers.LinkTypeRaw
	case *layers.IPv6:
		link = layers.LinkTypeRaw
	default:
		return nil
	}
	// Locate the network header in the original frame. gopacket removes IPv6
	// hop-by-hop bytes from LayerPayload, so rebuilding from layer slices would
	// silently lose extension headers before the shared decoder can validate them.
	offset := 0
	for _, layer := range packet.Layers() {
		if layer == network {
			break
		}
		offset += len(layer.LayerContents())
	}
	if offset >= len(packet.Data()) {
		return nil
	}
	raw := packet.Data()[offset:]
	ci.CaptureLength, ci.Length = len(raw), len(raw)
	o, _, err := radius.DecodePacket(raw, link, ci, radius.CaptureScope{}, radius.Identity{})
	if err != nil {
		return nil
	}
	return &signatures.DetectionResult{Protocol: "RADIUS", Confidence: 1, CacheStrategy: signatures.CacheNever, Metadata: map[string]interface{}{"code": o.Message.Code, "identifier": o.Message.Identifier}}
}
