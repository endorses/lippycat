package capture

import (
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// RADIUSDisplay decodes a packet for presentation without creating attribution
// or correlator state. Stateful ingress metadata takes precedence when available.
func RADIUSDisplay(info PacketInfo) *types.RADIUSMetadata {
	if info.RADIUS != nil {
		return types.RADIUSMetadataFromObservation(info.RADIUS)
	}
	if info.Packet == nil {
		return nil
	}
	o, _, err := radius.DecodePacket(info.Packet.Data(), info.LinkType, info.Packet.Metadata().CaptureInfo, radius.CaptureScope{}, radius.Identity{})
	if err != nil {
		return nil
	}
	return types.RADIUSMetadataFromObservation(o)
}
