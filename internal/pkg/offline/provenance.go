package offline

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketProvenance separates the physical input frame from the normalized
// logical packet. For reassembly, OriginalCapture identifies the completing
// frame; effective metadata describes the exact bytes referenced by Locator.
// Values are immutable after publication.
type PacketProvenance struct {
	Context           CaptureContext
	Locator           Locator
	Derived           bool
	SourceIndex       uint32
	SourcePath        string
	PhysicalOrdinal   uint64
	LogicalSequence   uint64
	OriginalCapture   gopacket.CaptureInfo
	OriginalLinkType  layers.LinkType
	EffectiveCapture  gopacket.CaptureInfo
	EffectiveLinkType layers.LinkType
}
