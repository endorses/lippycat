//go:build tap || all

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
)

type tapAssemblyContext struct{ info gopacket.CaptureInfo }

func (c tapAssemblyContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

func tapPacketContext(packet gopacket.Packet, source pipeline.SourceProvenance) tapAssemblyContext {
	info := packet.Metadata().CaptureInfo
	info.AncillaryData = append(append([]any(nil), info.AncillaryData...), source)
	return tapAssemblyContext{info}
}
