package capture

import (
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ConvertPacketToDisplay converts a gopacket.Packet to types.PacketDisplay.
// This provides a structured representation suitable for JSON output and other formats.
// Uses shared extraction logic from converter_shared.go.
func ConvertPacketToDisplay(pktInfo PacketInfo) types.PacketDisplay {
	fields := ExtractPacketFields(pktInfo.Packet)
	return FieldsToPacketDisplay(fields, pktInfo)
}
