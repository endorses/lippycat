//go:build processor && !tap && !all

package protocolmeta

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
)

// Enrich is a no-op in processor-only builds, which cannot capture locally.
func Enrich(_ gopacket.Packet, metadata *data.PacketMetadata, _ bool) *data.PacketMetadata {
	return metadata
}
