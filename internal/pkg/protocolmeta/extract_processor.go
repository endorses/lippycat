//go:build (processor || tui) && !tap && !all && !cli && !hunter

package protocolmeta

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
)

// Enrich is a no-op in processor-only and TUI-only builds, which cannot
// capture locally.
func Enrich(_ gopacket.Packet, metadata *data.PacketMetadata, _ bool) *data.PacketMetadata {
	return metadata
}
