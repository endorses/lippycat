//go:build tui || all

package tui

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/offline"
	tlspkg "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
)

// materializeOfflinePacket reconstructs only packet-local metadata. Application
// classification, Info and stateful results were frozen during ordered analysis;
// selection never consults a detector, tracker, key log or live configuration.
// The backend applies finalized exceptional metadata after this decode.
func materializeOfflinePacket(ctx context.Context, raw []byte, summary offline.Summary) (types.PacketDisplay, error) {
	if err := ctx.Err(); err != nil {
		return types.PacketDisplay{}, err
	}
	packet := summary.DisplayFields()
	packet.RawData = raw // The decoder contract transfers owned effective bytes.
	if summary.HasField("dns") {
		packet.DNSData = parseDNSFromRawData(raw, packet.LinkType)
	}
	if summary.HasField("http") {
		packet.HTTPData = parseHTTPFromRawData(raw, packet.LinkType)
	}
	if summary.HasField("tls") {
		decoded := gopacket.NewPacket(raw, packet.LinkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		packet.TLSData = tlspkg.NewParser().Parse(decoded)
	}
	return packet, ctx.Err()
}
