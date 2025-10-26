package voip

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
)

// Shared variables and helpers used by both CLI and hunter builds

var (
	globalBufferMgr    *BufferManager
	bufferOnce         sync.Once
	globalVifMgr       vinterface.Manager         // Virtual interface manager for packet injection
	globalTimingReplay *vinterface.TimingReplayer // Timing replayer for virtual interface
)

// injectPacketToVirtualInterface injects a packet into the virtual interface if enabled
// This should be called only for confirmed VoIP packets (SIP or RTP)
// If vif_replay_timing is enabled, respects original PCAP packet timing (like tcpreplay)
func injectPacketToVirtualInterface(pkt capture.PacketInfo) {
	if globalVifMgr == nil {
		return
	}

	// Handle packet timing replay (respects PCAP timestamps like tcpreplay)
	if globalTimingReplay != nil {
		globalTimingReplay.WaitForPacketTime(pkt.Packet.Metadata().Timestamp)
	}

	// Inject the packet
	display := capture.ConvertPacketToDisplay(pkt)

	// Preserve raw packet data for virtual interface injection
	// (normally nil to save memory, but required for packet reconstruction)
	display.RawData = pkt.Packet.Data()
	display.LinkType = pkt.LinkType

	logger.Debug("Injecting packet to virtual interface",
		"raw_data_len", len(display.RawData),
		"link_type", display.LinkType,
		"packet_len", pkt.Packet.Metadata().Length)

	if err := globalVifMgr.InjectPacketBatch([]types.PacketDisplay{display}); err != nil {
		logger.Debug("Failed to inject VoIP packet into virtual interface", "error", err)
	}
}

// containsUserInHeaders checks if any of the SIP headers contain a surveiled user
// Returns true if there are NO filters configured (promiscuous mode) OR if a match is found
func containsUserInHeaders(headers map[string]string) bool {
	// If no SIP users are configured, accept all VoIP traffic (promiscuous/testing mode)
	hasSurveiled := sipusers.HasSurveiled()
	logger.Debug("containsUserInHeaders check",
		"has_surveiled", hasSurveiled,
		"headers", headers)
	if !hasSurveiled {
		logger.Debug("Promiscuous mode - accepting all VoIP traffic")
		return true
	}

	// Check if any header matches a surveiled user
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		if sipusers.IsSurveiled(val) {
			logger.Debug("Matched surveilled user", "field", field, "value", val)
			return true
		}
	}
	logger.Debug("No match found - rejecting packet")
	return false
}
