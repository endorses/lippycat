package voip

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/viper"
)

// Shared variables and helpers used by both CLI and hunter builds

var (
	globalBufferMgr *BufferManager
	bufferOnce      sync.Once
	globalVifMgr    vinterface.Manager // Virtual interface manager for packet injection

	// Packet timing replay state
	vifTimingMu       sync.Mutex
	vifFirstTimestamp time.Time
	vifLastTimestamp  time.Time
	vifReplayStart    time.Time
)

// injectPacketToVirtualInterface injects a packet into the virtual interface if enabled
// This should be called only for confirmed VoIP packets (SIP or RTP)
// If vif_replay_timing is enabled, respects original PCAP packet timing (like tcpreplay)
func injectPacketToVirtualInterface(pkt capture.PacketInfo) {
	if globalVifMgr == nil {
		return
	}

	// Handle packet timing replay if enabled
	if viper.GetBool("voip.vif_replay_timing") {
		pktTimestamp := pkt.Packet.Metadata().Timestamp

		vifTimingMu.Lock()
		// Initialize timing on first packet
		if vifFirstTimestamp.IsZero() {
			vifFirstTimestamp = pktTimestamp
			vifReplayStart = time.Now()
			vifLastTimestamp = pktTimestamp
			vifTimingMu.Unlock()
		} else {
			// Calculate how much time has elapsed in the PCAP
			pcapElapsed := pktTimestamp.Sub(vifFirstTimestamp)

			// Calculate how much time has elapsed in real time since we started
			realElapsed := time.Since(vifReplayStart)

			// If we're ahead of schedule, sleep to match PCAP timing
			if pcapElapsed > realElapsed {
				sleepDuration := pcapElapsed - realElapsed
				vifTimingMu.Unlock()

				logger.Debug("Sleeping to match PCAP timing",
					"sleep_duration", sleepDuration,
					"pcap_elapsed", pcapElapsed,
					"real_elapsed", realElapsed)
				time.Sleep(sleepDuration)
			} else {
				vifTimingMu.Unlock()
			}

			vifTimingMu.Lock()
			vifLastTimestamp = pktTimestamp
			vifTimingMu.Unlock()
		}
	}

	// Inject the packet
	display := capture.ConvertPacketToDisplay(pkt)
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
