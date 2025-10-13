package voip

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// LocalFileHandler handles SIP messages for local capture mode (lc sniff voip)
// It writes matched calls to local PCAP files
type LocalFileHandler struct{}

// NewLocalFileHandler creates a handler for local file writing
func NewLocalFileHandler() *LocalFileHandler {
	return &LocalFileHandler{}
}

// HandleSIPMessage processes a complete SIP message for local file writing
func (h *LocalFileHandler) HandleSIPMessage(sipMessage []byte, callID string, flow gopacket.Flow) bool {
	if callID == "" {
		return false
	}

	// Flush any buffered TCP packets to this call
	flushTCPPacketsToCall(flow, callID, true)

	// Process the SIP message through the existing handler
	// This checks sipusers filter, creates call writers, extracts RTP ports
	matched := handleSipMessage(sipMessage)

	if matched {
		logger.Debug("TCP SIP message matched filter",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", flow.String())
	}

	return matched
}
