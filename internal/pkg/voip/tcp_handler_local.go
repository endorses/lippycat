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
	logger.Debug("TCP HandleSIPMessage called",
		"call_id", SanitizeCallIDForLogging(callID),
		"message_len", len(sipMessage),
		"flow", flow.String())

	if callID == "" {
		logger.Debug("Empty call-ID, skipping")
		return false
	}

	// Process the SIP message through the existing handler first
	// This checks sipusers filter and validates the message
	linkType := getCurrentLinkType() // Use global link type set by TCP stream processor
	matched := handleSipMessage(sipMessage, linkType)

	logger.Debug("TCP SIP filter check result",
		"call_id", SanitizeCallIDForLogging(callID),
		"matched", matched)

	if !matched {
		// Message didn't match filter, don't write anything
		logger.Debug("Message didn't match filter, not writing")
		return false
	}

	// Message matched - create call if needed to initialize writers
	call := GetOrCreateCall(callID, linkType)
	if call == nil {
		logger.Warn("Failed to create call for TCP SIP message", "call_id", SanitizeCallIDForLogging(callID))
		return false
	}

	logger.Debug("Created/retrieved call, about to flush TCP packets",
		"call_id", SanitizeCallIDForLogging(callID))

	// Now flush buffered TCP packets to file
	flushTCPPacketsToCall(flow, callID, true)

	logger.Info("TCP SIP message matched filter and written to file",
		"call_id", SanitizeCallIDForLogging(callID),
		"flow", flow.String())

	return true
}
