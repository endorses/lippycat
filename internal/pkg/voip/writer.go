package voip

import (
	"os"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

var (
	sipFile, rtpFile *os.File
	writerMutex      sync.Mutex
)

func CloseWriters() {
	writerMutex.Lock()
	defer writerMutex.Unlock()

	if sipFile != nil {
		if err := sipFile.Close(); err != nil {
			logger.Error("Error closing SIP file", "error", err)
		}
		sipFile = nil
	}
	if rtpFile != nil {
		if err := rtpFile.Close(); err != nil {
			logger.Error("Error closing RTP file", "error", err)
		}
		rtpFile = nil
	}
}

func WriteSIP(callID string, packet gopacket.Packet) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if call, ok := tracker.callMap[callID]; ok && call.SIPWriter != nil {
		if err := call.SIPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			logger.Error("Error writing SIP packet for call",
				"call_id", callID,
				"error", err)
			return
		}
		call.LastUpdated = time.Now()
	}
}

func WriteRTP(callID string, packet gopacket.Packet) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if call, ok := tracker.callMap[callID]; ok && call.RTPWriter != nil {
		if err := call.RTPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			logger.Error("Error writing RTP packet for call",
				"call_id", callID,
				"error", err)
			return
		}
		call.LastUpdated = time.Now()
	}
}
