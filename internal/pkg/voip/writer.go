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

	// Close async writer pool first
	CloseAsyncWriter()

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
	// Try async writer first for better performance
	asyncWriter := GetAsyncWriter()
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		if err := asyncWriter.WritePacketAsync(callID, packet, PacketTypeSIP); err != nil {
			// Fallback to synchronous writing if async fails
			logger.Debug("Async SIP write failed, falling back to sync",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			writeSIPSync(callID, packet)
		}
		return
	}

	// Fallback to synchronous writing
	writeSIPSync(callID, packet)
}

// writeSIPSync performs synchronous SIP packet writing (legacy method)
func writeSIPSync(callID string, packet gopacket.Packet) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if call, ok := tracker.callMap[callID]; ok && call.SIPWriter != nil {
		if err := call.SIPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			logger.Error("Error writing SIP packet for call",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			return
		}
		call.LastUpdated = time.Now()
	}
}

func WriteRTP(callID string, packet gopacket.Packet) {
	// Try async writer first for better performance
	asyncWriter := GetAsyncWriter()
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		if err := asyncWriter.WritePacketAsync(callID, packet, PacketTypeRTP); err != nil {
			// Fallback to synchronous writing if async fails
			logger.Debug("Async RTP write failed, falling back to sync",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			writeRTPSync(callID, packet)
		}
		return
	}

	// Fallback to synchronous writing
	writeRTPSync(callID, packet)
}

// writeRTPSync performs synchronous RTP packet writing (legacy method)
func writeRTPSync(callID string, packet gopacket.Packet) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if call, ok := tracker.callMap[callID]; ok && call.RTPWriter != nil {
		if err := call.RTPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			logger.Error("Error writing RTP packet for call",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			return
		}
		call.LastUpdated = time.Now()
	}
}

// WriteSIPSync forces synchronous SIP packet writing (for critical operations)
func WriteSIPSync(callID string, packet gopacket.Packet) error {
	asyncWriter := GetAsyncWriter()
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		return asyncWriter.WritePacketSync(callID, packet, PacketTypeSIP)
	}

	// Fallback to legacy synchronous method
	writeSIPSync(callID, packet)
	return nil
}

// WriteRTPSync forces synchronous RTP packet writing (for critical operations)
func WriteRTPSync(callID string, packet gopacket.Packet) error {
	asyncWriter := GetAsyncWriter()
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		return asyncWriter.WritePacketSync(callID, packet, PacketTypeRTP)
	}

	// Fallback to legacy synchronous method
	writeRTPSync(callID, packet)
	return nil
}

// GetWriterStats returns statistics from the async writer pool
func GetWriterStats() *AsyncWriterStats {
	asyncWriter := GetAsyncWriter()
	if asyncWriter != nil {
		return asyncWriter.GetStats()
	}
	return &AsyncWriterStats{} // Return empty stats if no async writer
}
