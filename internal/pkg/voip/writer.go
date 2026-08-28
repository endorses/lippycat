//go:build cli || all

package voip

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

func WriteSIP(tracker *CallTracker, callID string, packet gopacket.Packet) {
	// Try async writer first for better performance
	asyncWriter := GetAsyncWriter(tracker)
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		if err := asyncWriter.WritePacketAsync(callID, packet, PacketTypeSIP); err != nil {
			// Fallback to synchronous writing if async fails
			logger.Debug("Async SIP write failed, falling back to sync",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			tracker.writeSIPSync(callID, packet)
		}
		return
	}

	// Fallback to synchronous writing
	tracker.writeSIPSync(callID, packet)
}

// writeSIPSync performs synchronous SIP packet writing (legacy method)
func (tracker *CallTracker) writeSIPSync(callID string, packet gopacket.Packet) error {

	// Check if shutting down
	if tracker.shuttingDown.Load() == 1 {
		logger.Debug("Skipping SIP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}

	// Track active write
	tracker.activeWrites.Add(1)
	defer tracker.activeWrites.Done()

	// Double-check shutdown after acquiring write slot
	if tracker.shuttingDown.Load() == 1 {
		logger.Debug("Skipping SIP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}

	tracker.mu.Lock()
	call, ok := tracker.callMap[callID]
	tracker.mu.Unlock()

	if ok && call != nil {
		err := tracker.output.WritePacket(callID, packet, PacketTypeSIP)

		if err != nil {
			logger.Error("Error writing SIP packet for call",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			return err
		}

		// Update last updated time (with minimal locking)
		tracker.mu.Lock()
		if call, exists := tracker.callMap[callID]; exists {
			call.LastUpdated = time.Now()
		}
		tracker.mu.Unlock()
		return nil
	}
	return ErrCallNotFound
}

func WriteRTP(tracker *CallTracker, callID string, packet gopacket.Packet) {
	// Try async writer first for better performance
	asyncWriter := GetAsyncWriter(tracker)
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		if err := asyncWriter.WritePacketAsync(callID, packet, PacketTypeRTP); err != nil {
			// Fallback to synchronous writing if async fails
			logger.Debug("Async RTP write failed, falling back to sync",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			tracker.writeRTPSync(callID, packet)
		}
		return
	}

	// Fallback to synchronous writing
	tracker.writeRTPSync(callID, packet)
}

// writeRTPSync performs synchronous RTP packet writing (legacy method)
func (tracker *CallTracker) writeRTPSync(callID string, packet gopacket.Packet) error {

	// Check if shutting down
	if tracker.shuttingDown.Load() == 1 {
		logger.Debug("Skipping RTP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}

	// Track active write
	tracker.activeWrites.Add(1)
	defer tracker.activeWrites.Done()

	// Double-check shutdown after acquiring write slot
	if tracker.shuttingDown.Load() == 1 {
		logger.Debug("Skipping RTP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}

	tracker.mu.Lock()
	call, ok := tracker.callMap[callID]
	tracker.mu.Unlock()

	if ok && call != nil {
		err := tracker.output.WritePacket(callID, packet, PacketTypeRTP)

		if err != nil {
			logger.Error("Error writing RTP packet for call",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			return err
		}

		// Update last updated time (with minimal locking)
		tracker.mu.Lock()
		if call, exists := tracker.callMap[callID]; exists {
			call.LastUpdated = time.Now()
		}
		tracker.mu.Unlock()
		return nil
	}
	return ErrCallNotFound
}

// WriteSIPSync forces synchronous SIP packet writing (for critical operations)
func WriteSIPSync(tracker *CallTracker, callID string, packet gopacket.Packet) error {
	asyncWriter := GetAsyncWriter(tracker)
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		return asyncWriter.WritePacketSync(callID, packet, PacketTypeSIP)
	}

	// Fallback to legacy synchronous method
	return tracker.writeSIPSync(callID, packet)
}

// WriteRTPSync forces synchronous RTP packet writing (for critical operations)
func WriteRTPSync(tracker *CallTracker, callID string, packet gopacket.Packet) error {
	asyncWriter := GetAsyncWriter(tracker)
	if asyncWriter != nil && !asyncWriter.stopped.Load() {
		return asyncWriter.WritePacketSync(callID, packet, PacketTypeRTP)
	}

	// Fallback to legacy synchronous method
	return tracker.writeRTPSync(callID, packet)
}

// GetWriterStats returns statistics from the async writer pool
func GetWriterStats(tracker *CallTracker) *AsyncWriterStats {
	asyncWriter := GetAsyncWriter(tracker)
	if asyncWriter != nil {
		return asyncWriter.GetStats()
	}
	return &AsyncWriterStats{} // Return empty stats if no async writer
}
