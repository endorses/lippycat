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

	if !tracker.beginWrite() {
		logger.Debug("Skipping SIP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}
	defer tracker.activeWrites.Done()

	tracker.mu.Lock()
	call, ok := tracker.callMap[callID]
	tracker.mu.Unlock()

	if ok && call != nil {
		err := tracker.writePacket(callID, packet, PacketTypeSIP)

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

	if !tracker.beginWrite() {
		logger.Debug("Skipping RTP write during shutdown",
			"call_id", SanitizeCallIDForLogging(callID))
		return ErrShuttingDown
	}
	defer tracker.activeWrites.Done()

	tracker.mu.Lock()
	call, ok := tracker.callMap[callID]
	tracker.mu.Unlock()

	if ok && call != nil {
		err := tracker.writePacket(callID, packet, PacketTypeRTP)

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
