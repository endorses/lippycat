package voip

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCP packet buffer constants
const (
	DefaultTCPBufferSize = 10000
)

// Buffer strategies
var (
	currentLinkType    layers.LinkType = layers.LinkTypeEthernet
	currentLinkTypeMu  sync.RWMutex
	tcpPacketBuffers   = make(map[gopacket.Flow]*TCPPacketBuffer)
	tcpPacketBuffersMu sync.RWMutex
)

type TCPPacketBuffer struct {
	packets    []capture.PacketInfo
	createdAt  time.Time
	lastAccess time.Time
	flow       gopacket.Flow
	callID     string
	maxSize    int
	strategy   string
}

type TCPBufferPool struct {
	buffers []*TCPPacketBuffer
	maxSize int
	mu      sync.Mutex
}

var tcpBufferPool = &TCPBufferPool{
	buffers: make([]*TCPPacketBuffer, 0, DefaultTCPBufferPoolSize),
	maxSize: DefaultTCPBufferPoolSize,
}

var (
	bufferCreationCount int64
	bufferReuseCount    int64
	bufferReleaseCount  int64
)

func setCurrentLinkType(linkType layers.LinkType) {
	currentLinkTypeMu.Lock()
	defer currentLinkTypeMu.Unlock()
	currentLinkType = linkType
}

func getCurrentLinkType() layers.LinkType {
	currentLinkTypeMu.RLock()
	defer currentLinkTypeMu.RUnlock()
	return currentLinkType
}

func getOrCreateBuffer(strategy string, maxSize int) *TCPPacketBuffer {
	tcpBufferPool.mu.Lock()
	defer tcpBufferPool.mu.Unlock()

	// Try to reuse an existing buffer from the pool
	if len(tcpBufferPool.buffers) > 0 {
		buffer := tcpBufferPool.buffers[len(tcpBufferPool.buffers)-1]
		tcpBufferPool.buffers = tcpBufferPool.buffers[:len(tcpBufferPool.buffers)-1]

		// Reset the buffer for reuse
		buffer.packets = buffer.packets[:0]
		buffer.createdAt = time.Now()
		buffer.lastAccess = time.Now()
		buffer.maxSize = maxSize
		buffer.strategy = strategy
		buffer.callID = ""

		atomic.AddInt64(&bufferReuseCount, 1)
		return buffer
	}

	// Create a new buffer if pool is empty
	buffer := &TCPPacketBuffer{
		packets:    make([]capture.PacketInfo, 0, maxSize),
		createdAt:  time.Now(),
		lastAccess: time.Now(),
		maxSize:    maxSize,
		strategy:   strategy,
	}

	atomic.AddInt64(&bufferCreationCount, 1)
	return buffer
}

func releaseBuffer(buffer *TCPPacketBuffer) {
	tcpBufferPool.mu.Lock()
	defer tcpBufferPool.mu.Unlock()

	// Return buffer to pool if there's space
	if len(tcpBufferPool.buffers) < tcpBufferPool.maxSize {
		tcpBufferPool.buffers = append(tcpBufferPool.buffers, buffer)
		atomic.AddInt64(&bufferReleaseCount, 1)
	}
	// If pool is full, buffer will be garbage collected
}

// BufferTCPPacket buffers a TCP packet for a network flow.
// This is used by TCP SIP handlers to buffer packets before reassembly completes.
func BufferTCPPacket(flow gopacket.Flow, pkt capture.PacketInfo) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists {
		// Create new buffer with configured strategy and size
		config := GetConfig()
		buffer = getOrCreateBuffer(config.TCPBufferStrategy, config.MaxTCPBuffers)
		buffer.flow = flow
		tcpPacketBuffers[flow] = buffer
	}

	buffer.lastAccess = time.Now()

	// Handle different buffer strategies
	switch buffer.strategy {
	case "adaptive":
		// Remove oldest 25% when full
		if len(buffer.packets) >= buffer.maxSize {
			removeCount := buffer.maxSize / 4
			copy(buffer.packets, buffer.packets[removeCount:])
			buffer.packets = buffer.packets[:len(buffer.packets)-removeCount]
		}
		buffer.packets = append(buffer.packets, pkt)

	case "ring":
		// Circular buffer - overwrite oldest
		if len(buffer.packets) >= buffer.maxSize {
			// Shift all packets left and replace last
			copy(buffer.packets, buffer.packets[1:])
			buffer.packets[len(buffer.packets)-1] = pkt
		} else {
			buffer.packets = append(buffer.packets, pkt)
		}

	default: // "fixed" strategy
		// Drop new packets when full
		if len(buffer.packets) < buffer.maxSize {
			buffer.packets = append(buffer.packets, pkt)
		}
	}
}

func flushTCPPacketsToCall(flow gopacket.Flow, callID string, writeVoip bool) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists || len(buffer.packets) == 0 {
		return
	}

	// Update the buffer with call ID
	buffer.callID = callID

	// Write buffered packets to the call
	for _, pkt := range buffer.packets {
		// Inject TCP SIP packet into virtual interface
		injectPacketToVirtualInterface(pkt)

		if writeVoip {
			WriteSIP(callID, pkt.Packet)
		}
	}

	// Clear the buffer after flushing
	buffer.packets = buffer.packets[:0]

	// Return buffer to pool
	delete(tcpPacketBuffers, flow)
	releaseBuffer(buffer)
}

// getTCPBufferedPackets returns buffered packets for a flow without clearing them
// Used by hunter mode to forward packets to processor
func getTCPBufferedPackets(flow gopacket.Flow) []capture.PacketInfo {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists || len(buffer.packets) == 0 {
		return nil
	}

	// Copy packet info to return slice (includes interface name)
	packets := make([]capture.PacketInfo, len(buffer.packets))
	copy(packets, buffer.packets)

	// Clear and release buffer
	buffer.packets = buffer.packets[:0]
	delete(tcpPacketBuffers, flow)
	releaseBuffer(buffer)

	return packets
}

// discardTCPBufferedPackets removes buffered packets for a flow without writing them
// Used when SIP message doesn't match filter
func discardTCPBufferedPackets(flow gopacket.Flow) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists {
		return
	}

	// Clear and release buffer
	buffer.packets = buffer.packets[:0]
	delete(tcpPacketBuffers, flow)
	releaseBuffer(buffer)
}

// TCP buffer statistics
type tcpBufferStatsInternal struct {
	mu                   sync.RWMutex
	totalBuffersCreated  int64
	totalBuffersReleased int64
	activeBuffers        int64
	totalPacketsBuffered int64
	totalPacketsFlushed  int64
	lastStatsUpdate      time.Time
}

type TCPBufferStats struct {
	TotalBuffersCreated  int64     `json:"total_buffers_created"`
	TotalBuffersReleased int64     `json:"total_buffers_released"`
	ActiveBuffers        int64     `json:"active_buffers"`
	TotalPacketsBuffered int64     `json:"total_packets_buffered"`
	TotalPacketsFlushed  int64     `json:"total_packets_flushed"`
	LastStatsUpdate      time.Time `json:"last_stats_update"`

	// Aliases for backwards compatibility
	TotalBuffers   int64 `json:"total_buffers"`
	TotalPackets   int64 `json:"total_packets"`
	BuffersDropped int64 `json:"buffers_dropped"`
}

var tcpBufferStats = &tcpBufferStatsInternal{
	lastStatsUpdate: time.Now(),
}

func GetTCPBufferStats() TCPBufferStats {
	tcpBufferStats.mu.RLock()
	defer tcpBufferStats.mu.RUnlock()

	created := atomic.LoadInt64(&bufferCreationCount)
	released := atomic.LoadInt64(&bufferReleaseCount)
	active := int64(len(tcpPacketBuffers))

	return TCPBufferStats{
		TotalBuffersCreated:  created,
		TotalBuffersReleased: released,
		ActiveBuffers:        active,
		TotalPacketsBuffered: tcpBufferStats.totalPacketsBuffered,
		TotalPacketsFlushed:  tcpBufferStats.totalPacketsFlushed,
		LastStatsUpdate:      tcpBufferStats.lastStatsUpdate,

		// Backwards compatibility aliases
		TotalBuffers:   active,
		TotalPackets:   tcpBufferStats.totalPacketsBuffered,
		BuffersDropped: 0, // This would need to be tracked separately if needed
	}
}

func cleanupOldTCPBuffers(maxAge time.Duration) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	now := time.Now()
	expiredFlows := make([]gopacket.Flow, 0)

	for flow, buffer := range tcpPacketBuffers {
		if now.Sub(buffer.lastAccess) > maxAge {
			expiredFlows = append(expiredFlows, flow)
		}
	}

	for _, flow := range expiredFlows {
		buffer := tcpPacketBuffers[flow]
		delete(tcpPacketBuffers, flow)
		releaseBuffer(buffer)
	}

	if len(expiredFlows) > 0 {
		logger.Debug("Cleaned up expired TCP buffers", "count", len(expiredFlows))
	}
}
