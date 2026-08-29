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
	DefaultTCPBufferSize       = 10000
	maxPooledTCPBufferCapacity = 512
)

// Buffer strategies
var (
	currentLinkType    layers.LinkType = layers.LinkTypeEthernet
	currentLinkTypeMu  sync.RWMutex
	tcpPacketBuffers   = make(map[tcpBufferKey]*TCPPacketBuffer)
	tcpPacketBuffersMu sync.RWMutex
)

type tcpBufferKey struct {
	netFlow       gopacket.Flow
	transportFlow gopacket.Flow
}

// bufferedFrame stores the source-of-truth for one TCP packet without
// pinning the decoded gopacket.Packet (and its layer allocations).
// On retrieval, a Packet is reconstructed via gopacket.NewPacket with Lazy
// decoding so layers are only allocated for matched (non-discarded) flows.
type bufferedFrame struct {
	data           []byte
	timestamp      time.Time
	captureLength  int
	originalLength int
	iface          string
	linkType       layers.LinkType
	ancillaryData  []interface{}
}

type TCPPacketBuffer struct {
	packets    []bufferedFrame
	createdAt  time.Time
	lastAccess time.Time
	key        tcpBufferKey
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
		buffer.createdAt = time.Now()
		buffer.lastAccess = time.Now()
		buffer.key = tcpBufferKey{}
		buffer.maxSize = maxSize
		buffer.strategy = strategy
		buffer.callID = ""

		atomic.AddInt64(&bufferReuseCount, 1)
		return buffer
	}

	// Create a new buffer if pool is empty.
	// maxSize is the per-buffer packet limit, not the typical occupancy —
	// most flows hold only a few packets before flush/discard. Letting the
	// slice grow naturally avoids pre-allocating maxSize × sizeof(PacketInfo)
	// for every flow (which on "balanced" profile = 5000 × ~100B ≈ 500KB
	// per buffer × many flows = hundreds of MB of unused capacity).
	buffer := &TCPPacketBuffer{
		packets:    nil,
		createdAt:  time.Now(),
		lastAccess: time.Now(),
		maxSize:    maxSize,
		strategy:   strategy,
	}

	atomic.AddInt64(&bufferCreationCount, 1)
	return buffer
}

func releaseBuffer(buffer *TCPPacketBuffer) {
	if buffer == nil {
		return
	}

	if cap(buffer.packets) > 0 {
		clear(buffer.packets[:cap(buffer.packets)])
	}
	buffer.packets = buffer.packets[:0]
	buffer.callID = ""
	buffer.key = tcpBufferKey{}

	if cap(buffer.packets) > maxPooledTCPBufferCapacity {
		return
	}

	tcpBufferPool.mu.Lock()
	defer tcpBufferPool.mu.Unlock()

	// Return buffer to pool if there's space
	if len(tcpBufferPool.buffers) < tcpBufferPool.maxSize {
		tcpBufferPool.buffers = append(tcpBufferPool.buffers, buffer)
		atomic.AddInt64(&bufferReleaseCount, 1)
	}
	// If pool is full, buffer will be garbage collected
}

func newTCPBufferKey(netFlow, transportFlow gopacket.Flow) tcpBufferKey {
	if shouldReverseTCPBufferKey(netFlow, transportFlow) {
		netFlow = netFlow.Reverse()
		transportFlow = transportFlow.Reverse()
	}
	return tcpBufferKey{netFlow: netFlow, transportFlow: transportFlow}
}

func shouldReverseTCPBufferKey(netFlow, transportFlow gopacket.Flow) bool {
	netSrc, netDst := netFlow.Endpoints()
	if netDst.LessThan(netSrc) {
		return true
	}
	if netSrc.LessThan(netDst) {
		return false
	}

	transportSrc, transportDst := transportFlow.Endpoints()
	return transportDst.LessThan(transportSrc)
}

// BufferTCPPacket buffers a TCP packet for a network and transport flow.
// This is used by TCP SIP handlers to buffer packets before reassembly completes.
func BufferTCPPacket(netFlow, transportFlow gopacket.Flow, pkt capture.PacketInfo) {
	BufferTCPPacketWithConfig(netFlow, transportFlow, pkt, DefaultConfig())
}

func BufferTCPPacketWithConfig(netFlow, transportFlow gopacket.Flow, pkt capture.PacketInfo, config *Config) {
	key := newTCPBufferKey(netFlow, transportFlow)

	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[key]
	if !exists {
		// Create new buffer with configured strategy and size
		if config == nil {
			config = DefaultConfig()
		}
		buffer = getOrCreateBuffer(config.TCPBufferStrategy, config.MaxTCPBuffers)
		buffer.key = key
		tcpPacketBuffers[key] = buffer
	}

	buffer.lastAccess = time.Now()

	md := pkt.Packet.Metadata()
	frame := bufferedFrame{
		data:           pkt.Packet.Data(),
		timestamp:      md.Timestamp,
		captureLength:  md.CaptureLength,
		originalLength: md.Length,
		iface:          pkt.Interface,
		linkType:       pkt.LinkType,
		ancillaryData:  md.AncillaryData,
	}

	// Handle different buffer strategies
	switch buffer.strategy {
	case "adaptive":
		// Remove oldest 25% when full
		if len(buffer.packets) >= buffer.maxSize {
			removeCount := buffer.maxSize / 4
			copy(buffer.packets, buffer.packets[removeCount:])
			buffer.packets = buffer.packets[:len(buffer.packets)-removeCount]
		}
		buffer.packets = append(buffer.packets, frame)

	case "ring":
		// Circular buffer - overwrite oldest
		if len(buffer.packets) >= buffer.maxSize {
			// Shift all packets left and replace last
			copy(buffer.packets, buffer.packets[1:])
			buffer.packets[len(buffer.packets)-1] = frame
		} else {
			buffer.packets = append(buffer.packets, frame)
		}

	default: // "fixed" strategy
		// Drop new packets when full
		if len(buffer.packets) < buffer.maxSize {
			buffer.packets = append(buffer.packets, frame)
		}
	}
}

// reconstructPacket rebuilds a capture.PacketInfo from a bufferedFrame.
// Layers are decoded lazily so unused flows pay zero allocation cost.
func reconstructPacket(frame bufferedFrame) capture.PacketInfo {
	pkt := gopacket.NewPacket(frame.data, frame.linkType, gopacket.Lazy)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     frame.timestamp,
		CaptureLength: frame.captureLength,
		Length:        frame.originalLength,
		AncillaryData: frame.ancillaryData,
	}
	return capture.PacketInfo{
		LinkType:  frame.linkType,
		Packet:    pkt,
		Interface: frame.iface,
	}
}

// NOTE: there is deliberately no "flush this flow's packets to a call" helper.
// The buffer is keyed by canonical network and transport flow, so it isolates
// simultaneous TCP connections between the same hosts. The TCP handlers write
// one synthesized packet per reassembled SIP message (see buildSIPPacketInfo)
// and use this buffer only for the capture timestamp before releasing it.

// peekFirstTCPBufferedPacket reconstructs the first buffered packet for a flow
// without draining or modifying the buffer. Used by filter matching paths that
// only need a single packet to evaluate against (e.g., MatchPacket on the
// first packet in a SIP flow). Returns ok=false if no buffered packets exist.
func peekFirstTCPBufferedPacket(netFlow, transportFlow gopacket.Flow) (capture.PacketInfo, bool) {
	key := newTCPBufferKey(netFlow, transportFlow)

	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[key]
	if !exists || len(buffer.packets) == 0 {
		return capture.PacketInfo{}, false
	}
	return reconstructPacket(buffer.packets[0]), true
}

// discardTCPBufferedPackets removes buffered packets for a flow without writing them
// Used when SIP message doesn't match filter
func discardTCPBufferedPackets(netFlow, transportFlow gopacket.Flow) {
	key := newTCPBufferKey(netFlow, transportFlow)

	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[key]
	if !exists {
		return
	}

	delete(tcpPacketBuffers, key)
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
	PooledBuffers        int64     `json:"pooled_buffers"`
	PooledFrames         int64     `json:"pooled_frames"`
	PooledBytes          int64     `json:"pooled_bytes"`
	BufferedFrames       int64     `json:"buffered_frames"`
	BufferedBytes        int64     `json:"buffered_bytes"`
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

	tcpPacketBuffersMu.RLock()
	active := int64(len(tcpPacketBuffers))
	var bufferedFrames int64
	var bufferedBytes int64
	for _, buffer := range tcpPacketBuffers {
		bufferedFrames += int64(len(buffer.packets))
		for _, frame := range buffer.packets {
			bufferedBytes += int64(len(frame.data))
		}
	}
	tcpPacketBuffersMu.RUnlock()

	tcpBufferPool.mu.Lock()
	pooledBuffers := int64(len(tcpBufferPool.buffers))
	var pooledFrames int64
	var pooledBytes int64
	for _, buffer := range tcpBufferPool.buffers {
		pooledFrames += int64(cap(buffer.packets))
		for _, frame := range buffer.packets[:cap(buffer.packets)] {
			pooledBytes += int64(len(frame.data))
		}
	}
	tcpBufferPool.mu.Unlock()

	return TCPBufferStats{
		TotalBuffersCreated:  created,
		TotalBuffersReleased: released,
		ActiveBuffers:        active,
		PooledBuffers:        pooledBuffers,
		PooledFrames:         pooledFrames,
		PooledBytes:          pooledBytes,
		BufferedFrames:       bufferedFrames,
		BufferedBytes:        bufferedBytes,
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
	expiredKeys := make([]tcpBufferKey, 0)

	for key, buffer := range tcpPacketBuffers {
		if now.Sub(buffer.lastAccess) > maxAge {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		buffer := tcpPacketBuffers[key]
		delete(tcpPacketBuffers, key)
		releaseBuffer(buffer)
	}

	if len(expiredKeys) > 0 {
		logger.Debug("Cleaned up expired TCP buffers", "count", len(expiredKeys))
	}
}
