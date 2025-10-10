package store

import (
	"sync"

	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/filters"
)

// PacketStore manages packet storage and filtering with a circular buffer
type PacketStore struct {
	mu              sync.RWMutex
	Packets         []components.PacketDisplay // Ring buffer of packets (all captured)
	PacketsHead     int                        // Head index for circular buffer
	PacketsCount    int                        // Current number of packets in buffer
	FilteredPackets []components.PacketDisplay // Filtered packets for display
	MaxPackets      int                        // Maximum packets to keep in memory
	FilterChain     *filters.FilterChain       // Active filters
	TotalPackets    int                        // Total packets seen
	MatchedPackets  int                        // Packets matching filter
}

// NewPacketStore creates a new packet store with the given buffer size
func NewPacketStore(bufferSize int) *PacketStore {
	return &PacketStore{
		Packets:         make([]components.PacketDisplay, bufferSize),
		FilteredPackets: []components.PacketDisplay{},
		MaxPackets:      bufferSize,
		FilterChain:     filters.NewFilterChain(),
	}
}

// AddPacket adds a packet to the store and applies filters
func (ps *PacketStore) AddPacket(packet components.PacketDisplay) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Add to ring buffer
	ps.Packets[ps.PacketsHead] = packet
	ps.PacketsHead = (ps.PacketsHead + 1) % ps.MaxPackets
	if ps.PacketsCount < ps.MaxPackets {
		ps.PacketsCount++
	}

	ps.TotalPackets++

	// Apply filter
	if ps.FilterChain.Match(packet) {
		ps.FilteredPackets = append(ps.FilteredPackets, packet)
		ps.MatchedPackets++

		// Keep filtered packets bounded (same as total buffer)
		if len(ps.FilteredPackets) > ps.MaxPackets {
			ps.FilteredPackets = ps.FilteredPackets[1:]
		}
	}
}

// GetPacketsInOrder returns packets from the circular buffer in chronological order
func (ps *PacketStore) GetPacketsInOrder() []components.PacketDisplay {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.PacketsCount == 0 {
		return nil
	}

	if ps.PacketsCount < ps.MaxPackets {
		// Buffer not full yet, packets are in order from index 0
		result := make([]components.PacketDisplay, ps.PacketsCount)
		copy(result, ps.Packets[:ps.PacketsCount])
		return result
	}

	// Buffer is full, need to reorder starting from head
	result := make([]components.PacketDisplay, ps.MaxPackets)
	for i := 0; i < ps.MaxPackets; i++ {
		result[i] = ps.Packets[(ps.PacketsHead+i)%ps.MaxPackets]
	}
	return result
}

// GetFilteredPackets returns filtered packets for display
func (ps *PacketStore) GetFilteredPackets() []components.PacketDisplay {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]components.PacketDisplay, len(ps.FilteredPackets))
	copy(result, ps.FilteredPackets)
	return result
}

// SetFilter sets the active filter chain and reapplies to all packets
func (ps *PacketStore) SetFilter(filterChain *filters.FilterChain) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.FilterChain = filterChain
	ps.reapplyFilters()
}

// ClearFilter removes all filters and shows all packets
func (ps *PacketStore) ClearFilter() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.FilterChain = filters.NewFilterChain()
	ps.reapplyFilters()
}

// reapplyFilters re-evaluates all packets against current filter (must hold lock)
func (ps *PacketStore) reapplyFilters() {
	ps.FilteredPackets = []components.PacketDisplay{}
	ps.MatchedPackets = 0

	packets := ps.getPacketsInOrderLocked()
	for _, packet := range packets {
		if ps.FilterChain.Match(packet) {
			ps.FilteredPackets = append(ps.FilteredPackets, packet)
			ps.MatchedPackets++
		}
	}
}

// getPacketsInOrderLocked returns packets in order (must hold read lock)
func (ps *PacketStore) getPacketsInOrderLocked() []components.PacketDisplay {
	if ps.PacketsCount == 0 {
		return nil
	}

	if ps.PacketsCount < ps.MaxPackets {
		result := make([]components.PacketDisplay, ps.PacketsCount)
		copy(result, ps.Packets[:ps.PacketsCount])
		return result
	}

	result := make([]components.PacketDisplay, ps.MaxPackets)
	for i := 0; i < ps.MaxPackets; i++ {
		result[i] = ps.Packets[(ps.PacketsHead+i)%ps.MaxPackets]
	}
	return result
}

// Clear removes all packets from the store
func (ps *PacketStore) Clear() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.PacketsHead = 0
	ps.PacketsCount = 0
	ps.FilteredPackets = []components.PacketDisplay{}
	ps.TotalPackets = 0
	ps.MatchedPackets = 0
}

// Stats returns packet statistics
func (ps *PacketStore) Stats() (total, matched int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.TotalPackets, ps.MatchedPackets
}

// Count returns the current number of packets in the buffer
func (ps *PacketStore) Count() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.PacketsCount
}

// FilteredCount returns the number of filtered packets
func (ps *PacketStore) FilteredCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.FilteredPackets)
}

// HasFilter returns true if a filter chain is active
func (ps *PacketStore) HasFilter() bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return !ps.FilterChain.IsEmpty()
}

// MatchFilter checks if a packet matches the current filter chain
func (ps *PacketStore) MatchFilter(packet components.PacketDisplay) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.FilterChain.Match(packet)
}

// AddFilter adds a filter to the filter chain
func (ps *PacketStore) AddFilter(filter filters.Filter) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.FilterChain.Add(filter)
}

// GetPackets returns the raw packets (not in order, for direct access)
func (ps *PacketStore) GetPackets() []components.PacketDisplay {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]components.PacketDisplay, len(ps.Packets))
	copy(result, ps.Packets)
	return result
}

// GetFilteredPackets returns filtered packets for display (already public, keeping for completeness)

// SetPackets replaces the packet buffer (used during buffer resize)
func (ps *PacketStore) SetPackets(packets []components.PacketDisplay, head, count int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.Packets = packets
	ps.PacketsHead = head
	ps.PacketsCount = count
}

// GetBufferInfo returns buffer metadata (maxPackets, packetsCount, totalPackets, matchedPackets)
func (ps *PacketStore) GetBufferInfo() (maxPackets, packetsCount, totalPackets, matchedPackets int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.MaxPackets, ps.PacketsCount, ps.TotalPackets, ps.MatchedPackets
}

// SetBufferSize updates the maximum buffer size
func (ps *PacketStore) SetBufferSize(size int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.MaxPackets = size
}

// ResetCounts resets packet counts to zero
func (ps *PacketStore) ResetCounts() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.TotalPackets = 0
	ps.MatchedPackets = 0
}

// ClearAndResize clears all packets and resizes the buffer
func (ps *PacketStore) ClearAndResize(newSize int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.Packets = make([]components.PacketDisplay, 0, newSize)
	ps.PacketsHead = 0
	ps.PacketsCount = 0
	ps.FilteredPackets = make([]components.PacketDisplay, 0)
	ps.TotalPackets = 0
	ps.MatchedPackets = 0
	ps.MaxPackets = newSize
}

// UpdateMatchedCount updates the matched packet count based on filter status
func (ps *PacketStore) UpdateMatchedCount() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.FilterChain.IsEmpty() {
		ps.MatchedPackets = ps.PacketsCount
	} else {
		ps.MatchedPackets = len(ps.FilteredPackets)
	}
}
