//go:build tui || all

package store

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// PacketFilterScan owns a retained packet snapshot and an immutable filter chain.
// Run evaluates it without holding the store lock, while arrivals are filtered
// incrementally by the store. Packet metadata is shared and must remain immutable.
type PacketFilterScan struct {
	ctx     context.Context
	cancel  context.CancelFunc
	chain   *filters.FilterChain
	packets []components.PacketDisplay
	first   int64
}

// PacketFilterResult contains matching snapshot offsets, preserving arrival order.
// Only the store that started the still-current scan can install its result.
type PacketFilterResult struct {
	scan    *PacketFilterScan
	matches []int
}

// BeginFilter atomically installs a filter for new arrivals and snapshots retained
// packets for background evaluation. It cancels any previous scan. The supplied
// chain is copied; its predicates must be immutable and safe for concurrent reads.
func (ps *PacketStore) BeginFilter(chain *filters.FilterChain) *PacketFilterScan {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.cancelFilterScanLocked()
	ps.FilterChain = chain.Clone()
	ps.FilteredPackets = nil
	ps.MatchedPackets = 0
	packets := ps.getPacketsInOrderLocked()
	ctx, cancel := context.WithCancel(context.Background())
	scan := &PacketFilterScan{
		ctx: ctx, cancel: cancel, chain: chain.Clone(), packets: packets,
		first: ps.packetSequence - int64(len(packets)) + 1,
	}
	ps.filterScan = scan
	return scan
}

// Cancel stops evaluation between packets and prevents installation of its result.
func (scan *PacketFilterScan) Cancel() {
	scan.cancel()
}

// CancelFilter invalidates the current scan without changing the active filter.
// Use when shutting down or leaving a capture session.
func (ps *PacketStore) CancelFilter() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.cancelFilterScanLocked()
}

// Run evaluates the snapshot and returns nil when cancelled. Call Run once per
// scan, then pass its result to CompleteFilter on the UI update path.
func (scan *PacketFilterScan) Run() *PacketFilterResult {
	result := &PacketFilterResult{scan: scan}
	for i, packet := range scan.packets {
		if scan.ctx.Err() != nil {
			return nil
		}
		if scan.chain.Match(packet) {
			result.matches = append(result.matches, i)
		}
	}
	if scan.ctx.Err() != nil {
		return nil
	}
	return result
}

// CompleteFilter prepends still-retained snapshot matches to new arrival matches.
// Arrival identity, rather than packet content or timestamps, distinguishes the
// disjoint sets and excludes snapshot packets evicted during the scan. A true
// return requires a full display refresh because historical matches were inserted.
func (ps *PacketStore) CompleteFilter(result *PacketFilterResult) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if result == nil || result.scan != ps.filterScan || result.scan.ctx.Err() != nil {
		return false
	}
	firstRetained := ps.packetSequence - int64(ps.PacketsCount) + 1
	matches := result.matches
	for len(matches) > 0 && result.scan.first+int64(matches[0]) < firstRetained {
		matches = matches[1:]
	}
	ps.MatchedPackets += int64(len(matches))

	// New arrivals already have their own bounded filtered history. Retain its
	// existing semantics and use any remaining capacity for snapshot matches.
	capacity := max(0, ps.MaxPackets-len(ps.FilteredPackets))
	if len(matches) > capacity {
		matches = matches[len(matches)-capacity:]
	}
	merged := make([]components.PacketDisplay, len(matches)+len(ps.FilteredPackets))
	for i, offset := range matches {
		merged[i] = result.scan.packets[offset]
	}
	copy(merged[len(matches):], ps.FilteredPackets)
	ps.FilteredPackets = merged
	ps.cancelFilterScanLocked()
	return true
}

// cancelFilterScanLocked invalidates pending results, including across session
// resets where packet counters may have the same values as an earlier session.
func (ps *PacketStore) cancelFilterScanLocked() {
	if ps.filterScan != nil {
		ps.filterScan.Cancel()
		ps.filterScan = nil
	}
}
