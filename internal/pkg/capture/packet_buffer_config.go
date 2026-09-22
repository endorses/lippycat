package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

const defaultOverflowSummaryInterval = time.Minute

// PacketBufferConfig describes the three bounded lanes owned by a PacketBuffer.
// A zero SIPCapacity or OutputCapacity selects the regular lane capacity.
type PacketBufferConfig struct {
	RegularCapacity int
	SIPCapacity     int
	OutputCapacity  int
}

// ResolvedPacketBufferConfig contains immutable capacities for one buffer
// lifetime. Zero capacities are valid for compatibility with unbuffered tests
// and callers; production configuration resolves a positive regular capacity.
type ResolvedPacketBufferConfig struct {
	RegularCapacity int
	SIPCapacity     int
	OutputCapacity  int
}

// ResolvePacketBufferConfig validates and resolves automatic lane capacities.
func ResolvePacketBufferConfig(config PacketBufferConfig) (ResolvedPacketBufferConfig, error) {
	if config.RegularCapacity < 0 {
		return ResolvedPacketBufferConfig{}, fmt.Errorf("packet_buffer_size must be non-negative (got %d)", config.RegularCapacity)
	}
	if config.SIPCapacity < 0 {
		return ResolvedPacketBufferConfig{}, fmt.Errorf("sip_buffer_size must be non-negative (got %d)", config.SIPCapacity)
	}
	if config.OutputCapacity < 0 {
		return ResolvedPacketBufferConfig{}, fmt.Errorf("packet_buffer_output_size must be non-negative (got %d)", config.OutputCapacity)
	}

	resolved := ResolvedPacketBufferConfig{
		RegularCapacity: config.RegularCapacity,
		SIPCapacity:     config.SIPCapacity,
		OutputCapacity:  config.OutputCapacity,
	}
	if resolved.SIPCapacity == 0 {
		resolved.SIPCapacity = resolved.RegularCapacity
	}
	if resolved.OutputCapacity == 0 {
		resolved.OutputCapacity = resolved.RegularCapacity
	}
	return resolved, nil
}

// PacketBufferSnapshot is one approximate instantaneous view of queue state
// together with cumulative, monotonic accounting for one buffer lifetime.
type PacketBufferSnapshot struct {
	RegularLength   int
	RegularCapacity int
	SIPLength       int
	SIPCapacity     int
	OutputLength    int
	OutputCapacity  int
	SIPClassified   int64
	SIPDemoted      int64
	RegularDropped  int64
	SIPDropped      int64
}

// TotalLength returns the compatibility aggregate occupancy.
func (s PacketBufferSnapshot) TotalLength() int {
	return s.RegularLength + s.SIPLength + s.OutputLength
}

// TotalCapacity returns the total bounded capacity across all three lanes.
func (s PacketBufferSnapshot) TotalCapacity() int {
	return s.RegularCapacity + s.SIPCapacity + s.OutputCapacity
}

type overflowSummary struct {
	Final                bool
	IntervalRegularDrops int64
	IntervalSIPDemotions int64
	IntervalSIPDrops     int64
	Snapshot             PacketBufferSnapshot
}

type overflowSummaryGate struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	emit     func(overflowSummary)

	lastEmit        time.Time
	emitted         bool
	reportedRegular int64
	reportedDemoted int64
	reportedSIP     int64
	finalized       bool
}

func newOverflowSummaryGate(interval time.Duration, now func() time.Time, emit func(overflowSummary)) *overflowSummaryGate {
	if interval <= 0 {
		interval = defaultOverflowSummaryInterval
	}
	if now == nil {
		now = time.Now
	}
	if emit == nil {
		emit = logOverflowSummary
	}
	return &overflowSummaryGate{interval: interval, now: now, emit: emit}
}

func (g *overflowSummaryGate) report(snapshot PacketBufferSnapshot, final bool) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.finalized {
		return false
	}

	// Concurrent reporters can arrive out of snapshot order. Never allow an
	// older sample to move cumulative accounting backwards.
	snapshot.RegularDropped = max(snapshot.RegularDropped, g.reportedRegular)
	snapshot.SIPDemoted = max(snapshot.SIPDemoted, g.reportedDemoted)
	snapshot.SIPDropped = max(snapshot.SIPDropped, g.reportedSIP)
	deltaRegular := snapshot.RegularDropped - g.reportedRegular
	deltaDemoted := snapshot.SIPDemoted - g.reportedDemoted
	deltaSIP := snapshot.SIPDropped - g.reportedSIP
	if deltaRegular == 0 && deltaDemoted == 0 && deltaSIP == 0 {
		if final {
			g.finalized = true
		}
		return false
	}

	now := g.now()
	if !final && g.emitted && now.Sub(g.lastEmit) < g.interval {
		return false
	}
	summary := overflowSummary{
		Final:                final,
		IntervalRegularDrops: deltaRegular,
		IntervalSIPDemotions: deltaDemoted,
		IntervalSIPDrops:     deltaSIP,
		Snapshot:             snapshot,
	}
	g.reportedRegular = snapshot.RegularDropped
	g.reportedDemoted = snapshot.SIPDemoted
	g.reportedSIP = snapshot.SIPDropped
	g.lastEmit = now
	g.emitted = true
	if final {
		g.finalized = true
	}
	g.emit(summary)
	return true
}

func logOverflowSummary(summary overflowSummary) {
	s := summary.Snapshot
	logger.Warn("Packet buffer pressure summary",
		"final", summary.Final,
		"interval_regular_dropped", summary.IntervalRegularDrops,
		"interval_sip_demoted", summary.IntervalSIPDemotions,
		"interval_sip_dropped", summary.IntervalSIPDrops,
		"regular_dropped", s.RegularDropped,
		"sip_demoted", s.SIPDemoted,
		"sip_dropped", s.SIPDropped,
		"regular_len", s.RegularLength,
		"regular_cap", s.RegularCapacity,
		"sip_len", s.SIPLength,
		"sip_cap", s.SIPCapacity,
		"output_len", s.OutputLength,
		"output_cap", s.OutputCapacity)
}
