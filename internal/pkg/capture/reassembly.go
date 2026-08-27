package capture

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

const (
	// Reassembly pages are about 1900 bytes in gopacket. These defaults cap a
	// single pathological flow at roughly 190 KiB and all buffered gaps at about
	// 190 MiB while leaving normal SIP messages ample headroom.
	DefaultMaxBufferedPagesPerConnection = 100
	DefaultMaxBufferedPagesTotal         = 100000
)

// TCPAssembler wraps gopacket's connection-aware reassembly.Assembler with the
// behaviour lippycat needs at every feed site:
//
//   - timestamped feed (AssembleWithContext with a per-packet capture context),
//   - serialization (reassembly.Assembler is explicitly NOT concurrency-safe, and
//     lippycat feeds from a processor goroutine while a separate flusher goroutine
//     calls FlushCloseOlderThan — the mutex makes that safe),
//   - the panic-guard that the legacy SafeFlushOlderThan provided (see safeflush.go).
//
// Unlike the legacy tcpassembly.Assembler, reassembly is connection-aware: a
// Stream that returns true from ReassemblyComplete is evicted from the pool, so a
// reused TCP 4-tuple (a new SYN after the prior connection closed) gets a fresh
// Stream instead of having its bytes appended to the stale one. This is what
// fixes SIP-over-TCP port reuse dropping whole connections (RTP-only calls).
type TCPAssembler struct {
	mu            sync.Mutex
	pool          *reassembly.StreamPool
	asm           *reassembly.Assembler
	stats         ReassemblyGapStats
	explicitFlush atomic.Bool
}

// ReassemblyGapStats reports sequence gaps that gopacket is forced to expose
// while processing a packet. The gopacket callback exposes the gap but not the
// reason it was delivered, so these counters deliberately do not attribute a
// gap to either the per-connection or global page limit. With finite page
// limits, growth pressure is one possible cause.
//
// MissingSequenceBytes are bytes absent from the TCP sequence space, not
// captured payload bytes discarded by lippycat.
type ReassemblyGapStats struct {
	ForcedGapDeliveries  atomic.Uint64
	MissingSequenceBytes atomic.Uint64
}

// ReassemblyGapSnapshot is a consistent, copyable view of forced-gap counters.
type ReassemblyGapSnapshot struct {
	ForcedGapDeliveries  uint64
	MissingSequenceBytes uint64
}

type observedStreamFactory struct {
	factory       reassembly.StreamFactory
	stats         *ReassemblyGapStats
	explicitFlush *atomic.Bool
}

func (f observedStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return &observedStream{Stream: f.factory.New(netFlow, tcpFlow, tcp, ac), stats: f.stats, explicitFlush: f.explicitFlush}
}

type observedStream struct {
	reassembly.Stream
	stats         *ReassemblyGapStats
	explicitFlush *atomic.Bool
}

func (s *observedStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	// Explicit age/all flushes can expose gaps too; exclude those so this metric
	// describes forced delivery observed during normal packet assembly. The
	// callback does not say whether a page limit caused the delivery.
	if skip > 0 && !s.explicitFlush.Load() {
		s.stats.ForcedGapDeliveries.Add(1)
		s.stats.MissingSequenceBytes.Add(uint64(skip))
	}
	s.Stream.ReassembledSG(sg, ac)
}

// NewTCPAssembler creates a reassembly-backed assembler for the given factory.
func NewTCPAssembler(factory reassembly.StreamFactory) *TCPAssembler {
	return NewTCPAssemblerWithLimits(factory, DefaultMaxBufferedPagesPerConnection, DefaultMaxBufferedPagesTotal)
}

// NewTCPAssemblerWithLimits creates an assembler with explicit finite page
// limits. Non-positive values are replaced with the production-safe defaults;
// callers cannot accidentally restore gopacket's unlimited buffering.
func NewTCPAssemblerWithLimits(factory reassembly.StreamFactory, perConnection, total int) *TCPAssembler {
	if perConnection <= 0 {
		perConnection = DefaultMaxBufferedPagesPerConnection
	}
	if total <= 0 {
		total = DefaultMaxBufferedPagesTotal
	}
	a := &TCPAssembler{}
	pool := reassembly.NewStreamPool(observedStreamFactory{
		factory: factory, stats: &a.stats, explicitFlush: &a.explicitFlush,
	})
	asm := reassembly.NewAssembler(pool)
	asm.MaxBufferedPagesPerConnection = perConnection
	asm.MaxBufferedPagesTotal = total
	a.pool, a.asm = pool, asm
	return a
}

// BufferedPageLimits exposes the active bounds for diagnostics and tests.
func (a *TCPAssembler) BufferedPageLimits() (perConnection, total int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.asm.MaxBufferedPagesPerConnection, a.asm.MaxBufferedPagesTotal
}

// GapStats returns observed forced-gap counters. Gopacket does not expose
// whether a particular gap was forced by a configured page limit.
func (a *TCPAssembler) GapStats() ReassemblyGapSnapshot {
	return ReassemblyGapSnapshot{
		ForcedGapDeliveries:  a.stats.ForcedGapDeliveries.Load(),
		MissingSequenceBytes: a.stats.MissingSequenceBytes.Load(),
	}
}

// timestampContext carries a packet's capture timestamp into the assembler so
// FlushCloseOlderThan ages streams by capture time (essential for offline replay),
// not wall-clock time.
type timestampContext struct {
	ci gopacket.CaptureInfo
}

func (c timestampContext) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

// Assemble feeds a TCP packet to the assembler, tagged with its capture timestamp.
func (a *TCPAssembler) Assemble(netFlow gopacket.Flow, tcp *layers.TCP, ts time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asm.AssembleWithContext(netFlow, tcp, timestampContext{ci: gopacket.CaptureInfo{Timestamp: ts}})
}

// FlushCloseOlderThan flushes buffered data and closes streams with no activity
// since cutoff. Returns (flushed, closed) counts.
//
// Panic-guard rationale (carried over from SafeFlushOlderThan): a flush panic in
// gopacket leaves the assembler's internal mutex held; recovering would deadlock
// every subsequent Assemble/Flush. Re-panic so the process restarts cleanly.
func (a *TCPAssembler) FlushCloseOlderThan(cutoff time.Time) (flushed, closed int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.explicitFlush.Store(true)
	defer a.explicitFlush.Store(false)
	defer func() {
		if r := recover(); r != nil {
			logger.Error("reassembly.FlushCloseOlderThan panicked; crashing for restart",
				"panic", r,
				"stack", string(debug.Stack()),
			)
			panic(r)
		}
	}()
	return a.asm.FlushCloseOlderThan(cutoff)
}

// FlushAll flushes and closes every stream regardless of age. Returns the number
// of streams closed. Used at end-of-capture (offline) to drain all streams.
func (a *TCPAssembler) FlushAll() (closed int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.explicitFlush.Store(true)
	defer a.explicitFlush.Store(false)
	defer func() {
		if r := recover(); r != nil {
			logger.Error("reassembly.FlushAll panicked; crashing for restart",
				"panic", r,
				"stack", string(debug.Stack()),
			)
			panic(r)
		}
	}()
	return a.asm.FlushAll()
}
