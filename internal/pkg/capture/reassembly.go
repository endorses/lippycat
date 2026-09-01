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
	stats         ReassemblyLimitStats
	explicitFlush atomic.Bool
}

// ReassemblyLimitStats reports bounded-retention releases. With finite page
// limits, gopacket releases queued out-of-order data across a missing sequence
// gap instead of retaining pages indefinitely. Its public API does not identify
// whether the per-connection or global limit fired, so these counters report
// the observable release without inventing that attribution.
//
// MissingSequenceBytes are absent sequence-space bytes, not captured payload
// bytes discarded by lippycat.
type ReassemblyLimitStats struct {
	BufferedPageLimitReleases    atomic.Uint64
	MissingSequenceBytes         atomic.Uint64
	NormalDiscontinuities        atomic.Uint64
	NormalMissingBytes           atomic.Uint64
	ExplicitFlushDiscontinuities atomic.Uint64
	ExplicitFlushMissingBytes    atomic.Uint64
}

// ReassemblyLimitSnapshot is a consistent, copyable view of retention releases.
type ReassemblyLimitSnapshot struct {
	BufferedPageLimitReleases    uint64
	MissingSequenceBytes         uint64
	NormalDiscontinuities        uint64
	NormalMissingBytes           uint64
	ExplicitFlushDiscontinuities uint64
	ExplicitFlushMissingBytes    uint64
}

type observedStreamFactory struct {
	factory       reassembly.StreamFactory
	stats         *ReassemblyLimitStats
	explicitFlush *atomic.Bool
}

func (f observedStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return &observedStream{Stream: f.factory.New(netFlow, tcpFlow, tcp, ac), stats: f.stats, explicitFlush: f.explicitFlush}
}

type observedStream struct {
	reassembly.Stream
	stats         *ReassemblyLimitStats
	explicitFlush *atomic.Bool
}

func (s *observedStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	// Explicit age/all flushes can expose gaps too; exclude those so this metric
	// describes forced delivery observed during normal packet assembly. The
	// callback does not say whether a page limit caused the delivery.
	if skip > 0 {
		missing := uint64(skip)
		s.stats.MissingSequenceBytes.Add(missing)
		if s.explicitFlush.Load() {
			s.stats.ExplicitFlushDiscontinuities.Add(1)
			s.stats.ExplicitFlushMissingBytes.Add(missing)
		} else {
			s.stats.BufferedPageLimitReleases.Add(1)
			s.stats.NormalDiscontinuities.Add(1)
			s.stats.NormalMissingBytes.Add(missing)
		}
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

// LimitStats returns observable bounded-retention releases. Gopacket does not
// expose whether the per-connection or global page bound caused a release.
func (a *TCPAssembler) LimitStats() ReassemblyLimitSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ReassemblyLimitSnapshot{
		BufferedPageLimitReleases:    a.stats.BufferedPageLimitReleases.Load(),
		MissingSequenceBytes:         a.stats.MissingSequenceBytes.Load(),
		NormalDiscontinuities:        a.stats.NormalDiscontinuities.Load(),
		NormalMissingBytes:           a.stats.NormalMissingBytes.Load(),
		ExplicitFlushDiscontinuities: a.stats.ExplicitFlushDiscontinuities.Load(),
		ExplicitFlushMissingBytes:    a.stats.ExplicitFlushMissingBytes.Load(),
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

// AssembleTCP implements the transitional packet-assembler contract used while
// production composition roots migrate to pipeline.ReassemblyEngine.
func (a *TCPAssembler) AssembleTCP(netFlow gopacket.Flow, tcp *layers.TCP, ts time.Time) error {
	a.Assemble(netFlow, tcp, ts)
	return nil
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
