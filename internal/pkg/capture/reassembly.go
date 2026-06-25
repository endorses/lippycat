package capture

import (
	"runtime/debug"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
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
	mu   sync.Mutex
	pool *reassembly.StreamPool
	asm  *reassembly.Assembler
}

// NewTCPAssembler creates a reassembly-backed assembler for the given factory.
func NewTCPAssembler(factory reassembly.StreamFactory) *TCPAssembler {
	pool := reassembly.NewStreamPool(factory)
	return &TCPAssembler{
		pool: pool,
		asm:  reassembly.NewAssembler(pool),
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
