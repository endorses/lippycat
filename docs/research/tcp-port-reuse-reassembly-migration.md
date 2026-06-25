# TCP Port Reuse: Migrating from `tcpassembly` to `gopacket/reassembly`

**Date:** 2026-06-22
**Status:** Research — proposes the "proper" fix for SIP-over-TCP port reuse
**Related:** RTP-only calls for IMS Gm-leg calls (SIP-over-TCP-over-ESP-NULL); see also
[tcp-sip-detection.md](tcp-sip-detection.md)

## Executive Summary

VoIP/email/HTTP/DNS/TLS TCP reassembly in lippycat uses gopacket's **legacy**
`github.com/google/gopacket/tcpassembly` package. That package keys streams by
the IP/port **4-tuple only** and has no visibility into TCP control flags
(SYN/FIN/RST). When a 4-tuple is **reused** by a second TCP connection — common
for long-lived IMS Gm SIP-over-TCP sessions where the P-CSCF tears down and
re-establishes the connection on the same ports — the second connection's bytes
are appended to the first connection's stream with a large sequence
discontinuity. The reassembler treats this as a gap, the SIP framer sees
non-SIP data, and the **entire second connection is discarded**. Any call whose
SDP only appears on the reused connection is never parsed, so its media surfaces
as an "RTP-only" synthetic call.

The robust fix is to migrate TCP reassembly to gopacket's newer
`github.com/google/gopacket/reassembly` package, which is **connection-aware**:
its `Stream.Accept(tcp, …, start *bool, …)` callback sees TCP flags and can force
a fresh start, and `ReassemblyComplete() bool` lets a stream evict a connection
from the pool on FIN/RST so a subsequent SYN on the same 4-tuple gets a new
`Stream`. This document inventories the current usage, explains the API delta,
scopes the migration, and weighs it against the targeted "flush-on-SYN"
workaround.

## Problem Recap

Observed in an offline capture (`watch file`) of IMS traffic. The Gm signaling
between a UE and the P-CSCF is SIP-over-TCP inside ESP-NULL on a non-standard
port. The **same 4-tuple** `UE:62348 ↔ P-CSCF:39333` is used by two successive
TCP connections:

| Connection | SYN frame | Initial Seq (ISN) |
|------------|-----------|-------------------|
| A          | 807       | 2926177593        |
| B          | 913       | 3112959206        |

(Wireshark flags frame 913's SYN as "TCP Port numbers reused".)

Driving the real `voip.SipStreamFactory` over the offline-decapsulated packets:

- Connection B received **133 TCP packets fed**, a stream was created, **0
  streams dropped, 0 buffered data dropped — and 0 SIP messages framed**.
- Sibling TCP streams whose 4-tuples were *not* reused framed normally (e.g. a
  REGISTER stream framed 40 messages).
- The INVITE/183 carrying the call's SDP (`m=audio`) live on connection B and
  are therefore never parsed → the call's media is never registered → RTP-only.

This is independent of the ESP-NULL decode (explicit `--esp-null` recovers the
mis-classified segments but does **not** fix correlation — the port reuse defeats
reassembly regardless).

## Why `tcpassembly` Cannot Fix This

The legacy `tcpassembly.Stream` interface is flag-blind:

```go
// gopacket/tcpassembly
type Stream interface {
    Reassembled([]Reassembly)   // contiguous byte runs, no TCP header/flags
    ReassemblyComplete()        // no return value — cannot evict the connection
}
type StreamFactory interface {
    New(netFlow, tcpFlow gopacket.Flow) Stream  // no TCP layer, no context
}
```

`StreamPool.getConnection` keys on the 4-tuple and **reuses** the existing
`connection` until it is flushed by time (`FlushOlderThan`). There is no SYN-based
"new connection" detection and no way for application code to observe the SYN and
reset. A reused 4-tuple therefore lands on the stale stream object; the new ISN
is a multi-gigabyte sequence jump from `nextSeq`, which the assembler treats as a
gap. Bytes after the gap are delivered mid-message; lippycat's SIP framer
(`bufferedSIPStream.readCompleteSipMessageFromReader`) returns `errNotSIP` and
sets the `discard` flag, dropping the whole connection.

`FlushOlderThan` does *not* help here: in offline replay all packets arrive in a
burst, so connection A is not yet aged out when connection B's SYN arrives.

## The `reassembly` Package: Connection-Aware API

`github.com/google/gopacket/reassembly` (already present in the gopacket
v1.1.19 module — no new dependency) exposes TCP state to the application:

```go
// gopacket/reassembly
type Stream interface {
    // Sees the TCP header + flags. May set *start to force a fresh start
    // even without a SYN. Returning false ignores the packet.
    Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir TCPFlowDirection,
           nextSeq Sequence, start *bool, ac AssemblerContext) bool

    // Zero-copy delivery; copy out what you need (sg is reused).
    ReassembledSG(sg ScatterGather, ac AssemblerContext)

    // Return true to REMOVE the connection from the pool (on FIN/RST),
    // enabling a clean new Stream when the 4-tuple is reused.
    ReassemblyComplete(ac AssemblerContext) bool
}
type StreamFactory interface {
    New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac AssemblerContext) Stream
}
type AssemblerContext interface { GetCaptureInfo() gopacket.CaptureInfo }
```

Key differences that solve the bug:

1. **`Accept` sees `tcp.SYN`.** On a SYN observed for a connection that already
   has data, the stream can set `*start = true` (force reassembly to restart at
   the new ISN) or reject the packet so a fresh stream is created. The assembler
   already special-cases `half.nextSeq == invalidSequence && t.SYN` to start at
   `seq+1`.
2. **`ReassemblyComplete` returns `bool`.** Returning `true` on FIN/RST removes
   the connection from `StreamPool.conns`, so the next SYN on the same 4-tuple
   triggers `StreamFactory.New` for a genuinely fresh stream (the clean case for
   "connection closed, then reused").
3. **`FlushCloseOlderThan` / `FlushWithOptions`** replace `FlushOlderThan` for
   idle eviction (used in offline burst mode and the live cleanup loop).

### Port-reuse handling strategy with `reassembly`

The library handles the **FIN/RST-then-reuse** case for free once
`ReassemblyComplete` returns `true`. The **abrupt-reuse** case (a SYN arrives
while the old connection is still open — exactly frame 913 here) must be handled
in `Accept`:

```go
func (s *sipStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo,
    dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence,
    start *bool, ac reassembly.AssemblerContext) bool {
    // New connection on a reused 4-tuple: a SYN (no ACK) seen mid-stream.
    if tcp.SYN && !tcp.ACK && s.seenData {
        // Finalize the old logical connection and restart cleanly.
        *start = true
        s.reset()       // clear framer/detector state for the new connection
    }
    return true
}
```

This is the piece the legacy package cannot express at all.

## Migration Scope

`tcpassembly` is used across **every TCP protocol path**, not just VoIP. All of
the following implement a `StreamFactory`/`Stream` pair or call
`Assemble*`/`Flush*` and must move together (the assembler and its streams must
use the same package):

**Stream/Factory implementations**
- `internal/pkg/voip/tcp_factory.go`, `tcp_stream.go` (the `bufferedSIPStream`
  + `sipStreamFactory` — the highest-value target)
- `internal/pkg/email/{tcp_factory,tcp_stream,imap_tcp_factory,imap_tcp_stream,pop3_tcp_factory,pop3_tcp_stream,multi_protocol_factory}.go`
- `internal/pkg/http/{tcp_factory,tcp_stream}.go`
- (DNS/TLS use TCP assembly via `core.go` wiring)

**Assembler creation + feed + flush call sites**
- `internal/pkg/voip/{core.go,tcp_main.go,voip_packet_processor.go}`
- `internal/pkg/email/{core.go,email_packet_processor.go}`
- `internal/pkg/http/core.go`, `internal/pkg/dns/core.go`, `internal/pkg/tls/core.go`
- `internal/pkg/tui/bridge.go` (TUI live/offline)
- `internal/pkg/capture/{snifferstarter.go,capture.go,safeflush.go}`
- `cmd/{watch/file.go,watch/live.go,tap/tap_voip.go,hunt/voip.go}`

**Shared wrapper**
- `internal/pkg/capture/safeflush.go` — `SafeFlushOlderThan` wraps
  `*tcpassembly.Assembler.FlushOlderThan`; becomes a wrapper over
  `*reassembly.Assembler.FlushCloseOlderThan`. Its panic-guard rationale (a
  malformed flush panicking and then deadlocking the next assemble) still
  applies and should be preserved.

## Required Code Changes (per component)

### 1. `SIPMessageHandler` is unaffected
The handler contract (`HandleSIPMessage(msg, callID, src, dst, netFlow)`) does
not change. Only the plumbing that produces complete messages changes.

### 2. Stream interface rewrite (`bufferedSIPStream` and peers)
- `Reassembled([]Reassembly)` → `ReassembledSG(sg ScatterGather, ac)`. Replace
  the `r.Bytes` copy loop with `sg.Fetch(sg.Lengths())`-based copying. The
  existing **non-blocking buffered-channel** design (so `Reassembled` never
  blocks the capture loop) carries over directly — copy out of the `sg` then do
  the same non-blocking send.
- Add `Accept(...)` implementing the port-reuse reset logic above. This is also
  the natural place to apply early "is this even SIP?" rejection.
- `ReassemblyComplete()` → `ReassemblyComplete(ac) bool`; return `true` on
  FIN/RST so the pool evicts cleanly (keeps the connection map from growing and
  fixes the closed-then-reused case).

### 3. Factory signature
`New(net, transport gopacket.Flow)` → `New(net, transport gopacket.Flow, tcp *layers.TCP, ac AssemblerContext)`.
The extra `tcp`/`ac` are available for first-packet decisions; the existing
goroutine-pool / queue machinery in `sipStreamFactory` is otherwise unchanged.

### 4. Assembler creation + feed
- `tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))` →
  `reassembly.NewAssembler(reassembly.NewStreamPool(f))`.
- `AssembleWithTimestamp(netFlow, tcp, ts)` →
  `AssembleWithContext(netFlow, tcp, ctxWithTimestamp)`. Need a tiny
  `AssemblerContext` impl wrapping `gopacket.CaptureInfo{Timestamp: ts}`
  (gopacket ships `assemblerSimpleContext` for the flagless `Assemble`, but the
  timestamped path needs our own one-field struct).
- `FlushOlderThan(t)` → `FlushCloseOlderThan(t)` (note semantics: it both flushes
  buffered data and closes timed-out connections).

### 5. ScatterGather copy discipline
`sg` and its backing pages are reused after `ReassembledSG` returns. Every byte
that outlives the call must be copied (the current code already copies into a new
slice — keep that). `KeepFrom(offset)` lets a partial SIP message remain buffered
across calls without an app-side carry buffer, which can *simplify* the framer.

## Risks & Considerations

- **Breadth/regression surface.** This touches all five TCP protocols and the
  CLI/TUI wiring. Each protocol's framer must be re-validated. Recommend a
  protocol-by-protocol rollout (VoIP first) behind the same `Assembler`
  abstraction so they can be migrated independently if a shared adapter is
  introduced.
- **Performance.** `reassembly` uses a `ScatterGather`/page model designed for
  zero-copy and is at least as fast as `tcpassembly`; the per-CPU/percpu queue
  and goroutine-limit machinery in `sipStreamFactory` is orthogonal and stays.
  Validate against `make bench` (TCP benchmarks in `internal/pkg/voip`).
- **Behavioral parity for the offline burst path.** Offline replay feeds all
  packets then flushes; confirm `FlushCloseOlderThan(now)` + a final flush still
  drains every stream (the current `RunOfflineOrdered` ends with a flush + sleep).
- **`Accept`-based reset correctness.** Forcing `*start` mid-stream must reset
  the per-stream framer/detector state (`CallIDDetector`, pipe reader) so the new
  connection is parsed from byte 0. Get this wrong and you either leak the old
  connection's tail into the new one or drop the new SYN's first message.
- **Connection lifetime / memory.** Returning `true` from `ReassemblyComplete`
  on FIN/RST is important to bound `StreamPool` growth; today's
  `tcpassembly` relies solely on time-based flushing.
- **`safeflush.go` panic guard.** Preserve it; `reassembly` flushing can still
  hit malformed state, and the deadlock-then-crash-for-restart rationale is
  unchanged.

## Migration Plan

The committed end state is **all TCP protocols on `reassembly`** with the legacy
`tcpassembly` package fully removed. This is not optional: a split stack (some
protocols on each library) is an interim state to pass through, not a place to
stop. Two reassembly stacks means two mental models, a dual `safeflush`, two
bug surfaces, and — critically — it blocks removing the `*tcpassembly.Assembler`
leak from the shared capture-layer signatures (see [Migration Scope](#migration-scope)),
which is only possible once nothing uses `tcpassembly`.

VoIP leads because it is the reported bug, the most complex consumer (so it
surfaces every gotcha), and it *produces* the shared `reassembly ↔ io.Reader`
adapter the other protocols then reuse. The adapter is **derived from the VoIP
migration**, not designed speculatively up front — the four other protocols all
use the standard `tcpreader.ReaderStream` pattern, so once the adapter exists
they drop onto it near-mechanically.

| Phase | Work | Rough size |
|-------|------|-----------|
| 1 | Migrate VoIP (`tcp_factory`, `tcp_stream`, `tcp_main`, `voip_packet_processor`, `core`) + add `Accept` port-reuse reset; **extract** the reusable `reassembly ↔ io.Reader` adapter (Accept/SG-copy/lifecycle/non-blocking pump) as a shared helper rather than VoIP-private; validate against the offline IMS capture | M |
| 2 | Migrate TUI bridge + `cmd/{watch,tap,hunt}` VoIP wiring; have VoIP own its assembler internally (pass `nil` through the shared capture signature, as the TUI bridge already does) so the shared signatures stay `*tcpassembly.Assembler` during the interim | M |
| 3 | Migrate email (SMTP/IMAP/POP3), HTTP, DNS, TLS factories/streams onto the shared adapter from phase 1 | M–L |
| 4 | Once nothing uses `tcpassembly`: remove the `*tcpassembly.Assembler` param from the shared capture-layer signatures (`RunOffline`/`StartLiveSniffer`/processor callback), collapse `safeflush` to a single `reassembly` helper, delete all `tcpassembly` imports, `go mod tidy` | S–M |
| 5 | Regression: per-protocol reassembly tests, port-reuse unit test, `make bench` | M |

Sequencing note: phases 1–2 also resolve the reported RTP-only bug, so the fix
ships without waiting for the whole migration — but phases 3–4 remain part of the
committed scope. The interim split state (VoIP on `reassembly`, others on
`tcpassembly`) is tolerated only between phases 2 and 4, not as an end state.

## Alternative: Targeted "flush-on-SYN" Workaround

Without migrating, the bug can be mitigated inside the current `tcpassembly`
call sites by detecting a bare SYN and forcibly flushing that flow's stream
before `AssembleWithTimestamp`, so the reused connection starts (mostly) fresh:

```go
if tcp.SYN && !tcp.ACK {
    // Force the existing stream for this flow to flush/close so reuse restarts.
    capture.SafeFlushOlderThan(assembler, time.Now())  // coarse: flushes all
}
assembler.AssembleWithTimestamp(netFlow, tcp, ts)
```

Trade-offs:
- **Pro:** tiny, low-risk, localized to the VoIP/TUI assemble sites; no
  dependency or interface churn.
- **Con:** `tcpassembly` can only flush by *age*, not by *flow* — a coarse flush
  on every SYN is heavy-handed under load and still cannot truly start a new
  connection object (the stale `nextSeq` persists in the same stream). It is a
  mitigation, not a correct connection model. It also does nothing for the
  flag-blindness elsewhere (e.g. SIP detection on segment boundaries).

Recommended: treat this only as an emergency stopgap if VoIP correlation must be
fixed before phase 1 lands. It does not change the committed plan — the
`reassembly` migration (all protocols) is the durable fix and should supersede
the workaround, which is reverted once phase 1 ships.

## Validation Plan

1. **Unit:** synthesize two TCP connections sharing one 4-tuple with different
   ISNs, each carrying a complete SIP INVITE+SDP; assert both are framed and both
   media endpoints register. (No real-capture dependency; safe to commit.)
2. **Integration (local, non-committed):** replay the IMS capture through the
   migrated VoIP pipeline and confirm the previously-RTP-only call correlates
   (per-call SIP + RTP files are non-empty; no `rtp-<ssrc>` synthetic call).
3. **Parity:** existing email/HTTP/DNS/TLS reassembly tests pass unchanged.
4. **Perf:** `make bench` TCP benchmarks within noise of baseline.

## References

- Current legacy stack: `internal/pkg/voip/tcp_stream.go`,
  `internal/pkg/voip/tcp_factory.go`, `internal/pkg/capture/safeflush.go`
- gopacket reassembly API: `reassembly/tcpassembly.go` (Stream, StreamFactory,
  Assembler, AssemblerContext, ScatterGather), `reassembly/memory.go`
  (`StreamPool.getConnection`)
- Prior related research: [tcp-sip-detection.md](tcp-sip-detection.md)
