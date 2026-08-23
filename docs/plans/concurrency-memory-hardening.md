# Concurrency and Memory Hardening Plan

**Date:** 2026-08-23
**Status:** Draft
**Priority:** Critical

## Overview

Fix the remaining high-risk concurrency, lifecycle, and memory-retention issues in
the packet capture hot paths. The work should be shipped in small phases because
the TCP buffer retention fix is low-risk and directly affects long-running VoIP
nodes, while the later phases touch broader processor, detector, and watcher
lifecycles.

The first release should focus on TCP buffer retention and observability. Later
releases should add hard memory bounds, close resource lifecycle gaps, and remove
the remaining races in call buffering and keylog watching.

## Goals

- Stop pooled TCP SIP buffers from retaining packet payload backing arrays.
- Make TCP buffer memory visible in runtime metrics.
- Add hard bounds to protocol detector state and per-call PCAP writers.
- Make `CallBuffer` safe even when used through pointers across `BufferManager`
  methods.
- Ensure shutdown and reconnect paths cannot deadlock or close successor streams.
- Key TCP SIP packet buffers by connection, not only by IP pair.
- Make pprof activation explicit, documented, and safe by default.
- Fix keylog named-pipe shutdown and stats races.

## Non-Goals

- Do not redesign the packet processing pipeline.
- Do not change filter matching semantics.
- Do not remove the existing `LC_PPROF_ADDR` compatibility hook until a documented
  replacement exists.
- Do not change per-call PCAP file naming beyond what is needed for lifecycle
  cleanup.

## Current State

| Area | Current behavior | Gap |
|------|------------------|-----|
| TCP SIP buffers | `TCPPacketBuffer` stores `[]bufferedFrame`; buffers are pooled | `releaseBuffer` does not clear `packets[:cap]`, so pooled buffers can retain `bufferedFrame.data` slices |
| TCP buffer metrics | `GetTCPBufferStats()` reports active map entries | Pooled buffers, pooled frames, pooled bytes, live frames, and live bytes are not exposed |
| pprof | `main.go` starts pprof when `LC_PPROF_ADDR` is set | No CLI flag, no loopback guard, no startup error logging, docs mention a different env var in places |
| Call buffers | `BufferManager` owns a map of `*CallBuffer` | `CallBuffer` itself is unsynchronized, and `AddRTPPacket` can append to a buffer after another path deletes it |
| Detector state | `FlowTracker` and `DetectionCache` are TTL cleaned | No hard cap, so memory can grow with flow cardinality inside one TTL window |
| Per-call PCAP writers | Writers close when a terminal call state is observed | Writers can survive if the call is evicted or never reaches an observed terminal state |
| Closed-call suppression | Completion monitors keep permanent `map[string]struct{}` sets | Suppression maps grow forever |
| LocalSource shutdown | Dispatcher sends to worker channels directly | Shutdown can block if workers exit while the dispatcher is sending |
| Filter subscriptions | One update channel is stored per hunter ID | A stale stream can remove and close a newer stream's channel |
| TCP buffer key | Buffer map is keyed by network flow only | Concurrent TCP SIP connections between the same IP pair share one buffer |
| Keylog watcher | Named-pipe reader blocks in `scanner.Scan()` | `Stop()` does not close the active pipe file, and stats counters are not synchronized |

## Phase 0: TCP Buffer Hotfix

**Priority:** Critical

### Tasks

- [x] Update `internal/pkg/voip/tcp_buffer.go` so `releaseBuffer` owns all reset
      logic.
- [x] Clear `buffer.packets[:cap(buffer.packets)]` before truncating the slice so
      every retained `bufferedFrame.data` reference is dropped.
- [x] Remove redundant `buffer.packets = buffer.packets[:0]` resets from
      `getTCPBufferedPackets` and `discardTCPBufferedPackets` after `releaseBuffer`
      becomes authoritative.
- [x] Add a capacity guard in `releaseBuffer`; if `cap(buffer.packets)` exceeds a
      configured threshold, do not return it to the pool.
- [x] Keep `getOrCreateBuffer`'s reuse path limited to setting lifecycle fields
      (`createdAt`, `lastAccess`, `maxSize`, `strategy`, `callID`, `flow`) after the
      buffer has already been cleared by `releaseBuffer`.
- [x] Add tests that use `bufferedFrame` directly:
      `TestReleaseBufferDropsFrameDataReferences`,
      `TestCleanupOldTCPBuffersReleasesFrameData`, and
      `TestReleaseBufferDropsOversizedArrays`.

### Acceptance Criteria

- A released pooled buffer has no non-nil `bufferedFrame.data` references in
  `packets[:cap]`.
- Expired TCP buffers are released without retaining frame payload memory.
- Oversized buffer arrays are allowed to be garbage collected instead of pooled.

## Phase 1: TCP Buffer Metrics and Debug Profiling

**Priority:** Critical

### Tasks

- [x] Extend `TCPBufferStats` with `PooledBuffers`, `PooledFrames`,
      `PooledBytes`, `BufferedFrames`, and `BufferedBytes`.
- [x] Compute active buffered frame and byte counts from `tcpPacketBuffers`.
- [x] Compute pooled frame and byte counts from `tcpBufferPool`.
- [x] Surface the new fields through existing TCP metrics output in
      `internal/pkg/voip/tcp_metrics.go`.
- [x] Add an explicit `--debug-listen <addr>` flag for `tap`, `process`, and
      `hunt`, default off.
- [x] Keep `LC_PPROF_ADDR` as a compatibility fallback, but prefer the CLI flag.
- [x] Refuse non-loopback debug binds unless an explicit override flag or config
      setting is supplied.
- [x] Log pprof listener startup failures.
- [x] Update `docs/operational-procedures.md`, `docs/PERFORMANCE.md`,
      `docs/tcp-troubleshooting.md`, and manual performance docs so they all use
      the same supported pprof activation path.

### Acceptance Criteria

- Operators can see both live and pooled TCP buffer memory.
- pprof can be enabled intentionally on loopback with a documented command.
- Existing `LC_PPROF_ADDR` users are not broken, but stale documentation no longer
  points at unsupported environment variables.

## Phase 2: Race Fixes and Hard Bounds

**Priority:** High

### Tasks

- [x] Add `sync.RWMutex` to `CallBuffer`.
- [x] Guard all `CallBuffer` methods that read or mutate packet slices, RTP ports,
      metadata, filter state, interface name, and link type.
- [x] Add an unlocked helper for RTP port lookup so `AddRTPPort` does not recurse
      through a public locking method.
- [x] In `BufferManager.AddRTPPacket`, re-check `bm.buffers[callID] == buffer`
      after acquiring `bm.mu.Lock()` before appending.
- [x] Keep lock order consistent: acquire `BufferManager.mu` before
      `CallBuffer.mu` whenever both are needed.
- [x] Add `maxEntries` to `FlowTracker` and `DetectionCache`.
- [x] Evict oldest `LastSeen` / oldest expiring entries when detector maps hit the
      cap.
- [x] Delete expired detection cache entries on `Get`.
- [x] Add detector defaults and viper overrides:
      `detector.max_flows` and `detector.max_cache_entries`.
- [x] Log a rate-limited warning when a detector cap is first hit.

### Tests

- [x] `TestBufferManagerConcurrentSIPAndRTP`
- [x] `TestFlowTrackerRespectsMaxEntries`
- [x] `TestDetectionCacheRespectsMaxEntries`
- [x] `TestDetectionCacheDeletesOnExpiredGet`

## Phase 3: PCAP Writer and Completion Lifecycle

**Priority:** High

### Tasks

- [ ] Add `lastWrite time.Time` to `CallPcapWriter`, updated in
      `WriteSIPPacket` and `WriteRTPPacket` under `writer.mu`.
- [ ] Add `MaxIdle` and `MaxWriters` to `PcapWriterConfig`.
- [ ] Implement `PcapWriterManager.SweepIdle(maxIdle time.Duration) int`, closing
      idle writers through `CloseCallWriter` so close hooks still run.
- [ ] Enforce `MaxWriters` in `GetOrCreateWriter` by closing the least recently
      written writer before admitting a new one.
- [ ] Drive idle sweeping from the existing `CallCompletionMonitor.monitorLoop`
      ticker.
- [ ] Log warnings when idle or overflow reclamation closes a writer.
- [ ] Change `closedCalls` in processor and sniff completion monitors from
      `map[string]struct{}` to `map[string]time.Time`.
- [ ] Prune closed-call suppression entries older than a configurable TTL from
      existing monitor tickers.

### Tests

- [ ] `TestPcapWriterManagerSweepIdle`
- [ ] `TestPcapWriterManagerMaxWriters`
- [ ] `TestCallCompletionMonitorPrunesClosedCalls`
- [ ] `TestSniffCompletionMonitorPrunesClosedCalls`

## Phase 4: Shutdown, Reconnect, and TCP Connection Isolation

**Priority:** Medium

### Tasks

- [ ] Make the `LocalSource.batchingLoop` worker send cancellable with a `select`
      on `workerChans[idx] <- pktInfo` and `<-s.ctx.Done()`.
- [ ] Ensure the early cancellation path closes every worker channel and waits for
      workers before returning.
- [ ] Change `filtering.Manager.AddChannel` to close any pre-existing hunter
      channel before replacing it.
- [ ] Change `RemoveChannel` to accept the channel returned by `AddChannel` and
      delete/close only when the stored channel is the same instance.
- [ ] Update `Processor.SubscribeFilters` and `HunterTarget` wrappers for the new
      remove signature.
- [ ] Introduce a TCP buffer key that includes network flow and transport flow.
- [ ] Update TCP buffering producers to pass both flows.
- [ ] Update TCP SIP handlers and the `SIPMessageHandler` interface to carry the
      transport flow for buffer lookup and discard.
- [ ] Canonicalize TCP buffer keys or perform direction-aware lookup so assembler
      direction changes do not split one connection into two buffers.
- [ ] Add regression coverage for two simultaneous TCP SIP connections between the
      same IP pair.

### Tests

- [ ] `TestLocalSourceShutdownWithFullWorkerChannels`
- [ ] `TestAddChannelReplacesStaleSubscription`
- [ ] `TestRemoveChannelIgnoresSupersededChannel`
- [ ] `TestTCPBuffersAreIsolatedPerConnection`
- [ ] A per-call PCAP regression test for concurrent TCP SIP calls between the same
      hosts.

## Phase 5: Keylog Watcher Robustness

**Priority:** Medium

### Tasks

- [ ] Assign the active named-pipe `*os.File` to `Watcher.file` under `w.mu`.
- [ ] Close the active pipe file from `Stop()` after closing `stopChan` so a blocked
      `scanner.Scan()` wakes up.
- [ ] Clear `Watcher.file` when `readPipe` returns and the file is closed.
- [ ] Treat pipe read errors after shutdown starts as normal shutdown.
- [ ] Prevent `pipeReadLoop` from reopening the pipe after `stopChan` closes.
- [ ] Convert `linesRead`, `entriesAdded`, and `errors` to `atomic.Uint64`, or guard
      every increment and read with the same mutex.
- [ ] Deflake the named-pipe test by waiting for the expected entry count with a
      bounded timeout or holding the writer open until the watcher consumes data.

### Tests

- [ ] `TestWatcherNamedPipeStopWithIdleWriter`
- [ ] `TestWatcherStatsRaceFree`
- [ ] Updated `TestWatcherNamedPipe`

## Verification

- [ ] `make fmt`
- [ ] `go vet -tags all ./...`
- [ ] `go test -tags all ./...`
- [ ] `go test -tags all -race ./internal/pkg/voip/...`
- [ ] `go test -tags all -race ./internal/pkg/processor/...`
- [ ] `go test -tags all -race ./internal/pkg/detector/...`
- [ ] `go test -tags all -race ./internal/pkg/tls/keylog/...`
- [ ] Full `go test -tags all -race ./...` before merging the complete series.
- [ ] Replay a TCP-SIP-heavy capture through `lc tap voip` and confirm RSS plateaus
      across several TCP buffer cleanup cycles.
- [ ] Run a high-cardinality detector replay and confirm RSS plateaus at the
      configured detector caps.
- [ ] Run per-call PCAP capture with intentionally incomplete call termination and
      confirm writer count and open file descriptors plateau.

## Release Strategy

1. Ship Phase 0 as a standalone hotfix.
2. Ship Phase 1 once metrics and pprof docs are aligned.
3. Ship Phases 2 and 3 together only after targeted race tests pass.
4. Ship Phases 4 and 5 after soak testing because they touch shutdown, reconnect,
   and TCP stream plumbing.
