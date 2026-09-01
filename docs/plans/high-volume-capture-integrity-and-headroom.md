# High-Volume Capture Integrity and Headroom Plan

**Date:** 2026-09-01
**Status:** In Progress (Phases 0-3 complete)
**Priority:** High

## Overview

Improve live-display accuracy, SIP-over-TCP loss tolerance, overload attribution,
and multi-core capture headroom. The work is split into independently reviewable
phases: establish truthful telemetry first, repair data-integrity behavior second,
then scale TCP reassembly and optimize only profile-proven allocation hot spots.

This plan intentionally uses generic workloads and synthetic fixtures. Tests,
benchmarks, examples, logs, and documentation must not contain deployment names,
customer identifiers, intercepted identities, production addresses, or raw
production payloads.

## Goals

- Make live TUI rates and health indicators truthful above 1,000 packets/s.
- Separate exact ingress statistics from the sampled packet-detail display.
- Account for every local shedding and discontinuity stage with monotonic,
  attributable counters.
- Preserve SIP-over-TCP framing boundaries across capture, reassembly, and
  post-reassembly queues; recover at a later valid SIP message after a gap.
- Protect recognized SIP signaling from unrelated regular-lane saturation under
  explicitly documented capacity assumptions.
- Scale independent TCP flows across multiple reassembly assemblers without
  weakening per-flow ordering or lifecycle safety.
- Reduce hot-path allocation only where benchmarks and profiles show material
  benefit.

## Non-Goals

- Do not promise lossless capture when offered signaling load exceeds configured
  queue or downstream service capacity.
- Do not accept lone carriage returns as valid SIP header framing.
- Do not attribute unexplained sequence gaps to any external capture source until
  every local loss stage has been measured.
- Do not introduce AF_XDP or a multi-process capture architecture in this work.
- Do not perform a repository-wide typed-metadata redesign unless profiling after
  the narrow optimizations proves it necessary.
- Do not enable multiple reassembly shards by default until benchmarks establish
  a safe default.

## Counter Semantics and Compatibility

Before implementation, define the following cumulative counter families and keep
existing aggregate fields for backward compatibility:

- Capture ingress: received packets and bytes, kernel/interface drops where
  available.
- Capture-buffer shedding: regular-lane packets and recognized-SIP packets.
- Processor delivery: batch-channel packet drops.
- TCP reassembly: missing sequence bytes and discontinuity events, separated by
  normal/page-pressure release versus explicit flush where attribution permits.
- SIP stream delivery: post-reassembly chunks/bytes dropped, parser framing
  discontinuities, successful resynchronizations, and failed resynchronizations.
- TUI display: ingress, invalid envelopes, sampled-out packets, batch-queue packet
  drops, pending-buffer evictions, and packets delivered to the model/list.

Aggregate drop values must remain available and equal the documented sum of their
named local stages. New protobuf fields must be additive and use new field numbers.

## Phase 0: Baselines and Truthful Loss Telemetry

### Implementation

- [x] Write down exact counter ownership, units, reset behavior, aggregation, and
      compatibility rules in code comments and operator documentation before
      changing protobufs or health calculations.
- [x] Extend `internal/pkg/processor/source/source.go` and
      `internal/pkg/processor/source/local.go` so `Stats` preserves regular capture
      buffer drops, SIP-lane drops, and batch-channel drops while retaining
      `PacketsDropped` as the compatible aggregate.
- [x] Extend `api/proto/management.proto` `HunterStats` and any relevant
      `api/proto/data.proto` batch statistics with additive named loss counters;
      regenerate `api/gen` with the repository protobuf generation command.
- [x] Propagate the new fields through `internal/pkg/hunter/stats/collector.go`,
      `internal/pkg/hunter/connection/manager.go`,
      `internal/pkg/processor/hunter/manager.go`, processor heartbeat/status
      handlers, tap virtual-hunter synthesis, `internal/pkg/types/packet.go`, and
      `internal/pkg/remotecapture/client_conversion.go`.
- [x] Extend `internal/pkg/capture/reassembly.go` metrics so normal/page-pressure
      gaps and gaps exposed by explicit flush are visible without conflating their
      causes; retain `MissingSequenceBytes` semantics as absent TCP sequence space.
- [x] Extend `internal/pkg/voip/tcp_metrics.go` with post-reassembly dropped chunks
      and bytes, stream discontinuities, missing bytes, recovery successes, and
      recovery failures. Prefer instance/shard-local metrics that can be safely
      aggregated once sharding is introduced.
- [x] Surface the named counters in existing health/status paths, including the
      TUI health view and structured capture heartbeat/log output. Logging must not
      be the only signal, and logs must not include SIP payload or header values.
- [x] Update operational documentation to explain how to distinguish capture,
      buffer, reassembly, stream-queue, parser, and display loss without claiming
      an external root cause from incomplete local evidence.

### Tests

- [x] Add source-stat tests proving named counters remain separate and their sum
      matches the compatible aggregate.
- [x] Add protobuf serialization and heartbeat round-trip tests across hunter,
      processor, remote conversion, and TUI status paths.
- [x] Extend capture reassembly tests to distinguish normal forced-gap accounting
      from explicit-flush gap accounting.
- [x] Force a full SIP stream `dataChan` in tests and verify dropped chunk/byte
      counters are observable.

### Acceptance Criteria

- [x] An overload can be classified by local loss stage without reading disabled
      or debug-only logs.
- [x] Existing clients continue to receive the aggregate drop counter.
- [x] Named counters are monotonic during a capture session and reconcile with the
      documented aggregate semantics.

## Phase 1: Live TUI Statistics and Display Backpressure

### Implementation

- [x] Fix `displaySamplingPolicy` in `internal/pkg/tui/bridge_stages.go` to compute
      ingress packets/s from packet-count/time deltas, or weight each checkpoint
      by the packets it represents. Keep sampling before `convertEnvelope`.
- [x] Make sampling time injectable or pass explicit timestamps so rate and clamp
      behavior can be tested deterministically.
- [x] Preserve lossless offline/replay behavior and the intentional SIP display
      preference while defining the live detail-display budget independently from
      the observed ingress rate.
- [x] Add a lightweight ingress telemetry accumulator to the TUI bridge that sees
      every valid envelope before display sampling. Track packets, bytes, min/max
      size, protocol counts, and bounded source/destination talkers without copying
      raw packet data or performing full `PacketDisplay` conversion.
- [x] Publish accumulator snapshots to the Bubble Tea model at a bounded cadence.
      Update `internal/pkg/tui/helpers.go` so live `processPendingPackets` updates
      the packet store/list without double-counting exact ingress statistics.
- [x] Define whether upstream protocol statistics are L3/L4-only or enriched; if
      enriched application classification would duplicate expensive work, expose
      the cheaper exact classification and label it accurately.
- [x] Replace `pendingPacketBuffer`'s front-sliced queue in
      `internal/pkg/tui/bridge.go` with a bounded ring/deque for live capture so
      append, oldest eviction, and drain cost O(batch) rather than O(queue depth).
      Keep offline preservation as a separate lossless path.
- [x] Replace the fixed 50-packet live drain with a bounded adaptive drain based on
      backlog and/or a per-tick processing budget, with a hard maximum that protects
      terminal responsiveness.
- [x] Add packet-level counters for sampling, batch-channel loss, pending eviction,
      and model/list delivery. Rename or redefine `PacketsDisplayed`, which
      currently increments before pending eviction and is not a displayed count.
- [x] Thread the counters and an end-to-end display-retention ratio through
      `BridgeStats`, `components.BridgeStatistics`, `helpers.go`,
      `components/drop_stats.go`, and `components/statistics.go`.
- [x] Reset the accumulator, pending storage, and every new counter consistently in
      bridge/capture lifecycle reset paths.

### Tests and Benchmarks

- [x] Add deterministic sampling-policy tests for representative low and high
      rates, minimum/maximum clamps, SIP preference, and replay preservation.
- [x] Add ring/deque tests for ordering, wraparound, exact eviction counts, bounded
      capacity, partial drains, and offline no-loss behavior.
- [x] Add a sustained synthetic bridge test above 1,000 packets/s proving that
      ingress statistics cover all accepted packets while display retention is
      reported below 100% when shedding occurs.
- [x] Assert a documented reconciliation invariant across invalid, sampled-out,
      queue-dropped, pending-evicted, and delivered packet counts.
- [x] Add statistics/drop-health rendering tests and model tests proving ingress
      statistics are not double-counted by packet-list processing.
- [x] Add sampling and saturated pending-buffer benchmarks with allocation
      reporting; record before/after ns/op, B/op, and allocs/op.

      Benchmark record (linux/amd64, 13th Gen Intel Core i9-13900HX, three runs):
      sampling policy 62.10-68.17 ns/op, 24 B/op, 2 allocs/op; legacy saturated
      front-slice buffer 343337-376885 ns/op, 2605056-2605058 B/op, 2 allocs/op;
      saturated live ring 4436-4767 ns/op, 24576 B/op, 1 alloc/op.

### Acceptance Criteria

- [x] Live statistics no longer plateau at the detail drain ceiling.
- [x] The health view never reports full retention when packets were sampled,
      batch-dropped, or evicted from the pending queue.
- [x] Full display conversion runs only for packets selected for the detail feed.
- [x] Saturated pending-buffer work scales with the drained/appended batch, not the
      entire queued backlog.

## Phase 2: TCP Discontinuity Preservation and SIP Parser Recovery

### Implementation

- [x] Extend the SIP stream chunk contract in `internal/pkg/voip/tcp_stream.go`
      with discontinuity metadata: reason and known missing sequence bytes.
- [x] Read `sg.Info().skip` in `bufferedSIPStream.ReassembledSG` and attach a gap
      boundary to the bytes delivered after a positive skip.
- [x] When the non-blocking post-reassembly `dataChan` is full, record dropped
      chunks and bytes and set a per-stream pending-discontinuity marker; attach it
      to the next successfully enqueued chunk without blocking the assembler.
- [x] Update `streamChunkReader` so it never silently concatenates bytes across a
      known discontinuity. Abort the partial message and report a typed recoverable
      framing error to the SIP message loop.
- [x] Introduce a typed recoverable framing/discontinuity error distinct from
      `errNotSIP` and from a correctly framed Content-Length policy violation.
- [x] Detect impossible embedded carriage-return plus credible SIP-start patterns
      as framing loss. Do not accept a lone carriage return as valid SIP syntax.
- [x] Preserve or replay a credible SIP suffix already consumed by
      `ReadString('\n')`, then perform bounded resynchronization at the next valid
      SIP start line instead of terminating the stream.
- [x] Keep the current bounds explicit: at most 16 KiB per resynchronization
      attempt and 64 KiB cumulative non-SIP scanning before permanent discard.
      Prevent false-start loops and unbounded buffering.
- [x] Keep genuinely oversized, negative, non-numeric, or otherwise invalid
      correctly framed Content-Length values on the security-rejection path.
- [x] Rate-limit operational warnings, report counters instead of payload values,
      and ensure one malformed message cannot flood logs.

### Tests

- [x] Add a missing-middle-segment test where `skip > 0`; discard the partial SIP
      message and successfully process the next complete message.
- [x] Add a post-reassembly channel-overflow test followed by a complete SIP
      message; verify discontinuity accounting and recovery.
- [x] Add a malformed `Content-Length: digits\rSIP/2.0...` regression that
      preserves and processes the credible following response.
- [x] Verify that correctly framed invalid Content-Length values remain rejected
      and are not reclassified as transport gaps.
- [x] Verify per-attempt and cumulative resynchronization bounds, shutdown, and
      stream re-arm behavior under repeated gaps.
- [x] Add fuzz seeds for embedded CR, consumed suffixes, gaps at every header/body
      boundary, and repeated plausible start lines.

### Acceptance Criteria

- [x] No known reassembly or stream-queue discontinuity is hidden by byte
      concatenation.
- [x] A framing gap discards at most the incomplete message and allows a later
      correctly framed SIP message on the same live stream to be processed.
- [x] Security validation remains strict for correctly framed hostile input.

## Phase 3: Stateful SIP-First Capture Shedding

### Implementation

- [x] Add a bounded, expiring, concurrency-safe TCP SIP-flow classifier owned by
      `capture.PacketBuffer` in `internal/pkg/capture/capture.go`.
- [x] Use a canonical direction-independent network/transport flow key so a
      credible SIP start promotes both directions of the connection to the SIP
      lane.
- [x] Add a small bounded prefix accumulator sufficient to recognize a SIP start
      split across TCP segments; never retain arbitrary payload or unbounded state.
- [x] Route continuation segments and bodies for a promoted flow through the SIP
      lane. Expire state on FIN/RST and idle timeout, and handle tuple reuse on
      either observed SYN or SYN-ACK without inheriting stale classification.
- [x] Document the join-midstream limitation before the first recognizable SIP
      start and the fallback behavior when the SIP lane itself is saturated.
- [x] If stateful classification proves too costly or error-prone, evaluate a
      separately bounded protected-TCP lane; do not route all TCP into the SIP lane
      by default because unrelated TCP could starve signaling.

### Tests and Benchmarks

- [x] Strengthen the existing packet-buffer priority test: regular-lane saturation
      must produce regular drops and exactly zero recognized-SIP drops while SIP
      offered load remains within priority-lane service capacity.
- [x] Cover split start lines, same-direction continuations, reverse-direction
      responses, bodies, FIN/RST, idle expiry, tuple reuse, and priority-lane
      capacity exhaustion with truthful SIP-drop accounting.
- [x] Add concurrent/race tests for multiple capture senders and bounded-state
      tests under high flow cardinality.
- [x] Benchmark fast classification and flow-cache hit/miss behavior with allocation
      reporting.

      Benchmark record (linux/amd64, 13th Gen Intel Core i9-13900HX, three runs):
      promoted-flow hit 65.79-67.90 ns/op, 0 B/op, 0 allocs/op; bounded new-flow
      miss 818.5-902.4 ns/op, 130-131 B/op, 4 allocs/op; full-cache eviction
      873.4-915.3 ns/op, 130-131 B/op, 4 allocs/op.

      Post-implementation audit: classifier snapshots now remove passively expired
      entries, and classification/lifecycle counters are included in cumulative
      capture telemetry and heartbeat output rather than remaining getter-only.

### Acceptance Criteria

- [x] Regular traffic saturation does not evict recognized SIP traffic within the
      documented SIP-lane capacity envelope.
- [x] Every priority classification and loss case is attributable through named
      telemetry.
- [x] Flow state remains bounded and does not survive connection close or idle
      expiry incorrectly.

## Phase 4: Flow-Sharded TCP Reassembly

### Implementation

- [ ] Extend `pipeline.ReassemblyConfig` in
      `internal/pkg/pipeline/reassembly.go` with a shard count that defaults to one
      for compatibility.
- [ ] Make `ReassemblyEngine` own one `capture.TCPAssembler` and stream pool per
      shard. Select shards with a tested direction-independent hash over network
      and transport endpoints.
- [ ] Define buffered-page limits precisely under sharding. Keep the configured
      total memory bound global where practical rather than multiplying it by the
      shard count; preserve a safe per-connection cap.
- [ ] Aggregate per-shard reassembly statistics, flush every shard, flush all
      shards during close, and call the shared stream factory shutdown exactly
      once.
- [ ] Refactor the engine lifecycle lock so concurrent assembly on different
      shards is possible while `Close` still excludes new input safely; do not
      retain an engine-wide write lock around every `Assemble` call.
- [ ] Update `internal/pkg/processor/source/local.go` to route TCP flows across
      detection workers with the same canonical hash, remove worker-0 pinning and
      the global `assemblerMu`, and preserve same-flow ordering.
- [ ] Add shard configuration to the applicable local/tap composition and Viper
      configuration. Audit every other `ReassemblyEngine` user and retain one
      shard unless explicitly enabled and tested for that path.
- [ ] Document configuration, memory implications, telemetry aggregation, and
      rollback to one shard.

### Tests and Benchmarks

- [ ] Test one-, two-, and four-shard construction; reverse directions must select
      one shard and independent flows must distribute across shards.
- [ ] Test concurrent assembly, periodic flushing, shutdown, factory shutdown-once,
      stats aggregation, and `Assemble`/`Close` race safety.
- [ ] Test local-source routing so separate TCP flows execute concurrently while
      packet order remains stable within each flow.
- [ ] Add a representative SIP-over-TCP benchmark at one, two, four, and eight
      shards. Record packets/s, CPU, heap, allocations, gaps, and all drop stages.
- [ ] Run race tests for pipeline, processor source, capture, and VoIP packages.

### Acceptance Criteria

- [ ] Independent TCP flows can use multiple cores without concurrent access to a
      single gopacket assembler.
- [ ] Per-flow direction and ordering guarantees are unchanged.
- [ ] Lifecycle, memory bounds, and aggregated metrics remain correct under race
      testing.
- [ ] The production default is chosen from benchmark evidence; the plan makes no
      fixed Nx throughput promise.

## Phase 5: Profile-Guided Detector Allocation Diet

### Baseline

- [ ] Extend `internal/pkg/detector/detector_bench_test.go` with
      `ReportAllocs`, isolated `BuildContext` and flow-ID benchmarks, cache
      hit/miss churn, and realistic mixed high-cardinality TCP/UDP cases.
- [ ] Capture bounded CPU and allocation profiles using synthetic or anonymized
      replay data and the existing loopback-only profiling facility.
- [ ] Record baseline ns/op, B/op, allocs/op, packets/s, CPU, and heap before
      selecting changes.

### Candidate Optimizations

- [ ] Replace `fmt.Sprintf("%x", sum)` in detector flow-ID generation with a
      measured lower-allocation numeric/fixed-hex representation while preserving
      bidirectional stability and external compatibility where required.
- [ ] Avoid allocating empty metadata maps for unknown detection results if all
      consumers are verified nil-safe.
- [ ] If profiles justify it, introduce an internal comparable binary flow key and
      materialize strings only at API/log boundaries.
- [ ] Treat removal of `SrcIP.String()`/`DstIP.String()` and migration to
      `netip` as a separate cross-package change with explicit benchmarks and
      compatibility tests.
- [ ] Treat typed protocol metadata as a later API migration, not a pooling patch,
      unless profiles prove it is necessary and ownership/reset semantics are
      fully defined.

### Tests and Acceptance Criteria

- [ ] Test stable direction-independent flow identity and cache behavior after any
      key representation change.
- [ ] Test nil-metadata compatibility across every affected detector consumer.
- [ ] Demonstrate a measurable end-to-end improvement without increasing false
      detection, memory retention, or allocations elsewhere.
- [ ] Reject optimizations that improve a microbenchmark but regress representative
      pipeline throughput or maintainability.

## Phase 6: Documentation, Validation, and Release

- [ ] Run `gofmt` on every changed Go file before staging.
- [ ] Regenerate and verify protobuf outputs after schema changes.
- [ ] Run targeted unit, integration, fuzz-seed, benchmark, and race tests for each
      phase before proceeding to the next.
- [ ] Run the full tagged test suite relevant to tap, processor, hunter, TUI, and LI
      builds after all phases are integrated.
- [ ] Verify specialized builds compile and non-LI builds continue to exclude LI
      code.
- [ ] Update operator documentation for TUI retention semantics, loss-stage
      counters, SIP-priority capacity assumptions, parser recovery, and reassembly
      shard tuning.
- [ ] Use only synthetic/anonymized evidence in committed tests and documentation;
      perform a final repository search for deployment identifiers and captured
      identities before staging.
- [ ] Check off only tasks verified by code, tests, or recorded benchmark evidence.
- [ ] Commit the implementation, generated code, documentation, benchmark summary,
      and this completed plan together as required by the repository workflow.

## Recommended Delivery Order

1. Phase 0: observability and compatibility plumbing.
2. Phase 1: TUI integrity and bounded display work.
3. Phase 2: discontinuity propagation and parser recovery.
4. Phase 3: SIP continuation prioritization.
5. Phase 4: TCP reassembly sharding and benchmark-derived default.
6. Phase 5: profile-guided allocation changes.
7. Phase 6: full validation, documentation, and release review.

Phases 1 and 2 may proceed in parallel after Phase 0 counter semantics are fixed.
Phase 4 should not select a default until Phases 0 and 2 provide trustworthy gap
and loss measurements. Phase 5 should begin with baselines but land optimizations
only after profiling the preceding architecture.

## Principal Risks

- Protobuf compatibility or aggregate-counter semantic drift.
- Double-counting the same packet at multiple loss stages.
- TUI ingress statistics accidentally triggering full per-packet conversion.
- SIP flow-cache false promotion, unbounded state, or stale tuple reuse.
- Parser resynchronization accepting false SIP starts or looping indefinitely.
- Hiding correctly framed hostile Content-Length values behind recovery behavior.
- Multiplying reassembly memory limits by shard count.
- Retaining an engine-wide lock that silently defeats sharding.
- Shared factory shutdown or flush races across assemblers.
- Optimizing allocations without end-to-end evidence.
