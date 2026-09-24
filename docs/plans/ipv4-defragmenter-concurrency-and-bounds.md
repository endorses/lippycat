# IPv4 defragmenter concurrency, bounds, and outcome telemetry

**Status:** Implemented; closure audit complete
**Baseline:** `v0.12.1` checkout, 2026-09-24

## Objective

Make shared IPv4 defragmentation safe across capture interfaces, bound retained
incomplete datagrams under first-fragment floods, and report reassembly
outcomes without treating the existing mixed fragment counters as an IPv4
completeness measure.

The motivating analysis is in
`/home/grischa/ipv4-defrag-unsynchronised-and-untunable.md`. Its production
measurements are context, not test fixtures or a substitute for a race test.

## Design contract

- [x] Guard each `fragmentList` mutation, traversal, completion, and removal
      with the same synchronization used for the owning map. Cleanup must
      never read `LastSeen` concurrently with an insertion.
- [x] Make completion and expiry remove only the flow instance they inspected;
      no stale delete may erase a replacement flow with the same key.
- [x] Keep multi-interface reassembly supported. Do not move to per-interface
      defragmenters merely to avoid shared-state synchronization.
- [x] Bound active IPv4 datagrams, total retained fragments, and retained
      payload bytes. Enforce limits before retaining an incoming fragment,
      including the per-flow fragment limit.
- [x] Define deterministic eviction or rejection when capacity is exhausted;
      report the reason. Prefer bounded-cost maintenance over scanning every
      flow on every fragment. Use measured memory and capture tests to select
      and document defaults before exposing overrides.
- [x] Keep per-interface ingress counts available, while reporting shared,
      family-specific IPv4 outcomes once per capture session. Distinguish
      observed fragments, attempted reassembly, completed datagrams, rejected
      fragments, expiry, and capacity eviction.
- [x] Do not label `ip_fragments / reassembled` as a completeness percentage:
      it mixes IPv4/IPv6 and disabled-reassembly traffic, and datagrams may
      contain different numbers of fragments.
- [x] Preserve IPv4 small-final-fragment behavior and existing IPv6 behavior.

## Phase 1: Fix the shared-state race

- [x] Extend the IPv4 mutex across lookup, insert/build, limit checks, and
      conditional removal. Avoid calling `flush` while holding that mutex;
      make the locked removal path explicit.
- [x] Make `DiscardOlderThan` use the same synchronization. Resolve insert
      versus sweep and insert versus completion interleavings without losing
      a live fragment or publishing a partial packet.
- [x] Handle duplicate fragments and insertion errors without advancing
      retained-state accounting incorrectly. Check per-flow capacity before
      insertion; preserve the RFC 791 small-final-fragment exception.
- [x] Add deterministic concurrent tests in which fragments of one datagram
      arrive from multiple goroutines while cleanup runs. Verify exact
      reassembly, no lost replacement flow, and no race under `go test -race`.

Primary files: `internal/pkg/capture/defrag.go` and
`internal/pkg/capture/defrag_test.go`.

## Phase 2: Bound retained datagrams

- [x] Define one configuration type for maximum active IPv4 datagrams, total
      retained fragments, retained payload bytes, stale age, and sweep
      interval. Validate invalid values and resolve documented defaults.
- [x] Track total retention under the defragmenter's lock. Account for new,
      duplicate, rejected, completed, expired, and evicted fragments exactly
      once; release all accounting on every removal path.
- [x] Add bounded-cost expiry/eviction ordering, with a generation or identity
      check so stale queue entries cannot remove a newer datagram sharing a
      flow key. Define which incomplete datagram is discarded first at each
      limit and how the incoming fragment is handled.
- [x] Wire settings through every production capture constructor and the
      relevant hunt, tap, sniff, and watch-live configuration surfaces. Keep
      offline PCAP timestamp semantics explicit when selecting stale age.
- [x] Keep the sweep goroutine single per capture session and shut it down
      cleanly. Measure lock hold time and throughput with representative
      fragmented and mostly unfragmented traffic before considering sharding.
- [x] Test first-fragment floods with distinct IDs, limit enforcement, expiry,
      duplicate/overlap handling, out-of-order fragments, and recovery after
      eviction. Assert retained counts and bytes never exceed configured caps.

Primary files: `internal/pkg/capture/defrag.go`,
`internal/pkg/capture/capture.go`, capture configuration, and affected commands.

## Phase 3: Add interpretable outcome telemetry

- [x] Retain the existing heartbeat fields for compatibility and document their
      current mixed meaning. Do not silently reinterpret them as IPv4-only.
- [x] Add per-interface ingress counters split by IPv4 and IPv6 and by whether
      reassembly was attempted. Add one shared IPv4 defragmenter snapshot for
      completed datagrams, invalid/rejected fragments, expired datagrams,
      capacity evictions, and current in-flight state.
- [x] Sample shared outcomes once per capture session; do not add the same
      shared totals once for every interface. Expose interval deltas or clearly
      defined cumulative totals and reset behavior.
- [x] Expose new fields through existing local heartbeat/status consumers. If
      distributed hunter/processor status carries them, add backward-compatible
      protocol fields and old-peer decoding tests.
- [x] Document what the counters can establish: a completed datagram is known
      locally, while an expired or evicted one is incomplete at the sensor;
      counts alone cannot prove which upstream fragment was lost.
- [x] Test two-interface fragment completion, simultaneous IPv4 and IPv6
      traffic, disabled reassembly, expiry, and capacity eviction. Verify that
      per-interface ingress and shared outcomes have distinct scopes.

Primary files: `internal/pkg/capture/capture.go`,
`internal/pkg/capture/telemetry.go`, capture telemetry tests, and relevant
status/protobuf adapters if the new fields leave the local process.

## Phase 4: Validation and documentation

- [x] Run focused IPv4 and IPv6 defrag tests, the concurrent race test, and
      relevant capture-path integration tests for live and offline traffic.
- [x] Run affected build variants and configuration contract tests. Compare
      throughput and memory against baseline with bounded synthetic traffic.
- [x] Update performance and operations documentation with limits, expiry,
      field meanings, and how to diagnose incomplete fragmented SIP/SDP.
- [x] Use synthetic packet payloads, addresses, identifiers, and measurements
      in committed tests and documentation.

## Completion criteria

- [x] Concurrent insertion and cleanup are race-free; fragmented datagrams
      arriving across interfaces still reassemble correctly.
- [x] Retained IPv4 state remains within configured limits under incomplete
      first-fragment floods, with observable expiry and eviction.
- [x] The published IPv4 outcome counters have a consistent session-wide
      scope and do not claim completeness from the old mixed ratio.

## Verification note

The capture package passed its full race suite, including cross-interface
completion and cleanup tests. Hunt, tap, sniff, watch, TUI, hunter capture, and
local source packages passed under their relevant build tags and together with
`-tags all`. Synthetic two-fragment benchmark results and memory allocations
are recorded in `docs/PERFORMANCE.md`; the baseline was measured from `HEAD`
in a temporary archive and removed afterward. Temporary benchmark-only
instrumentation measured about 202 ns of IPv4 lock hold time at one worker
and 210 ns at eight workers; it was removed afterward.
