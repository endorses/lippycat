# Security and Streaming Correctness Hardening Plan

**Date:** 2026-08-27
**Status:** Draft
**Priority:** Critical

## Overview

Harden the distributed capture, lawful-interception, shutdown, VoIP, filtering,
build, protocol-fingerprinting, and TUI paths against correctness failures that
can cause unauthenticated administration, invalid concurrent gRPC stream use,
process panics, unbounded memory growth, silently missing filters, incorrect TLS
fingerprints, and data races.

The changes should ship as small, independently testable phases. Stream ownership
and X1 authentication come first because they define security and transport
invariants. Shutdown, memory bounds, and filter delivery follow. Build-matrix and
protocol/UI fixes can then land without obscuring the higher-risk lifecycle work.

## Goals

- Give every bidirectional gRPC stream exactly one serialized send path.
- Require authenticated X1 administration whenever the X1 server is enabled.
- Make processor shutdown stop packet producers before closing packet consumers.
- Eliminate tap VoIP's writes into an unused global RTP association map.
- Keep hunter memory bounded during processor-requested pauses.
- Guarantee that a filter modification reaches newly targeted hunters.
- Restore all documented build variants and package-wide build/test commands.
- Generate standards-compatible JA4 fingerprints.
- Synchronize VoIP writer lifetime with every packet write.
- Keep Bubble Tea component mutation on the Bubble Tea event loop.

## Non-Goals

- Do not redesign the protobuf services or change packet-batch wire formats.
- Do not introduce packet loss as the default response to a short processor pause.
- Do not alter JA3 or JA3S output while correcting JA4.
- Do not change filter ID allocation or filter-targeting semantics.
- Do not replace Bubble Tea, the VoIP processor, or the TCP reassembly library.
- Do not combine unrelated reconnect, parser, or performance cleanup into these
  phases unless it is required to preserve an invariant introduced here.

## Engineering Invariants

1. A gRPC stream has one sender goroutine, or one mutex held across every `Send`
   and `CloseSend`; copying the stream pointer under a mutex is insufficient.
2. X1 must fail closed. Server certificate and key without a trusted client CA
   are not a valid X1 server configuration.
3. Shutdown order is producer stop, producer drain, consumer drain, consumer
   close. No producer may retain a path to a closed channel.
4. Bounded queues remain bounded in every flow-control state.
5. Filter updates are idempotent: ADD deduplicates and MODIFY upserts.
6. Writer pointers and their backing files are inspected, used, and cleared
   under the same per-writer mutex.
7. Bubble Tea component state is mutated only while handling `tea.Msg` on the UI
   goroutine.

## Phase 1: Serialize gRPC Stream Sends

**Priority:** Critical

### Processor to upstream

- [ ] Add a connection-scoped outbound queue and sender loop to
      `internal/pkg/processor/upstream.Manager`.
- [ ] Make `Forward` enqueue a batch rather than call `stream.Send` directly.
- [ ] Define explicit behavior for a full outbound queue: report pressure to the
      flow controller and apply the configured bounded drop/backlog policy.
- [ ] Tie the sender loop to the connection generation so an old sender cannot
      send on or close a successor stream.
- [ ] Route `CloseSend` through the stream owner after it has stopped accepting
      batches and drained or discarded the bounded queue.
- [ ] Preserve packet-forwarded and consecutive-failure accounting in the sender
      loop rather than at enqueue time.

### Hunter to processor

- [ ] Make `batchSender` the sole owner of `stream.Send`.
- [ ] Remove the goroutine-per-send timeout pattern from `SendBatchToStream`.
- [ ] Enforce send deadlines through the stream/connection context. If the gRPC
      API cannot apply a per-message deadline, cancel the connection generation
      on timeout and wait for its sender to exit before reconnecting.
- [ ] Ensure shutdown flushing is requested through `batchSender`; do not drain
      `batchQueue` from a second goroutine.
- [ ] Route `CloseSend` through the sender owner after sends have stopped.
- [ ] Make failure callbacks non-blocking with respect to sender teardown and
      ensure only one disconnect transition occurs per connection generation.

### Tests

- [ ] Add an upstream test with many concurrent `Forward` callers and a fake
      stream that detects overlapping `Send` calls.
- [ ] Add a hunter test with a blocked fake stream and verify that a send timeout
      leaves no abandoned send goroutine and starts no second send.
- [ ] Add shutdown tests proving `CloseSend` never overlaps `Send`.
- [ ] Add reconnect-generation tests proving an old sender cannot affect the new
      stream.
- [ ] Run relevant packages under `go test -race`.

### Acceptance Criteria

- At most one `Send` is active on each stream.
- No send goroutine survives its connection generation.
- Slow or failed links consume bounded memory and trigger deterministic
  disconnect/backpressure behavior.

## Phase 2: Require Authenticated X1 Administration

**Priority:** Critical

### Tasks

- [ ] Validate X1 configuration before constructing or starting the X1 server:
      listen address, server certificate, server key, and client CA must be
      present together.
- [ ] Return an actionable startup error when X1 is enabled without a client CA.
- [ ] Set `ClientAuth` to `tls.RequireAndVerifyClientCert` unconditionally for an
      enabled X1 server.
- [ ] Raise the X1 minimum TLS version to TLS 1.3 for consistency with the data
      plane unless a documented ETSI interoperability requirement mandates a
      separately configured compatibility mode.
- [ ] Apply production-mode validation to X1 independently of the gRPC listener.
- [ ] Ensure logs never describe a running X1 server as unauthenticated; missing
      authentication must prevent startup.
- [ ] Update LI deployment, certificate, manual, and command documentation so the
      X1 CA is shown as required rather than optional.

### Tests

- [ ] Table-test every partial X1 TLS configuration and require startup failure.
- [ ] Verify a client without a certificate cannot complete the TLS handshake.
- [ ] Verify a certificate signed by an untrusted CA is rejected.
- [ ] Verify a trusted ADMF client can perform an authenticated X1 request.
- [ ] Verify production mode rejects an incomplete X1 configuration even when the
      data-plane TLS configuration is valid.

### Acceptance Criteria

- No X1 handler can be reached without a client certificate chaining to the
  configured CA.
- An incomplete X1 authentication configuration fails before accepting traffic.

## Phase 3: Correct Processor Shutdown Ordering

**Priority:** Critical

### Tasks

- [ ] Document the complete processor shutdown dependency graph, including gRPC
      handlers, local `PacketSource`, upstream forwarding, unified PCAP,
      auto-rotate PCAP, per-call PCAP, LI, virtual interfaces, and subscribers.
- [ ] Stop new packet ingress first: cancel local sources and stop accepting new
      gRPC streams.
- [ ] Gracefully stop gRPC handlers before closing the unified PCAP write queue.
- [ ] Wait for local-source and handler goroutines that can call `QueuePackets` to
      exit before `pcapWriter.Stop` closes `writeQueue`.
- [ ] Preserve bounded shutdown with a graceful-stop timeout and explicit forced
      stop fallback.
- [ ] Make `pcap.Writer.Stop` idempotent and make enqueue-after-stop return a
      failure instead of panicking as defense in depth.
- [ ] Close downstream writers only after their final producers have exited.

### Tests

- [ ] Start a processor with a continuously streaming fake hunter, initiate
      shutdown, and assert no panic and no goroutine leak.
- [ ] Race local-source packet delivery against shutdown.
- [ ] Call shutdown concurrently and repeatedly to verify idempotence.
- [ ] Verify accepted queued PCAP batches drain before file closure.
- [ ] Verify forced shutdown completes when a client refuses graceful closure.

### Acceptance Criteria

- Shutdown cannot send to a closed PCAP queue.
- Graceful shutdown terminates within its configured deadline and drains work
  accepted before ingress was stopped.

## Phase 4: Remove Tap VoIP Global Tracker Retention

**Priority:** Critical

### Tasks

- [ ] Remove the global `ExtractPortFromSdp` call from the tap-specific TCP SIP
      handler.
- [ ] Trace TCP-signaled SDP through tap and determine whether the active
      `voip/processor` instance already receives the parsed SDP metadata.
- [ ] If TCP-signaled RTP association is required, add an explicit method on the
      tap VoIP processor to register SDP endpoints in its per-call tracker.
- [ ] Ensure that processor-owned mappings are removed on terminal call state,
      timeout, eviction, and processor shutdown.
- [ ] Keep the global tracker behavior unchanged for `sniff voip` and hunter paths
      that actively use it.
- [ ] Configure finite `MaxBufferedPagesPerConnection` and
      `MaxBufferedPagesTotal` reassembly limits with production-safe defaults and
      observable drop/error counters.

### Tests and validation

- [ ] Add a tap TCP-SIP regression test that creates and completes many calls and
      verifies the global tracker's `portToCallID` size does not grow.
- [ ] Verify TCP-signaled calls still associate RTP with the correct tap processor
      call when that behavior is supported.
- [ ] Verify processor-owned mappings are removed after call completion.
- [ ] Add reassembly limit tests for missing/out-of-order TCP segments.
- [ ] Run a bounded soak test with repeated TCP SIP calls and record heap profiles,
      live mapping counts, reassembly pages, and goroutine counts.

### Acceptance Criteria

- Tap TCP SIP traffic does not write to the legacy global RTP association map.
- Repeated completed calls reach a stable mapping and heap baseline.
- TCP reassembly has explicit, tested memory bounds.

## Phase 5: Make PAUSE Memory-Bounded and SLOW Effective

**Priority:** Critical

### Tasks

- [ ] Remove the PAUSE early return from batch rotation in `SendBatch`.
- [ ] Continue rotating `currentBatch` at the configured batch size and enqueue it
      into the bounded memory queue while paused.
- [ ] Gate transmission in the sole sender loop so PAUSE stops dequeue/send, not
      capture-side batching.
- [ ] Retain the existing disk-overflow behavior when the memory queue fills and
      account for drops when both tiers are exhausted.
- [ ] Define and implement SLOW semantics, such as bounded pacing or an adaptive
      send rate, without spawning timers or goroutines per batch.
- [ ] Replace protobuf numeric comparison with an explicit flow-control severity
      function.
- [ ] Replace lifetime-counter subtraction with a real outstanding-queue metric or
      interval-based ingress/egress rate calculation.
- [ ] Define state transitions and hysteresis for CONTINUE, SLOW, PAUSE, and
      RESUME.

### Tests

- [ ] Hold a hunter in PAUSE while injecting more than one batch and assert
      `currentBatch` remains bounded.
- [ ] Fill memory and disk queues during PAUSE and verify deterministic drop
      accounting.
- [ ] Verify RESUME drains queued batches in order.
- [ ] Verify upstream backlog requests SLOW even when the PCAP queue requests
      RESUME.
- [ ] Verify SLOW reduces the send rate without blocking capture batching.
- [ ] Add long-duration state-transition tests using a fake clock.

### Acceptance Criteria

- PAUSE cannot grow `currentBatch` beyond its configured bound.
- All four flow-control states have observable, tested behavior.
- A drained PCAP queue cannot mask a more severe upstream condition.

## Phase 6: Make Filter MODIFY an Idempotent Upsert

**Priority:** High

### Tasks

- [ ] Change hunter-side `UPDATE_MODIFY` handling to replace an existing filter or
      add it when absent.
- [ ] Keep ID-based deduplication so repeated MODIFY messages cannot create
      duplicates.
- [ ] Rebuild application/GPU filter state exactly once after an effective change.
- [ ] Preserve processor-side DELETE delivery to hunters removed from the target
      scope.
- [ ] Add structured logging that distinguishes modify, modify-as-add, no-op, and
      delete operations.
- [ ] Confirm LI-created filters use the same upsert path without separate
      semantics.

### Tests

- [ ] Retarget one filter from hunter A to hunter B and verify removal from A and
      installation on B without reconnecting either hunter.
- [ ] Broaden a targeted filter to all hunters and verify every newly included
      hunter installs it.
- [ ] Narrow an all-hunter filter and verify excluded hunters delete it.
- [ ] Replay the same MODIFY and verify only one filter exists.
- [ ] Exercise CPU, GPU-capable, and LI filter types where supported.

### Acceptance Criteria

- Any currently connected compatible hunter in the new target scope holds the
  latest filter immediately after a successful update.
- Replayed updates are harmless and deterministic.

## Phase 7: Repair and Enforce the Build Matrix

**Priority:** High

### Tasks

- [ ] Make Go and assembly constraints for `internal/pkg/simd` use matching modern
      `//go:build` expressions.
- [ ] Ensure CUDA builds select a complete SIMD implementation or an intentional
      pure-Go fallback; no declaration may be left without a compiled body.
- [ ] Update `make build-cuda` to include the appropriate root command tag.
- [ ] Scope tap LI and GPU stub files to the command variants that compile the tap
      package, mirroring the positive implementation constraints.
- [ ] Audit all `cmd/*/flags_{li,gpu}*.go` pairs for symmetric constraints.
- [ ] Add a build-matrix script or Make target used identically by developers and
      CI.
- [ ] Keep non-LI builds free of LI implementation code and preserve documented
      command visibility for specialized binaries.

### Required matrix

- [ ] `go build -tags all .`
- [ ] `go build -tags 'all,li' .`
- [ ] `go build -tags 'all,cuda' .` on a CUDA-capable builder.
- [ ] `go build -tags 'tap,li,cuda' .` on a CUDA-capable builder.
- [ ] `go test -tags all ./...`
- [ ] `go test -tags li ./internal/pkg/li/...`
- [ ] `go test -tags hunter ./...`
- [ ] `go test -tags processor ./...`
- [ ] `go test -tags tap ./...`
- [ ] `go test -tags cli ./...`
- [ ] `go test -tags tui ./...`
- [ ] `make vet` or equivalent vet runs for every supported package partition.

### Acceptance Criteria

- Every documented build variant compiles in CI.
- Package-wide test/vet commands do not fail because unrelated command stubs pull
  in packages excluded by the selected role tag.

## Phase 8: Generate Standards-Compatible JA4

**Priority:** High

### Tasks

- [ ] Replace the JA4 truncated MD5 helper with SHA-256 truncated to the required
      12 hexadecimal characters.
- [ ] Encode ALPN using the JA4-defined first and last character transformation.
- [ ] Verify cipher, extension, GREASE, SNI, signature-algorithm, sorting, and empty
      value behavior against the current JA4 specification.
- [ ] Keep JA3 and JA3S hashing on MD5 as required by those formats; avoid sharing
      a misleading generic hash helper.
- [ ] Document that corrected JA4 values change existing stored fingerprints and
      filters.
- [ ] Decide whether configuration migration needs a temporary compatibility
      warning for known legacy JA4 filters; do not silently match both formats.

### Tests

- [ ] Add official or independently generated JA4 test vectors.
- [ ] Cover ALPN values such as `h2`, `http/1.1`, one-character values, and no
      ALPN.
- [ ] Cover GREASE removal, extension exclusions, signature algorithms, and empty
      hashes.
- [ ] Assert JA3 and JA3S fixtures remain unchanged.
- [ ] Add a `FILTER_TLS_JA4` integration test using a standard fingerprint.

### Acceptance Criteria

- JA4 output matches an independent conforming implementation for all fixtures.
- Published JA4 fingerprints can be used directly in filters.

## Phase 9: Synchronize VoIP Writer Lifetime

**Priority:** High

### Tasks

- [ ] Move SIP/RTP writer nil checks inside their corresponding writer mutexes in
      both synchronous and asynchronous write paths.
- [ ] Hold the mutex continuously across pointer inspection and `WritePacket`.
- [ ] Keep `CallInfo.Close` responsible for closing the file and clearing writer
      pointers under the same mutex.
- [ ] Audit every access to `SIPWriter`, `RTPWriter`, `sipFile`, and `rtpFile` and
      route it through locked helpers where practical.
- [ ] Define lock ordering between tracker locks and per-call writer locks and
      document it beside `CallInfo`.
- [ ] Ensure LRU eviction and completion cleanup remove tracker state without
      introducing tracker-lock/writer-lock inversion.
- [ ] Preserve `activeWrites` for whole-tracker shutdown, but do not depend on it
      for per-call close safety.

### Tests

- [ ] Race RTP writes against completion-monitor close.
- [ ] Race SIP writes against LRU eviction.
- [ ] Exercise synchronous and asynchronous writer modes.
- [ ] Assert late packets return a defined not-initialized/closed result instead
      of panicking.
- [ ] Run the VoIP package with `go test -race` and repeated stress counts.

### Acceptance Criteria

- No writer can be cleared between its nil check and dereference.
- Closing one call cannot panic or corrupt concurrent writes for that call or any
  other call.

## Phase 10: Move TUI View Updates onto the Event Loop

**Priority:** High

### Tasks

- [ ] Introduce typed `tea.Msg` results for background DNS, HTTP, email, and local
      call processing.
- [ ] Make `BackgroundProcessor` parse/enrich immutable packet input and publish
      result messages without mutating component instances.
- [ ] Handle each result in the top-level Bubble Tea model's `Update` method and
      call component mutation methods only there.
- [ ] Preserve bounded background queues and expose dropped-result counters.
- [ ] Copy or transfer ownership of slices/maps in messages so the background
      worker cannot mutate data after delivery.
- [ ] Make `Configure` and mode switching generation-aware so results from a prior
      mode cannot update newly selected views.
- [ ] Stop and wait for the background processor during model shutdown.

### Tests

- [ ] Feed concurrent DNS, HTTP, and email packets while rendering views under the
      race detector.
- [ ] Switch capture modes while background results are in flight and verify stale
      results are ignored.
- [ ] Stress query-list rebuilding and selection to guard against index errors.
- [ ] Stress HTTP request-map updates and reads to guard against concurrent-map
      failures.
- [ ] Verify queue overflow increments counters without blocking the UI.

### Acceptance Criteria

- Background workers never call component `UpdateFromPacket` methods directly.
- TUI protocol views pass race-detector stress tests without map or slice races.
- UI input and rendering remain responsive under sustained background traffic.

## Cross-Phase Verification

- [ ] Run `gofmt` and `go vet` for every affected build partition.
- [ ] Run unit and integration tests with `-tags all` and the dedicated LI suite.
- [ ] Run targeted race tests for hunter forwarding, processor upstream,
      processor lifecycle, VoIP, filtering, and TUI.
- [ ] Run a distributed slow-link scenario with multiple hunters feeding one
      upstream processor while monitoring memory, goroutines, queue depths, and
      flow-control transitions.
- [ ] Run tap TCP-SIP and processor-shutdown soak tests with heap and goroutine
      profiles captured at the beginning and end.
- [ ] Update command reference, configuration reference, security documentation,
      operational procedures, and release notes for behavioral/configuration
      changes.

## Rollout and Compatibility

- Ship phases 1-3 together or in immediate succession; they jointly establish
  stream ownership and safe lifecycle ordering.
- Treat the X1 CA requirement as a deliberate fail-closed configuration change.
  Release notes must provide the exact required flags and certificate migration
  steps.
- Announce the JA4 correction as an output compatibility change. Existing stored
  non-standard values and filters must be regenerated.
- Introduce flow-control metrics before or with the PAUSE/SLOW changes so bounded
  drops and disk spill are visible during rollout.
- Gate CUDA matrix jobs on suitable runners, but keep constraint-only compilation
  checks available on ordinary CI where possible.
- Do not mark a phase complete until its acceptance criteria and race-sensitive
  tests pass in the relevant build variants.

## Coordination with Existing Plans

- Preserve the completed lifecycle and memory work in
  `docs/plans/concurrency-memory-hardening.md`, especially connection-generation,
  per-call PCAP bounds, and local-source shutdown behavior.
- Preserve the intended role-tag and optional-feature conventions documented in
  `docs/plans/build-tagged-cli-flags.md`; this plan repairs constraint gaps rather
  than introducing a new flag architecture.
- Reuse existing flow-control and subscriber test fixtures where they model the
  same queues, but add explicit slow-stream and connection-generation fakes.

## Definition of Done

- All ten phases meet their acceptance criteria.
- Supported build variants compile and their package partitions pass tests.
- Targeted race suites pass repeatedly.
- X1 cannot start without verified client authentication.
- Distributed slow-link and shutdown scenarios remain memory-bounded and
  panic-free.
- Tap TCP SIP reaches a stable memory baseline after completed calls.
- JA4 output interoperates with standard tooling.
- Documentation describes the new security requirements, compatibility changes,
  operational metrics, and failure behavior.
