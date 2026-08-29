# Pipeline Unification Migration Plan

**Date:** 2026-08-27
**Status:** Draft

## Objective

Build one composable packet-processing architecture for `sniff`, `watch`, `hunt`,
`process`, and `tap` while preserving each command's topology and observable
behavior.

The modes remain distinct compositions:

| Mode | Ingress | Processing location | Egress |
|------|---------|---------------------|--------|
| `sniff` | Live interface or PCAP | Local | CLI, optional PCAP, optional virtual interface |
| `watch live/file` | Live interface or PCAP | Local | TUI events |
| `hunt` | Live interface | Edge | gRPC forwarding |
| `process` | gRPC packet batches | Central | PCAP, TUI subscribers, upstream, optional LI |
| `tap` | Live interface | Local processor | Processor outputs plus optional upstream |

The implementation should share packet representation, analysis, call state,
reassembly ownership, and lifecycle rules. Topology-specific transport and output
policy remain explicit adapters rather than branches hidden inside the engine.

## Principles

1. Preserve user-facing commands, flags, configuration keys, output formats, and
   distributed protobuf contracts.
2. Introduce an abstraction only when at least two production consumers use it.
3. Separate parsing and analysis from call-selection policy and output delivery.
4. Keep capture timestamps first-class so live capture and offline replay use the
   same code without adopting wall-clock timestamps accidentally.
5. Make ownership explicit: every goroutine, channel, tracker, writer, and stream
   factory has one owner and a deterministic shutdown path.
6. Bound every queue and retained-data structure, and expose drops or forced
   releases through metrics and logs.
7. Migrate one consumer at a time. The old path is deleted only after its
   replacement has passed equivalence and lifecycle tests.
8. Prefer semantic equivalence tests over byte comparisons where timestamps,
   serialization headers, or concurrency make byte identity inappropriate.

## Target Architecture

```text
                       topology adapters
     live capture    PCAP replay    gRPC receive
           |             |              |
           +-------------+--------------+
                         |
                Normalized PacketEnvelope
                         |
        decode/detect/reassemble/analyze/filter
                         |
                  domain events/results
                         |
          +--------------+------------------+
          |              |                  |
     CLI/TUI sinks   PCAP/session sinks   gRPC/LI sinks
```

The architecture has four explicit layers:

1. **Ingress adapters** acquire data and preserve provenance.
2. **Pipeline stages** transform normalized envelopes and emit domain results.
3. **State services** own bounded call and stream state.
4. **Sinks** apply topology-specific delivery, buffering, and failure policy.

`tap = process + local ingress + edge filtering`, with no network hop between its
local ingress and processor outputs. Shared processor capabilities therefore
become available to tap through composition rather than copied command wiring.

## Core Contracts

These contracts must be agreed and tested before migrating commands.

### PacketEnvelope

`PacketEnvelope` is the internal unit passed between ingress and pipeline stages.
It is a domain type, not a protobuf type.

It must carry:

- Raw captured bytes and link type when available.
- A lazily or eagerly decoded `gopacket.Packet`.
- Capture timestamp, never inferred from processing time when source data has one.
- Source and interface identity.
- Sequence/batch provenance when received over gRPC.
- Existing protocol metadata and matched filter IDs from an upstream hunter.
- Stage provenance indicating which edge-safe operations already ran.

The provenance contract prevents a processor from unintentionally applying an
edge operation twice while still allowing central analysis to enrich a packet.
It must use named capabilities or typed fields, not a collection of arbitrary
string flags.

### Analysis Results

Analyzers return domain results such as `SIPEvent`, `RTPEvent`, `DNSEvent`, or a
generic packet result. Domain results must not depend on generated protobuf
types. Transport adapters perform protobuf conversion at the gRPC boundary.

A SIP result should include at least:

- Call ID, method, CSeq method, response code, and normalized identities.
- SDP content or parsed media endpoints.
- Source/destination endpoint and capture timestamp.
- The synthesized or original packet representation required by sinks.
- Filter matches and call-lifecycle observations.

### Stage Outcome

Pipeline and sink APIs must distinguish:

- accepted output;
- intentionally filtered output;
- bounded-buffer drop;
- retryable delivery failure;
- permanent failure; and
- shutdown cancellation.

Do not encode these outcomes as a boolean. Use a typed outcome and return an
error where the caller can act on it. Drops must increment an attributable
metric and include structured context when logged.

### Ownership and Shutdown

Every long-lived component exposes a blocking `Run(ctx)` or a clearly documented
`Start`/`Close` pair. Composition roots are responsible for:

1. stopping ingress;
2. draining or explicitly dropping queued work;
3. stopping reassembly and flushing streams;
4. completing call lifecycle notifications;
5. flushing and closing sinks; and
6. waiting for owned goroutines.

`Close`/`Stop` methods must be idempotent. No component may launch an untracked
goroutine from a constructor.

## Current Safety Baseline

The migration starts from the following established behavior and must preserve
it:

- TCP reassembly uses finite per-connection and global page limits through
  `capture.NewTCPAssembler`.
- Tap routes SDP learned from reassembled TCP SIP into its processor-owned VoIP
  tracker.
- The processor tracker removes call-to-media associations on completion,
  timeout, and close.
- Reassembly assembly and flushing are serialized.
- Offline replay can use packet capture timestamps for stream aging.

These safeguards receive regression tests before their surrounding code moves.

---

## Phase 0 — Build Matrix and Behavioral Baselines

### Goal

Make every supported build variant and important observable behavior verifiable.

### Tasks

- [x] Compile and vet `all`, `hunter`, `processor`, `tap`, `cli`, and `tui`.
- [ ] Compile and vet supported combinations with `li` and `cuda`, including
      `all,li`, `tap,li`, and `all,cuda`.
- [x] Repair build constraints or CUDA/root-tag combinations found by the matrix.
- [ ] Add a Make/CI target that runs the complete build-tag matrix. The local
      `make build-matrix-cuda` target exists, but CI still needs a CUDA builder.
- [x] Document that the required test entry point is `make test` plus the
      dedicated LI package run; untagged `go test ./...` is not sufficient.
- [x] Record golden CLI and TUI event fixtures from representative PCAPs.
- [x] Record semantic per-call PCAP fixtures: packet count, link type, timestamp,
      five-tuple, SIP fields, payload digest, and call association.
- [x] Add memory/lifecycle baselines for TCP SIP reassembly and call cleanup.

### Exit Criteria

- Every documented build variant compiles and vets.
- Unit and distributed integration suites are green.
- Stable semantic fixtures exist for each protocol and affected mode.

---

## Phase 1 — Normalize the Pipeline Contracts

### Goal

Introduce the internal packet and result contracts without changing command
behavior.

### Tasks

- [x] Add `PacketEnvelope` to a protocol-neutral internal package.
- [x] Define typed source provenance and stage provenance.
- [x] Add lossless conversions from local capture records and gRPC batches.
- [x] Define typed stage and sink outcomes, including drop reasons.
- [x] Define protocol-domain result types independent of protobuf generation.
- [x] Move protobuf conversion into gRPC ingress/egress adapters.
- [x] Add round-trip tests proving that source identity, timestamps, filter IDs,
      metadata, link type, and packet bytes survive adapter conversion.
- [x] Document which operations are edge-safe, central-only, or idempotent
      ([operation safety contract](../pipeline-operation-safety.md)).

### Exit Criteria

- Local and gRPC ingress can produce the same normalized envelope.
- Existing metadata is preserved and is not recomputed accidentally.
- No command has changed behavior yet.

---

## Phase 2 — Self-Owning TCP Reassembly

### Goal

Replace open-coded assembler/factory/flusher combinations with one bounded,
lifecycle-safe component.

### Design

```go
type StreamFactory interface {
    reassembly.StreamFactory
    Shutdown() error
}

type ReassemblyConfig struct {
    FlushInterval                 time.Duration
    IdleTimeout                   time.Duration
    MaxBufferedPagesPerConnection int
    MaxBufferedPagesTotal         int
    Clock                         Clock
}

type ReassemblyEngine struct { /* owned state */ }

func NewReassemblyEngine(factory StreamFactory, cfg ReassemblyConfig) *ReassemblyEngine
func (e *ReassemblyEngine) Run(ctx context.Context) error
func (e *ReassemblyEngine) Assemble(env PacketEnvelope) error
func (e *ReassemblyEngine) Close() error
```

`Run` owns periodic flushing. `Close` prevents new assembly, performs the final
flush, shuts down the factory exactly once, and waits for the flush loop. The
engine uses capture time for offline replay and a configurable clock for live
idle checks and deterministic tests.

### Tasks

- [x] Implement the engine over the existing bounded `capture.TCPAssembler`.
- [x] Make the concrete SIP stream factory shutdown reachable without a type
      assertion.
- [x] Preserve configurable page limits and expose forced-release metrics.
- [x] Migrate: tap VoIP, hunt VoIP, TUI bridge, capture sniffer,
      email, HTTP, and the legacy VoIP loop.
- [x] Remove each open-coded flush loop after its consumer migrates.
- [x] Add race-tested lifecycle cases: concurrent assemble/flush, cancellation,
      close during input, repeated close, factory shutdown error, and offline
      timestamp aging.

### Exit Criteria

- Production code contains no direct periodic `FlushCloseOlderThan` loop outside
  the engine.
- Every composition root closes and waits for its engine.
- Reassembly remains bounded under missing-segment and long-lived-flow tests.

---

## Phase 3 — Shared SIP Parsing and Metadata

### Goal

Make SIP interpretation pure and identical across UDP/TCP and all modes before
unifying call policy or delivery.

### Tasks

- [x] Define one SIP request-method table and use it in UDP detection, TCP stream
      framing, and request-line validation.
- [x] Define one RFC-correct compact-header map at package scope.
- [x] Extract a pure parser that accepts bytes and returns a domain `SIPEvent`.
- [x] Centralize identity, tag, CSeq, response, and SDP extraction.
- [x] Preserve per-message TCP semantics and capture timestamps.
- [x] Use the parser from tap and hunt first, then sniff and the processor VoIP
      analyzer.
- [x] Add corpus tests for compact headers, pipelined messages, fragmented TCP,
      malformed lengths, PUBLISH, provisional/final responses, and SDP.
- [x] During transition, compare normalized results from old and new parsing on
      a synthetic reference corpus suitable for CI.

Verification correction (2026-08-28): the VoIP compatibility fallback now uses
the package-scope RFC compact-header map, and the synthetic corpus compares the
shared parser with frozen legacy results rather than shared-parser-backed
compatibility adapters.

Verification follow-up (2026-08-28): removed the remaining metadata-producing
legacy fallback and optional plugin parser, removed the unused duplicate SIMD
method matcher, centralized SDP classification on `SIPEvent`, and expanded the
corpus to cover transport framing, folded headers, malformed and conflicting
lengths, response-code bounds, normalized identities, SDP, and provenance.

### Exit Criteria

- One implementation produces SIP domain metadata.
- UDP and reassembled TCP produce equivalent fields for equivalent messages.
- Parsing has no filtering, writer, tracker, Viper, gRPC, or TUI dependency.

---

## Phase 4 — Explicit Call Registry and Selection Policy

### Goal

Replace package-global call state with one bounded, instance-owned registry while
keeping output resources outside the analyzer.

### Design

The call registry owns:

- call identity and lifecycle state;
- matched/unmatched call selection state;
- SIP-to-RTP endpoint associations;
- bounded retention and timeout cleanup; and
- lifecycle notifications.

It does not own PCAP files, command hooks, gRPC streams, or UI state. Those are
managed by sinks that react to call lifecycle events.

Selection policy is explicit and topology-aware. It decides whether a parsed
message starts or updates a selected call, and whether later in-dialog SIP/RTP
belongs to that selection. Hunter, local CLI, and processor compositions may use
different policies without duplicating parsing.

### Tasks

- [x] Define `CallRegistry` and `CallLifecycleObserver` contracts.
- [x] Adapt the current processor-owned tracker into the registry implementation.
- [x] Support multi-valued endpoint associations required by B2BUA traffic.
- [x] Inject registry queries into TCP stream timeout decisions.
- [x] Move per-call PCAP writer and grace-period behavior into a session-output
      manager observing call lifecycle events.
- [x] Port global tracker consumers by capability: RTP lookup, SIP updates,
      writer/session lifecycle, completion, and timeout.
- [x] Remove Viper reads from VoIP library code; pass immutable config structs.
- [x] Delete global tracker access only after all production and test consumers
      use explicit instances.
- [x] Remove unused alternative trackers and unused performance machinery after
      a production-reference search and build-tag matrix confirm no callers.
- [x] Add tests for timeout, completion, B2BUA shared endpoints, writer-close
      ordering, bounded capacity, and concurrent shutdown.

Implementation verification (2026-08-29): introduced protocol-neutral registry
and observer contracts, migrated processor and legacy VoIP paths to explicit
tracker ownership, separated processor session output from registry state,
injected call-active queries into TCP reassembly, and removed unused lock-free,
hybrid, memory-mapped writer, and PCAP-encryption alternatives. `make test`, the
dedicated `all,li` package tests, focused race tests, and the non-CUDA supported
build matrix pass. The operational 24-hour and traffic soak tests remain a
release qualification activity under the plan's Soak Tests section.

Follow-up audit fixes (2026-08-29): tap TCP reassembly now uses its local
registry for call-aware timeout decisions; session output is registered as a
local-registry lifecycle observer; B2BUA RTP associations and inherited filter
IDs preserve every call leg; and the TUI call tracker is session-owned and
passed explicitly through capture, reassembly, conversion, and aggregation.

Second follow-up audit fixes (2026-08-29): legacy VoIP call state no longer owns
PCAP files or writers; an injected, instance-owned session-output manager owns
those resources and the async writer pool is tracker-scoped. Legacy tracker
configuration is snapshotted at construction, capacity is a hard bound even
when every resident call is pinned, and obsolete per-CPU/work-stealing
machinery was removed. TUI reassembly now receives its session registry's
call-active query, and tap deterministically closes its local VoIP registry.
Focused race tests, `make test`, and the supported non-CUDA build matrix pass.

### Audit Findings Requiring Remediation (2026-08-29)

The checked Phase 4 tasks are not yet fully implemented. A codebase-wide audit
found the following remaining ownership, lifecycle, selection, boundedness, and
concurrency defects:

- [x] Separate legacy sniff registry state from output resources. `CallTracker`
      still owns and invokes its `CallOutput` and `SniffCompletionMonitor`
      directly (`internal/pkg/voip/calltracker.go`, `internal/pkg/voip/core.go`),
      rather than emitting lifecycle events to an observing session-output
      manager.
- [x] Prevent async writer creation after legacy tracker shutdown begins.
      `WriteSIP`/`WriteRTP` can call `GetAsyncWriter` after `Shutdown` has stopped
      the previous pool, creating workers that are never stopped and that can
      race output shutdown (`internal/pkg/voip/writer.go`,
      `internal/pkg/voip/async_writer.go`).
- [x] Make processor registry lifecycle notifications causally ordered with
      registry mutations. Concurrent create, complete, timeout, eviction, and
      shutdown operations can currently deliver `OnCallEnded` before
      `OnCallStarted`, or deliver a start after shutdown
      (`internal/pkg/voip/processor/processor.go`).
- [x] Remove the package-global TUI `LocalCallAggregator` accessor and inject the
      session-owned aggregator into `TUISIPHandler`. The current global pointer
      contradicts explicit instance ownership and can retain a stopped session
      (`internal/pkg/tui/bridge.go`, `internal/pkg/tui/tcp_handler_tui.go`).
- [x] Implement legacy call timeout cleanup. The janitor runs, but
      `cleanupOldCalls` is a no-op, so inactive calls persist until capacity
      eviction or shutdown (`internal/pkg/voip/calltracker.go`).
- [x] Clear all legacy call indexes during shutdown. `Shutdown` removes
      `callMap` and recency entries but leaves endpoint associations, LRU state,
      and pins populated (`internal/pkg/voip/calltracker.go`).
- [x] Reject endpoint registration for calls that were not admitted. Legacy SDP
      registration can add mappings after hard-capacity admission rejects the
      call, creating stale associations outside `MaxCalls`
      (`internal/pkg/voip/calltracker.go`, `internal/pkg/voip/rtp.go`).
- [x] Return copies from legacy multi-call endpoint queries.
      `GetAllCallIDsForPacket` currently returns an internal mutable slice after
      releasing its read lock, allowing caller mutation and races with cleanup
      (`internal/pkg/voip/rtp.go`).
- [x] Refresh registry activity from RTP packets. The processor updates call
      activity only from SIP, so a media-active call with no recent signaling is
      timed out and loses its endpoint associations
      (`internal/pkg/voip/processor/rtp_detector.go`).
- [x] Bound media associations per call and globally. Processor, legacy, and TUI
      trackers can accumulate arbitrarily many unique endpoints for a resident
      call through repeated SDP updates (`internal/pkg/voip/processor/processor.go`,
      `internal/pkg/voip/rtp.go`, `internal/pkg/tui/call_tracker.go`).
- [x] Normalize or reject negative processor `MaxCalls` values. A negative value
      causes every inserted call to be immediately evicted while creation still
      returns state and emits lifecycle notifications
      (`internal/pkg/voip/processor/processor.go`).
- [x] Preserve selected-call policy for reassembled TCP SIP. The local TCP path
      drops non-matching in-dialog BYE, ACK, and re-INVITE messages, while the UDP
      path correctly inherits cached selection from the matched call
      (`internal/pkg/processor/source/local.go`).
- [x] Bound the local-source Call-ID-to-filter-ID cache and remove entries on
      completion, timeout, and eviction. Its current five-minute TTL permits
      burst growth and stale filter or LI attribution when a Call-ID is reused
      (`internal/pkg/processor/source/local.go`).
- [x] Permit safe Call-ID reuse in legacy session output.
      `SniffCompletionMonitor` suppresses closure scheduling for any Call-ID in
      its closed-call TTL set, so a new call reusing that ID can leave its writer
      open until shutdown (`internal/pkg/voip/sniff_completion_monitor.go`).
- [x] Make TUI endpoint associations multi-valued. Its current
      endpoint-to-single-Call-ID map overwrites an earlier B2BUA leg sharing the
      same media endpoint (`internal/pkg/tui/call_tracker.go`).
- [x] Remove TUI RTP-touch state on eviction and capture reset. `lastRTPTouch` is
      not cleared by call eviction or `Clear`, retaining Call-IDs across sessions
      (`internal/pkg/tui/call_tracker.go`).
- [x] Route complete reassembled TCP SIP events through tap's local registry.
      Tap currently registers only SDP endpoints and terminal responses; an
      SDP-less dialog is never created, and SDP-bearing calls remain `NEW` with
      incomplete identity and activity state (`internal/pkg/voip/tcp_handler_tap.go`,
      `internal/pkg/processor/source/local.go`).
- [x] Preserve final-packet writer ordering for tap TCP calls. The TCP handler
      calls `CompleteCall` before the synthesized terminal SIP packet reaches
      the packet pipeline, allowing lifecycle-driven writer closure before the
      final packet is written (`internal/pkg/voip/tcp_handler_tap.go`,
      `internal/pkg/processor/processor_packet_pipeline.go`).
- [x] Define and inject the explicit topology-aware `SelectionPolicy` contract
      described by this phase. Selection remains embedded and duplicated across
      the processor analyzer, tap TCP handler, and legacy paths
      (`internal/pkg/callregistry/call_registry.go`,
      `internal/pkg/voip/processor/sip_detector.go`).
- [x] Finish immutable configuration injection in the legacy VoIP library.
      Viper reads were removed, but production packet, TCP, plugin, security,
      and output paths still consult package-global `GetConfig()` during
      processing instead of using only construction-time snapshots
      (`internal/pkg/voip/core.go`, `internal/pkg/voip/udp.go`,
      `internal/pkg/voip/tcp_handler_local.go`,
      `internal/pkg/voip/tcp_buffer.go`,
      `internal/pkg/voip/plugin_integration.go`,
      `internal/pkg/voip/security.go`).

Audit remediation verification (2026-08-29): registry lifecycle and output
ownership are separated; processor notifications are serialized with mutation;
legacy, processor, and TUI association state is bounded and cleaned up; tap TCP
uses the shared processor registry and defers terminal completion until after
the final packet is enqueued; and a topology-aware sticky selection policy is
injected across processor, tap/local-source, and legacy paths. Construction-time
configuration snapshots now cover legacy packet-processing paths. Focused race
tests, `make test` (including LI packages), and the supported non-CUDA build
matrix pass.

Immutable-configuration follow-up (2026-08-29): TCP SIP framing now validates
Content-Length and total message size against the stream factory's injected
security configuration rather than consulting package-global configuration
during processing. A regression test changes the global configuration after
stream construction and verifies that framing behavior remains unchanged.

### Post-Audit Repair Verification (2026-08-29)

- [x] Reject legacy call admission once shutdown starts and serialize synchronous
      and accepted asynchronous write accounting with shutdown.
- [x] Make legacy timeout activity include RTP endpoint lookups even when
      per-call packet output is disabled.
- [x] Make completion-monitor cleanup generation-aware so a reused Call-ID cannot
      be closed or suppressed by an older dialog.
- [x] Carry tap TCP terminal completion through the local batch and run it only
      after processor output handling, including deterministic drop paths.
- [x] Require the session-owned TUI call aggregator in local watch bridges and
      wire it explicitly from both `watch live` and `watch file`.

Focused race tests cover legacy VoIP lifecycle, local-source callback ownership,
processor completion ordering, and TUI aggregation wiring.

Legacy lifecycle ordering follow-up (2026-08-29): legacy registry admission now
emits lifecycle start notifications regardless of packet-output configuration,
after the call is visible and without holding the registry data lock. Admission,
eviction, timeout, completion, and shutdown notifications are serialized so a
concurrent shutdown cannot emit an end before its corresponding start callback
completes. Regression tests cover registry queries from start observers and
start-before-end ordering during concurrent shutdown.

### Exit Criteria

- No package-global call tracker or `getTracker()` consumer remains.
- Analyzer state and output-resource state have separate owners.
- Call and media associations are bounded and removed deterministically.

---

## Phase 5 — Compose Shared SIP Handling

### Goal

Replace mode-specific SIP handlers with shared analysis plus explicit selection
and sink adapters.

### Processing Sequence

```text
reassembled message
  -> pure SIP parser
  -> call-selection policy
  -> call registry update
  -> typed SIP result
  -> one or more configured sinks
```

### Sinks

- CLI/session PCAP output for sniff.
- Hunter gRPC forwarding.
- Tap local injection into processor outputs.
- TUI event publication.
- Optional virtual-interface injection.

Each sink owns its queue, backpressure policy, metrics, and error handling. A
slow optional sink must not control upstream hunter flow unless it is explicitly
designated as a processor-level required sink.

### Tasks

- [ ] Implement shared SIP message orchestration over the Phase 3 and 4 contracts.
- [ ] Implement typed sink results and per-sink drop metrics.
- [ ] Preserve call-level matching for subsequent in-dialog messages.
- [ ] Preserve BYE/CANCEL handling and call completion policy explicitly.
- [ ] Preserve per-message TCP forwarding and synthesized-packet semantics.
- [ ] Migrate tap, then hunt, then sniff.
- [ ] Delete each legacy handler immediately after its consumer migrates.
- [ ] Extend the same parser/registry path to overlapping UDP SIP handling.

### Exit Criteria

- One SIP parsing/orchestration implementation serves TCP and UDP compositions.
- Mode-specific behavior is visible in policy or sink types, not handler copies.
- Distributed VoIP flows and semantic PCAP fixtures remain unchanged.

---

## Phase 6 — Migrate `sniff` and `watch`

### Goal

Retire the remaining legacy local-capture pipelines.

### Tasks

- [ ] Implement a CLI sink using existing output formatters.
- [ ] Implement a TUI event adapter using the existing `EventHandler` boundary.
- [ ] Adapt live and file capture to emit normalized envelopes.
- [ ] Migrate non-VoIP protocol subcommands incrementally.
- [ ] Migrate VoIP after the shared parser, registry, and sink path is proven by
      tap and hunt.
- [ ] Preserve file replay ordering and capture-time-based aging.
- [ ] Preserve optional PCAP and virtual-interface behavior as explicit sinks.
- [ ] Reduce the TUI bridge to capture composition and event translation.
- [ ] Delete the legacy capture loop, global completion monitor, and unused
      compatibility paths after the final consumer moves.

### Exit Criteria

- All five modes use normalized ingress and shared pipeline components.
- CLI text and TUI event fixtures match their baselines.
- The legacy VoIP capture loop and global lifecycle machinery are gone.

---

## Phase 7 — Table-Driven Command Composition

### Goal

Remove repeated protocol wiring after the stable runtime composition is known.

### Design

```go
type ProtocolSpec struct {
    Name                 string
    SupportedFilterTypes []management.FilterType
    Defaults             ProtocolDefaults
    BuildBPF             func(ProtocolConfig) (string, error)
    NewAnalyzer          func(AnalyzerConfig) (Analyzer, error)
}
```

Shared runners construct ingress, pipeline stages, and sinks from a spec. Build
tag-specific features remain behind existing tagged factories and stubs.

### Tasks

- [ ] Extract hunter configuration construction and compare generated configs
      against existing command fixtures.
- [ ] Extract shared tap runtime construction.
- [ ] Extract shared sniff runtime construction.
- [ ] Convert each protocol subcommand to flags plus a `ProtocolSpec`.
- [ ] Snapshot and compare help text, flag defaults, Viper keys, and examples.
- [ ] Keep command packages as composition roots; do not move Cobra or Viper into
      internal analyzers.

### Exit Criteria

- Protocol subcommand files primarily declare flags and protocol differences.
- Adding a protocol requires one specification, its flags, and its analyzer—not
  a separate runtime implementation for every mode.
- User-visible CLI behavior is unchanged.

---

## Phase 8 — Package and Dead-Code Cleanup

### Goal

Leave packages aligned with their responsibilities after migration.

### Tasks

- [ ] Move protocol-neutral GPU backends out of the VoIP package while preserving
      CUDA/non-CUDA build constraints.
- [ ] Move or fold generic pools into protocol-neutral owners.
- [ ] Remove orphaned buffer strategies, duplicate metrics, compatibility shims,
      and unused writer implementations.
- [ ] Verify removals with production-call searches, all build tags, and tests.
- [ ] Update architecture, command, and contributor documentation.

### Exit Criteria

- The VoIP package contains SIP/RTP/SDP analysis and integration, not generic
  runtime infrastructure.
- No dead alternate pipeline or tracker implementation remains.
- The complete build/test matrix is green.

## Sequencing

```text
Phase 0: verification baseline
   |
Phase 1: normalized contracts
   |
Phase 2: reassembly ownership
   |
Phase 3: pure SIP analysis
   |
Phase 4: call registry and lifecycle
   |
Phase 5: shared SIP orchestration
   |
Phase 6: sniff/watch migration
   |
Phase 7: command composition
   |
Phase 8: package cleanup
```

Small, isolated correctness fixes may ship at any point, but structural command
deduplication waits until the runtime composition has stabilized. This avoids
encoding transitional wiring into a long-lived command abstraction.

## Verification Required for Every Phase

- `make test`
- Dedicated LI tests
- Full supported build-tag compile and vet matrix
- Distributed hunter-to-processor integration tests
- Race tests for changed concurrent components
- Semantic CLI, TUI event, and PCAP comparisons where applicable
- Leak checks for goroutines, reassembly streams, call state, and writer handles
- Backpressure tests proving bounded queues and attributable drops
- Shutdown tests proving accepted work is drained or explicitly reported dropped

## Soak Tests

Before completing Phases 4, 5, and 6:

- Run tap VoIP for at least 24 hours on TCP-SIP-heavy traffic and verify stable
  retained heap, RSS trend, goroutine count, call count, and media associations.
- Run long-lived and port-reusing TCP flows with missing segments.
- Run hunter-to-processor capture with a deliberately slow TUI subscriber and
  verify it does not alter processor-level hunter flow control.
- Replay large PCAPs faster than wall time and verify capture-time semantics.

## Non-Goals

- Changing the gRPC protobuf protocol.
- Renaming commands, flags, configuration keys, or environment variables.
- Introducing a general plugin framework.
- Making every topology execute every stage; edge and central responsibilities
  remain explicit.
- Combining analyzer state, transport state, writer ownership, and UI state into
  one engine object.
- Changing filtering or call-selection behavior during mechanical migration.

## Success Metrics

- One normalized internal packet contract across local, file, and gRPC ingress.
- One SIP parser and metadata implementation for UDP and TCP.
- One instance-owned call registry and zero global tracker access.
- One self-owning TCP reassembly lifecycle and no open-coded flush loops.
- Explicit, bounded sink backpressure with attributable drop metrics.
- `tap` receives processor capabilities through shared composition.
- New protocol support requires an analyzer, protocol flags, and one protocol
  specification rather than per-mode runtime copies.
- Material net reduction in duplicated and unused code without increasing the
  responsibility of any single component into a pipeline-wide god object.
