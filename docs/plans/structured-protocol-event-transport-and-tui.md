# Structured Protocol Event Transport and TUI Implementation Plan

**Date:** 2026-08-30
**Status:** Phase 4 complete
**Research:**
[`structured-protocol-event-transport.md`](../research/structured-protocol-event-transport.md),
[`tui-structured-protocol-events.md`](../research/tui-structured-protocol-events.md),
[`zeek-log-expansion-assessment.md`](../research/zeek-log-expansion-assessment.md)

## Objective

Create one versioned protobuf contract for normalized protocol events, expose
processor events in a common TUI Events view, then add negotiated event-only
forwarding from hunters and taps. Keep packet and event forwarding mutually
exclusive per producer session.

## Required invariants

- [ ] Reuse the effective hunter, processor, or tap ID as the producer node ID.
- [ ] Identify events by node ID, producer-session ID, and per-event sequence;
      preserve identity through retry, relay, and fan-out.
- [ ] Keep normalized events output-neutral; protobuf, TUI, logstream, and LI
      are projections or consumers of the same immutable event.
- [ ] Keep packet mode processor-authoritative and event mode edge-authoritative;
      never derive two canonical event streams for one producer session.
- [ ] Keep TUI delivery bounded and best-effort so it cannot affect capture,
      hunter flow control, structured logs, LI, or other subscribers.
- [ ] Exclude file content from the generic event transport and TUI view.
- [ ] Add future event kinds as typed protobuf alternatives; do not use generic
      maps or speculative placeholder messages.

## Phase 1 — Event identity and protobuf contract

- [x] Add event identity and producer-session metadata to
      `internal/pkg/events.Envelope`, with constructors that assign identity
      before dispatcher enqueue.
- [x] Define deterministic session and ordering rules for offline PCAP analysis;
      use random session IDs for live nodes.
- [x] Add `api/proto/events/v1/events.proto` with a versioned
      `lippycat.events.v1` package containing:
  - [x] common envelope, flow, provenance, capture-scope, and loss types;
  - [x] typed conn, DNS, TLS, HTTP, SMTP, and file-metadata payloads;
  - [x] `ProtocolEvent` with a typed `oneof`;
  - [x] event batches with producer session, batch sequence, first/last event
        sequence, and loss counters; and
  - [x] subscription request/control messages that support event-kind and node
        constraints.
- [x] Update protobuf generation without renaming the existing unversioned
      `data` and `management` APIs.
- [x] Add strict adapters between protobuf values and every supported
      `events.Event` type; validate addresses, ports, timestamps, identity,
      collection sizes, and content policy.
- [x] Preserve unknown protobuf fields and report unsupported `oneof` kinds as
      compatibility omissions rather than failing an entire stream.
- [x] Add round-trip, malformed-input, unknown-field, and mixed-capability tests.

**Gate:** Every current metadata event round-trips without semantic loss, and
the contract contains no TUI layout or log-rendering fields.

### Phase 1 verification

Re-audited against the implementation on 2026-08-30. The audit corrected
pointer-event adapter coverage, typed-nil handling, canonical event-ID
validation, envelope validation for compatibility omissions, admission-grade
batch member validation, source-consistent loss accounting, and recursive
unknown-field admission bounds for nested event and batch messages. Focused
race tests and the full `make test` suite pass. A subsequent independent audit
also corrected count-only loss validation and ensured tap-local events use the
effective tap ID as producer identity while retaining the local capture source
in provenance. The final implementation audit extended that normalization to
connection events, ensuring all event kinds from one tap share a producer
session and carry consistent capture-source provenance.
This audit also wired deterministic offline sessions into actual PCAP sniff
production and rejected loss ranges that contradict delivered events or overlap
across loss records.
A final replay audit made connection expiry, shutdown, and equal-age eviction
ordering deterministic so offline event IDs remain stable, and rejected valid
protobuf durations that cannot be represented by Go without saturation.
This assessment also tightened unsupported-kind detection so scalar unknown
protobuf fields cannot substitute for a missing typed event payload.

## Phase 2 — Processor event subscription

- [x] Add an event broadcaster sink with an independent bounded queue per
      subscriber and counters for subscriber drops.
- [x] Register the broadcaster before the processor dispatcher starts and keep
      normalized event generation active even when file logging is disabled or
      no TUI is connected.
- [x] Add a dedicated event service with a server-streaming `SubscribeEvents`
      RPC using the Phase 1 messages.
- [x] Make subscription version 1 live-only; send a stream ID, live boundary,
      monotonic delivery sequence, and explicit overflow/reconnect gaps.
- [x] Apply server-side authentication, authorization, event-kind/node filters,
      sensitive-field projection, and message-size limits.
- [x] Exclude `FileContentEvent` and unauthorized optional HTTP, SMTP, and file
      fields before enqueueing subscriber batches.
- [x] Register the service in processor and tap builds without changing packet
      subscription behavior.
- [x] Test multiple subscribers, slow-client isolation, disconnect cleanup,
      authorization, loss reporting, and operation with structured logs off.

**Gate:** A processor event can be streamed, decoded to an equivalent typed
event, and consumed without affecting packet processing or another sink.

### Phase 2 verification

Verified on 2026-08-30 with protobuf regeneration, focused event-service and
broadcaster race tests, complete processor and tap build-tag suites, and the
full `make test` suite. The implementation uses independent bounded subscriber
queues, reports subscriber overflow and reconnect boundaries explicitly,
applies authentication and conservative field projection before serialization,
and keeps normalized event production active without structured log output.
An independent follow-up audit corrected the admission boundary so it is
captured atomically with broadcaster registration, ensured sustained
cross-producer delivery cannot starve overflow-gap reporting, and excluded the
best-effort broadcaster sink queue from hunter flow-control pressure.
A later dispatcher-boundary audit corrected a silent-loss path: when the
bounded dispatcher queue feeding the broadcaster overflows, the broadcaster
now records the dropped event for every matching subscriber so the event
service emits an explicit subscriber gap instead of only incrementing a global
sink-drop counter.
A final independent audit extended that correction to the dispatcher's main
admission queue, where rejected events already had delivery identity but were
not reported to matching subscribers. It also bounded and validated event
subscription node selectors before allocating server-side filter maps.
A renewed implementation audit bounded both detailed overflow ranges and
producer-session loss records, preserved producer-session identity in gap
reports, moved dispatcher shutdown after packet-producer quiescence, and
decoupled HTTP file-metadata generation from structured-log output. Focused
race tests cover each corrected boundary.
A final message-boundary audit split accumulated subscriber-loss reports across
bounded GAP controls so a valid small receive limit cannot turn a reportable
overflow into a `ResourceExhausted` stream termination. If one detailed loss
record alone cannot fit, the stream retains its explicit loss kind and count in
a bounded summary.
A renewed audit corrected three remaining boundaries: filtered events with
non-contiguous producer sequences are now split into separate valid batches;
oversized-event omission reports preserve producer-session identity when it
fits and use the bounded GAP path; and failed processor/tap startup now rolls
back the event dispatcher, broadcaster, listener, and other started resources.
A subsequent independent audit bounded the reconnect stream identifier before
subscriber admission and sorted and merged dispatcher-loss ranges that can
arrive out of event-sequence order from separate queue-overflow boundaries.
A final live-boundary audit timestamped dispatcher drop decisions and excludes
notifications for drops that predate subscriber admission, preventing a new
live-only stream from reporting historical overflow during a registration race.
A renewed end-to-end audit propagated dispatcher admission time through
successful sink delivery as well as drop reporting, preventing queued
pre-admission events from leaking into a live-only stream. It also bounded
reconnect-gap metadata to the negotiated message size and made packet and event
subscriptions share the configured maximum-subscriber limit.
An implementation reachability audit found that the conservative sensitive-field
and file-metadata authorization policy could only be enabled by unit tests. The
processor and every tap command path now expose explicit, default-deny flags and
configuration keys for those permissions, while file content remains excluded.
A follow-up configuration audit bound those flags to their Viper keys so explicit
CLI authorization reliably takes precedence over configured default-deny values.
A final processor-provenance audit made the `processor_node_ids` subscription
selector reachable for real processor and tap events by recording the effective
handling processor ID in every locally produced event envelope.
A renewed independent audit corrected two bounded-loss edge cases: catch-all
loss records no longer attribute losses from multiple producer sessions to the
first overflow producer, and reconnect GAP controls omit an oversized processor
identity when necessary to honor the subscriber's negotiated message limit.

## Phase 3 — Common TUI Events view and remote delivery

- [x] Add a bounded `EventStore` with stable event-ID selection, arrival
      sequence, capture timestamp, per-kind/source projections, pause/reset
      behavior, eviction counters, and transport-loss counters.
- [x] Add a generic Events component with a compact timeline and sanitized,
      bounded details for all Phase 1 event kinds.
- [x] Derive canonical field names and types from `internal/pkg/logschema` while
      keeping TUI summary and layout logic separate.
- [x] Add `EventBatchMsg` and a focused event callback to the TUI/remotecapture
      bridge without coupling normalized events to packet display types.
- [x] Extend the remote client to negotiate and consume `SubscribeEvents`, and
      surface incompatible kinds, reconnect gaps, and subscriber drops.
- [x] Add Events to Capture-tab view cycling:
  - [x] `p` changes traffic/protocol scope;
  - [x] `v` changes Packets, Events, or an available specialized view;
  - [x] exact event-kind filtering is used initially; and
  - [x] the Events view is preserved across compatible scope changes.
- [x] Add event details, navigation, filtering entry points, contextual footer
      help, and a clear message when related packets are no longer buffered.
- [x] Keep existing Calls and protocol-specific views until separate parity
      decisions are made.
- [x] Test selection across append/eviction, narrow layouts, sanitization,
      filtering, pause/reset, reconnect, and local-versus-remote decoding parity.

**Gate:** `lc watch remote` can browse live processor events without requiring
`--log-dir`; packet and call views remain unchanged.

### Phase 3 verification

Verified on 2026-08-30 with focused EventStore, Events component, remote-client,
and TUI integration race tests; TUI, processor, and tap build-tag suites; and
the full `make test` suite including localhost integration tests outside the
sandbox. The remote event subscription is independent of packet delivery and
legacy servers, decodes through the shared protobuf adapter, validates stream
identity and delivery ordering, preserves reconnect cursors, and exposes
subscriber, reconnect, transport, and compatibility gaps. The bounded Events
view retains stable event-ID selection, exact kind/source projections,
sanitized `logschema`-derived details for every metadata event kind, contextual
navigation and view cycling, and an explicit related-packet eviction notice.

## Phase 4 — Shared stateful event-analysis runtime and local TUI parity

- [x] Extract a reusable normalized-event analysis runtime from processor-owned
      flow tracking and protocol event mapping into an internal package with no
      command or UI dependencies.
- [x] Give the runtime explicit source provenance, capture clock, reset,
      timeout/expiry, shutdown, EOF flush, partial-flow, and drop semantics.
- [x] Reuse existing protocol analyzers and reassembly; do not introduce a
      second DNS, TLS, HTTP, SMTP, or file parser for the TUI.
- [x] Migrate processor, tap, and sniff event production to the shared runtime
      without changing structured-log output.
- [x] Feed `watch live` events from the shared runtime into the common
      `EventStore` through a bounded local sink.
- [x] Feed `watch file` through the same runtime, preserving capture timestamps,
      deterministic ordering, source-file provenance, EOF flush, and reset when
      inputs change.
- [x] Add fixture equivalence tests across processor, tap, sniff, live-watch,
      and file-watch paths.
- [x] Add EOF, mid-flow input, timeout, restart, queue-pressure, and graceful
      shutdown tests.

**Gate:** The same packet fixture produces equivalent normalized events in all
local and processor analysis paths, subject only to documented source metadata.

### Phase 4 verification

Verified on 2026-08-30 with shared-runtime lifecycle and mapping tests,
processor/tap adapter tests, sniff-without-log-output tests, local live/file TUI
bridge tests, exact multi-file provenance tests, ordered-replay cancellation
tests, and bounded delivery pressure tests. Independent audits corrected
specialized TUI build tags, zero capture timestamps, out-of-order batch expiry,
runtime parser locking, partial-batch error reporting, same-basename source-file
identity, restart and replay cancellation deadlocks, local/remote timeline
mixing, and silent dispatcher-level TUI loss. Focused race tests, specialized
`cli`, `tui`, `processor`, and `tap` build-tag suites, and the complete
`make test` suite (including localhost integration tests outside the sandbox)
pass.
An implementation follow-up corrected the remaining local parity gap for
stateful application protocols: the shared runtime now feeds raw TCP through
the project's bounded connection-aware reassembler and frames complete HTTP,
TLS, and SMTP messages before invoking the existing semantic parsers. Events
retain final-byte capture timestamps and source provenance, while mid-flow or
gapped streams are partial and incomplete or oversized framing stays bounded.
A shared segmented HTTP fixture now verifies equivalent normalized output at
the processor, tap-local, sniff, watch-live, and watch-file composition
boundaries, subject only to their documented provenance differences.
A renewed implementation audit corrected full-capture TCP provenance: the
shared runtime now admits payload-free SYN, FIN, and RST packets to reassembly,
so complete HTTP, TLS, and SMTP streams are not incorrectly marked partial
merely because their opening SYN carried no application payload. A shared
segmented-protocol regression test covers all three protocols.
A 2026-08-31 lifecycle audit corrected two remaining failure paths: stopping a
paused local capture now resumes its bridge before waiting, allowing EOF and
dispatcher draining during restart or mode changes; and failure to initialize
sniff's auxiliary normalized-event analysis no longer suppresses the primary
packet capture/output callback. Race-enabled Phase 4 package tests and the
processor integration suite pass.
A 2026-08-31 renewed runtime audit corrected three stateful-protocol parity
gaps: filter-derived capture scope and partial state now survive TCP
reassembly; chunked HTTP responses wait for and decode the complete bounded
body before event and file analysis; and SMTP DATA bodies now feed bounded
attachment analysis when body preview is explicitly enabled. Sniff also passes
its existing email-body-preview setting into the shared runtime. Regression
tests cover filtered segmented HTTP, chunked final-byte timing, and SMTP
attachment metadata, and the Phase 4 race-enabled package tests pass.

## Phase 5 — Hunter/tap event-mode negotiation and analysis

- [ ] Extend hunter registration capabilities with requested/accepted
      `packets` or `events` mode, supported event API majors and kinds, semantic
      profile revision, stateful-analysis features, sensitive enrichment, and
      resource limits.
- [ ] Reject an insufficient event profile; permit explicit, visible fallback
      to packet mode only when configured.
- [ ] Add `--forward-mode packets|events` and corresponding configuration to
      hunt and tap, retaining `packets` as the compatibility default.
- [ ] Add a bidirectional `StreamEvents` ingestion RPC with cumulative ACK,
      NACK/gap ranges, flow control, producer session, and batch sequencing.
- [ ] Add processor deduplication keyed by node ID, producer-session ID, and
      event sequence.
- [ ] Implement a processor ingress WAL/spool; acknowledge the reliable profile
      only after validation, authorization, dedup registration, and recoverable
      admission.
- [ ] Add an explicitly labeled memory-only profile that ACKs queue admission
      and documents processor-crash loss.
- [ ] Implement a separate crash-recoverable hunter event spool with byte/age
      limits, checksummed records, cumulative-ACK deletion, and no startup
      deletion.
- [ ] Default spool exhaustion to dropping oldest complete batches while
      reporting exact lost ranges; support an operator-selected `drop_new`
      policy.
- [ ] Fix forwarding mode for the lifetime of a producer session; flush and
      start a new session when mode, filtering, capture scope, or analysis policy
      changes.
- [ ] Run the shared stateful runtime on event-mode hunters and taps; assign
      identity before buffering and send no raw packet bytes.
- [ ] Keep tap PCAP writing, rotation, per-call output, and post-write hooks
      local while forwarding only events upstream.
- [ ] Report capture, analysis, queue, unsupported-kind, and transport losses
      separately in heartbeat/status output.
- [ ] Test mixed packet-mode and event-mode hunters on one processor, explicit
      fallback, configuration boundaries, graceful flush, retry deduplication,
      crash recovery, spool exhaustion, and verification that event mode
      transmits no raw packet content.

**Gate:** An event-mode hunter or tap produces centrally logged and remotely
visible events equivalent to packet mode for its negotiated profile, without
forwarding packets. Reliable ingestion is at-least-once to recoverable processor
admission; sink durability remains separately observable.

## Phase 6 — Documentation, compatibility, and release verification

- [ ] Document forwarding modes, feature loss in event mode, tap-based local
      evidence retention, security/privacy controls, and compatibility fallback.
- [ ] Document that TUI subscription v1 is live-only and distinguish transport
      gaps from normal local ring eviction.
- [ ] Update command references, configuration examples, manual architecture,
      structured-log documentation, and operational procedures.
- [ ] Add compatibility tests for old packet-only hunters/processors and newer
      event-capable nodes.
- [ ] Run formatting before staging, then run the relevant unit, integration,
      race, build-tag, and full test suites.
- [ ] Check off only verified tasks in this plan and commit the implementation,
      generated protobuf code, documentation, and completed plan together.

## Deferred work

- [ ] Add bounded TUI reconnect catch-up only after live-only subscription use
      demonstrates a requirement.
- [ ] Add typed DHCP, NTP, SSH, FTP, PostgreSQL, QUIC, tunnel, inventory, notice,
      and diagnostic events incrementally with their analyzers and log schemas.
- [ ] Evaluate cross-sensor observation identity only with protocol-specific
      equivalence rules; version 1 deduplicates retries only.
- [ ] Add hierarchical processor event relay with immutable origin identity,
      per-hop WAL/ACK/dedup, appended hop provenance, and existing
      `terminal|all|none` emission semantics.
- [ ] Consider a prospective evidence-capture RPC only when an event-mode hunter
      must provide packets and deployment as a tap is not possible.
