# Structured Protocol Event Transport and TUI Implementation Plan

**Date:** 2026-08-30
**Status:** Phase 5 complete
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
A final offline-identity audit added the email body-preview policy to sniff's
deterministic analysis profile, preventing distinct SMTP/file event streams
from sharing a producer-session identity.
The same audit made transported TCP metadata pass through bounded reassembly
instead of bypassing it, retained analyzer hints for protocols on non-standard
ports, and ensured quitting from every TUI tab performs graceful capture and
event-pipeline shutdown.
A renewed Phase 4 audit preserved per-packet interface name and index on
transported processor/tap events and corrected TLS framing so handshake
messages split across multiple TLS records are emitted only after complete
reassembly, with the final-record capture timestamp. Regression tests and the
race-enabled event-analysis, TLS, TUI, sniff, and processor suites pass.
A subsequent local-TUI audit preserved the capture interface index at the
envelope-to-runtime boundary and removed duplicate shutdown loss reporting;
dispatcher drops are already reported exactly once through the bounded local
sink's drop-observer path.
A final cross-path equivalence audit found that transported segmented HTTP
flows retained their detector-provided connection service while locally
reassembled flows did not. Reassembly now updates the existing connection's
service without changing packet accounting, and processor, tap, sniff,
watch-live, and watch-file fixture tests assert both HTTP and connection-event
semantics. The same audit preserved explicitly configured flow and connection
timeouts when their capacity fields use runtime defaults.
A renewed lifecycle audit found that live connection expiry was still driven
only by packet arrival, so a quiet flow could remain open past its idle or
half-open timeout until another packet arrived or shutdown began. The shared
runtime now advances expiry periodically for processor, live sniff, and
watch-live sessions, while offline sniff and watch-file replay remain driven by
capture timestamps and EOF for deterministic output. A race-enabled regression
test verifies that a quiet live connection expires without another packet.
A final offline-session audit corrected watch-file identity reuse when a PCAP
changed in place or the effective BPF filter changed. Watch-file now uses the
ordered input contents and filter-aware analysis profile for deterministic
producer-session identity, sharing the content-identity helper with sniff.
Regression tests verify repeatability and distinct identities for content,
source-order, and filter changes.
A final multi-hunter isolation audit found that processor-side TCP reassembly
keyed streams only by their network tuple, allowing identical tuples from
different hunters to contribute bytes to one application stream. The shared
runtime now namespaces reassembly by capture producer/input while retaining one
globally bounded assembler and the original flow in emitted events. A regression
test interleaves segmented HTTP from two sources and verifies independent event
payloads and provenance.
A renewed implementation audit corrected four remaining parity gaps: effective
local sniff/watch filters now mark emitted events filtered and partial; mixed
scope TCP segments retain conservative provenance; application frames released
together retain their own final-byte timestamps; and close-delimited HTTP
response bodies are completed at stream close. Regression tests cover each
boundary across the shared runtime and local integration adapters.
A final bounded-state audit capped the number of active TCP application
reassembly streams and replaced the monotonically retained capture-source
namespace map with deterministic source hashing. Capacity eviction is observable
through runtime statistics, and a source/flow-churn regression test verifies
that state remains within the configured limit.
A final connection-isolation audit aligned connection tracking with TCP
reassembly by namespacing identical network tuples by capture source, interface,
and input file. Multi-interface capture and multi-file replay now emit separate
connection summaries with accurate counters and provenance.

## Phase 5 — Hunter/tap event-mode negotiation and analysis

- [x] Extend hunter registration capabilities with requested/accepted
      `packets` or `events` mode, supported event API majors and kinds, semantic
      profile revision, stateful-analysis features, sensitive enrichment, and
      resource limits.
- [x] Reject an insufficient event profile; permit explicit, visible fallback
      to packet mode only when configured.
- [x] Add `--forward-mode packets|events` and corresponding configuration to
      hunt and tap, retaining `packets` as the compatibility default.
- [x] Add a bidirectional `StreamEvents` ingestion RPC with cumulative ACK,
      NACK/gap ranges, flow control, producer session, and batch sequencing.
- [x] Add processor deduplication keyed by node ID, producer-session ID, and
      event sequence.
- [x] Implement a processor ingress WAL/spool; acknowledge the reliable profile
      only after validation, authorization, dedup registration, and recoverable
      admission.
- [x] Add an explicitly labeled memory-only profile that ACKs queue admission
      and documents processor-crash loss.
- [x] Implement a separate crash-recoverable hunter event spool with byte/age
      limits, checksummed records, cumulative-ACK deletion, and no startup
      deletion.
- [x] Default spool exhaustion to dropping oldest complete batches while
      reporting exact lost ranges; support an operator-selected `drop_new`
      policy.
- [x] Fix forwarding mode for the lifetime of a producer session; flush and
      start a new session when mode, filtering, capture scope, or analysis policy
      changes.
- [x] Run the shared stateful runtime on event-mode hunters and taps; assign
      identity before buffering and send no raw packet bytes.
- [x] Keep tap PCAP writing, rotation, per-call output, and post-write hooks
      local while forwarding only events upstream.
- [x] Report capture, analysis, queue, unsupported-kind, and transport losses
      separately in heartbeat/status output.
- [x] Test mixed packet-mode and event-mode hunters on one processor, explicit
      fallback, configuration boundaries, graceful flush, retry deduplication,
      crash recovery, spool exhaustion, and verification that event mode
      transmits no raw packet content.

**Gate:** An event-mode hunter or tap produces centrally logged and remotely
visible events equivalent to packet mode for its negotiated profile, without
forwarding packets. Reliable ingestion is at-least-once to recoverable processor
admission; sink durability remains separately observable.

### Phase 5 verification

Verified on 2026-08-31 with focused race tests for event identity, hunter
connection management, recoverable producer spools, event forwarding, processor
upstream routing, and all hunt/process/tap command paths; processor negotiation,
ingress, deduplication, WAL recovery, and clean-checkpoint tests; specialized
hunter, processor, and tap build-tag compilation; and the complete `make test`
suite including localhost gRPC integration tests outside the sandbox.
Independent cross-component audits corrected atomic memory-only admission,
durable dispatch and recovery ordering, clean WAL checkpointing, ACK-carried
flow control, recovered-spool ordering, producer-lifetime fallback pinning,
relayed-source authorization, and hierarchical tap capability negotiation.
A renewed implementation audit found and corrected spool-exhaustion deadlocks,
cross-batch event overlap, partial reliable batch admission, loss-insensitive
gap handling, clean-restart dedup state loss, and negotiation that advertised
but did not validate stateful-analysis features. Focused race tests and hunter,
processor, and tap build-tag suites pass. The audit also found that live filter
changes do not yet rotate the hunter producer session, and that capture and
unsupported-kind heartbeat counters have no production loss-boundary wiring;
those two Phase 5 tasks are therefore reopened rather than claimed complete.
A completion pass closed both reopened tasks. Effective live and reconnect-time
filter changes now quiesce capture, drain packets already admitted under the
old policy, flush and ACK-drain the old event session, apply the policy, and
install a fresh producer/runtime/stream generation. Failed boundaries stop the
hunter instead of continuing with a closed or semantically mixed pipeline.
No-op updates do not rotate. Capture-buffer overflow and unsupported transport
kinds now feed their dedicated heartbeat counters; unsupported omissions carry
exact sequence ranges, including a durable loss-only terminal batch. Queue-loss
sampling also accounts for a retiring dispatcher before session replacement.
Focused race tests cover policy coordination, reconnect filtering, producer
rotation, capture-loss delta sampling, terminal unsupported loss, loss-only
ingress high-water advancement, and the complete hunter/processor/tap command
paths. Phase 5 is complete.
A renewed independent audit corrected accepted-profile validation on the hunter,
loss-only event high-water restoration in both producer and processor recovery,
and WAL replay under a configured batch limit above the default. Reliable ingress
now distinguishes durably admitted batches from batches actually queued for
delivery, so clean shutdown retains an ACKed but undispatched record for recovery
instead of checkpointing it away. Regression tests also explicitly cover mixed
packet/event hunter registration and verify that the event transport schema has
no raw-byte field.
A final spool durability audit corrected `drop_oldest` replacement ordering. The
replacement batch and its exact loss ranges are now published and synced before
any superseded durable record is deleted, so a replacement write failure cannot
silently erase both the old data and its loss report. A regression test verifies
that the original record survives that failure boundary.
A renewed Phase 5 audit corrected three remaining boundaries. Processor event
ingress is now authorized against the forwarding mode, API major, event kinds,
and semantic profile actually accepted during hunter registration, including
replacement on re-registration. Processor WAL recovery truncates an incomplete
final record while retaining earlier durable admissions, and failed appends roll
back to their previous durable offset. Finally, the first processor-provided BPF
policy now quiesces the hunter's provisional capture, discards pre-policy
packets, and restarts capture with the accepted filter before forwarding begins.
Focused regressions, the race-enabled Phase 5 package suite, and hunter,
processor, and tap specialized-build compilation pass.
A final cross-component audit corrected accepted-profile validation for
hierarchical processor/tap forwarding, revalidates producer and relay
authorization for every ingress batch after re-registration, and preserves
processor flow-control state on duplicate ACK and gap NACK responses. Explicit
tap packet fallback now completes initial upstream negotiation before local
capture starts, preventing pre-negotiation events from being stranded or later
replayed across the forwarding-mode boundary.
A 2026-08-31 implementation audit corrected three additional defects: authenticated
event ingestion now authorizes hunter credentials, repeated producer-spool
eviction preserves inherited and loss-only exact gap records, and hierarchical
event routing flushes terminal unsupported-kind losses. The same audit found
that effective live tap filter changes still do not quiesce and drain capture,
flush/reset analysis, ACK-drain the old upstream route, and rotate the producer
session transactionally. The producer-session lifetime task and Phase 5 status
are therefore reopened until that coordinated tap boundary is implemented.
A completion pass added that boundary. Effective tap policy mutations now
serialize, quiesce capture, drain capture workers and processor admission,
flush/reset stateful analysis, flush and cumulatively ACK-drain the old
upstream route, rotate producer identity, apply the new BPF and application
policy, and resume with a fresh capture generation. Effective no-op mutations
do not rotate. Local filter state is staged and cloned, commits only after
successful reconciliation, and failed boundaries stop the tap rather than
continuing with mixed semantics. Focused race tests cover source draining,
transaction rollback and no-op behavior, producer rotation, and upstream route
retirement; processor and tap suites pass.
A final processor-ingress audit replaced delimiter-concatenated deduplication
keys with typed producer identity keys and a versioned, collision-free WAL
checkpoint representation that migrates legacy checkpoints. It also made exact
gap coverage independent of the order of loss records. Regression tests cover
identities containing delimiter bytes and valid loss ranges reported in
non-global order.
A renewed status-path audit found that the five event-loss counters emitted in
hunter heartbeats were discarded from processor state and consequently reported
as zero by hunter status and topology responses. Processor hunter state now
preserves capture, analysis, queue, unsupported-kind, and transport losses and
projects them through both management responses. Focused race tests cover the
heartbeat, status, and topology paths.
A final durable-routing audit replaced lossy filesystem sanitization and
delimiter-concatenated in-memory keys for hierarchical event routes. Distinct
valid producer identities now use typed route keys and fixed-length,
identity-derived spool path components, so punctuation collisions cannot make
one producer reject or share another producer's recoverable spool. A restart
regression covers identities that previously mapped to the same directory.
A final receiver-boundary audit made packet ingestion enforce the forwarding
mode accepted at registration. Packet streams now require a current packet-mode
hunter registration, pin the exact registration for the stream lifetime, and
fail if the producer identity changes or the hunter re-registers. This prevents
an event-mode producer from also supplying raw packets through the legacy data
RPC and preserves one canonical event stream per producer session.
A renewed memory-only recovery audit found that a processor restart discarded
its ingress high-water marks after the hunter had already deleted cumulatively
ACKed batches. The fresh processor therefore NACKed an unrecoverable prefix and
wedged that producer session. Memory-only ingress now treats the first retained
batch of an unknown session as its post-restart baseline while keeping all
subsequent gap checks strict; reliable ingress remains WAL-backed and strict.
A race-enabled regression covers restart recovery and post-baseline NACKs.

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
