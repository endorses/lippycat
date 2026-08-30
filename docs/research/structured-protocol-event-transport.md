# Structured Protocol Event Transport

**Date:** 2026-08-30

**Status:** Proposed design

**Decision:** Define one versioned, typed protobuf representation of normalized
protocol events and reuse it across distinct transport roles. Implement
processor-to-TUI subscription first, then add an event-only hunter forwarding
mode after the shared stateful analysis runtime is suitable for execution on
hunter nodes.

## Executive summary

lippycat currently sends filtered packet batches from hunters to processors.
Each packet contains raw bytes and may also contain protocol metadata produced
by hunter-side analysis. The processor remains the canonical event authority:
it tracks connections, maps protocol metadata into `internal/pkg/events`, and
dispatches normalized events to structured logs and other sinks.

The proposed TUI Events view also needs a protobuf representation of those
normalized events so a remote TUI can subscribe to the processor event stream.
That wire model should not be designed as a TUI-specific projection. It should
be the common event contract for:

- processor-to-TUI best-effort event subscription;
- future hunter-to-processor event ingestion;
- possible processor-to-processor event forwarding; and
- other typed event consumers that must not depend on TSV or JSONL rendering.

The event payload can be shared, but delivery semantics must remain separate.
Hunter ingestion needs acknowledgement, sequencing, buffering, and flow
control. TUI delivery needs isolated bounded queues and must never influence
hunter flow control or durable sinks.

Distributed capture should initially expose two mutually exclusive forwarding
modes:

| Mode | Canonical event authority | Hunter sends packets | Hunter sends events |
|------|---------------------------|----------------------|---------------------|
| `packets` | Processor | Yes | No |
| `events` | Hunter | No | Yes |

There is no general-purpose hybrid mode in the initial design. Sending both all
packets and their derived events is redundant and creates ambiguous ownership,
deduplication, and consistency behavior. Selective packet escalation can be
designed later as a separate evidence-capture feature.

## 1. Current architecture

The existing distributed data service transports `PacketBatch` messages:

```text
hunter capture
  -> filter
  -> edge detection and analysis
  -> raw CapturedPacket + optional PacketMetadata
  -> StreamPackets
  -> processor packet pipeline
  -> normalized events.Event
  -> logstream, LI metadata, and future TUI event consumers
```

The protobuf `CapturedPacket.data` field carries raw packet bytes. Its metadata
field can carry DNS, TLS, HTTP, email, SIP, RTP, and other analysis results, but
there is no normalized event message or event ingestion RPC today.

At the processor, `processBatch` performs processor-owned lifecycle work before
dispatching events. This includes connection tracking and protocol event
mapping. Therefore current hunter-provided metadata is an analysis input, not a
separate canonical event stream.

## 2. Goals

- Preserve one normalized semantic model across logs, TUI, LI projections, and
  distributed event forwarding.
- Avoid transmitting rendered TSV or JSONL as an internal protocol.
- Allow event-only deployments to avoid raw-packet bandwidth when packet
  evidence and processor-side reanalysis are not required.
- Preserve source, flow, event identity, capture scope, partial state, schema
  compatibility, and observable loss.
- Keep ingestion reliability independent from interactive subscription
  backpressure.
- Support multiple hunters and leave room for explicit hierarchical processor
  ownership.
- Make packet and event forwarding authority unambiguous.

## 3. Non-goals

- Replacing the structured log schema with a protobuf schema. The protobuf is a
  typed transport representation; `internal/pkg/logschema` remains the output
  field and type contract.
- Transporting rendered log records.
- Making TUI delivery durable or allowing a slow TUI to throttle capture.
- Sending file content through the generic metadata event stream.
- Introducing a mode that always sends both packets and their derived events.
- Guaranteeing cross-sensor deduplication without an explicit observation
  identity and ownership policy.

## 4. One event model, separate transport roles

```text
Hunter                              Processor                         TUI
------                              ---------                         ---
stateful analysis                   validate/decode                   decode
      |                                   |                              |
ProtocolEventBatch --ingestion----> events.Event --subscription------> EventStore
                                          |
                                          |-- structured logs
                                          |-- authorized LI metadata
                                          `-- event-derived statistics
```

The common protobuf types should describe event meaning. RPC-specific request,
control, acknowledgement, replay, and authorization messages should describe
delivery behavior.

### 4.1 Hunter-to-processor ingestion

Event ingestion is part of the capture data plane. It needs:

- bidirectional streaming;
- monotonically increasing batch sequences within a stream session;
- explicit stream or producer-session identity;
- acknowledgements and gap detection;
- bounded in-memory and optional disk buffering;
- reconnect behavior that does not silently duplicate records;
- processor flow control independent of TUI subscriber pressure;
- schema and capability negotiation; and
- drop and analysis-loss reporting.

### 4.2 Processor-to-TUI subscription

Interactive subscription is a bounded, best-effort fan-out. It needs:

- independent per-subscriber queues;
- server-side kind, node, and authorization filtering;
- explicit indication of subscription overflow and reconnect gaps;
- optional bounded replay as a separately defined capability; and
- no effect on event ingestion, logs, LI, other subscribers, or packet flow
  control.

### 4.3 Processor-to-processor forwarding

Hierarchical event forwarding should not be inferred automatically from the
other two roles. Before enabling it, define:

- which processor owns event generation;
- whether intermediate processors dispatch or merely relay events;
- how event provenance accumulates without replacing the originating node;
- how retransmission and duplicate suppression work across hops; and
- whether terminal/all/none emission policy applies to received events exactly
  as it does to locally derived events.

The safest initial hierarchy rule is single analysis ownership: a packet-mode
path derives events at its designated processor, while an event-mode path keeps
the originating hunter as event authority. Downstream processors must not
derive a second event stream from the same observation.

## 5. Canonical protobuf model

The exact field numbering requires an implementation review, but the semantic
shape should be similar to:

```protobuf
message ProtocolEvent {
  string event_id = 1;
  uint64 event_sequence = 2;
  EventEnvelope envelope = 3;

  oneof payload {
    ConnEvent conn = 10;
    DNSEvent dns = 11;
    TLSEvent tls = 12;
    HTTPEvent http = 13;
    SMTPEvent smtp = 14;
    FileMetadataEvent file = 15;
  }
}

message EventEnvelope {
  google.protobuf.Timestamp timestamp = 1;
  string uid = 2;
  string community_id = 3;
  string node_id = 4;
  FlowTuple flow = 5;
  CaptureScope capture_scope = 6;
  bool partial = 7;
  SourceProvenance provenance = 8;
}

message ProtocolEventBatch {
  string source_node_id = 1;
  string producer_session_id = 2;
  uint64 sequence = 3;
  repeated ProtocolEvent events = 4;
  EventBatchStats stats = 5;
  uint32 semantic_profile_revision = 6;
}
```

Typed `oneof` payloads are preferable to maps, arbitrary JSON, serialized Go
interfaces, or rendered log lines. They preserve types, allow generated
compatibility behavior, and make authorization and validation explicit.

The protobuf model must round-trip every supported `events.Event` value without
changing the event observed by other dispatcher sinks. It should not encode
TUI summaries, table layouts, log rotation state, or TSV formatting.

## 6. Event identity

Every event needs an explicit identity from the first wire version. Flow UID
and Community ID identify flows, not individual transactions or connection
lifecycle records.

Event identity is needed for:

- stable TUI selection;
- retransmission without duplicate logging;
- reconnect cursors or bounded replay;
- related-event navigation;
- deterministic tests; and
- possible hierarchical duplicate suppression.

One identifier may not solve both delivery deduplication and cross-sensor
observation deduplication. The design should distinguish:

- `event_id`: unique identity of the produced event, stable across retries; and
- a future deterministic observation identity or fingerprint used only when
  equivalent observations from different sensors can be defined soundly.

Do not derive either identity informally from Community ID alone.

## 7. Packet mode and event mode

### 7.1 Packet mode

Packet mode preserves current behavior:

```text
hunter -> filtered raw packets + analysis metadata -> processor -> events
```

The processor owns canonical event generation even when hunter metadata avoids
some repeated parsing. This mode supports central PCAP output, processor-side
enrichment, packet-level TUI views, later reanalysis, content workflows, and LI
content delivery where authorized.

### 7.2 Event mode

Event mode changes analysis ownership:

```text
hunter -> normalized typed events -> processor dispatcher -> sinks
```

The hunter sends no raw packet bytes on the event stream. The processor must
not independently derive duplicate events for that source/session. Features
requiring packet content are unavailable unless a separate packet evidence
workflow is explicitly configured.

Event mode should be negotiated during registration. Negotiation should cover:

- requested and accepted forwarding mode;
- supported event schema versions and kinds;
- analysis capabilities and optional enrichments;
- sensitive-field policy;
- maximum batch sizes and buffering behavior; and
- fallback behavior when there is no compatible event schema.

Fallback to packet mode must be explicit and observable. A node must not
silently claim event mode while omitting event kinds it cannot produce.

### 7.3 Why there is no initial hybrid mode

If a hunter forwards the complete packet stream, the processor can produce the
events. Sending both representations wastes bandwidth and raises questions
about which copy is canonical.

Selective evidence escalation may eventually send packets for particular
flows while ordinary traffic remains event-only. That feature needs its own
flow-lifecycle and authority rules because changing analysis authority halfway
through a stateful flow produces partial histories. It should not block the
initial two-mode design.

## 8. Hunter analysis requirements

Event-only forwarding is safe only when the hunter runs the complete shared
stateful normalized-event analysis runtime. Reusing event constructors is not
enough. The runtime must cover:

- connection tracking, expiry, and shutdown flushing;
- DNS query/response correlation and RTT;
- TCP reassembly where required;
- HTTP and SMTP transaction/session state;
- TLS handshake correlation;
- file observation and bounded hashing when configured;
- capture timestamps rather than forwarding wall-clock time;
- mid-flow startup and partial-capture semantics; and
- bounded queues with observable packet and event loss.

Expensive or sensitive enrichments remain capability-, configuration-, and
authorization-driven. Event-only mode does not imply HTTP header collection,
email body preview, file extraction, or content delivery.

## 9. Completeness and loss semantics

Central logs can appear authoritative even when an upstream hunter lost packets
or events. The protocol must make incompleteness observable.

At minimum, report:

- batch sequence and producer session;
- capture scope and per-event `partial` state;
- packets dropped before analysis;
- events dropped at analysis or dispatcher ingress;
- batches discarded because memory and disk buffers were exhausted;
- reconnect gaps and retransmitted ranges; and
- unsupported or policy-omitted event kinds and fields.

Normal TUI ring eviction is separate from transport loss. Subscriber overflow
is also separate from hunter ingestion loss. These counters must not be merged
into a single ambiguous drop total.

## 10. Security and authorization

Normalized events can contain sensitive DNS names, HTTP paths and headers,
email addresses and subjects, file metadata, and fingerprints. Event transport
requires explicit authentication and authorization even though it contains no
raw packet bytes.

The generic event schema should carry `FileMetadataEvent` only when permitted.
`FileContentEvent` and extracted content should remain outside generic event
subscription and ingestion unless a separate content workflow is designed.

Authorization must be applied server-side for TUI subscriptions. Hunter event
ingestion must validate that the registered node is permitted to submit the
claimed source identity and event kinds. All received strings and collections
require size bounds and validation before storage or display.

## 11. Proposed RPC roles

Conceptually:

```protobuf
service DataService {
  rpc StreamPackets(stream PacketBatch)
      returns (stream StreamControl);

  rpc StreamEvents(stream ProtocolEventBatch)
      returns (stream EventStreamControl);

  rpc SubscribeEvents(EventSubscribeRequest)
      returns (stream ProtocolEventBatch);
}
```

`StreamEvents` and `SubscribeEvents` reuse the event payload but not their
control plane. If remote TUI delivery is later combined with an existing
multiplexed stream, the common event messages remain reusable.

## 12. Implementation order

### Phase 1: Wire contract and identity

1. Define event identity semantics in `internal/pkg/events`.
2. Define versioned protobuf envelope, payload, and batch messages.
3. Add strict protobuf-to-event and event-to-protobuf adapters.
4. Add round-trip tests for every event kind, optional field, collection,
   timestamp, provenance value, and compatibility case.

The messages must remain transport-neutral. Do not add presentation fields only
because the first consumer is the TUI.

### Phase 2: Processor-to-TUI subscription

1. Register a permanent bounded event broadcaster with the processor
   dispatcher.
2. Add independently buffered subscriber queues and authorization filtering.
3. Add `SubscribeEvents` with sequencing and loss reporting.
4. Decode events into the common TUI `EventStore` described by the TUI research.
5. Verify that TUI pressure cannot affect logs, LI, packet processing, or other
   subscribers.

This phase is first because the processor already produces canonical events. It
validates the wire schema without moving analysis ownership or risking central
log completeness.

### Phase 3: Shared stateful analysis runtime

1. Consolidate event generation used by processor, tap, sniff, and local/file
   watch modes.
2. Make source clocks, EOF/shutdown, expiry, reset, and partial semantics
   explicit.
3. Prove equivalent event output from common packet fixtures.
4. Make the runtime usable by a hunter without importing command or processor
   presentation concerns.

### Phase 4: Hunter event ingestion

1. Add registration capability and forwarding-mode negotiation.
2. Add `StreamEvents`, acknowledgement, flow control, and sequence validation.
3. Reuse or adapt hunter memory/disk buffering without confusing packet and
   event checkpoints.
4. Route decoded events into the processor dispatcher without re-derivation.
5. Expose source loss, restart, incompatibility, and fallback state.
6. Test reconnect, duplicate retry, overload, mixed packet-mode/event-mode
   hunters, and graceful shutdown.

### Phase 5: Hierarchies and selective evidence

1. Define event ownership and relay semantics across processor levels.
2. Add provenance and duplicate-handling tests.
3. Evaluate bounded replay for operational consumers.
4. Research selective raw-packet evidence capture independently from forwarding
   mode.

## 13. Testing strategy

### Wire contract

- every normalized event kind round-trips without semantic loss;
- unknown fields and newer event variants follow documented compatibility
  behavior;
- invalid addresses, ports, timestamps, identifiers, oversized fields, and
  disallowed content are rejected safely;
- event IDs remain stable across encode, retry, decode, and fan-out.

### TUI subscription

- slow clients do not block dispatcher sinks or other clients;
- subscription overflow and reconnect gaps reach the client;
- authorization removes event kinds and fields server-side;
- decoded local and remote events behave identically in the TUI store.

### Hunter ingestion

- event-only mode transmits no raw packet bytes;
- packet mode transmits no separate normalized event stream;
- the same fixture produces equivalent normalized events in processor-owned and
  hunter-owned analysis modes, subject to declared capabilities;
- retry does not duplicate central log records;
- gaps and upstream packet loss are visible;
- graceful shutdown flushes connection and transaction lifecycle state;
- packet-mode and event-mode hunters can connect to one processor without
  ambiguous ownership.

### Cross-sink consistency

- logstream, TUI, statistics, and authorized LI consumers observe the same
  immutable normalized event;
- sink-specific field projection does not mutate the shared event;
- log emission stage policies do not accidentally create duplicate records in
  hierarchical deployments.

## 14. Resolved design decisions

### 14.1 Event identity

Delivery identity is the composite of:

- the node's existing effective hunter, processor, or tap ID;
- random 128-bit producer session ID; and
- monotonically increasing per-event sequence within that session.

After registration, a hunter uses the processor-assigned effective ID rather
than its originally requested ID. Registration should reject conflicting node
IDs. The session ID prevents collisions when a node ID is reused or a node
restarts and resets its sequence.

The producer assigns identity before enqueue and preserves it across buffering,
retry, relay, and fan-out. `event_id` is an opaque representation of the
composite. Event sequence is independent from batch sequence.

Live process restart creates a new producer session. Deterministic offline
analysis may derive a repeatable session ID from input identity, analysis
profile, and source ordering, then use the same monotonic event sequence. Event
payloads, flow UID, and Community ID must not be hashed to create delivery
identity.

No cross-sensor observation ID is defined in version 1. The protobuf should
reserve an optional field for it, but equivalent observations differ by event
kind and protocol. Incorrectly merging two real observations is worse than
displaying duplicates. Version 1 deduplicates retries of the same produced
event only.

### 14.2 Schema evolution

The current `lippycat.data` and `lippycat.management` protobuf packages are not
API-major-versioned; registration version fields describe software versions.
Introduce the canonical event contract as a dedicated versioned package such
as `lippycat.events.v1` without forcing an immediate migration of the existing
services.

Compatible additions remain within `v1`. Never reuse field numbers, and reserve
removed fields. Removing fields, changing meaning, or adding required semantics
requires `v2` and explicit capability negotiation.

A per-event schema integer is not used for ordinary additive changes. Producer
sessions advertise the supported API major and a semantic analysis-profile
revision. Unknown fields follow normal protobuf preservation behavior. An
unknown `oneof` event kind is skipped, counted, and reported as a compatibility
loss; it must not cause the entire stream to be rejected.

Version 1 initially defines the implemented normalized kinds: conn, DNS, TLS,
HTTP, SMTP, and file metadata. Add DHCP, NTP, SSH, and other typed payloads
additively as their event semantics are implemented. Do not add speculative
placeholder messages or generic field maps for the future Zeek-style streams.
Capability negotiation identifies which kinds each node supports.

### 14.3 Delivery guarantee and acknowledgement

Hunter event ingestion provides at-least-once delivery to the accepting
processor, not end-to-end exactly-once delivery to every sink. The processor
deduplicates using event identity and returns cumulative acknowledgements plus
explicit negative acknowledgement or gap ranges.

The reliable event-ingestion profile acknowledges a batch only after:

1. protobuf and semantic validation;
2. source authorization;
3. duplicate registration; and
4. admission to processor-owned recoverable ingress storage.

Recoverable admission means an fsynced processor event WAL or spool. The
processor dispatcher consumes and checkpoints that spool. The current
non-blocking `Dispatcher.Enqueue` and its independently bounded sink queues are
not an acknowledgement boundary because either can drop events.

A deployment may explicitly negotiate a memory-only profile, in which case the
acknowledgement means accepted into the processor ingress queue and loss on
processor failure remains possible. Health and registration output must label
that weaker profile; it must not be presented as recoverable delivery. Sink
durability remains a separate property even when ingestion uses a WAL.

### 14.4 Hunter backlog

Event buffering uses a separate event spool rather than serializing events into
the packet disk-buffer format. The spool must support crash recovery and retain
accepted entries until their cumulative processor acknowledgement. Unlike the
current packet overflow buffer, it must not delete backlog merely because the
hunter restarts or closes normally before delivery completes.

Configure both byte and age limits. Initial defaults are 1 GiB and 24 hours
when disk buffering is enabled, with restrictive directory and file
permissions, checksummed framing, and metrics for current size, oldest age,
writes, reads, corruption, and drops. These defaults require operational
validation before release.

When the spool is exhausted, the default policy drops the oldest complete
unacknowledged batches so current visibility can continue. It records explicit
lost event ranges, marks health degraded, and reports the gap to the processor.
An operator may select `drop_new` when retaining the oldest evidence is more
important. Capture must not block indefinitely and loss must never be silent.

### 14.5 Required event capabilities

There is no universal requirement that every event-mode hunter support every
event kind. The processor derives a required event profile from configured
consumers, requested streams, and enrichment policy. The hunter advertises:

- supported event API majors and semantic profile revision;
- supported event kinds;
- connection lifecycle and graceful flush support;
- DNS, TLS, HTTP, and SMTP correlation capabilities;
- TCP reassembly and file-analysis capabilities;
- optional sensitive-field and hashing capabilities; and
- queue, batch, and spool limits.

Every event-mode producer must support identity and session sequencing, capture
timestamps, origin node and flow provenance, capture scope, partial semantics,
and loss/gap reporting. It must additionally support every event kind and
enrichment required by the negotiated profile. Otherwise the processor rejects
event mode. Fallback to packet mode occurs only when explicitly configured and
is prominently reported.

### 14.6 Mixed forwarding modes

Forwarding mode is selected per producer session. One processor may
simultaneously accept packet-mode hunters, event-mode hunters, and local packet
sources. Canonical analysis authority is keyed by source node and producer
session rather than by a global processor setting.

A producer cannot switch modes inside a session. It flushes and ends the old
analysis session, negotiates the new mode, and starts a new session. Flows that
span the boundary are marked partial as appropriate.

### 14.7 Hierarchical ownership

Analysis authority remains at the origin that created the event:

- an event-mode hunter originates events;
- a packet-mode path has one designated processor originate events; and
- a processor local source is processor-originated.

Intermediate processors relay immutable normalized events and must not derive
them again or replace origin provenance. Hop provenance is appended separately,
and the origin event identity is preserved end to end. Each reliable hop uses
its own ingress WAL, acknowledgement, and deduplication boundary; it
acknowledges its downstream only after local recoverable admission.

The existing log emission policy remains meaningful: `terminal` emits at the
final processor, `all` intentionally emits at every configured processor, and
`none` suppresses log output. Relaying is independent from whether an
intermediate processor emits a local log projection.

### 14.8 TUI reconnect catch-up

Reconnect catch-up means resending a bounded retained event window after a TUI
disconnect or late subscription. It does not mean replaying PCAPs, rerunning
analysis, reading log files, or restoring locally evicted TUI rows.

Catch-up is not required for subscription version 1. The initial TUI RPC is
explicitly live-only and communicates:

- a processor subscription-stream ID;
- a monotonic delivery sequence;
- the initial live boundary; and
- explicit subscriber overflow and reconnect gaps.

Local TUI ring eviction remains distinct from transport loss. Bounded catch-up
may be added later behind a negotiated cursor capability without changing the
event payload contract.

### 14.9 Analysis and sensitive-configuration boundaries

Each producer session advertises a non-secret analysis profile ID and revision,
an enrichment/redaction policy digest, capture-scope or filter generation, and
its effective time. Secrets themselves are never included.

Restarting the producer or changing forwarding mode, API major, event meaning,
capture scope, filters, sensitive enrichment, redaction, hashing, or content
policy flushes the old analysis state and starts a new producer session. Flows
that cannot be completed before the boundary produce partial lifecycle records.
A transport reconnect preserves the session and sequence, as do changes only
to batch size, timeout, or spool limit.

### 14.10 Raw evidence from event-only hunters

Use tap mode when an edge site needs normalized event forwarding plus local
packet evidence. Tap already supports unified, rotating, and per-call PCAPs and
post-write command hooks. In event mode it can retain packets locally while
sending only normalized events upstream.

An event-only hunter remains the lightweight option with no packet-retention
expectation. Do not add an evidence service or hybrid forwarding mode to the
initial implementation. Reconsider an audited, prospective capture RPC only if
operators need occasional evidence from sites where deploying tap is not
possible. The originating node remains the canonical event authority.

## 15. Recommendation

Adopt a single canonical protobuf event contract with typed payloads, explicit
event identity, versioning, provenance, sequencing, and loss information.
Reuse that contract across distinct ingestion and subscription RPCs while
keeping their backpressure and reliability semantics independent.

Implement processor-to-TUI subscription first. It exercises the event wire
model while the processor remains the established event authority. Then make
the complete stateful analysis runtime reusable and add a negotiated hunter
`events` forwarding mode. Retain existing `packets` mode and do not introduce a
general hybrid mode in the initial implementation.
