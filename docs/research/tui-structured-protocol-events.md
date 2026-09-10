# Structured Protocol Events in the TUI

**Date:** 2026-08-28

**Status:** Proposed design

**Related design:** The transport-neutral protobuf event model, event identity,
and delivery roles are defined in
[`structured-protocol-event-transport.md`](structured-protocol-event-transport.md).
This document owns TUI behavior and processor-to-TUI subscription requirements;
it does not define a separate TUI-specific event schema.

**Decision:** Add a reusable **Events** view to the Capture tab. Keep protocol
selection and presentation as separate concepts: `p` selects the traffic or
protocol scope, while `v` switches among packet, event, and available
protocol-specific views. Support the same event experience in `watch live`,
`watch file`, and `watch remote`, using mode-specific transports into one TUI
event store.

## Executive summary

lippycat now produces normalized structured protocol events for connection,
DNS, TLS, HTTP, SMTP, and file observations. The same events can feed rotating
structured log files and other event consumers. The TUI currently exposes
packets and several protocol-specific projections, but it does not expose this normalized event
stream directly.

The structured records should be presented as an interactive **Events** view on
the Capture tab, alongside the packet list. They should not primarily live on
the Statistics tab: statistics are aggregate dashboards, while structured
events are selectable, filterable observations with details and relationships
to packets, flows, nodes, and files.

The current Protocol Selector should not be renamed to Mode. In the existing
product, "mode" already describes live, offline, and remote capture; hunter and
tap protocol modes; and several internal component states. More importantly,
protocol scope and presentation are independent dimensions:

```text
Traffic scope:  All | VoIP | DNS | HTTP | TLS | Email | ...
                       |
Capture view:   Packets | Events | protocol-specific view
Statistics:     Aggregate dashboards for the same traffic scope
```

The Events component and its interaction model can be shared across all watch
commands. The ingestion path differs:

| Command           | Event source             | Required work                                                          |
| ----------------- | ------------------------ | ---------------------------------------------------------------------- |
| `lc watch live`   | Local packet analysis    | Feed normalized events into a bounded in-memory TUI sink               |
| `lc watch file`   | Local PCAP analysis      | Reuse the live path and flush lifecycle state deterministically at EOF |
| `lc watch remote` | Processor event pipeline | Add a bounded gRPC event subscription                                  |

## 1. Motivation

Structured protocol events provide a middle level of abstraction between raw
packets and aggregate statistics:

- Packets answer what was observed on the wire.
- Events answer what protocol transaction, handshake, connection, or file
  observation was inferred.
- Specialized views answer domain-specific questions, such as VoIP call state
  and media quality.
- Statistics answer how traffic and system behavior are distributed in
  aggregate.

Making events visible in the TUI provides interactive access to the same
normalized model used by external sinks. It also reduces pressure to build a
separate custom table architecture for every protocol.

## 2. Current TUI behavior

The global `p` key opens `ProtocolSelector`. Selecting an entry currently has
several effects:

1. It replaces the active packet filter with the selected protocol filter.
2. It sets the selected protocol used by protocol-specific statistics.
3. It enables or disables VoIP-specific processing behavior.
4. It selects a presentation view, choosing Calls for VoIP and Packets for
   other selections.

On the Capture tab, `v` can then toggle between Packets and an available
protocol-specific view:

- VoIP: Calls
- DNS: Queries
- Email: Emails
- HTTP: HTTP transactions

The Statistics tab separately uses `v` to switch between Overview and
Distributed subviews. It already supports protocol-specific aggregate providers.

This behavior works, but the selected protocol is doing three distinct jobs:

- defining traffic scope;
- controlling analysis behavior; and
- choosing how results are represented.

Adding "Metadata" as another protocol or renaming the selector to "Mode" would
preserve that coupling and make the selector semantically ambiguous.

## 3. Proposed interaction model

### 3.1 Keep scope and representation separate

Use `p` for protocol or traffic scope and `v` for the current tab's
representation.

The selector may remain named **Protocol**, or it may be renamed **Traffic** if
the UI needs to emphasize that it controls the visible traffic set. **Mode** is
not recommended.

Examples:

| Selected scope | Available Capture views                              |
| -------------- | ---------------------------------------------------- |
| All            | Packets, Events                                      |
| DNS            | Packets, Events                                      |
| HTTP           | Packets, Events                                      |
| TLS            | Packets, Events                                      |
| Email          | Packets, Events                                      |
| VoIP           | Packets, Calls, Events when VoIP event classes exist |

Selecting a protocol should preserve the current view where possible. For
example, changing from DNS Events to HTTP should remain in Events. If the new
scope does not support the current specialized view, fall back predictably to
Events or Packets and display a short toast.

### 3.2 Name the view Events, not Metadata

**Events** is the preferred user-facing term because the stream contains more
than metadata annotations:

- `conn` records summarize connection lifecycles;
- DNS, HTTP, and SMTP records describe transactions;
- TLS records describe handshakes and negotiated properties;
- file records describe file observations;
- LI distinguishes metadata from content as an authorization boundary.

Calling the view Metadata could be confused with packet metadata or imply that
all `events.Event` implementations are safe for the same delivery profile.
Documentation can use the longer term **structured protocol events**.

### 3.3 Events table

The default layout should be a compact, heterogeneous timeline:

```text
TIME          TYPE   SOURCE              DESTINATION         SUMMARY
12:41:02.391  dns    10.0.0.8:53012      1.1.1.1:53          A example.com -> 93.184.216.34
12:41:02.418  tls    10.0.0.8:49220      93.184.216.34:443   example.com TLS 1.3 JA4 ...
12:41:02.611  http   10.0.0.8:49220      93.184.216.34:443   GET /index.html 200
12:41:04.109  files  93.184.216.34:443   10.0.0.8:49220      text/html index.html SHA256 ...
```

The common columns come from `events.Envelope`. Each event kind supplies only a
short summary formatter. Protocol-specific fields belong in the details panel,
not in an excessively wide universal table.

For remote and merged-file capture, a Node or Source column should be available.
It may be hidden responsively on narrow terminals.

### 3.4 Event details

Selecting an event should expose a structured details panel with two sections:

```text
Event
  Kind              HTTP
  Timestamp         2026-08-28T12:41:02.611Z
  UID               C...
  Community ID      1:...
  Node              hunter-a
  Capture scope     full
  Partial           false
  Flow              10.0.0.8:49220 -> 93.184.216.34:443/tcp

HTTP
  Method            GET
  Host              example.com
  URI               /index.html
  Status            200 OK
  User agent        ...
  Response bytes    ...
```

Field names, types, and meanings should be derived from or kept consistent with
`internal/pkg/logschema`. The TUI must not define a competing structured-log
schema. Display ordering does not need to copy TSV column order: the details
panel may put important fields first, group related fields, hide empty values,
and expand collections. Shared field descriptors should carry canonical names,
types, sensitivity, and formatting hints where practical, while leaving layout
to the TUI.

Likely interactions are:

- `v`: cycle Capture views;
- `j`/`k`: navigate events;
- `d` or `Enter`: show or focus details;
- `/`: enter event-filter mode;
- `g`: locate related buffered packets;
- `f`: locate related file observations, if available;
- `w`: export selected or filtered events, if event export is added later.

Exact keys should follow existing Capture-tab conventions and remain visible in
the context-aware footer.

### 3.5 Relationship to specialized views

The Events view should be generic rather than creating separate DNS, HTTP, TLS,
SMTP, and Files component architectures. A protocol can supply summary columns
or presentation helpers without owning a separate store.

The Calls view should remain specialized. It represents correlated, stateful
VoIP behavior, call legs, RTP metrics, loss, jitter, and quality rather than a
simple projection of event records.

The existing Queries, Emails, and HTTP views can remain during migration. After
the Events view matures, they can be evaluated individually:

- retain a view if it supports a distinct workflow beyond record browsing;
- otherwise replace it with a protocol-filtered Events projection;
- do not remove an existing view until feature and interaction parity is clear.

## 4. Why Events should not be a Statistics subview

The Statistics tab is the right location for event-derived aggregates, but not
for the primary record browser.

Overview and Distributed are dashboards. An event timeline has different
interaction requirements: row selection, details, filtering, correlation, and
jumping to packets. Placing it in Statistics would make the tab alternate
between aggregate and investigative mental models.

Useful additions to Statistics can still be derived from the event stream:

- event rates and event queue drops;
- DNS query types and response codes;
- HTTP methods and status classes;
- TLS versions, ciphers, validation states, and fingerprints;
- SMTP outcomes and TLS usage;
- connection states and durations;
- file MIME types, hashes, truncation, and extraction outcomes;
- counts of partial or filtered-scope events.

These are aggregate consumers of the same normalized events, not replacements
for the Events view.

## 5. Common TUI architecture

### 5.1 One event model for every watch command

After ingestion, capture mode should not affect rendering. A common message can
carry event batches into the Bubble Tea update loop:

```go
type EventBatchMsg struct {
    Events []events.Event
    Source EventSource
}
```

The model should own a bounded `EventStore`, analogous to the bounded packet
store. The store should support:

- a monotonic local arrival sequence as well as the event capture timestamp;
- a configurable maximum record count;
- filtered and unfiltered projections;
- selection by explicit event identity rather than row index;
- pause and resume behavior;
- reset on capture restart or input replacement;
- per-kind and per-source filtering;
- explicit counters for discarded events.

Event time and arrival order are not interchangeable. Connection summaries can
be emitted at close or timeout, remote batches can arrive late, and clocks can
differ between nodes. Live and remote views should append by arrival order, or
reorder only within a documented bounded window, so existing rows do not move
unexpectedly. Offline views should sort deterministically by capture timestamp
with an explicit stable tie-breaker.

`events.Event` implementations are typed Go values. For remote transport, the
wire representation should decode back into these normalized types before the
TUI store receives them.

Every normalized event should carry an explicit event ID in `events.Envelope`,
and the first TUI wire schema should preserve it. Flow UID and Community ID
identify flows, not individual transactions or lifecycle records. Event
identity is needed for stable selection, related-event navigation, export,
reconnect or replay cursors, deduplication in future hierarchical forwarding,
and deterministic tests. The implementation must define whether IDs are
globally unique or deterministic for repeatable offline analysis; the TUI must
not derive identity informally from flow fields.

### 5.2 Independent bounded delivery

The TUI must be an independent consumer of the event dispatcher:

```text
Analyzer -> normalized event dispatcher
              |-- structured log sink
              `-- TUI event subscriber(s)
```

Slow TUI clients must not block file logs, LI delivery, packet processing, or
other clients. Each subscription needs bounded buffering and a documented drop
policy. TUI event pressure must not feed hunter flow control; it has the same
isolation requirement as slow packet subscribers.

The UI should expose both dispatcher and local-store loss when available, so a
quiet-looking event view cannot conceal overload.

### 5.3 Event generation lifecycle and consumers

Normalized event generation should not require a structured log directory.
Base normalized event analysis should run independently of whether a TUI client
is connected, and the processor should register a permanent bounded TUI
broadcaster sink before the dispatcher starts. This matches the dispatcher's
current pre-`Start` registration lifecycle and avoids enabling stateful analysis
halfway through a flow when the first remote viewer connects.

A processor or local watcher needs an active normalized-event pipeline when any
configured or built-in consumer requires it:

```text
file logs enabled
OR TUI event delivery is available
OR an event-derived statistics consumer is enabled
```

The broadcaster may have zero subscribers without disabling analysis. If a
future optimization dynamically activates event generation, it must specify
warm-up, partial-flow, tracker, and subscriber-join semantics explicitly.

Basic normalized events are output-neutral. Expensive or sensitive enrichment
must remain configuration- and authorization-driven. Examples include complete
HTTP headers, email body previews, file hashing, and content extraction.

### 5.4 Share the stateful analysis pipeline

Shared event builders alone do not guarantee equivalent output. DNS RTT,
connection summaries, reassembled HTTP or SMTP transactions, TLS handshakes,
and file observations depend on stateful protocol analysis, flow tracking,
timeouts, and lifecycle flushing.

The reuse boundary should therefore be the complete normalized-event analysis
pipeline:

```text
decoded packet
  -> shared protocol and flow analysis runtime
  -> normalized event builders
  -> event dispatcher
```

`watch live`, `watch file`, sniff, and processor paths should configure and run
this common pipeline rather than independently parsing the same protocols and
sharing only constructors. Mode-specific adapters may supply capture clocks,
source provenance, EOF signals, and transport, but must not create competing
event semantics.

## 6. `lc watch live`

Live watch should emit normalized events from locally analyzed packets and
deliver them to an in-memory TUI sink:

```text
interface capture
  -> packet decoding
  -> shared stateful normalized-event pipeline
  -> bounded local event subscriber
  -> EventBatchMsg
  -> EventStore
```

The current TUI already analyzes local packets for DNS, HTTP, email, and VoIP
projections. The event work should not introduce a second protocol parser.
Instead, local watch should use the same stateful protocol and flow analysis
runtime as processor and sniff paths, including correlation, reassembly,
timeouts, and lifecycle handling.

No `--log-dir` should be necessary, and opening the Events view must not
implicitly enable file output.

Pause behavior should be consistent with the packet list. The implementation
must define whether pause stops upstream ingestion or freezes the visible
projection while retaining bounded arrivals; the selected behavior should apply
to both packets and events.

## 7. `lc watch file`

Offline watch should reuse the local event-building path:

```text
PCAP decoder
  -> packet decoding
  -> shared stateful normalized-event pipeline
  -> bounded local event subscriber
  -> EventStore
```

Offline processing adds lifecycle requirements:

1. Event timestamps must come from captured packets, not wall-clock replay time.
2. Connection tracking and incomplete transaction state must be flushed at EOF.
3. Captures beginning or ending mid-flow must produce accurate `partial`
   semantics.
4. Opening another input or restarting analysis must clear event builders,
   trackers, filters, selection, and store state.
5. Multiple PCAP inputs must preserve source-file provenance where useful.
6. Deterministic processing of the same inputs should produce the same ordered
   event projection, subject to documented tie-breaking for equal timestamps.

This turns `watch file` into an interactive explorer for records equivalent to
`conn.log`, `dns.log`, `ssl.log`, `http.log`, `smtp.log`, and `files.log`, while
retaining access to the underlying packets.

## 8. `lc watch remote`

Remote watch requires a new processor-to-TUI transport. The current data service
streams packet batches and call updates but does not expose normalized protocol
events. The subscription must reuse the canonical event protobuf defined in the
shared transport design rather than introduce a TUI-specific projection.

### 8.1 Proposed subscription

Add a server-streaming RPC conceptually similar to:

```protobuf
rpc SubscribeEvents(EventSubscribeRequest)
    returns (stream ProtocolEventBatch);
```

The request should be able to constrain delivery by:

- normalized event kind;
- hunter or node ID;
- processor scope in a hierarchy;
- optional server-side filter expression, if supported safely;
- authorization-sensitive capabilities such as file metadata.

The initial implementation can subscribe to all safe metadata kinds and filter
locally, but the protocol should leave room for server-side subscription
narrowing to reduce network and serialization load.

The response must preserve:

- event kind and all normalized fields;
- capture timestamp;
- UID and Community ID;
- originating node or hunter identity;
- processor provenance where needed;
- capture scope and `partial` state;
- a schema or API version sufficient for compatible evolution.

Use the shared typed protobuf representation rather than transporting rendered
TSV or JSONL log lines. File output formats are sink concerns and would discard
type information needed by the TUI. The event payload may also be used by
hunter ingestion later, but ingestion acknowledgements and flow control are not
part of the TUI subscription contract.

An explicit event ID should be included in the first protobuf schema. Batch
messages should also carry enough sequence and loss information to distinguish
normal live-only subscription from replay, reconnect gaps, and subscriber queue
overflow.

Before choosing a separate RPC, compare it with extending the existing TUI data
stream. A separate stream provides independent subscription and backpressure;
a unified stream provides one reconnect lifecycle and preserves transport order
among packets, calls, status, and events. If separate streams are used, the TUI
must treat cross-stream arrival order as undefined and correlate using event
identity, timestamps, and flow references rather than arrival order.

### 8.2 Processor fan-out

The processor should publish events directly from the normalized dispatcher. It
must not tail structured log files and ordinary TUI delivery must not be routed
through X2.

Each TUI subscriber should have its own bounded queue. On overflow, the server
should count dropped event batches or records and communicate loss to the client
when practical.

### 8.3 Hierarchical processors

Hierarchical deployments need an explicit event ownership model. At minimum,
the connected processor can expose events it analyzes locally from received
packet batches. If normalized events are later forwarded between processor
levels, the design must address:

- duplicate analysis of the same packets at multiple levels;
- stable provenance across hops;
- transaction events sharing a flow UID;
- ordering between events from different processors;
- reconnect and replay boundaries.

UID alone should not be assumed to uniquely identify every event in a flow. If
deduplication or event correlation is required, introduce an explicit event
identity rather than deriving one informally in the TUI.

## 9. Filtering semantics

Packet filters and event filters are related but not identical.

The protocol selector can apply a shared traffic scope:

| Selector entry | Packet projection     | Event projection                                |
| -------------- | --------------------- | ----------------------------------------------- |
| All            | All buffered packets  | All permitted event kinds                       |
| DNS            | DNS-related packets   | `dns` events, optionally related `conn` records |
| HTTP           | HTTP-related packets  | `http` and related `files`; optionally `conn`   |
| TLS            | TLS-related packets   | `tls`; optionally `conn`                        |
| Email          | Email-related packets | `smtp` and related `files`; optionally `conn`   |
| VoIP           | SIP/RTP packets       | Future VoIP events or Calls view                |

Whether related `conn` and `files` records follow a selected application
protocol is a UX policy that should be made explicit. The initial implementation
should filter by exact event kind. Including related records should be added
only after the association model can distinguish transactions on persistent
flows reliably; a broad same-flow match can otherwise include unrelated HTTP or
SMTP activity. Once reliable, an explicit **include related events** toggle can
expand the projection using UID, transaction associations, and file IDs.

The existing packet filter grammar should not automatically be applied to
events. Event fields include transaction and lifecycle attributes not present on
individual packets. A unified grammar may be desirable, but it should operate
through a shared filterable-record abstraction with documented field behavior.

## 10. Correlation with packets and other events

The strongest reason to put Events on the Capture tab is correlation.

An event should be able to locate relevant buffered packets using, in decreasing
order of precision:

1. an explicit packet/event reference if one is introduced;
2. UID or Community ID plus event time bounds;
3. normalized flow tuple plus time bounds.

Community ID identifies a flow, not a single transaction or packet. HTTP and
SMTP can produce multiple events on one connection, so a jump based only on
Community ID should land on the closest matching packet and visibly indicate
that the relationship is flow-level.

Related-event navigation can group DNS, TLS, HTTP, file, and conn observations
by UID while retaining separate rows in the timeline.

Correlation is bounded by the stores: an event can outlive its corresponding
packet in the packet ring, or vice versa. The UI should report "related packets
no longer buffered" rather than silently failing.

## 11. Security and LI boundaries

TUI event delivery is not X2 delivery and must not inherit LI authorization by
accident.

The remote event RPC needs its own authentication and authorization policy. A
client authorized to subscribe to packet metadata is not necessarily authorized
to receive full HTTP headers, email headers, file paths, or extracted content.

Initial scope should include normalized metadata event classes:

- DNS;
- TLS;
- HTTP with configuration-approved fields;
- SMTP with configuration-approved fields;
- Conn; and
- FileMetadata when explicitly permitted.

`FileContentEvent` should be excluded from the generic Events view and remote
subscription by default. Content access, if ever added, requires a separate,
explicitly authorized workflow with bounded rendering and storage.

The authorization model should account for existing raw-packet access. A client
that receives packet content may already be able to derive fields that an event
policy hides. Capabilities should therefore be coherent and explicit across raw
packet content, normalized event metadata, sensitive enriched fields, file
metadata, and file content. Denying a structured projection does not make the
underlying information unavailable to a client that is still authorized for
the corresponding packet bytes.

The TUI must render untrusted strings safely. Protocol fields may contain
terminal control characters, extremely long values, invalid text, or attacker-
controlled formatting. Summary and detail renderers must sanitize control
sequences and bound displayed field sizes. The same sanitization policy should
also be applied to existing packet-derived and specialized views.

## 12. Backpressure, retention, and observability

Event delivery is best-effort for the interactive TUI and must remain isolated
from durable or regulated sinks.

Recommended boundaries are:

- bounded dispatcher input queue;
- bounded queue per sink or remote subscriber;
- bounded gRPC batches;
- bounded Bubble Tea message batches;
- bounded TUI event ring;
- bounded field and collection rendering.

At least the following loss counters should be observable:

- events rejected or dropped at dispatcher ingress;
- events dropped for the TUI sink or remote subscription;
- batches lost during disconnect or reconnect;
- events evicted from the local display ring;
- events omitted because the client lacks capability or authorization.

Eviction from the display ring is normal retention behavior and should be
distinguished from overload loss.

## 13. Suggested implementation phases

### Phase 1: Shared pipeline, model, and offline proof

1. Establish the shared stateful normalized-event analysis pipeline and event
   identity semantics.
2. Define the bounded TUI `EventStore` and generic Events component.
3. Add common and per-kind summary/detail formatters.
4. Feed fixture and `watch file` events through the component without requiring
   file logging.
5. Verify deterministic timestamp ordering, EOF flush, partial semantics, and
   reset behavior.
6. Add exact-kind protocol-scope filtering and Packets/Events view switching.

### Phase 2: Live parity and correlation

1. Feed `watch live` through the same analysis pipeline and event store.
2. Define live arrival-order, bounded reordering, pause, and restart behavior.
3. Add event-to-packet navigation within bounded stores.
4. Verify that live viewing does not require or create structured log files.

### Phase 3: Remote transport

1. Choose a separate `SubscribeEvents` RPC or an extension of the existing TUI
   stream, documenting cross-stream ordering and reconnect semantics.
2. Reuse the versioned protobuf event messages, explicit event IDs, sequencing,
   and loss reporting from the shared event transport contract.
3. Register a permanent bounded broadcaster sink with the processor event
   dispatcher and attach independent subscribers to it.
4. Extend `remotecapture.EventHandler` or add a focused event callback.
5. Deliver `EventBatchMsg` into the same TUI store used by local modes.
6. Surface subscription drops, reconnect state, node provenance, and
   authorization capabilities.

### Phase 4: Event-derived statistics and specialization

1. Add event-rate and drop indicators to Statistics.
2. Add high-value protocol aggregates.
3. Evaluate Queries, HTTP, and Emails views for consolidation into Events.
4. Retain Calls as the specialized VoIP workflow.
5. Consider saved event export independently from packet PCAP saving.

## 14. Testing strategy

### Shared component tests

- each event kind produces bounded, sanitized summary and detail output;
- displayed values, names, and types remain consistent with the canonical
  schema while allowing TUI-specific grouping and ordering;
- selection is stable during append and eviction;
- selection and related-event navigation use explicit event identity;
- filters behave identically for local and decoded remote events;
- narrow terminal layouts degrade without corrupting content;
- pause, clear, restart, and view switching preserve documented state.

### Live and file tests

- the same packet fixtures produce equivalent normalized events across local,
  sniff, and processor analysis modes;
- PCAP timestamps are preserved;
- EOF emits final connection records;
- partial input produces correct scope and partial markers;
- multiple PCAP files have deterministic ordering and provenance;
- events do not require or create a structured log directory.

### Remote tests

- protobuf round trips preserve every normalized field and envelope value;
- event IDs, batch sequence, and loss boundaries survive protobuf round trips;
- slow subscribers do not block processor delivery or other clients;
- overflow counters reach the TUI;
- reconnect does not silently imply replay;
- separate packet and event streams, if used, do not rely on cross-stream
  arrival order;
- unauthorized event kinds and sensitive fields are denied server-side;
- hierarchical provenance is preserved.

### Cross-sink consistency tests

For a fixture event, verify that:

- the Events details panel represents the normalized value accurately;
- the structured log record uses the canonical schema projection;
- none of the sinks modifies the event observed by another sink.

## 15. Open decisions

The following choices should be resolved before implementation:

1. Should the `p` modal remain **Select Protocol** or become **Select Traffic**?
2. When changing protocol scope, should Events be preserved as the active view?
3. When should application scopes offer **include related events**, and what
   transaction association is sufficient to avoid broad same-flow matches?
4. Should pause stop event ingestion or freeze only the displayed projection?
5. What is the default and configurable event-ring capacity?
6. Does the remote subscription begin at connection time only, or is bounded
   replay required?
7. Which remote roles may receive each event kind and optional field set?
8. Should event IDs be globally unique, deterministic for repeatable offline
   analysis, or composed from both forms?
9. Should remote events extend the existing TUI stream or use a separate RPC?
10. Which existing specialized views provide enough distinct value to retain?

## 16. Recommendation

Adopt Events as a first-class Capture-tab representation and require behavioral
parity across live, file, and remote watch modes.

Keep the concepts explicit:

- `p` selects traffic or protocol scope;
- `v` selects representation;
- Packets show wire observations;
- Events show normalized protocol observations;
- Calls and future specialized views support richer domain workflows;
- Statistics shows aggregates derived from packets, events, and system metrics.

Implement live and file through one shared local normalized-event path, then add
a typed, bounded remote subscription from processors. This gives the TUI access
to the structured event model without coupling it to file logs or LI transport,
and it preserves the backpressure and authorization boundaries required by the
existing architecture.
