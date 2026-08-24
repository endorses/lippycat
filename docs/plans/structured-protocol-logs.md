# Structured Protocol Logs Implementation Plan

**Date:** 2026-08-22
**Status:** In progress (Phases 0-4 complete)
**Priority:** High

## Overview

Add a normalized protocol event layer to lippycat, then use that layer to drive
Zeek-compatible structured logs, LI metadata delivery, and future event sinks.

The first sink is structured file logging alongside PCAP output, TUI monitoring,
virtual interface injection, and LI delivery.

The first target is Zeek-compatible file naming and field semantics for the core
streams operators already expect:

| Stream | File |
|--------|------|
| Connection summary | `conn.log` |
| DNS | `dns.log` |
| TLS/SSL handshake metadata | `ssl.log` |
| HTTP | `http.log` |
| SMTP/email envelope | `smtp.log` |
| File transfers and attachments | `files.log` |

File logs are append-only, rotate on a configured interval, and support both
Zeek-style TSV and JSONL encodings. The TSV mode should be compatible with common
Zeek log shipping pipelines. The JSONL mode should be easier to consume directly
from SIEMs, tests, and local tools.

## Goals

- Add typed normalized protocol events below output-specific formatting.
- Produce structured logs from normalized events without blocking packet processing.
- Support structured logs in `process`, `tap`, and eventually `sniff` using the
  same event and logstream packages.
- Use Zeek-compatible stream names and TSV headers by default.
- Include distributed-capture provenance on every event and record via `node_id`.
- Include stable flow identity from the first release: Zeek-style `uid` and
  `community_id`.
- Emit useful DNS and email logs before building the full connection tracker.
- Add TLS and HTTP distributed metadata so `ssl.log` and `http.log` work in hunter
  to processor deployments.
- Allow LI builds to map authorized metadata events to X2 IRI delivery without
  coupling LI to file logs.
- Build `conn.log` with explicit partial-visibility semantics for filtered capture.
- Defer `files.log` until HTTP body recovery and SMTP attachment parsing are ready.

## Non-Goals

- Do not embed Zeek or implement Zeek scripting.
- Do not claim full Zeek protocol breadth or script compatibility.
- Do not add log shipping. lippycat writes files; Filebeat, Vector, Fluent Bit, or
  similar tools ship them.
- Do not treat Zeek log rows as the internal LI data model. LI delivery maps from
  normalized events, not from files.
- Do not send packet payloads, bodies, files, or media as part of metadata-only LI
  delivery.
- Do not replace the virtual-interface-to-Zeek workflow. That remains valid for
  users who want Zeek's broader analyzer ecosystem.
- Do not build full Zeek file-analysis parity in the first release.

## Current State

| Area | Current support | Gap |
|------|-----------------|-----|
| DNS metadata | `internal/pkg/dns` correlates query/response metadata and tunneling scores | Needs normalized event mapping and sinks |
| Email metadata | `internal/pkg/email` tracks SMTP envelope and IMAP/POP3 command state | Needs normalized event mapping and sinks |
| TLS metadata | `internal/pkg/tls` parses ClientHello/ServerHello, SNI, JA3/JA3S/JA4, ALPN, risk flags | Not present in `api/proto/data.proto` or local/tap processor metadata path |
| HTTP metadata | `internal/pkg/http` parses request/response fields and headers | Not present in `api/proto/data.proto` or local/tap processor metadata path |
| Connection tracking | `internal/pkg/detector.FlowTracker` tracks protocol-detection context | No direction normalization, packet/byte counters, TCP state, UID lifecycle, or scale controls |
| File logs | Body previews exist in places | No carving, MIME sniffing, hashing, dedup, extraction limits, or SMTP attachment walking |
| Processor pipeline | `processBatch()` already fans out to PCAP, enrichment, aggregators, LI, upstream, TUI, virtual interface | Needs an event dispatcher at the same non-blocking fan-out layer |
| Sniff CLI path | `lc sniff <protocol>` already performs local capture and protocol analysis for CLI output | Needs event emission and logstream wiring after processor/tap support is proven |
| Flow control | Processor flow control can use PCAP queue pressure and upstream backlog | Needs support for multiple named processor-level pressure sources |
| LI delivery | LI packages already provide X1/X2/X3 concepts for authorized interception | Needs a metadata-event mapper for internet usage IRI tasks |

## Architecture

### Event Generation Point

Normalized protocol events are generated first by processor nodes. Tap mode uses the
same processor pipeline with a local packet source, so it should get the same feature
set in the same implementation.

This keeps logs, LI delivery, PCAPs, TUI data, and upstream forwarding aligned around
the same packet batches and source identity. It also avoids inventing a separate
event transport layer between hunters and processors.

`sniff` should also be capable of writing the same structured logs, but it should
reuse `internal/pkg/events`, `internal/pkg/flowid`, and `internal/pkg/logstream`
rather than getting a separate logging path. Wire `sniff` after the processor/tap
path is working, because processor/tap covers distributed aggregation, flow control,
and LI integration.

### Normalized Event Layer

Add `internal/pkg/events` as the semantic event model and dispatcher.

This package owns event types, envelopes, sink interfaces, and asynchronous
dispatch. It must not know about Zeek formatting, JSONL formatting, or LI-specific
ETSI encoding.

High-level flow:

```text
packet/protocol analyzers
        |
        v
normalized protocol events
        |
        +--> logstream sink: conn.log / dns.log / ssl.log / http.log / smtp.log
        +--> LI metadata mapper sink: authorized X2 IRI delivery
        +--> future sinks: metrics, streaming export, TUI summaries
```

Use typed events rather than an unstructured map-based bus:

```go
type Sink interface {
    HandleEvent(ctx context.Context, ev Event) error
    Flush(ctx context.Context) error
    Close(ctx context.Context) error
}

type Event interface {
    Kind() Kind
    Envelope() Envelope
}

type Envelope struct {
    Timestamp    time.Time
    UID          string
    CommunityID  string
    NodeID       string
    Flow         FlowTuple
    Partial      bool
    CaptureScope string
}
```

Initial concrete event classes:

- `DNSEvent`
- `SMTPEvent`
- `TLSEvent`
- `HTTPEvent`
- `ConnEvent`
- `FileMetadataEvent`
- `FileContentEvent` only when content extraction is explicitly enabled

Metadata and content must be distinct event classes. This prevents an IRI-only LI
task from accidentally receiving bodies, payloads, files, or media through a generic
"file" or "HTTP" event.

The event dispatcher should use bounded queues and async fan-out. Packet processing
enqueues events and moves on. Sinks do their own serialization or mapping outside
the packet hot path.

### Log Sink Package

Add `internal/pkg/logstream` as a sink implementation over `internal/pkg/events`.
Keep it processor-independent so CLI paths can use it later.

Core responsibilities:

- Subscribe to relevant normalized event kinds.
- Stream registry keyed by Zeek stream name: `conn`, `dns`, `ssl`, `http`, `smtp`,
  `files`.
- Lazy writer creation on first record for each enabled stream.
- One async single-writer queue per stream.
- Bounded queues with drop-on-full behavior and drop counters.
- Periodic warning logs for dropped records, not one warning per drop.
- Flush and footer write on graceful shutdown.
- Time-interval rotation using Zeek-style names, for example `conn.log` rotated to
  `conn-2026-08-22-14-30-00.log`.
- Optional post-rotate command hook using the existing processor command-executor
  pattern.

Supported encodings:

- `tsv`: Zeek-style headers, fields, types, escaping, unset fields, empty fields,
  and `#close` footer.
- `json`: JSONL, one object per record.

### Record Builders

Add typed record builders under `internal/pkg/logstream/records`.

Each stream gets a typed struct with fixed field order. Builders map normalized
events into those records. Field names should follow Zeek where lippycat has
equivalent semantics, and use explicit lippycat-specific fields where semantics
differ.

Every file record includes values from the event envelope:

- `ts`: observation timestamp.
- `uid`: Zeek-style connection UID.
- `community_id`: Community ID v1 for cross-tool joins.
- `node_id`: hunter/source identity, using `batch.SourceID`.

Connection records additionally include:

- `capture_scope`: `full` or `filtered`.
- `partial`: true when the connection began before observation, lacks SYN visibility,
  or only one direction was observed.

### Flow Identity

Add a small flow identity layer before the full connection tracker.

This layer should:

- Normalize 5-tuples consistently for TCP, UDP, and ICMP.
- Generate one Zeek-style UID per observed flow.
- Generate Community ID v1 using the normalized tuple.
- Maintain a bounded UID cache with idle expiration.
- Avoid string formatting on the hot path where practical.

This identity layer is intentionally smaller than `conntrack`. It lets `dns.log`,
`smtp.log`, `ssl.log`, and `http.log` ship before `conn.log` is complete.

### LI Metadata Sink

In LI builds, add an optional sink that consumes normalized metadata events and maps
them to authorized X2 IRI delivery. This is for ADMF tasks where the requested
product is internet usage metadata, not full traffic content.

The LI sink must be gated by:

- `li` build tag.
- LI runtime enablement.
- Active ADMF/X1 task.
- Target match.
- Delivery profile authorizing the event kind.
- Metadata-only policy for IRI tasks.

Suggested first metadata mappings:

| Event | LI delivery class |
|-------|-------------------|
| `DNSEvent` | X2 IRI |
| `TLSEvent` | X2 IRI |
| `HTTPEvent` metadata fields | X2 IRI |
| `SMTPEvent` envelope fields | X2 IRI |
| `ConnEvent` | X2 IRI |
| `FileMetadataEvent` | X2 IRI if profile allows file metadata |

Explicitly excluded from metadata-only delivery:

- HTTP request/response bodies.
- Email bodies.
- Extracted file content.
- RTP/media.
- Raw packet payloads.
- Mirrored packet streams.

The LI sink must not depend on file rotation, Zeek TSV output, or JSONL output.

### Backpressure and Flow Control

Event dispatch and sink processing must not block packet processing. When an event
or sink queue fills, events or sink records are dropped according to configured
policy and counted.

Sustained event or sink backpressure is still processor-level pressure, so it should
participate in hunter flow control. Update `internal/pkg/processor/flow.Controller`
to accept multiple named queue metrics rather than adding one-off queues beside the
PCAP queue.

Example shape:

```go
type QueuePressureSource struct {
    Name     string
    Depth    func() int
    Capacity func() int
}
```

The controller should return the most severe signal across PCAP queues, event queues,
sink queues, and upstream backlog.

### Hierarchical Processor Behavior

Hierarchical deployments can otherwise produce duplicate logs. Add an explicit
configuration option:

- `logs.emit_stage: terminal` by default.
- `terminal`: emit only on processors that are not forwarding upstream.
- `all`: emit on every processor/tap node that has logging enabled.
- `none`: initialize config but do not emit records.

If a processor forwards upstream and `emit_stage=terminal`, it should not write
structured logs locally.

## Configuration

Add `events:` and `logs:` YAML blocks and matching process/tap flags first. Reuse
the same log flags for `sniff` when its integration phase starts.

```yaml
events:
  queue_size: 20000
  drop_policy: drop_new

logs:
  enabled: false
  dir: ./logs
  format: tsv
  streams: [conn, dns, ssl, http, smtp]
  rotate_interval: 1h
  queue_size: 10000
  emit_stage: terminal
  post_rotate_command: ""
  include_http_headers: false
  include_email_body_preview: false

li:
  metadata_events:
    enabled: false
    delivery_profile: internet_metadata
```

Flags:

- `--event-queue-size`
- `--log-dir`
- `--log-format tsv|json`
- `--log-streams conn,dns,ssl,http,smtp,files`
- `--log-rotate-interval`
- `--log-queue-size`
- `--log-emit-stage terminal|all|none`
- `--log-post-rotate-command`
- `--log-include-http-headers`
- `--log-include-email-body-preview`
- LI flags should follow the existing `flags_li.go` / `flags_li_stub.go` pattern
  and should not appear in non-LI builds.

Defaults should be conservative:

- Logging disabled unless `--log-dir`, `logs.enabled`, or an equivalent explicit
  setting enables it.
- TSV output by default when enabled.
- Do not include full HTTP headers by default.
- Do not include email body previews by default.
- Do not enable `files.log` until Phase 9 is implemented.
- Do not enable LI metadata-event delivery unless LI is built, enabled, and an ADMF
  task authorizes it.

## Phase 0: Schema and Compatibility Decisions

**Priority:** Critical

Finalize the minimum viable schema before writing code.

### Tasks

- [x] Define stream names and file names: `conn.log`, `dns.log`, `ssl.log`,
      `http.log`, `smtp.log`, `files.log`.
- [x] Define TSV fields and types for Phase 4 streams: `dns`, `smtp`.
- [x] Define TSV fields and types for Phase 5 streams: `ssl`, `http`.
- [x] Define TSV fields and types for Phase 8 stream: `conn`.
- [x] Decide which fields are Zeek-compatible and which are lippycat extensions.
- [x] Document extension fields: `node_id`, `community_id`, `capture_scope`,
      `partial`.
- [x] Define the normalized event envelope fields and event kinds.
- [x] Define which event fields are metadata and which are content.
- [x] Define the first LI metadata profile: `internet_metadata`.
- [x] Add schema fixtures for TSV header output and JSONL objects.

The Phase 0 compatibility contract is documented in
[`docs/structured-protocol-log-schema.md`](../structured-protocol-log-schema.md).
Its canonical ordered schemas and fixtures live in `internal/pkg/logschema`.

### Acceptance Criteria

- A reviewer can tell exactly what fields each first-release stream emits.
- Field order is fixed and covered by tests.
- Zeek-compatible names are used consistently.
- Metadata-only event classes are distinguishable from content-bearing event classes.

## Phase 1: Normalized Event Framework

**Priority:** Critical

Build the typed event model and async dispatcher before any output sink.

### Tasks

- [x] Add `internal/pkg/events`.
- [x] Define `Event`, `Sink`, `Envelope`, `Kind`, and `FlowTuple`.
- [x] Define initial typed events: `DNSEvent`, `SMTPEvent`, `TLSEvent`,
      `HTTPEvent`, `ConnEvent`, `FileMetadataEvent`, `FileContentEvent`.
- [x] Keep metadata and content as distinct event classes.
- [x] Implement async bounded dispatcher queues.
- [x] Implement per-sink registration by event kind.
- [x] Implement drop accounting and periodic warnings.
- [x] Implement lifecycle: `Start`, `Stop`, `Flush`, and `Close`.
- [x] Expose dispatcher queue depth/capacity for flow control.
- [x] Add unit tests for dispatch, sink filtering, shutdown flush, queue-full
      behavior, and sink error handling.

### Acceptance Criteria

- `go test ./internal/pkg/events/...` passes.
- Packet-path code can enqueue typed events without depending on file or LI packages.
- Slow sinks do not block packet processing.
- Metadata-only and content-bearing events cannot be confused by type.

## Phase 2: Flow Identity Layer

**Priority:** Critical

Add stable flow identity for protocol events before implementing full `conn.log`.

### Tasks

- [x] Add `internal/pkg/flowid`.
- [x] Implement normalized flow keys for TCP, UDP, and ICMP.
- [x] Implement Zeek-style UID generation: `C` plus 17 base62 characters.
- [x] Implement Community ID v1.
- [x] Add a bounded UID cache with idle expiration.
- [x] Add cache size, eviction, and lookup metrics.
- [x] Attach `uid` and `community_id` to event envelopes.
- [x] Add tests for tuple normalization.
- [x] Add tests using public Community ID vectors.
- [x] Benchmark UID lookup at high flow counts.

### Acceptance Criteria

- Multiple packets from the same flow receive the same UID.
- Opposite directions of the same flow normalize to the same Community ID.
- Cache growth is bounded and observable.
- Event envelopes carry stable identity before any sink receives them.

## Phase 3: Log Sink Framework

**Priority:** Critical

Build the file-writing sink over normalized events.

### Tasks

- [x] Add `internal/pkg/logstream`.
- [x] Implement an `events.Sink` adapter.
- [x] Implement stream registry and lazy stream creation.
- [x] Implement async bounded queues per stream if per-stream buffering is needed
      after event dispatch.
- [x] Implement drop-on-full accounting and periodic warnings.
- [x] Implement lifecycle: `Start`, `Stop`, flush on shutdown, and footer close.
- [x] Implement Zeek TSV encoder:
      `#separator`, `#set_separator`, `#empty_field`, `#unset_field`, `#path`,
      `#open`, `#fields`, `#types`, record rows, and `#close`.
- [x] Implement JSONL encoder.
- [x] Implement time-based rotation and post-rotate command hook.
- [x] Add unit tests for headers, footers, escaping, unset/empty fields, JSONL
      encoding, rotation, shutdown flushing, and queue-full accounting.

### Acceptance Criteria

- `go test ./internal/pkg/logstream/...` passes.
- A test stream can rotate and produce valid TSV and JSONL output.
- Queue-full behavior drops log records without blocking callers.
- `logstream` depends on `events`, but `events` does not depend on `logstream`.

## Phase 4: DNS and SMTP Events and Logs from Existing Metadata

**Priority:** High

Ship the first useful protocol events and file logs using metadata already available
in the processor path.

### Tasks

- [x] Map protobuf DNS metadata into `events.DNSEvent`.
- [x] Map protobuf email metadata into `events.SMTPEvent`.
- [x] Add `node_id`, `uid`, and `community_id` to each event envelope.
- [x] Add `records/dns.go`.
- [x] Add `records/smtp.go`.
- [x] Map `events.DNSEvent` into `dns.log` records.
- [x] Map `events.SMTPEvent` into `smtp.log` records.
- [x] Wire the event dispatcher into `processBatch()` after enrichment and before
      upstream forwarding/broadcasting.
- [x] Register the logstream sink when logging is enabled.
- [x] Respect `logs.streams`.
- [x] Update processor initialization and shutdown lifecycle.
- [x] Update `flow.Controller` to accept multiple named queue pressure sources.
- [x] Register active event and log queues with flow control.
- [x] Add config and flags for `process` and `tap`.
- [x] Add packet-metadata integration tests asserting record counts and key fields.

### Acceptance Criteria

- `lc process` and `lc tap` can emit `dns.log` and `smtp.log`.
- DNS and SMTP events can be observed in tests without enabling file logging.
- Log writing does not block packet processing under queue pressure.
- Flow control can slow or pause hunters under sustained event or log queue pressure.
- Existing behavior is unchanged when logging is disabled.

## Phase 5: TLS and HTTP Metadata Parity

**Priority:** High

Add the missing distributed and local processor metadata needed for `TLSEvent`,
`HTTPEvent`, `ssl.log`, and `http.log`.

### Tasks

- [ ] Add `TLSMetadata` to `api/proto/data.proto` without reusing field numbers.
- [ ] Add `HTTPMetadata` to `api/proto/data.proto` without reusing field numbers.
- [ ] Regenerate `api/gen/data`.
- [ ] Populate TLS metadata hunter-side from existing TLS parsing.
- [ ] Populate HTTP metadata hunter-side from existing HTTP parsing.
- [ ] Populate TLS metadata in the tap/local processor source path.
- [ ] Populate HTTP metadata in the tap/local processor source path.
- [ ] Gate full HTTP header maps behind explicit config.
- [ ] Confirm older hunters without TLS/HTTP fields still interoperate.
- [ ] Measure protobuf batch size with and without HTTP headers.
- [ ] Map TLS metadata into `events.TLSEvent`.
- [ ] Map HTTP metadata into `events.HTTPEvent`.
- [ ] Add `records/ssl.go`.
- [ ] Add `records/http.go`.
- [ ] Map `events.TLSEvent` into `ssl.log` records.
- [ ] Map `events.HTTPEvent` into `http.log` records.
- [ ] Add integration tests for distributed and tap/local paths.

### Acceptance Criteria

- `ssl.log` is emitted for TLS metadata in tap and distributed modes.
- `http.log` is emitted for HTTP metadata in tap and distributed modes.
- Older hunters degrade gracefully and do not break processor ingestion.
- HTTP header shipping is opt-in.

## Phase 6: `sniff` Command Integration

**Priority:** Medium-high

Allow standalone CLI captures to write the same structured logs as processor and tap
without changing the subject-verb-object command grammar.

`logs` should remain an output capability configured with flags, not an object under
`sniff`. For example:

```bash
lc sniff dns --log-dir ./logs --log-streams dns,conn
lc sniff tls --log-dir ./logs --log-streams ssl,conn
lc sniff http --log-dir ./logs --log-format json
```

### Tasks

- [ ] Add shared log/event flag registration helpers usable by `process`, `tap`,
      and `sniff`.
- [ ] Wire `internal/pkg/events` dispatcher into `cmd/sniff` capture paths.
- [ ] Reuse `internal/pkg/flowid` for `sniff` event envelopes.
- [ ] Register `logstream` sink when `sniff` logging is enabled.
- [ ] Map existing sniff DNS metadata into `events.DNSEvent`.
- [ ] Map existing sniff email metadata into `events.SMTPEvent`.
- [ ] Map existing sniff TLS metadata into `events.TLSEvent`.
- [ ] Map existing sniff HTTP metadata into `events.HTTPEvent`.
- [ ] Ensure stdout/CLI output remains unchanged when logging is disabled.
- [ ] Flush and close log streams on normal exit and signal shutdown.
- [ ] Add integration tests for `lc sniff dns`, `lc sniff tls`, and `lc sniff http`
      log output from PCAP input where supported.

### Acceptance Criteria

- `lc sniff <protocol> --log-dir ...` writes the same Zeek-compatible stream names
  as `tap` and `process`.
- `sniff` logging uses `events` and `logstream`; it does not introduce a parallel
  logging implementation.
- Existing `sniff` stdout behavior is unchanged when logging is disabled.
- `logs` is not added as a `sniff` object.

## Phase 7: LI Metadata Event Sink

**Priority:** Medium-high

Allow LI builds to deliver authorized internet usage metadata in real time without
coupling LI to Zeek log files.

### Tasks

- [ ] Add an LI-only sink implementation behind the `li` build tag.
- [ ] Add a no-op non-LI stub following the existing LI flag/config pattern.
- [ ] Define `internet_metadata` delivery profile.
- [ ] Map `DNSEvent` to X2 IRI records.
- [ ] Map `TLSEvent` to X2 IRI records.
- [ ] Map metadata-only `HTTPEvent` fields to X2 IRI records.
- [ ] Map `SMTPEvent` envelope fields to X2 IRI records.
- [ ] Map `ConnEvent` to X2 IRI records after Phase 8 is available.
- [ ] Map `FileMetadataEvent` to X2 IRI only if the profile explicitly allows file
      metadata.
- [ ] Enforce that `FileContentEvent`, bodies, media, and raw payloads cannot be
      delivered by metadata-only profiles.
- [ ] Gate delivery by active ADMF/X1 task and target match.
- [ ] Add per-event audit logging for delivered, skipped, and rejected events.
- [ ] Add tests for profile gating and content-exclusion behavior.

### Acceptance Criteria

- LI metadata delivery works only in LI builds with LI enabled and an authorizing
  task.
- Metadata events can be delivered in real time without waiting for log rotation.
- Content-bearing events are rejected by metadata-only profiles.
- `logstream` and file configuration are not required for LI metadata delivery.

## Phase 8: Connection Tracker and `conn.log`

**Priority:** Medium-high

Build real connection accounting instead of extending the protocol-detection flow
cache.

### Tasks

- [ ] Add `internal/pkg/conntrack`.
- [ ] Use comparable struct flow keys, not formatted strings, on the hot path.
- [ ] Use sharded maps to reduce lock contention.
- [ ] Track originator/responder orientation:
      SYN direction for TCP, first-packet heuristic for UDP/ICMP.
- [ ] Track `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`.
- [ ] Track L4 payload byte counts where packet data allows it.
- [ ] Implement TCP state machine for Zeek-style `conn_state`.
- [ ] Implement Zeek-style `history` string where visibility is sufficient.
- [ ] Emit `history` conservatively when `partial=true`.
- [ ] Track `duration` as observed duration.
- [ ] Populate `service` from existing detector/enricher results.
- [ ] Add inactivity timeout, half-open timeout, and hard flow cap.
- [ ] Add eviction counters and tracker depth metrics via `sysmetrics`.
- [ ] Emit `events.ConnEvent` on flow expiry and graceful shutdown.
- [ ] Map `events.ConnEvent` into `conn.log` records.
- [ ] Add `ConnEvent` delivery to the LI metadata sink where authorized.
- [ ] Add tests against `captures/` fixtures for common states.
- [ ] Benchmark at 100k or more concurrent flows.

### Acceptance Criteria

- `conn.log` records include stable UID and Community ID matching protocol logs.
- Tracker memory use remains bounded under high-cardinality traffic.
- Partial observations are explicitly marked.
- Known TCP state fixtures produce expected `conn_state` values.

## Phase 9: File Metadata Events and `files.log`

**Priority:** Medium

Add file observations only after the event layer, structured log sink, LI metadata
sink, and protocol logs are stable.

### Scope

First release scope:

- HTTP response bodies.
- SMTP MIME attachments.
- Hashes, MIME type, observed size, and optional bounded extraction.

Out of scope:

- Full Zeek file-analysis framework parity.
- All protocols that can carry files.
- Unlimited extraction.

### Tasks

- [ ] Recover HTTP entity bodies with chunked decoding.
- [ ] Support gzip content decoding where safe and bounded.
- [ ] Walk SMTP MIME multipart attachments.
- [ ] Add content-based MIME sniffing.
- [ ] Add incremental MD5, SHA1, and SHA256 hashing.
- [ ] Add file IDs and deduplication.
- [ ] Add per-file and total extraction size limits.
- [ ] Add optional extraction directory.
- [ ] Emit `events.FileMetadataEvent` for metadata-only observations.
- [ ] Emit `events.FileContentEvent` only when content extraction is explicitly
      enabled.
- [ ] Add `records/files.go`.
- [ ] Map `events.FileMetadataEvent` into `files.log`.
- [ ] Add LI metadata sink support for `FileMetadataEvent` only where authorized.
- [ ] Add tests for hash correctness, MIME detection, truncation, and extraction
      limits.

### Acceptance Criteria

- `files.log` emits bounded, privacy-aware file observations.
- Extraction cannot exceed configured per-file or total limits.
- Hashes are computed incrementally without loading large bodies into memory.
- Metadata-only LI profiles cannot receive file content.

## Phase 10: Documentation and Operations

**Priority:** High

Document schema, operational behavior, and the important difference between complete
and filtered capture.

### Tasks

- [ ] Add `docs/STRUCTURED_LOGS.md`.
- [ ] Document every stream's fields and types.
- [ ] Document TSV vs JSON output.
- [ ] Document rotation and post-rotate hooks.
- [ ] Document SIEM ingestion examples.
- [ ] Document `capture_scope` and `partial` semantics.
- [ ] Document privacy considerations and conservative defaults.
- [ ] Update `cmd/process/README.md`.
- [ ] Update `cmd/tap/README.md`.
- [ ] Update `cmd/sniff/README.md`.
- [ ] Update `docs/manual` process and tap pages.
- [ ] Update `docs/manual` sniff page.
- [ ] Update `AGENTS.md` architecture notes after implementation.

### Acceptance Criteria

- Operators can enable logs without reading source code.
- Consumers can distinguish lower-bound observations from complete measurements.
- Documentation is honest that logs are joinable and familiar to Zeek users, not a
  replacement for Zeek's full analyzer ecosystem.

## Testing Strategy

### Unit Tests

- Event dispatch, sink subscription, sink failure handling, and shutdown flush.
- Metadata/content event type separation.
- TSV header/footer correctness.
- TSV escaping and unset/empty field behavior.
- JSONL encoding.
- Rotation boundaries.
- Event queue, sink queue, and log queue pressure/drop counters.
- UID generation and cache behavior.
- Community ID known vectors.
- Record builder field order and missing-field handling.
- LI metadata profile gating in LI builds.

### Integration Tests

- PCAP replay to normalized DNS events.
- PCAP replay to DNS logs.
- PCAP replay to normalized SMTP events.
- PCAP replay to SMTP logs.
- Tap/local TLS and HTTP metadata to `ssl.log` and `http.log`.
- `sniff` PCAP input to DNS/TLS/HTTP logs where protocol sniff commands support
  file input.
- Simulated hunter protobuf metadata to processor logs.
- LI metadata sink receives only authorized metadata events in LI builds.
- LI metadata sink rejects content-bearing events for metadata-only profiles.
- Logging disabled path.
- Event sink disabled path.
- Queue-full path under load.
- Graceful shutdown flush.

### Performance Tests

- Log queue enqueue cost per packet.
- Event enqueue and dispatch cost per packet.
- Record allocation count per packet.
- UID cache lookup under high flow cardinality.
- `conntrack` memory ceiling and lock contention at 100k or more flows.
- Protobuf batch size impact for TLS/HTTP metadata, especially HTTP headers.

### Build Verification

Run:

```bash
make test
make binaries
make verify-no-li
```

Also verify LI builds after processor/tap wiring changes:

```bash
make build-li
make processor-li
make tap-li
```

## Risks

### `conn.log` Scale

Connection tracking is the highest-risk part of the project. High-cardinality traffic
can become a memory or lock-contention problem quickly. Keep the tracker bounded from
the first implementation and benchmark before enabling it by default.

### Zeek `history` Fidelity

The `history` field is easy to get subtly wrong. Consumers may rely on it for
detection logic. If visibility is partial or the implementation is uncertain, emit a
conservative value or leave it unset rather than presenting misleading precision.

### Proto Growth

TLS metadata is modest. HTTP metadata can grow quickly if full headers are shipped.
Header maps must remain opt-in and measured before any default changes.

### Filtered Capture Semantics

lippycat often sees targeted or partial traffic. Byte counts and duration may be
lower bounds, not complete measurements. `capture_scope` and `partial` are required
schema fields, not documentation-only caveats.

### Duplicate Logs in Hierarchies

Processor-to-processor forwarding can duplicate records if multiple processors emit
logs. `logs.emit_stage` must be implemented before recommending structured logs for
hierarchical deployments.

### Sensitive Data

Structured logs can expose domains, SNI, URLs, email metadata, user agents, headers,
subjects, and file hashes. Defaults should avoid body/header capture, and docs must
cover retention and access control expectations.

### Metadata and Content Separation

The event model must not encode content as optional fields on generic metadata
events. Bodies, extracted files, RTP/media, and raw payloads need separate
content-bearing event classes so metadata-only sinks cannot accidentally receive
them.

### LI Scope Creep

The LI metadata sink must be task- and profile-gated. It should never become a
generic "send all logs to LI" switch, because operational logs and legally authorized
IRI delivery have different authorization, audit, and retention requirements.

### Event Bus Over-Generalization

A fully dynamic map-based event bus would make sinks brittle and increase the chance
of accidental sensitive-field routing. Prefer typed Go event structs and explicit
sink mappings until real extension pressure justifies something more generic.

## Suggested Delivery Order

1. Phase 0: schema decisions.
2. Phase 1: normalized event framework.
3. Phase 2: flow identity.
4. Phase 3: logstream sink.
5. Phase 4: DNS and SMTP events/logs.
6. Phase 5: TLS and HTTP metadata plus `ssl.log` and `http.log`.
7. Phase 6: `sniff` command integration.
8. Phase 7: LI metadata event sink.
9. Phase 8: `conn.log`.
10. Phase 9: `files.log`.
11. Phase 10: complete user and operator documentation.

Phases 1 through 4 are the smallest useful release: they provide a typed event
layer, stable flow identity, a tested log sink, and useful DNS/email output without
changing the protobuf wire format. Phase 5 makes distributed TLS and HTTP logging
complete. Phase 6 brings the same sink stack to `sniff`. Phase 7 adds real-time
authorized metadata delivery for LI builds without coupling it to file logs. Phase 8
should only ship after benchmarks show the tracker behaves well under realistic flow
cardinality.
