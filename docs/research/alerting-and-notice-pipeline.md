# Alerting and Notice Pipeline Research

**Date:** 2026-08-28
**Status:** Research
**Related:** `internal/pkg/events`, `internal/pkg/dns`, `internal/pkg/logstream`, `internal/pkg/voip`

## Executive Summary

lippycat is not only a passive structured-log producer. It already performs
stateful DNS tunneling detection, applies alert thresholds and debounce, and can
execute an operator-configured command when a detection fires. It also has a
separate alert manager for VoIP/TCP resource health.

What lippycat does not yet have is a common security-notice abstraction. DNS
tunneling alerts are wired directly to a command callback, operational alerts
use a different type and manager, and structured DNS logs do not record the
tunneling score, entropy, or alert decision. Consequently, operators using only
the Zeek-style logs cannot determine why a domain was considered suspicious or
whether lippycat fired an alert.

The recommended direction is to generalize the existing detector pattern into
a typed, bounded notice pipeline. Detectors should continue to operate on
normalized events and domain state, but publish typed notices to independent
sinks such as `notice.log`, the TUI, command hooks, webhooks, and SIEM outputs.
This adds a coherent alerting layer without requiring lippycat to implement a
general-purpose scripting language immediately.

## Why the Structured Logs Matter

The structured logs convert packet data into compact, queryable telemetry:

| Stream | Primary value |
|---|---|
| `conn.log` | Connection endpoints, state, duration, volume, and flow identity |
| `dns.log` | Consolidated DNS transactions, answers, response flags, and RTT |
| `ssl.log` | Consolidated TLS handshakes, SNI, cipher, and fingerprints |
| `http.log` | Consolidated HTTP transactions and associated files |
| `files.log` | Per-observation file identity, hashes, MIME type, and extraction metadata |

These records support retention, investigation, baselining, dashboards, threat
intelligence matching, and cross-protocol correlation through `uid` and
`community_id`. They are much cheaper to retain and search than full PCAP and
allow lippycat to act as a sensor for an existing SIEM.

Logs alone are nevertheless passive. They record observations and leave
detection, correlation, notification, and response to downstream systems.

## Existing Real-Time Detection and Alerting

### DNS tunneling detector

`internal/pkg/dns/tunneling.go` already implements a stateful detector. It
maintains bounded per-domain statistics and considers:

- Shannon entropy of query names and long subdomains;
- the number and ratio of unique subdomains;
- the proportion of high-entropy subdomains;
- suspicious DNS record types, including TXT and NULL;
- query volume and average query length;
- contributing source IPs and hunter identity.

The detector writes `EntropyScore` and `TunnelingScore` into DNS metadata. Its
alert configuration provides:

- a score threshold;
- per-domain debounce;
- an asynchronous callback;
- alert context containing domain, score, entropy, query count, source IPs,
  hunter ID, and timestamp.

This is a genuine event-to-state-to-decision pipeline, not merely log
generation.

### Processor and tap actions

The processor connects the DNS detector callback to the command executor when
a tunneling command is configured. `lc process` and `lc tap dns` expose:

```text
--tunneling-command
--tunneling-threshold
--tunneling-debounce
```

The command template supports:

```text
%domain% %score% %entropy% %queries% %srcips% %hunter% %timestamp%
```

This can drive a local notification script, SIEM submission, webhook client,
PCAP-retention workflow, or another operator-controlled response. Thresholding
and debounce happen before command execution, reducing alert floods.

The callback is only installed when a tunneling command is configured. The
detector can still calculate scores and maintain suspicious-domain state
without a command, but that does not create a durable security notice.

### CLI visibility

The DNS-specific sniff path enables tunneling detection by default and annotates
high-scoring output. It can also display suspicious-domain statistics. This is
useful interactively but is not a durable, machine-readable alert channel.

### Operational alerts

`internal/pkg/voip/alerts.go` implements another alert subsystem for TCP
assembler, queue, buffer, goroutine, and failure-rate health. It includes
severity, active/resolved state, handlers, and default thresholds.

These are operational health alerts rather than network-threat detections, but
their lifecycle and handler concepts overlap with a future notice system.

## Current Gaps

### No common notice type

DNS tunneling alerts and VoIP resource alerts use separate types, managers, and
delivery mechanisms. Other protocol detectors have no standard way to publish
a finding.

### Alert evidence is absent from structured logs

The canonical `dns.log` schema does not include entropy, tunneling score, or an
alert identifier. An operator with only the structured logs cannot answer:

- What score did lippycat calculate for this query or domain?
- Which observations contributed to the decision?
- Did the score cross the configured threshold?
- Was an alert suppressed by debounce?
- Was an action attempted, and did it succeed?

Adding every detector-specific field to protocol logs would make those schemas
unstable. A separate `notice.log` is a cleaner compatibility boundary.

### Command hooks are the only durable security-alert action

Command hooks are flexible but place parsing, retries, authentication, and
delivery reliability in external scripts. There is no built-in notice log,
webhook sink, message-bus sink, or structured SIEM alert sink.

### No unified TUI or remote alert stream

There is no normalized security-notice event that the local or remote TUI can
subscribe to. Processor hierarchy and remote monitoring therefore cannot
present alerts consistently across nodes.

### No general rule framework

Built-in detectors can implement efficient stateful logic, but users cannot
currently define general conditions across DNS, TLS, HTTP, connections, and
files. Examples that require an external SIEM today include:

- a suspicious DNS response followed by TLS to the resolved address;
- a known JA3/JA4 fingerprint observed across many destinations;
- an executable downloaded over HTTP;
- repeated NXDOMAIN responses from one origin within a time window;
- a domain contacted for the first time and followed by an unusual upload.

## Comparison with Zeek Scripting

Zeek exposes protocol activity as runtime events. Scripts can maintain state,
correlate events, enrich records, create notices, suppress duplicates, and
invoke actions before or while logs are written.

lippycat currently has the same architectural ingredients in narrower forms:

```text
Packets
  -> normalized protocol events
  -> built-in stateful detector
  -> threshold and debounce
  -> command callback
```

Its general structured-log path is:

```text
Packets
  -> normalized protocol events
  -> transaction coalescing
  -> Zeek-style TSV or JSONL
  -> downstream SIEM rules
```

The missing layer is a general notice and policy boundary between normalized
events and output sinks. A full scripting language could eventually occupy
that boundary, but it is not required to make alerting coherent.

## Recommended Architecture

### Typed notice event

Add a shared notice type under `internal/pkg/events` or a dedicated
`internal/pkg/notices` package. A notice should represent a detector decision,
not a raw protocol event.

Suggested fields:

```go
type Notice struct {
    Timestamp    time.Time
    ID           string
    Type         string
    Category     string
    Severity     Severity
    Message      string
    Detector     string
    Score        float64
    Threshold    float64
    NodeID       string
    HunterID     string
    UID          string
    CommunityID  string
    SourceIPs    []netip.Addr
    Destination  string
    Evidence     map[string]any
    FirstSeen    time.Time
    LastSeen     time.Time
    Count        uint64
    Status       Status
}
```

The type should use stable category and severity enums. `Evidence` is useful
for detector-specific context, but frequently queried fields should remain
first-class and versioned.

### Notice dispatcher

Use the existing bounded asynchronous event-dispatch pattern:

```text
Detector
  -> bounded notice dispatcher
       -> notice.log sink
       -> TUI sink
       -> command sink
       -> webhook/SIEM sink
       -> remote processor stream
```

Requirements:

- packet processing must never wait on notice I/O;
- queues must be bounded and expose drops/pressure;
- slow sinks must not block other sinks;
- shutdown must drain accepted notices;
- sink failures must be logged with notice and sink identifiers;
- delivery retry belongs to sinks, not detectors.

Security-notice pressure should be observable, but it should not automatically
control hunter packet flow unless explicitly designed to do so.

### `notice.log`

Add a canonical schema to `internal/pkg/logschema` and writers in
`internal/pkg/logstream`. The filename and broad semantics should follow the
familiar Zeek convention while documenting lippycat-specific fields.

Candidate fields:

```text
ts uid community_id node_id hunter_id
notice_id note category severity message
detector score threshold
src dst domain
first_seen last_seen count status
evidence action action_status
```

The notice record should remain useful without the original PCAP. Protocol logs
should retain observations; `notice.log` should retain decisions and evidence.

### Adapt the DNS detector first

Keep `TunnelingDetector` responsible for statistics and scoring. Replace its
direct command-specific callback with notice publication, then implement the
existing command behavior as a notice sink or compatibility adapter.

This preserves current flags and behavior while enabling additional consumers:

```text
DNS tunneling detector
  -> DNS_TUNNELING notice
       -> notice.log
       -> existing command template
       -> TUI
```

The notice should include the existing alert fields plus threshold, debounce
state, and enough evidence to explain the score.

### Separate security and operational categories

The common envelope can support both, but consumers should be able to select:

- security detections;
- operational health alerts;
- policy/compliance notices;
- delivery and sensor failures.

Do not silently reclassify all internal log messages as notices. Notices must
represent actionable state with stable identity and lifecycle.

## Rule Engine Options

After a typed notice pipeline exists, lippycat can add user-defined rules
without coupling rule execution to output formats.

### Phase 1: declarative stateless rules

Support bounded predicates over one normalized event:

```yaml
rules:
  - id: suspicious-file-download
    event: files
    when:
      mime_type: application/x-dosexec
      source: HTTP
    notice:
      severity: high
      category: file-transfer
```

This covers allow/deny lists, suffix matching, fingerprint matching, unusual
ports, status codes, MIME types, and file hashes.

### Phase 2: bounded stateful correlation

Add explicit windows, grouping keys, thresholds, and bounded state:

```yaml
rules:
  - id: dns-failure-burst
    event: dns
    group_by: id.orig_h
    window: 60s
    when:
      rcode_name: NXDOMAIN
    threshold: 50
```

State limits, eviction behavior, late events, and shutdown semantics must be
part of the rule contract.

### Phase 3: embedded scripting only if justified

An embedded language could offer Zeek-like flexibility, but it also introduces
resource isolation, API stability, security, debugging, and deployment costs.
Candidate language evaluation should happen only after real declarative-rule
limitations are documented.

Any embedded runtime must have:

- CPU and memory limits;
- bounded event queues;
- no unrestricted filesystem or process execution by default;
- explicit capability grants for actions;
- versioned event APIs;
- deterministic shutdown and reload behavior.

## Suggested Delivery Phases

### Phase 1: notice foundation

- [ ] Define versioned notice types, severity, category, and lifecycle status.
- [ ] Implement a bounded notice dispatcher and sink interface.
- [ ] Add counters for emitted, dropped, delivered, and failed notices.
- [ ] Add graceful drain and shutdown behavior.

### Phase 2: DNS migration

- [ ] Convert `TunnelingAlert` into a typed DNS tunneling notice.
- [ ] Preserve current threshold and debounce semantics.
- [ ] Keep `--tunneling-command` through a compatibility command sink.
- [ ] Record score components as structured evidence.

### Phase 3: durable and interactive outputs

- [ ] Add versioned `notice.log` TSV and JSONL schemas.
- [ ] Add notice display and filtering to the TUI.
- [ ] Add notice delivery to remote monitoring clients.
- [ ] Expose notice and sink health in processor status.

### Phase 4: additional detectors and actions

- [ ] Adapt operational resource alerts to the common envelope.
- [ ] Add file/hash, TLS fingerprint, and connection-anomaly detectors where
  justified by bounded state and measurable signal quality.
- [ ] Add authenticated webhook or message-bus sinks.
- [ ] Add optional matching-PCAP retention as a notice action.

### Phase 5: user-defined rules

- [ ] Implement stateless declarative predicates.
- [ ] Add bounded windowed aggregation and correlation.
- [ ] Evaluate whether an embedded scripting language is still necessary.

## Operational and Security Considerations

### Command execution

The existing command hook is powerful and should remain opt-in. Template
values originate in observed network traffic and must never be interpolated
through an implicit shell. Prefer structured argument substitution, fixed
executables, concurrency limits, timeouts, and explicit logging of failures.

### Alert floods

Per-key debounce is necessary but insufficient for a generalized pipeline. Add
global rate limits, bounded queues, aggregation, and explicit drop metrics.
Never allow notices to exhaust memory during an attack.

### Delivery semantics

Document each sink as best-effort or durable. File logging can drain on graceful
shutdown; webhooks may require bounded retry and a dead-letter policy. Do not
claim exactly-once delivery without durable identifiers and storage.

### Distributed ownership

Stateful detection should run where the required context is complete:

- hunters may perform inexpensive local signatures;
- processors should own cross-hunter aggregation and correlation;
- tap should retain processor-equivalent detection locally;
- upstream processor hierarchies need an explicit deduplication/ownership rule.

Notice IDs must remain stable enough to suppress duplicates when notices cross
processor boundaries.

### Explainability

Every detection should identify its detector version, threshold, score, and
supporting evidence. This is essential for tuning, incident review, and false
positive analysis.

## Success Criteria

The notice pipeline is successful when:

1. DNS tunneling alerts produce the same command behavior as today and also
   create durable, structured notices.
2. A slow or failed notice sink cannot block packet processing or other sinks.
3. Operators can correlate a notice with `dns.log`, `conn.log`, `ssl.log`,
   `http.log`, `files.log`, and retained PCAP.
4. TUI and remote clients consume the same typed notices without parsing log
   files or command output.
5. Drops, retries, delivery failures, and debounce decisions are observable.
6. New detectors publish notices without implementing their own delivery and
   lifecycle infrastructure.

## Conclusion

lippycat already contains a meaningful real-time alerting capability. DNS
tunneling detection proves that it can maintain bounded state, score behavior,
apply alert policy, and trigger actions. The next step is not to replace that
work with a scripting language; it is to extract the reusable alert concepts
into a typed notice pipeline.

Structured protocol logs remain valuable as durable observations for SIEMs and
investigations. A notice pipeline would complement them with durable decisions,
explanation, and actions. Once that boundary exists, built-in detectors,
declarative rules, and a possible future scripting runtime can all publish
through the same safe and observable mechanism.
