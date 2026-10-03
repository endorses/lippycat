# Zeek-Style Log Expansion Assessment

**Date:** 2026-08-28
**Codebase reassessment:** 2026-10-03
**Status:** Research
**Related:** `internal/pkg/events`, `internal/pkg/logschema`,
`internal/pkg/logstream`, `internal/pkg/detector`,
`internal/pkg/protocolmeta`, `internal/pkg/conntrack`,
`internal/pkg/eventanalysis`, `internal/pkg/eventquery`,
`api/proto/events/v1`, `internal/pkg/tui`

## Executive Summary

lippycat supports eleven structured streams. The default seven remain
`conn.log`, `dns.log`, `ssl.log`, `http.log`, `smtp.log`, `files.log`, and
`radius.log`; `dhcp.log`, `ntp.log`, `known_hosts.log`, and `known_services.log`
are opt-in additions from the first expansion wave. RADIUS is a
lippycat message-observation schema, not a claim of Zeek RADIUS compatibility.
Its packet detector already recognizes considerably more protocols, including
DHCP, NTP, SSH, FTP,
PostgreSQL, QUIC, ICMP, and multiple VPN and tunneling protocols.

The immediate limitation is not always packet recognition. Rich generic
detector results are generally reduced to a protocol name and display string
before they reach the structured-event pipeline. However, the shared event
platform is now implemented: hunter, processor, tap, and local/offline TUI paths
reuse `eventanalysis.Runtime`; remote TUI clients consume typed subscriptions.
The runtime produces DNS, SMTP, TLS, HTTP, RADIUS, DHCPv4, and NTP events, with
connection, file, and explicitly configured inventory events produced through
lifecycle components. Versioned event
transport, identity, provenance, delivery-loss reporting, and reliable ingress
are available for new protocol kinds to reuse.

This creates three implementation classes:

1. **Primarily plumbing and bounded state:** the remaining `software.log`,
   `traceroute.log`, `tunnel.log`, and an initial `reporter.log`. DHCP, NTP,
   known hosts, and known services now have typed production and delivery.
2. **Useful partial logs with current parsers:** `ssh.log`, `ftp.log`,
   `postgresql.log`, `quic.log`, and an initial `notice.log`. These need deeper
   session analysis or finding/policy semantics for Zeek-like fidelity.
3. **New analysis subsystems:** `x509.log`, `pe.log`, the SMB/DCE-RPC/Kerberos/
   NTLM family, `irc.log`, LDAP logs, `rdp.log`, and comprehensive analyzer,
   weird, notice, and capture-loss diagnostics. `known_certs.log` depends on
   the new certificate extraction needed for `x509.log`.

The implemented first wave covers DHCP, NTP, known hosts, and known services.
Software, traceroute, tunnels, and reporter diagnostics remain follow-on work
on the existing runtime, event contract, transport, log sinks, and TUI projections.
The remaining foundation work is protocol-specific observation preservation,
correlation, and integration. Node-level diagnostics additionally need a model
that does not require a packet flow. A second event pipeline is unnecessary.

## Scope and Interpretation

This report assesses the common log families listed in Zeek's log reference,
not every optional log shipped by Zeek or third-party Zeek packages. Zeek's
current reference divides its logs among protocol analysis, detection, network
observations, miscellaneous analysis, and diagnostics:

- <https://docs.zeek.org/en/current/reference/logs/index.html>
- <https://docs.zeek.org/en/master/reference/zeekscript/log-files.html>

"Implementable with current capabilities" does not mean that the log file can
be enabled without code changes. It means lippycat already extracts most of the
underlying observation and primarily needs typed metadata transport, event and
schema definitions, mapping, bounded correlation, and tests. Logs that require
decoding a new protocol or reconstructing an unimplemented session are treated
as new capabilities.

The October reassessment covers repository implementation changes. The Zeek
references below retain the original comparison scope; this is not a fresh
audit against every current Zeek release.

## Current Structured-Log Baseline

The canonical schema registry defines:

| Current stream | Main source |
|---|---|
| `conn.log` | Bounded direction-aware connection tracking |
| `dns.log` | DNS parser and query/response tracking |
| `ssl.log` | TLS handshake metadata and fingerprints |
| `http.log` | HTTP request/response metadata |
| `smtp.log` | SMTP and message metadata |
| `files.log` | HTTP/SMTP file observation, hashing, and extraction |
| `radius.log` | Validated RADIUS message observations and bounded request association |
| `dhcp.log` | DHCPv4 messages with bounded client/XID/relay association |
| `ntp.log` | NTP time-message modes 1–5 with exact wire fields and bounded association |
| `known_hosts.log` | Observed eligible unicast endpoints proven by observed TCP handshake or bidirectional UDP |
| `known_services.log` | Observed eligible unicast responders with handshake/application or matched UDP protocol evidence |

The normalized event model contains twelve kinds: eleven metadata kinds cross
the versioned event API, while file content stays local and outside the TUI
metadata store. DHCP/NTP add independent message observations. Inventory derives
once when local packet analysis confirms sufficient evidence and retains the
qualifying flow envelope;
event ingress and hierarchy relay the resulting source event without deriving
it again. Existing seven-stream defaults remain unchanged.

Inventory events are enabled by default; optional local CIDRs filter subjects.
Inventory log streams remain opt-in. Its bounded
retention is an observation deduplication policy, not persistent asset identity.
Protocol/profile compatibility remains additive: codec support is separate from
inventory production policy; required streams fail clearly when unavailable.

RADIUS demonstrates the current extension pattern: typed observations feed
normalized events, protobuf adapters, canonical records, and TUI query
projection. Its public attributes are allowlisted; credentials, authenticators,
and raw packet bytes are excluded. A message observation or request association
does not establish authenticated identity or a complete subscriber session.

### Implemented event paths

| Path | Current behavior |
|---|---|
| Hunter | Packet forwarding remains the default; negotiated event mode runs the shared runtime and forwards normalized events through a separate bounded spool |
| Processor | Produces events from packet sources when analysis is enabled, admits event-mode sources without re-deriving their events, and supports upstream event relay |
| Tap | Reuses processor analysis and event delivery with local capture; can retain local PCAP evidence while forwarding events upstream |
| TUI live/file | Uses the shared runtime for local capture and deterministic offline analysis |
| TUI remote | Consumes `SubscribeEvents`, tracks compatibility omissions and delivery gaps, and can analyze explicitly designated monitoring packet streams with filtered/partial provenance |

Event mode negotiates supported kinds and analysis capabilities. Incompatible
sessions fail unless explicit packet fallback is configured. Reliable ingress
acknowledges recoverable processor WAL admission; memory-only admission has
weaker durability. Neither implies exactly-once durable output at every sink.
Relays preserve origin identity and append hop provenance.

TUI subscriptions are live-only: reconnect information reports gaps rather than
replaying missed events. Subscriber loss is distinct from ordinary eviction of
already-received rows from the bounded TUI store. Analysis remains
configuration- and demand-driven; these paths do not imply every packet-mode
deployment always generates every event kind.

The generic detector has broader coverage. It registers signatures for QUIC,
DHCP, NTP, SSH, SNMP, FTP, PostgreSQL, several database and application
protocols, ICMP, ARP, and OpenVPN, WireGuard, L2TP, PPTP, and IKE. However,
central enrichment currently preserves generic results as `Protocol` and
`Info`; only SIP and RTP receive typed protocol-specific mapping in that path.

This distinction is central to the estimates below: detection is not the same
as a durable, flow-oriented protocol analyzer.

### Implementation references

- [Canonical schemas](../../internal/pkg/logschema/schema.go),
  [normalized events](../../internal/pkg/events/events.go), and
  [RADIUS event](../../internal/pkg/events/radius.go).
- [Shared analysis runtime](../../internal/pkg/eventanalysis/runtime.go) and
  [TCP/application reassembly](../../internal/pkg/eventanalysis/tcp_reassembly.go).
- [Hunter integration](../../internal/pkg/hunter/hunter.go),
  [processor/tap integration](../../internal/pkg/processor/protocol_events.go),
  and [upstream event relay](../../internal/pkg/processor/upstream/event_router.go).
- [Versioned wire contract](../../api/proto/events/v1/events.proto),
  [ingress](../../internal/pkg/processor/event_ingress.go), and
  [subscription service](../../internal/pkg/processor/event_service.go).
- [Local TUI bridge](../../internal/pkg/tui/bridge.go),
  [offline indexer](../../internal/pkg/tui/offline_indexer.go), and
  [remote subscriptions](../../internal/pkg/remotecapture/client_streaming.go).
- [Generic enrichment gap](../../internal/pkg/processor/enrichment/enricher.go)
  and [current typed mappings](../../internal/pkg/eventanalysis/mapping.go).
- [Event validation and adapters](../../internal/pkg/events/protoadapter/adapter.go),
  [query projection](../../internal/pkg/eventquery/projection.go), and
  [TUI detail rendering](../../internal/pkg/tui/components/eventsview.go).

## Logs Feasible with Existing Capabilities

### Readiness matrix

| Log | Readiness | Existing usable capability | Remaining work |
|---|---|---|---|
| `known_hosts.log` | Implemented, opt-in | Positive connection evidence and explicit local CIDRs | Persistent asset identity is out of scope |
| `known_services.log` | Implemented, opt-in | Confirmed TCP/application and matched DNS/NTP/DHCP exchanges | Broader protocol evidence remains future work |
| `software.log` | Medium-high | SSH banners, HTTP user-agent/server data, SMTP metadata, TLS fingerprints | Typed product/version normalization, metadata preservation, deduplication |
| `dhcp.log` | Implemented, opt-in | Typed bounded DHCPv4 decoder and message association | DHCPv6 and complete lease history excluded |
| `ntp.log` | Implemented, opt-in | Exact header fields/timestamps and bounded client/server association | Authentication, NTS and control/private formats excluded |
| `ssh.log` | Medium | SSH banner, protocol version, software, and comments | Bidirectional banner correlation and history; deeper handshake parsing for algorithms, keys, and auth status |
| `ftp.log` | Medium | Commands, redacted arguments, response codes/messages, multiline flag; reusable bounded TCP reassembly | Control-stream parser integration, session state, request/reply and data-channel correlation |
| `postgresql.log` | Medium-low | Startup and SSL requests, startup parameters, cancel requests, and message names | TCP framing/state; query arguments, backend results, success, and row counts |
| `quic.log` | Medium-low | QUIC header/version and connection-ID lengths | Extract actual CIDs; bidirectional connection state, Initial decryption/TLS extraction, ALPN, and history |
| `traceroute.log` | Medium-high | ICMP type/code plus IP and transport observations | Correlate low-TTL probes with Time Exceeded replies; false-positive suppression |
| `tunnel.log` | Medium-high | OpenVPN, WireGuard, L2TP, PPTP, and IKE detection and metadata | Typed preservation, session/action tracking, and outer/inner flow association |
| `known_certs.log` | Blocked on certificate extraction | TLS endpoint, SNI, and fingerprint context; reusable handshake reassembly | X.509 certificate extraction and identity; bounded certificate deduplication |
| `reporter.log` | High for local adapter; distributed model needed | Structured warnings/errors, categorized event losses, subsystem counters | Non-flow diagnostic model, non-recursive logger sink, stable component/location fields, rate limiting |
| `notice.log` | Medium, limited | DNS tunneling scores and TLS risk flags in analyzer metadata; malformed-input and capacity conditions | Preserve findings in typed events; severity/actions, evidence, suppression, and policy configuration |

### `known_hosts.log`

Implemented from locally produced connection summaries. An observed complete TCP
three-way handshake or bidirectional UDP traffic qualifies each local endpoint.
A lone SYN, offered DHCP address, cached label, or destination alone does not.
Explicit IPv4/IPv6 local CIDRs exclude special and configured broadcast subjects.
Emission waits for summary availability at expiry, eviction, EOF, reset, or close.

Deduplication is bounded globally and per sensor/epoch/interface/input scope by
entry and accounted-byte limits. Capture-time retention, deterministic eviction,
and counters make later re-emission explicit. Independent sensors remain separate.

### `known_services.log`

Implemented with a separate responder subject in the qualifying flow envelope.
TCP requires an observed handshake plus actual HTTP/TLS/SMTP analysis. UDP
requires decoded request/response roles and a successful same-flow DNS, NTP, or
DHCP match; broadcast and relay DHCP endpoints cannot establish services.
Port numbers and cached protocol labels never suffice. Unsupported or ambiguous
responders are omitted. Subscriber policy omits inventory without sensitive-field
authorization and reports the omission explicitly.

### `software.log`

Several current analyzers expose software hints:

- SSH protocol banners contain implementation and version strings.
- HTTP metadata includes user-agent and server headers.
- SMTP events have a user-agent field, although current metadata mapping is
  incomplete.
- TLS fingerprints and ALPN can identify implementations probabilistically,
  but should not be reported as a definitive product without an explicit
  fingerprint database and confidence field.

These hints are not uniformly available to event-only consumers. HTTP
user-agent is mapped, but server software is only available through optional
headers rather than a dedicated normalized field. SMTP's user-agent field is
not populated by the current runtime mapping, and SSH still needs typed
preservation. Extraction should happen at the analysis authority or the needed
evidence must be added to its metadata events; an upstream processor cannot
recover omitted fields from event-only delivery.

A common software observation should carry host, direction, software type,
name, version, evidence source, confidence, UID, and node. Product parsing must
be conservative because banner formats are not standardized.

### `dhcp.log`

Implemented as one record per accepted DHCPv4 message, including retransmissions.
The detector and runtime share a bounded decoder for fixed headers, overloaded
option areas, and repeated options. Binary hardware/client identifiers are
preserved safely; malformed optional data is explicitly partial. Unknown/vendor
options are not exported. Bare BOOTP detection remains available outside this log.

Bounded association uses origin/epoch/source, client identity, transaction ID and
relay context, retaining server distinctions. It never rewrites the observed
broadcast/unicast flow UID or fabricates a completed lease transaction. Fields
include addresses, server identifier, requested address, lease, selected names,
router/DNS lists, parameter requests, and association state. Names and client/
hardware identifiers follow subscriber sensitive-field projection. DHCPv6 and
complete lease history remain excluded.

### `ntp.log`

Implemented as one record per standard time-message datagram (modes 1–5).
Signed poll/precision, exact fixed-point root delay/dispersion, raw reference ID,
and all four raw timestamps are preserved. Converted eras are resolved nearest
capture time; wire zero means unavailable. Reference-ID interpretation is
contextual rather than always IPv4. Bounded client/server association uses
endpoints and echoed request timestamp; ambiguous/unmatched messages remain
independent observations. No sniffer-derived clock offset or server authentication
is claimed. NTS, control/private formats, and authentication analysis are excluded.

### `ssh.log`

An initial SSH log can record client and server banners, protocol version,
software, and connection history. These fields are visible before SSH
encryption begins.

Zeek-like fields such as negotiated cipher, MAC, compression, key exchange,
host-key fingerprint and authentication result require parsing SSH binary
transport and handshake state. User authentication is normally encrypted, so
success cannot generally be determined through passive capture unless the
analyzer infers it from encrypted message sizes/state or has decryption keys.
The initial log should explicitly mark unavailable fields rather than infer
authentication outcomes from an established TCP connection.

### `ftp.log`

The FTP signature already recognizes commands and replies and redacts `PASS`
arguments. A reliable log nevertheless needs a reassembled control stream and
session state: commands and replies may cross TCP segments, replies can be
multiline, and requests must be correlated with responses.

The shared runtime already has bounded TCP reassembly. Extend its application
dispatch with FTP framing and session handling rather than building another
general reassembler.

For full value, the analyzer should track login user, current directory,
transfer command, filename, reply code, and passive/active endpoint
negotiation. Data-channel flows then need to be associated with the control UID
and fed to file analysis.

### `postgresql.log`

The current signature recognizes PostgreSQL startup framing, SSL requests,
startup parameters, cancel requests, and generic message types. That is enough
for a partial startup/activity log after typed metadata preservation.

The existing bounded TCP infrastructure can be reused, but PostgreSQL framing
and session dispatch are not implemented there.

Zeek's current PostgreSQL output includes user, database, application name,
frontend operation and argument, backend result, success, and row count. Those
require a stateful framed TCP analyzer for both directions, including simple
and extended query flows and PostgreSQL's transition to TLS:

<https://docs.zeek.org/en/current/reference/logs/postgresql.html>

### `quic.log`

The existing QUIC signature recognizes long and short headers and extracts
selected header metadata, including connection-ID lengths. It does not yet
preserve the actual connection-ID bytes. A partial log can expose version and
existing header fields; actual CIDs need explicit extraction and typed mapping.

A useful Zeek-like log needs flow state across changing QUIC connection IDs,
client/server Initial correlation, QUIC Initial key derivation and decryption,
TLS ClientHello extraction, ALPN, retry/version-negotiation handling, and a
connection history. Zeek's principal QUIC fields include version, initial
destination/source connection IDs, client protocol, and history:

<https://docs.zeek.org/en/lts/logs/quic.html>

### `traceroute.log`

The current ICMP detector exposes type, code, identifier, sequence, gateway,
and selected error metadata. Connection envelopes supply the endpoints and
transport. A bounded correlator can detect repeated low-TTL probes and ICMP
Time Exceeded responses, then emit timestamp, source, destination, and probe
protocol. This is a small log once detection is trustworthy:

<https://docs.zeek.org/en/master/logs/traceroute.html>

### `tunnel.log`

lippycat already detects OpenVPN, WireGuard, L2TP, PPTP, and IKEv1/v2. Existing
metadata includes useful message types, phases, exchange identifiers, tunnel
and session IDs, and control/data distinctions depending on the protocol.

An initial tunnel log can describe the outer flow, tunnel type, version,
action/message type and node. Full outer-to-inner association requires actual
decapsulation. Some tunnels are encrypted and cannot expose inner flows without
keys; the schema should distinguish detection, established session, and
successfully decoded encapsulated traffic.

### `reporter.log`

lippycat already emits structured internal logs and maintains counters for
event drops, log drops, queue pressure, source drops, connection-tracker
evictions, and reassembly limits. An initial reporter stream can adapt selected
warnings/errors into a rotating structured file.

The event API already carries separate capture, analysis, dispatch, buffer,
transport, subscriber, compatibility, policy-omission, and reconnect loss
categories. These are useful diagnostic inputs, not existing reporter records.
Its current envelope validator requires valid source/destination IP addresses
and a nonzero protocol. Node-level warnings therefore need an explicit non-flow
diagnostic contract or a separate diagnostic path; they should not invent
packet endpoints to fit the current model.

The adapter must not feed failures from `reporter.log` back into itself. Stable
error codes, component, source/node, level and message fields are preferable to
depending only on free-form text. Rate limiting and a stderr fallback are
required for failure storms.

### Initial `notice.log`

An initial notice catalogue can use findings that already exist, especially
DNS tunneling alerts and TLS risk flags. The related notice-pipeline research
in `docs/research/alerting-and-notice-pipeline.md` describes the broader design.

The current DNS and TLS normalized-event mappers omit tunneling/entropy scores
and risk scores/flags respectively. Preserve these findings in typed payloads
or emit typed notices at the producer before assuming that an event-only
processor can evaluate them. The event platform supplies delivery, not the
missing finding semantics or notice policy.

This should remain distinct from `reporter.log`: notices describe inspection-
worthy network findings, whereas reporter records describe lippycat's own
operation. Zeek makes the same conceptual distinction:

<https://docs.zeek.org/en/current/reference/logs/weird-and-notice.html>

## Logs Requiring New Capabilities

### `x509.log`

The current TLS event and `ssl.log` schema reserve certificate file IDs,
subjects, issuers, and validation status, but the TLS event mapper currently
populates only handshake version, SNI, cipher/group, ALPN, establishment state,
and JA3/JA3S/JA4.

The shared runtime already reassembles TLS records and handshake messages
across TCP segments, with regression coverage. The parser currently extracts
ClientHello/ServerHello metadata; certificate parsing and association remain
new work on top of that infrastructure.

Required work:

- [ ] Extend existing TLS handshake reassembly/dispatch to certificate analysis.
- [ ] Parse TLS 1.2 and TLS 1.3 `Certificate` messages.
- [ ] Decode DER X.509 certificates.
- [ ] Generate stable FUIDs and associate certificates with `ssl.log` and
      `files.log`.
- [ ] Extract subject, issuer, serial, validity, SANs, public-key properties,
      signature algorithm, and constraints.
- [ ] Validate chains against a configurable trust store.
- [ ] Deduplicate certificates for `known_certs.log`.

### `pe.log`

The current file analyzer can identify, hash, and optionally extract bounded
HTTP and SMTP file content, but it does not parse executable formats.

Required work:

- [ ] Detect PE files by magic and structure rather than filename alone.
- [ ] Add a bounded PE/COFF parser.
- [ ] Extract architecture, compile timestamp, subsystem, section table,
      imports/exports, linker/OS versions, and certificate-table metadata.
- [ ] Support incremental or securely spooled parsing beyond body-preview limits.
- [ ] Preserve explicit truncated/incomplete state.
- [ ] Optionally parse and validate Authenticode signatures.

### SMB, DCE-RPC, Kerberos, and NTLM logs

lippycat has no SMB analyzer. Zeek's SMB processing can generate
`smb_cmd.log`, `smb_files.log`, `smb_mapping.log`, `dce_rpc.log`,
`kerberos.log`, `ntlm.log`, `pe.log`, and notices:

<https://docs.zeek.org/en/lts/logs/smb.html>

Required SMB work includes:

- [ ] Integrate NetBIOS Session Service framing with the bounded TCP reassembler.
- [ ] SMB1, SMB2, and SMB3 header and command parsers.
- [ ] Request/response, session, tree, file-handle, and compound-command state.
- [ ] Share/path mapping and file-content reconstruction.
- [ ] Signing metadata and SMB3 encryption detection.
- [ ] Bounded per-session state, retransmission handling, and timeout cleanup.

Associated analyzers require DCE/RPC PDU and bind-context decoding,
SPNEGO/GSS-API handling, NTLMSSP challenge/response metadata, and Kerberos
ASN.1 request, response, ticket, and error parsing. This is a new protocol
analysis subsystem rather than a set of log mappers.

### `irc.log`

Required work:

- [ ] Add IRC detection and a line parser using the bounded TCP reassembler.
- [ ] Track client/server direction and session identity.
- [ ] Parse registration, nick, user, join, part, quit, mode, topic, messages,
      numeric replies, IRCv3 tags, and capability negotiation.
- [ ] Hand TLS-wrapped IRC to TLS analysis; application contents require configured
      TLS decryption.

### `ldap.log` and `ldap_search.log`

Required work:

- [ ] Implement TCP/UDP LDAP framing and BER/ASN.1 decoding.
- [ ] Correlate transactions by message ID.
- [ ] Parse bind, unbind, modify, add, delete, compare, and extended operations.
- [ ] Parse search base, scope, dereference mode, filter AST, and attributes.
- [ ] Correlate results, result codes, and returned object counts.
- [ ] Support StartTLS and SASL while strictly redacting credentials and sensitive
      attribute values.

### `rdp.log`

Required work:

- [ ] Parse TPKT and X.224 framing and negotiation.
- [ ] Decode MCS/GCC connection setup and virtual-channel negotiation.
- [ ] Extract client core, security, and network metadata.
- [ ] Integrate CredSSP/SPNEGO observations.
- [ ] Hand off TLS and associate certificates.
- [ ] Optionally parse legacy Standard RDP Security; modern encrypted content
      remains opaque without keys.

Zeek's RDP overview is available at:

<https://docs.zeek.org/en/current/reference/logs/rdp.html>

### `analyzer.log`

This log is not just an inventory of detected protocols. A robust implementation
requires a common lifecycle for protocol, packet, and file analyzers:

- candidate/attach;
- confirm or reject;
- detach/complete;
- parse violation;
- unsupported feature;
- internal analyzer error.

Every analyzer needs stable identifiers, typed outcomes, UID/FUID association,
and rate-limited structured diagnostics. Detector confidence and protocol
misclassification can be recorded without turning normal detection into noisy
debug output. Zeek describes this stream as analyzer violations/debug
information in its log reference:

<https://docs.zeek.org/en/master/reference/zeekscript/log-files.html>

### `weird.log`

Zeek weirds represent unexpected network or protocol conditions encountered by
analyzers, while notices represent higher-level findings. lippycat needs:

- typed anomaly hooks in packet decoding, IP defragmentation, TCP tracking, and
  protocol parsers;
- a stable anomaly-name catalogue;
- packet, connection, host, file, and node context;
- per-anomaly sampling, suppression, and counters;
- explicit handling for malformed lengths, invalid state transitions,
  overlapping fragments, sequence inconsistencies, and unexpected messages.

`analyzer.log` and `weird.log` should share instrumentation and error taxonomy
instead of being implemented independently.

### Full `notice.log`

Moving beyond the initial built-in findings requires a policy layer consuming
normalized events and maintaining bounded correlation state. It should provide
typed categories, severity, evidence, actions, per-key suppression, allowlists,
threshold configuration, and cross-event correlation. A general scripting
language is not required for the first version, but the event and notice APIs
should not prevent one later.

### `capture_loss.log`

lippycat already counts user-space source/buffer drops and exposes TCP
reassembly gap counters. These are useful inputs but do not reproduce Zeek's
loss estimate, which compares TCP sequence gaps with observed acknowledgements:

<https://docs.zeek.org/en/current/reference/logs/capture-loss-and-reporter.html>

Required work:

- [ ] Periodically sample per-interface and per-node statistics.
- [ ] Read kernel/libpcap drop counters in addition to user-space queue drops.
- [ ] Track TCP ACKs and sequence gaps.
- [ ] Separate actual loss from BPF and application filtering.
- [ ] Emit interval, peer/interface, gap count, ACK count, and loss percentage.
- [ ] Aggregate hunter-side, transport, and processor losses without conflating
      them.
- [ ] Handle counter resets and node reconnects.

The current TCP assembler's missing-sequence metric explicitly describes absent
sequence space observed during bounded reassembly, not necessarily packets
dropped by lippycat. It must not be relabeled as capture loss without the
additional accounting above.

Reuse the existing event loss categories, producer-session identities, and
source provenance for delivery accounting. They do not implement the missing
TCP ACK/gap estimator, and TUI ring eviction must remain separate from capture
and transport loss.

## Cross-Cutting Architecture Recommendation

Extend the existing analysis and event platform with typed observations for
each new protocol. The implemented paths are:

```text
accepted packets / reassembled streams
        |
        v
shared eventanalysis.Runtime at the analysis authority
        |
        v
typed normalized events + identity / provenance / partial state
        |
        +-- local dispatcher -> logs / local TUI / authorized consumers
        |
        +-- events.v1 ingress -> processor dispatcher
                                   |
                                   +-- structured logs / authorized consumers
                                   +-- SubscribeEvents -> remote TUI
                                   +-- upstream event relay
```

Packet mode sends packets to the designated analysis authority; event mode
produces the normalized observations at the edge. A relay preserves producer
identity rather than repeating analysis. The runtime is also used for local
sniff and watch paths, including offline input. This architecture exists today;
notice policy and the candidate protocol kinds remain additions.

Generic detector metadata is still represented as `map[string]interface{}` and
mostly collapsed into a protocol name and display string. Fix this at the
producer boundary for each candidate protocol. Reuse one typed protocol model
and the canonical record/query projection rather than adding independent
parsers or field definitions in processor, log writer, and TUI code.

The existing platform already supplies flow UID/Community ID, producer identity,
capture scope, provenance, partial state, sequencing, retry deduplication,
versioned adapters, and content exclusion. Each new kind must define its own
fields, direction and observation-versus-transaction semantics, bounded
correlation state, truncation behavior, and sensitive-field projection. Retry
deduplication does not replace host/service inventory deduplication or
protocol-specific correlation; cross-sensor observation merging is not implied.

Extend `events.v1` payloads, adapters, supported-kind negotiation, and relevant
required profiles together. Preserve compatibility omissions and explicit
fallback behavior. New metadata kinds must remain separate from content and
LI-specific authorization or evidence handling. Reporter and other non-flow
diagnostics need a deliberate envelope design before using the event API.

TUI details already use `logschema` and `eventquery.Project`, which selects
canonical record builders. New kinds need projection, summary, filter, and
protocol-scope integration, not a new presentation transport. Preserve
live-only subscription semantics, independent subscriber buffering, and the
distinction between transport loss and local store eviction.

## Recommended Roadmap

### Phase 0: extend the implemented event platform

The shared runtime, event API, spool/WAL delivery, subscriptions, and TUI event
store are baseline capabilities. Remaining integration work should accompany
each stream rather than become a second infrastructure project:

- [ ] Define protocol-specific typed observations and completion semantics,
      preserving useful detector fields in the shared runtime.
- [ ] Extend normalized events, additive protobuf payloads, adapters, and
      capability/required-profile lists; add packet metadata only where needed.
- [ ] Implement bounded protocol correlation or inventory deduplication using
      existing identity, direction, provenance, and lifecycle facilities.
- [ ] Add canonical schemas/records and query/TUI projections, summaries,
      filters, and relevant protocol scopes.
- [ ] Define sensitive-field projection and extend compatibility, mixed-version,
      producer-parity, and delivery tests for each new kind.
- [ ] Resolve non-flow diagnostic modeling before distributed reporter output.

### Phase 1: high-value, low-parser-cost streams

- [x] `dhcp.log`
- [x] `ntp.log`
- [x] `known_hosts.log`
- [x] `known_services.log`
- [ ] `software.log`
- [ ] `traceroute.log`
- [ ] `tunnel.log`
- [ ] Initial `reporter.log`

### Phase 2: partial protocol streams and notices

- [ ] Banner-level `ssh.log`
- [ ] Reassembled control-session `ftp.log`
- [ ] Startup/activity `postgresql.log`
- [ ] Header/Initial-level `quic.log`
- [ ] Initial built-in `notice.log`
- [ ] Analyzer lifecycle and anomaly taxonomy design

Each partial stream should document its supported fields and emit explicit
partial/truncated state rather than silently resembling full Zeek fidelity.

### Phase 3: TLS and file depth

- [ ] Certificate decoding/linkage using existing handshake reassembly and `x509.log`
- [ ] Populate certificate fields in `ssl.log`
- [ ] `known_certs.log`
- [ ] Streaming/spooled file analysis
- [ ] PE parsing and `pe.log`

### Phase 4: major protocol analyzers

Prioritize according to deployment demand:

- [ ] SMB plus DCE-RPC, NTLM, and Kerberos
- [ ] LDAP
- [ ] RDP
- [ ] IRC

### Phase 5: operational and analysis parity

- [ ] `analyzer.log`
- [ ] `weird.log`
- [ ] Full notice policy and action framework
- [ ] Zeek-style TCP-based `capture_loss.log`
- [ ] Expanded reporter and sensor health telemetry

## Acceptance Criteria for Any New Stream

A new stream should not be considered complete merely because it writes a
file. It should include:

- [ ] A canonical output-neutral schema in `internal/pkg/logschema` and typed
      normalized events in `internal/pkg/events`.
- [ ] Shared-runtime production at the appropriate analysis authority, with
      per-protocol state bounded and flushed at EOF/session boundaries.
- [ ] Additive event API payloads/adapters, capability negotiation, and mixed-version
      behavior; packet metadata evolution where that path needs it.
- [ ] Bounded, non-blocking live production with explicit loss accounting;
      bounded lossless offline delivery where deterministic completeness is required.
- [ ] Deterministic direction, flow UID, producer identity, and origin provenance,
      with retry/relay identity preservation.
- [ ] Explicit partial/truncated semantics and observation-versus-transaction
      behavior, including any coalescing before log output.
- [ ] Sensitive-field authorization/redaction and exclusion of content from the
      generic metadata transport and TUI store.
- [ ] TSV and JSONL record tests, plus canonical query projection, summary,
      filtering, and relevant TUI scope coverage.
- [ ] Applicable rotation, queue-pressure, graceful-drain, and error-path tests,
      extending the existing sink/delivery coverage rather than rebuilding it.
- [ ] Live, offline, tap, packet-mode, event-mode, and hierarchical-path coverage
      where applicable, including subscriber loss versus local ring eviction.
- [ ] Documentation of intentional differences from Zeek and unavailable fields.

## Conclusion

lippycat now has an implemented event platform spanning hunter, processor,
tap, and TUI, with eleven metadata streams including opt-in DHCP, NTP, known
hosts, and known services. The new protocol messages and bounded, evidence-backed
inventories reuse that platform without changing the default seven streams.
Software, traceroute, and tunnel logs still require preservation of additional
observations and bounded correlation. Reporter output can reuse diagnostic
inputs but needs a non-flow model for distributed delivery.

X.509 and PE analysis, SMB and its authentication ecosystem, IRC, LDAP, RDP,
and comprehensive anomaly diagnostics require new analyzers or
analysis infrastructure. Treating signature detection as equivalent to a
session analyzer would produce superficially compatible but operationally
misleading logs. The remaining work is to extend typed protocol production,
state, and consumer projections on the shared runtime and transport, while
reusing the TCP and TLS reassembly already implemented.
