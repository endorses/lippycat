# Zeek-Style Log Expansion Assessment

**Date:** 2026-08-28
**Status:** Research
**Related:** `internal/pkg/events`, `internal/pkg/logschema`,
`internal/pkg/logstream`, `internal/pkg/detector`,
`internal/pkg/protocolmeta`, `internal/pkg/conntrack`

## Executive Summary

lippycat currently emits six Zeek-style streams: `conn.log`, `dns.log`,
`ssl.log`, `http.log`, `smtp.log`, and `files.log`. Its packet detector already
recognizes considerably more protocols, including DHCP, NTP, SSH, FTP,
PostgreSQL, QUIC, ICMP, and multiple VPN and tunneling protocols.

The immediate limitation is not always packet recognition. Rich generic
detector results are generally reduced to a protocol name and display string
before they reach the structured-event pipeline. The processor only maps DNS,
SMTP, TLS, and HTTP metadata into protocol events; connection and file events
are produced through separate lifecycle components.

This creates three implementation classes:

1. **Primarily plumbing and bounded state:** `dhcp.log`, `ntp.log`,
   `known_hosts.log`, `known_services.log`, `software.log`, `traceroute.log`,
   `tunnel.log`, and an initial `reporter.log`.
2. **Useful partial logs with current parsers:** `ssh.log`, `ftp.log`,
   `postgresql.log`, `quic.log`, `known_certs.log`, and an initial
   `notice.log`. These need deeper session analysis for Zeek-like fidelity.
3. **New analysis subsystems:** `x509.log`, `pe.log`, the SMB/DCE-RPC/Kerberos/
   NTLM family, `irc.log`, LDAP logs, `rdp.log`, and comprehensive analyzer,
   weird, notice, and capture-loss diagnostics.

The recommended first wave is DHCP, NTP, known hosts, known services, software,
traceroute, tunnels, and reporter diagnostics. Before implementing these one by
one, lippycat should establish a typed detector-to-event boundary so the same
observations can serve distributed transport, structured logs, notices, LI,
and the TUI without protocol-specific duplication.

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

## Current Structured-Log Baseline

The canonical schema registry defines only:

| Current stream | Main source |
|---|---|
| `conn.log` | Bounded direction-aware connection tracking |
| `dns.log` | DNS parser and query/response tracking |
| `ssl.log` | TLS handshake metadata and fingerprints |
| `http.log` | HTTP request/response metadata |
| `smtp.log` | SMTP and message metadata |
| `files.log` | HTTP/SMTP file observation, hashing, and extraction |

The normalized event model similarly contains only DNS, SMTP, TLS, HTTP,
connection, file-metadata, and file-content event kinds. In the processor,
packet metadata is mapped to events only when DNS, email, TLS, or HTTP typed
metadata is present.

The generic detector has broader coverage. It registers signatures for QUIC,
DHCP, NTP, SSH, SNMP, FTP, PostgreSQL, several database and application
protocols, ICMP, ARP, and OpenVPN, WireGuard, L2TP, PPTP, and IKE. However,
central enrichment currently preserves generic results as `Protocol` and
`Info`; only SIP and RTP receive typed protocol-specific mapping in that path.

This distinction is central to the estimates below: detection is not the same
as a durable, flow-oriented protocol analyzer.

## Logs Feasible with Existing Capabilities

### Readiness matrix

| Log | Readiness | Existing usable capability | Remaining work |
|---|---|---|---|
| `known_hosts.log` | High | Addresses and timestamps from every observed flow | Bounded deduplication, local-network policy, event/schema/record |
| `known_services.log` | High | Responder address, port, transport, connection state, and detected service | Emit only sufficiently confirmed services; bounded deduplication and expiry |
| `software.log` | Medium-high | SSH banners, HTTP user-agent/server data, SMTP metadata, TLS fingerprints | Typed product/version normalization, metadata preservation, deduplication |
| `dhcp.log` | High | DHCP/BOOTP operation, transaction ID, client/assigned/server/gateway addresses, message type, hostname, and selected options | Typed protobuf/event model, option normalization, request/reply correlation |
| `ntp.log` | Medium-high | Version, mode, stratum, poll, precision, and leap indicator | Typed transport plus remaining NTP timestamps, reference ID, root delay, and dispersion |
| `ssh.log` | Medium | SSH banner, protocol version, software, and comments | Bidirectional banner correlation and history; deeper handshake parsing for algorithms, keys, and auth status |
| `ftp.log` | Medium | Commands, redacted arguments, response codes/messages, multiline flag | TCP reassembly, control-session state, request/reply and data-channel correlation |
| `postgresql.log` | Medium-low | Startup and SSL requests, startup parameters, cancel requests, and message names | TCP framing/state; query arguments, backend results, success, and row counts |
| `quic.log` | Medium-low | QUIC header/version and selected connection/header metadata | Bidirectional connection state, Initial decryption/TLS extraction, CIDs, ALPN, and history |
| `traceroute.log` | Medium-high | ICMP type/code plus IP and transport observations | Correlate low-TTL probes with Time Exceeded replies; false-positive suppression |
| `tunnel.log` | Medium-high | OpenVPN, WireGuard, L2TP, PPTP, and IKE detection and metadata | Typed preservation, session/action tracking, and outer/inner flow association |
| `known_certs.log` | Medium-low | TLS endpoint, SNI, and fingerprint context | Depends on X.509 certificate extraction; bounded certificate deduplication |
| `reporter.log` | High, analogous | Existing structured warnings and errors plus subsystem counters | Non-recursive logger sink, stable component/location fields, node provenance, rate limiting |
| `notice.log` | Medium, limited | DNS tunneling scores, TLS risk flags, malformed-input and capacity conditions | Typed notices, severity/actions, evidence, suppression, and policy configuration |

### `known_hosts.log`

Every valid normalized envelope already contains source and destination
addresses, timestamp, node provenance, and capture scope. A bounded host
inventory can therefore be built without a new packet parser.

The policy must define what "known" means. Zeek commonly scopes this to local
networks and logs a host after useful evidence such as a completed TCP
handshake. lippycat should support configurable local CIDRs and avoid treating
every Internet destination as a local known host. State must be bounded,
expirable, and partitioned by node or sensor scope where appropriate.

### `known_services.log`

Connection tracking already records responder orientation, port, transport,
connection state, and detected service. The log should prefer established TCP
flows or clear request/response evidence so a single outbound SYN does not
invent a server. UDP service confidence should require a response or a
high-confidence application detection.

### `software.log`

Several current analyzers expose software hints:

- SSH protocol banners contain implementation and version strings.
- HTTP metadata includes user-agent and server headers.
- SMTP events have a user-agent field, although current metadata mapping is
  incomplete.
- TLS fingerprints and ALPN can identify implementations probabilistically,
  but should not be reported as a definitive product without an explicit
  fingerprint database and confidence field.

A common software observation should carry host, direction, software type,
name, version, evidence source, confidence, UID, and node. Product parsing must
be conservative because banner formats are not standardized.

### `dhcp.log`

The existing DHCP signature is close to an initial log producer. It parses the
BOOTP header, DHCP magic cookie and selected options, including message type,
hostname, and requested address. DHCP is message-oriented over UDP, so it does
not require general TCP stream analysis.

Work should include a typed `DHCPMetadata` protobuf message, `DHCPEvent`,
canonical schema and record mapper. A bounded transaction table keyed by
transaction ID plus client identity can combine discover/offer/request/ack
activity and produce stable client, assigned-address, server, lease, router,
DNS, domain, and hostname fields. DHCPv6 is separate work and should not be
implied by an initial IPv4 DHCP log.

### `ntp.log`

The current NTP signature extracts enough fields for a useful first log, but
not a complete Zeek-compatible record. Extending the existing fixed-header
parser to cover root delay, root dispersion, reference identifier, and the four
NTP timestamps is small compared with adding a new analyzer. Request/response
correlation would allow round-trip and offset-related fields while remaining
bounded.

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

For full value, the analyzer should track login user, current directory,
transfer command, filename, reply code, and passive/active endpoint
negotiation. Data-channel flows then need to be associated with the control UID
and fed to file analysis.

### `postgresql.log`

The current signature recognizes PostgreSQL startup framing, SSL requests,
startup parameters, cancel requests, and generic message types. That is enough
for a partial startup/activity log after typed metadata preservation.

Zeek's current PostgreSQL output includes user, database, application name,
frontend operation and argument, backend result, success, and row count. Those
require a stateful framed TCP analyzer for both directions, including simple
and extended query flows and PostgreSQL's transition to TLS:

<https://docs.zeek.org/en/current/reference/logs/postgresql.html>

### `quic.log`

The existing QUIC signature recognizes long and short headers and extracts
selected header metadata. A partial log could expose version and header-level
connection IDs where present.

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

The adapter must not feed failures from `reporter.log` back into itself. Stable
error codes, component, source/node, level and message fields are preferable to
depending only on free-form text. Rate limiting and a stderr fallback are
required for failure storms.

### Initial `notice.log`

An initial notice catalogue can use findings that already exist, especially
DNS tunneling alerts and TLS risk flags. The related notice-pipeline research
in `docs/research/alerting-and-notice-pipeline.md` describes the broader design.

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

Required work:

- Reassemble TLS handshake messages across records and TCP segments.
- Parse TLS 1.2 and TLS 1.3 `Certificate` messages.
- Decode DER X.509 certificates.
- Generate stable FUIDs and associate certificates with `ssl.log` and
  `files.log`.
- Extract subject, issuer, serial, validity, SANs, public-key properties,
  signature algorithm, and constraints.
- Validate chains against a configurable trust store.
- Deduplicate certificates for `known_certs.log`.

### `pe.log`

The current file analyzer can identify, hash, and optionally extract bounded
HTTP and SMTP file content, but it does not parse executable formats.

Required work:

- Detect PE files by magic and structure rather than filename alone.
- Add a bounded PE/COFF parser.
- Extract architecture, compile timestamp, subsystem, section table,
  imports/exports, linker/OS versions, and certificate-table metadata.
- Support incremental or securely spooled parsing beyond body-preview limits.
- Preserve explicit truncated/incomplete state.
- Optionally parse and validate Authenticode signatures.

### SMB, DCE-RPC, Kerberos, and NTLM logs

lippycat has no SMB analyzer. Zeek's SMB processing can generate
`smb_cmd.log`, `smb_files.log`, `smb_mapping.log`, `dce_rpc.log`,
`kerberos.log`, `ntlm.log`, `pe.log`, and notices:

<https://docs.zeek.org/en/lts/logs/smb.html>

Required SMB work includes:

- TCP reassembly and NetBIOS Session Service framing.
- SMB1, SMB2, and SMB3 header and command parsers.
- Request/response, session, tree, file-handle, and compound-command state.
- Share/path mapping and file-content reconstruction.
- Signing metadata and SMB3 encryption detection.
- Bounded per-session state, retransmission handling, and timeout cleanup.

Associated analyzers require DCE/RPC PDU and bind-context decoding,
SPNEGO/GSS-API handling, NTLMSSP challenge/response metadata, and Kerberos
ASN.1 request, response, ticket, and error parsing. This is a new protocol
analysis subsystem rather than a set of log mappers.

### `irc.log`

Required work:

- Add IRC detection and a reassembled line protocol parser.
- Track client/server direction and session identity.
- Parse registration, nick, user, join, part, quit, mode, topic, messages,
  numeric replies, IRCv3 tags, and capability negotiation.
- Hand TLS-wrapped IRC to TLS analysis; application contents require configured
  TLS decryption.

### `ldap.log` and `ldap_search.log`

Required work:

- Implement TCP/UDP LDAP framing and BER/ASN.1 decoding.
- Correlate transactions by message ID.
- Parse bind, unbind, modify, add, delete, compare, and extended operations.
- Parse search base, scope, dereference mode, filter AST, and attributes.
- Correlate results, result codes, and returned object counts.
- Support StartTLS and SASL while strictly redacting credentials and sensitive
  attribute values.

### `rdp.log`

Required work:

- Parse TPKT and X.224 framing and negotiation.
- Decode MCS/GCC connection setup and virtual-channel negotiation.
- Extract client core, security, and network metadata.
- Integrate CredSSP/SPNEGO observations.
- Hand off TLS and associate certificates.
- Optionally parse legacy Standard RDP Security; modern encrypted content
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

- Periodically sample per-interface and per-node statistics.
- Read kernel/libpcap drop counters in addition to user-space queue drops.
- Track TCP ACKs and sequence gaps.
- Separate actual loss from BPF and application filtering.
- Emit interval, peer/interface, gap count, ACK count, and loss percentage.
- Aggregate hunter-side, transport, and processor losses without conflating
  them.
- Handle counter resets and node reconnects.

The current TCP assembler's missing-sequence metric explicitly describes absent
sequence space observed during bounded reassembly, not necessarily packets
dropped by lippycat. It must not be relabeled as capture loss without the
additional accounting above.

## Cross-Cutting Architecture Recommendation

Implement a typed observation boundary before adding several new logs:

```text
packet or reassembled stream
        |
        v
typed protocol observation
        |
        +-- protobuf transport: hunter -> processor
        +-- normalized event dispatcher
        +-- Zeek-style log sink
        +-- notice and LI metadata consumers
        +-- TUI presentation
```

Today, generic detector metadata is represented as `map[string]interface{}` and
is mostly collapsed into a protocol name and display string. Adding ad hoc
mapping branches for every log would reproduce each protocol model across the
detector, protobuf definitions, processor, TUI, and log records.

Typed observations should instead define:

- stable protocol fields and explicit direction;
- observation versus completed transaction/session semantics;
- UID/community ID/node provenance;
- partial/truncated state;
- schema evolution rules for distributed version skew;
- bounded ownership of correlation state;
- content classification so metadata-only consumers cannot receive payloads.

DHCP, NTP, SSH, FTP, PostgreSQL, QUIC, tunnel, ICMP, software, and diagnostic
events can then reuse the existing dispatcher and sink model.

## Recommended Roadmap

### Phase 0: typed observation foundation

1. Define the typed observation and lifecycle conventions.
2. Preserve typed detector output across hunter-to-processor protobuf transport.
3. Add common helpers for direction, partial state, deduplication, and bounded
   transaction/session tables.
4. Add schema compatibility and mixed-version tests.

### Phase 1: high-value, low-parser-cost streams

1. `dhcp.log`
2. `ntp.log`
3. `known_hosts.log`
4. `known_services.log`
5. `software.log`
6. `traceroute.log`
7. `tunnel.log`
8. Initial `reporter.log`

### Phase 2: partial protocol streams and notices

1. Banner-level `ssh.log`
2. Reassembled control-session `ftp.log`
3. Startup/activity `postgresql.log`
4. Header/Initial-level `quic.log`
5. Initial built-in `notice.log`
6. Analyzer lifecycle and anomaly taxonomy design

Each partial stream should document its supported fields and emit explicit
partial/truncated state rather than silently resembling full Zeek fidelity.

### Phase 3: TLS and file depth

1. Certificate handshake reassembly and `x509.log`
2. Populate certificate fields in `ssl.log`
3. `known_certs.log`
4. Streaming/spooled file analysis
5. PE parsing and `pe.log`

### Phase 4: major protocol analyzers

Prioritize according to deployment demand:

1. SMB plus DCE-RPC, NTLM, and Kerberos
2. LDAP
3. RDP
4. IRC

### Phase 5: operational and analysis parity

1. `analyzer.log`
2. `weird.log`
3. Full notice policy and action framework
4. Zeek-style TCP-based `capture_loss.log`
5. Expanded reporter and sensor health telemetry

## Acceptance Criteria for Any New Stream

A new stream should not be considered complete merely because it writes a
file. It should include:

- a canonical output-neutral schema in `internal/pkg/logschema`;
- typed normalized events in `internal/pkg/events`;
- distributed metadata evolution where hunters produce the observation;
- a bounded, non-blocking producer path;
- deterministic direction and UID behavior;
- explicit partial/truncated semantics;
- Zeek TSV and JSONL record tests;
- rotation, queue-pressure, graceful-drain, and error-path tests;
- live, offline, tap, and distributed-path coverage where applicable;
- documentation of intentional differences from Zeek.

## Conclusion

lippycat can add approximately eight useful Zeek-style streams largely through
typed metadata plumbing and bounded correlation, and another group can be
introduced with deliberately partial fidelity. DHCP and NTP are the strongest
protocol-specific first candidates; known-host, known-service, software,
traceroute, tunnel, and reporter logs reuse existing cross-protocol state.

X.509 and PE analysis, SMB and its authentication ecosystem, IRC, LDAP, RDP,
and comprehensive anomaly diagnostics require genuinely new analyzers or
analysis infrastructure. Treating signature detection as equivalent to a
session analyzer would produce superficially compatible but operationally
misleading logs. A typed observation boundary followed by staged protocol depth
provides a safer and more reusable expansion path.
