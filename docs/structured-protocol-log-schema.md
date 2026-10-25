# Structured Protocol Log Schema v1

This document is the compatibility contract for the first structured protocol
log release. The machine-readable field order lives in
`internal/pkg/logschema`; changes to an existing field's name, type, order, or
meaning require a schema-version decision. Adding fields is append-only within a
schema version.

## Streams and compatibility

| Stream           | File                 | Compatibility                                                        |
| ---------------- | -------------------- | -------------------------------------------------------------------- |
| `conn`           | `conn.log`           | Zeek `Conn::Info` fields followed by lippycat extensions             |
| `dns`            | `dns.log`            | Zeek `DNS::Info` fields followed by lippycat extensions              |
| `ssl`            | `ssl.log`            | Zeek `SSL::Info` fields, common JA3 fields, then lippycat extensions |
| `http`           | `http.log`           | Zeek `HTTP::Info` fields followed by lippycat extensions             |
| `smtp`           | `smtp.log`           | Zeek `SMTP::Info` fields followed by lippycat extensions             |
| `files`          | `files.log`          | Zeek `Files::Info` fields followed by lippycat extensions            |
| `radius`         | `radius.log`         | Lippycat message observations                                        |
| `dhcp`           | `dhcp.log`           | Opt-in DHCPv4 message observations; not transaction aggregates       |
| `ntp`            | `ntp.log`            | Opt-in NTP time-message observations                                 |
| `known_hosts`    | `known_hosts.log`    | Opt-in bounded, scoped host observations                             |
| `known_services` | `known_services.log` | Opt-in bounded, scoped responder/service observations                |
| `notice`         | `notice.log`         | Opt-in typed detector decisions with bounded references              |
| `ssh`            | `ssh.log`            | Directional initial cleartext handshake observations and HASSH       |

“Zeek-compatible” means the field has the same name, Zeek TSV type, and
meaning. It does not promise that lippycat observes every value Zeek would.
Unavailable values use Zeek's unset marker (`-`); empty strings/containers use
the empty marker `(empty)`. The definitive ordered field/type lists are tested
against `internal/pkg/logschema/testdata/headers.golden`.

The extensions are:

- `community_id` (`string`): Community ID v1 for the normalized bidirectional
  flow. This is unset when a valid supported flow tuple is unavailable.
- `node_id` (`string`): the originating hunter/source identity. A local source
  uses its configured node identity, not the processor that happens to write the
  record.
- `capture_scope` (`enum`, `full|filtered`): whether the source intended to
  observe the whole interface stream or a filtered subset. It describes capture
  configuration, not proof of complete packet delivery.
- `partial` (`bool`): true if observation began mid-connection, TCP SYN was not
  observed, only one direction was observed, packets were known to be dropped,
  or accounting is otherwise a lower bound.
- `ja3`, `ja3s`, and `ja4` are established fingerprint extensions carried by
  lippycat; they are not fields in Zeek's base `SSL::Info` record.
- `client_hello_count` and `ech_offered_count` (`count`) append to `ssl.log`.
  They count completely framed ClientHello observations, not connections or log
  rows. `ech_offered` (`bool`) reports whether at least one counted observation
  contained extension 65037. All three fields are unset without known complete
  ClientHello evidence (including legacy peers and ServerHello-only input). A
  known ClientHello without the extension has counts `1,0` and `false`; TLS
  coalescing preserves the numerator and denominator across ClientHellos.
- `hash_complete` (`bool`) is true only when file hashes cover the complete
  decoded entity. When false, MD5/SHA1/SHA256 cover only the recovered prefix.

`capture_scope` and `partial` apply to `conn.log`; the event envelope carries
them for all event kinds so future schemas can expose them without inference.

## Normalized event contract

Every event has this envelope:

| Field           | Type        | Meaning                                                                                                         |
| --------------- | ----------- | --------------------------------------------------------------------------------------------------------------- |
| `timestamp`     | timestamp   | UTC observation time; packet time for replay                                                                    |
| `uid`           | string      | `C` plus 17 base62 characters, stable for the observed flow                                                     |
| `community_id`  | string      | Community ID v1 for the normalized flow                                                                         |
| `node_id`       | string      | originating capture source (`batch.SourceID`)                                                                   |
| `flow`          | `FlowTuple` | IP protocol, source/destination addresses and ports; ICMP type/code occupy the port slots for identity purposes |
| `partial`       | bool        | incomplete-visibility indicator defined above                                                                   |
| `capture_scope` | enum        | `full` or `filtered`                                                                                            |

The typed event-kind set is `dns`, `smtp`, `tls`, `http`, `conn`,
`file_metadata`, `file_content`, `radius`, `dhcp`, `ntp`, `known_host`, and
`known_service`, `notice`, and `ssh`. Event kinds are stable lowercase wire labels; Go type names
and plural inventory stream names are not wire labels. `file_content` remains
local-only and is never accepted on the protocol-event transport.

### Metadata versus content

`DNSEvent`, `TLSEvent`, `SSHEvent`, `ConnEvent`, `NoticeEvent`, and `FileMetadataEvent` are metadata-only.
`SMTPEvent` contains SMTP envelope/header metadata only: HELO, sender,
recipients, routing headers, message identifiers, subject, replies, TLS state,
and file IDs. `HTTPEvent` contains request/response metadata only: method, host,
URI, status, sizes, selected standard headers, and file IDs. Arbitrary HTTP
headers are metadata but require the explicit header-capture option and are not
part of the fixed `http.log` schema.

Bodies, raw packet bytes, extracted attachment/file bytes, and media never
appear as optional fields on those event types. Extracted bytes exist only in
`FileContentEvent`. Future HTTP/email body events must likewise be distinct
content-bearing types. `files.log` is built from `FileMetadataEvent`, never
`FileContentEvent`.

## Record rules

- TSV uses Zeek headers and escaping. Times are Unix seconds with six decimal
  places, intervals are decimal seconds, bools are `T`/`F`, vectors and sets use
  comma as `#set_separator`, and bytes/control characters use `\\xHH` escapes.
- JSON is JSONL with native booleans/numbers/arrays. Unset optional values are
  `null`; empty values remain `""` or `[]`. Keys use the exact TSV field names,
  including dotted connection keys such as `id.orig_h`.
- Each protocol transaction produces its own DNS/HTTP/SMTP record. TLS produces
  one record per correlated handshake when possible. Connection and file
  records are lifecycle summaries.
- Passwords and bodies are not captured by default. `http.password` remains
  unset unless an explicit future credential policy authorizes collection.

## Fixtures

- `internal/pkg/logschema/testdata/headers.golden` fixes TSV `#path`, `#fields`,
  and `#types` output for all streams.
- `internal/pkg/logschema/testdata/records.jsonl` contains one complete JSONL
  object per stream, including explicit nulls for unset data.
- `go test ./internal/pkg/logschema` verifies stream/file names, field order,
  types, fixture coverage, and duplicate fields.

## RADIUS observation stream (v1 additive extension)

`radius.log` is a lippycat observation schema, not Zeek RADIUS compatibility.
The new stream leaves all existing v1 field orders and meanings unchanged.
Every valid message produces its own record; responses are not coalesced with
requests. Endpoints retain observed packet direction. The numeric `identifier`
is the eight-bit wire value, while `observation_id` and `request_instance_id`
are opaque capture-epoch/sequence identities. Missing request identity is unset.
`association` reports the shared correlator status, including `request`, `unique`,
`missing`, `ambiguous`, `expired`, `incompatible`, and `capacity_suppressed`.
Association is observational and does not authenticate a message.

`attributes` is an ordered vector of allowlisted instances. Ordinary attributes
use `TYPE:hex:VALUE`; DSL Forum Agent-Circuit-Id uses `26/3561/1:hex:VALUE`.
Hex is lowercase, preserves arbitrary bytes and empty values, and prevents
terminal/control-character injection. Repeated attributes remain separate and
in wire order. The allowlist is User-Name (1), NAS-IP-Address (4), NAS-Port (5),
Service-Type (6), Framed-IP-Address (8), Called-Station-Id (30),
Calling-Station-Id (31), NAS-Identifier (32), Acct-Status-Type (40),
Acct-Session-Id (44), NAS-Port-Type (61), NAS-Port-Id (87), NAS-IPv6-Address (95),
and vendor 3561/type 1. These values can contain subscriber identities.
Password/CHAP/EAP attributes, State/Class, authenticators, other vendor data,
and unknown attributes are omitted. Filter/task evidence is also omitted.
Routine display and text/JSON summaries use the same allowlist.
Explicit packet sinks preserve captured bytes, including omitted attributes;
this presentation policy never rewrites packet data.

`origin_node_id`, `source_id`, and `capture_epoch` retain capture provenance;
`node_id` follows the existing event envelope convention. Relayed provenance is
validated against captured bytes but remains a claim, not LI authorization.

The Phase 6 command/configuration surface does not change this schema version or
field order. Capture profiles and state limits configure observation production;
queue loss, malformed-input and LI delivery counters are operational statistics,
not additional record fields. `radius` output requires independent log enablement
with `--log-dir`; an X1 task does not turn it on. See the
[RADIUS operator guide](RADIUS.md) for supported scope and counter ownership.

## DHCP, NTP and bounded inventory (v1 additive extension)

The first-wave extension adds four opt-in streams. Existing field orders,
meanings, and the default seven streams remain unchanged. DHCP and NTP are
**one record per observed message**, including protocol retransmissions; they
are not Zeek transaction/session aggregates. Transport retries preserve the
original event identity. Neither log enablement nor transaction coalescing may
suppress their independent typed observations.

The wire contract stays at API major 1 and semantic profile revision 1: new
payloads and kinds are additive; existing payload semantics are unchanged.
Append kind IDs 8 (`dhcp`), 9 (`ntp`), 10 (`known_host`), 11 (`known_service`)
and oneof fields 17–20 respectively. A peer's supported kinds are distinct from
kinds required by configured consumers. Old peers continue existing workloads
when additions are optional; unsupported optional observations are reported as
compatibility loss. Requiring an unavailable stream fails negotiation or uses
an explicitly enabled packet fallback. Unknown fields remain opaque and are
preserved by transparent relays. Inventory production is advertised only when
its producer policy is enabled. These changes do not alter WAL/spool admission
or acknowledgement boundaries.

The ordered common prefix for each new stream is:

| Field       | Type     |
| ----------- | -------- |
| `ts`        | `time`   |
| `uid`       | `string` |
| `id.orig_h` | `addr`   |
| `id.orig_p` | `port`   |
| `id.resp_h` | `addr`   |
| `id.resp_p` | `port`   |
| `proto`     | `enum`   |

For DHCP/NTP the endpoints retain **observed packet direction**. Each inventory
record instead retains its qualifying connection's envelope, including flow
UID, capture scope and provenance; `host` is the separate inventory subject.
The ordered suffix for all four streams is `community_id` (`string`), `node_id`
(`string`), `capture_scope` (`enum`), `partial` (`bool`). The middle fields below
are in canonical order. An absent optional value is unset, never a fabricated
zero, address or empty association. Partial decoding sets envelope `partial`;
`truncated` distinguishes an incomplete datagram/option from other invalid input.

### `dhcp.log`

| Field                    | Type            | Meaning                                                         |
| ------------------------ | --------------- | --------------------------------------------------------------- |
| `op`                     | `count`         | BOOTP operation 1 or 2                                          |
| `message_type`           | `count`         | DHCP option 53, numeric 1–8                                     |
| `transaction_id`         | `count`         | Unsigned 32-bit XID                                             |
| `hardware_type`          | `count`         | Hardware type byte                                              |
| `hardware_address`       | `string`        | Lowercase hex; at most 16 bytes                                 |
| `client_identifier`      | `string`        | Optional lowercase hex, arbitrary binary identifier             |
| `client_addr`            | `addr`          | Header ciaddr, including observed zero                          |
| `offered_addr`           | `addr`          | Header yiaddr                                                   |
| `next_server`            | `addr`          | Header siaddr; not DHCP server identifier                       |
| `relay_addr`             | `addr`          | Header giaddr                                                   |
| `server_identifier`      | `addr`          | Optional option 54                                              |
| `requested_addr`         | `addr`          | Optional option 50                                              |
| `hostname`               | `string`        | Optional bounded option 12                                      |
| `domain`                 | `string`        | Optional bounded option 15                                      |
| `lease_seconds`          | `count`         | Optional unsigned seconds; present zero is distinct from absent |
| `routers`                | `vector[addr]`  | Ordered option 3 addresses                                      |
| `dns_servers`            | `vector[addr]`  | Ordered option 6 addresses                                      |
| `parameter_request_list` | `vector[count]` | Ordered option 55 bytes                                         |
| `association`            | `enum`          | Observational association status                                |
| `association_id`         | `string`        | Opaque scoped exchange/server ID when available                 |
| `truncated`              | `bool`          | Incomplete input                                                |

Only DHCPv4 is eligible; DHCPv6 and bare BOOTP produce no DHCP log. Unknown and
vendor option contents never enter routine records. Repeated options concatenate
in wire order, including overloaded file/sname areas in protocol order, before
known-field validation. Fixed-width fields must retain their required size;
malformed options do not silently produce a complete record. Identifiers remain
binary internally and hex in logs. Names use bounded safe text, not raw terminal
control bytes. Offers do not establish known hosts or a lease history.

Association keys include capture authority/epoch/source, client identity, XID
and relay context; responses retain server distinctions. The statuses are
`request`, `unique`, `missing`, `ambiguous`, `expired`, `capacity_suppressed`,
and `not_applicable`. Correlation never replaces the observed flow UID.

### `ntp.log`

| Field                 | Type     | Meaning                                   |
| --------------------- | -------- | ----------------------------------------- |
| `version`             | `count`  | Header version                            |
| `mode`                | `count`  | Time-message mode 1–5                     |
| `leap`                | `count`  | Leap indicator 0–3                        |
| `stratum`             | `count`  | Exact header byte                         |
| `poll`                | `int`    | Signed exponent                           |
| `precision`           | `int`    | Signed exponent                           |
| `root_delay_raw`      | `int`    | Signed 16.16 wire value                   |
| `root_dispersion_raw` | `count`  | Unsigned 16.16 wire value                 |
| `reference_id`        | `string` | Exactly four bytes, lowercase hex         |
| `reference_raw`       | `string` | Exact 64-bit 32.32 value as 16 hex digits |
| `origin_raw`          | `string` | Exact origin timestamp                    |
| `receive_raw`         | `string` | Exact receive timestamp                   |
| `transmit_raw`        | `string` | Exact transmit timestamp                  |
| `reference_time`      | `time`   | Capture-relative era conversion or unset  |
| `origin_time`         | `time`   | Capture-relative era conversion or unset  |
| `receive_time`        | `time`   | Capture-relative era conversion or unset  |
| `transmit_time`       | `time`   | Capture-relative era conversion or unset  |
| `association`         | `enum`   | Same finite statuses as DHCP              |
| `association_id`      | `string` | Opaque matched-request ID when available  |
| `truncated`           | `bool`   | Incomplete trailing input                 |

Raw timestamps preserve exact values even when log time formatting rounds.
Wire zero means unavailable; choose the era nearest capture time for nonzero
values. The reference ID is not universally an IPv4 address: stratum 0/1 has
code semantics, secondary servers use version/address-family-dependent values.
Retain raw bytes as canonical output. Client/server association requires scope,
reversed endpoints and the echoed request transmit timestamp. Duplicate request
timestamps are ambiguous. Broadcast and symmetric messages remain independent
observations. Modes 6/7, NTS analysis, authentication and client clock-offset
estimation are excluded. Malformed/oversized trailing extensions cannot be
silently accepted as complete time messages.

### `known_hosts.log` and `known_services.log`

`known_hosts` middle fields are `host` (`addr`), `evidence` (`enum`).
`known_services` middle fields are `host` (`addr`), `port` (`port`),
`transport` (`enum`), `service` (`string`), `evidence` (`enum`). Stable service
IDs are lowercase protocol identifiers, independent of display labels.

Evidence is finite: `tcp_handshake`, `udp_bidirectional`, `dns_exchange`,
`ntp_exchange`, `dhcp_exchange`. Host evidence requires a completed observed TCP
handshake or both UDP directions. Service evidence additionally requires a
reliably oriented responder and actual protocol analysis. Port hints and cached
labels are insufficient. UDP services require decoded, successfully associated
request/reply roles; ambiguous, broadcast and relay cases do not invent a client
service. Inventory records are emitted as soon as the required packet evidence
is available, without waiting for connection expiry. Ordinary connection
summaries retain their existing expiry, eviction, EOF, reset, or close behavior.
Ingress and relays carry source-derived inventories without deriving them again.

Inventory is enabled by default. Without configured CIDRs, all observed eligible
unicast subjects are included. Explicit IPv4/IPv6 local CIDRs optionally filter
inventory subjects and classify connection endpoints as local; they do not
restrict packet capture. An empty list does not mark every address as local.
Normalize mapped addresses; exclude unspecified, multicast and broadcast subjects.
Evaluate both qualifying endpoints. Do not assume private address ranges are local. Partial capture scope remains visible despite positive
evidence. The dedup key includes origin node, producer/capture epoch, interface
or offline input identity and subject; services add port, transport and protocol.
Expiry/eviction permit later re-emission. This is bounded observation inventory,
not permanent asset identity.

### Configuration and privacy

Shared keys and finite defaults (configuration choices, not performance gates):

| Key                                      | Default                                     |
| ---------------------------------------- | ------------------------------------------- |
| `events.inventory.enabled`               | `true`; set to `false` to disable inventory |
| `events.inventory.local_cidrs`           | empty; no inventory subject filter          |
| `events.inventory.max_entries`           | `16384`                                     |
| `events.inventory.max_bytes`             | `8388608`                                   |
| `events.inventory.max_entries_per_scope` | `4096`                                      |
| `events.inventory.max_bytes_per_scope`   | `2097152`                                   |
| `events.inventory.retention`             | `24h`                                       |
| `events.dhcp.max_entries`                | `4096`                                      |
| `events.dhcp.max_bytes`                  | `4194304`                                   |
| `events.dhcp.timeout`                    | `2m`                                        |
| `events.ntp.max_entries`                 | `4096`                                      |
| `events.ntp.max_bytes`                   | `4194304`                                   |
| `events.ntp.timeout`                     | `30s`                                       |

Explicit zero/negative caps or timeouts are invalid. Disabled inventory allocates
no retained state. Capture-time watermarks never move backward; late input does
not resurrect expired entries. Expiry/eviction and association pressure have
counters separate from event loss. Reset clears correlation/dedup state. Offline
session identity includes effective policy and analysis revision; live policy
changes require a producer-session boundary.

Subscriber projection omits DHCP hardware/client identifiers, hostname and
domain unless sensitive fields are both requested and allowed. Internal
correlation can use omitted fields without exposing them. Inventory subject and
service details likewise require sensitive-field permission; their projection
must explicitly account for policy omission. NTP header metadata needs no
additional sensitive-field permission. Projection copies events and never
mutates shared originals. Explicit local log selection includes these fields;
operators must restrict file access and retention. Raw options, vendor contents,
credentials and authentication material are excluded.

## DNS security notice schema 1

`notice.log` is selected explicitly with `--log-streams notice`; the default seven
streams remain unchanged. Wire API v1 adds event kind `12` and typed oneof field
`21`, without changing existing event messages or requiring notice support for
workloads that do not request it. An unsupported optional kind is a compatibility
omission; configured notice requirements must negotiate or use explicit packet
fallback. `RequiredKinds` reflects selected streams rather than all supported
encodings.

A notice records a detector decision, not an external-action receipt. The initial
producer uses detector `dns.tunneling`, detector version `1`, category `security`,
severity `warning`, and status `triggered`. `ts` is capture observation time.
Envelope endpoints and `uid` identify the real triggering flow; a domain finding
can span several observations and never invents a synthetic aggregate flow.
`node_id` remains the capture origin. `detector_node_id` and
`detector_generation` identify the actual analysis authority independently of the
origin. `event_id` and the event envelope's session/sequence retain delivery
identity through retries and relays. Authority strings received over the wire do
not authorize local command execution.

`queries` is the legacy count of DNS observations, including responses, rather
than a unique query or connection count. Unique subdomain/source-address evidence
and references are bounded; truncation flags preserve that limitation. References
are sorted by capture timestamp, then node and UID, and identify actual
contributing observations without requiring a preassigned delivery event ID.
The current producer retains the trigger reference and marks aggregated evidence
incomplete when additional observations contributed. Source addresses are
canonical, sorted, and unique. Wire collections are limited to 4096 entries;
configured producer limits may be smaller. Scores and thresholds must be finite
in `[0,1]`, entropy finite and nonnegative, and a triggered score must meet its
threshold. Schema version, authority identity, timestamp order, positive counts,
and collection limits are validated during encoding and decoding.

The canonical field order is:

| Field                         | Type             |
| ----------------------------- | ---------------- |
| `ts`                          | `time`           |
| `uid`                         | `string`         |
| `id.orig_h`                   | `addr`           |
| `id.orig_p`                   | `port`           |
| `id.resp_h`                   | `addr`           |
| `id.resp_p`                   | `port`           |
| `proto`                       | `enum`           |
| `schema_version`              | `count`          |
| `detector`                    | `string`         |
| `detector_version`            | `string`         |
| `category`                    | `enum`           |
| `severity`                    | `enum`           |
| `status`                      | `enum`           |
| `detector_node_id`            | `string`         |
| `detector_generation`         | `string`         |
| `domain`                      | `string`         |
| `score`                       | `double`         |
| `threshold`                   | `double`         |
| `entropy`                     | `double`         |
| `queries`                     | `count`          |
| `unique_subdomains`           | `count`          |
| `source_ips`                  | `vector[addr]`   |
| `unique_subdomains_truncated` | `bool`           |
| `source_ips_truncated`        | `bool`           |
| `evidence_node_ids`           | `vector[string]` |
| `evidence_uids`               | `vector[string]` |
| `evidence_timestamps`         | `vector[time]`   |
| `evidence_truncated`          | `bool`           |
| `evidence_redacted`           | `bool`           |
| `event_id`                    | `string`         |
| `community_id`                | `string`         |
| `node_id`                     | `string`         |
| `capture_scope`               | `enum`           |
| `partial`                     | `bool`           |

The three evidence vectors are aligned by position. JSONL preserves address and
timestamp vectors as typed arrays; TSV uses ordinary vector escaping and the
stream's canonical headers. Capacity truncation and authorization redaction are
separate: a nonsensitive subscriber receives no source-address list or cross-flow
references and has `evidence_redacted=true`, while original truncation flags stay
unchanged. Removed vectors are unset. Domain, score/count evidence, identity,
origin, authority, and triggering flow remain available. Local file selection is
explicit and includes sensitive evidence; operators must protect those files.
No packet/file body or executable command payload is part of the notice schema.

Notice events pass through log coalescing unchanged. Per-stream queue bounds,
overflow accounting, rotation and graceful drain apply as for existing streams.
This file sink is independent of best-effort TUI subscriptions and asynchronous
command actions. Neither stable event identity nor reliable ingress promises
exactly-once file output or external side effects across crashes.

## SSH observation stream (v1 additive extension)

`ssh.log` records initial cleartext SSH observations, rather than Zeek SSH
connection/authentication summaries. The stream is optional and leaves all
existing field orders unchanged. A banner observation may be followed by a
complete KEXINIT or terminal partial observation for the same direction. Each
observation has a distinct `event_id`; `uid` and `community_id` identify the
shared bidirectional flow. Endpoint columns preserve the emitting direction.
Counts of log rows therefore count observations, not unique connections.

The canonical columns after the standard endpoint/protocol prefix are `role`,
`role_evidence`, `status`, `reason`, `banner`, `banner_escaped`, `protocol_version`,
`software_version`, `kex_algorithms`, `server_host_key_algorithms`,
`encryption_client_server`, `encryption_server_client`, `mac_client_server`,
`mac_server_client`, `compression_client_server`, `compression_server_client`,
`languages_client_server`, `languages_server_client`, `first_kex_packet_follows`,
`hassh`, `hassh_algorithms`, `hassh_version`, and `event_id`, followed by
`community_id`, `node_id`, `capture_scope`, and `partial`. The machine-readable
registry and header fixture define their exact order and types.

`role` is `client`, `server`, or `unknown` for the source endpoint. Independent
`role_evidence` is `tcp_syn`, `tcp_synack`, `protocol`, `unknown`, or `conflict`.
A captured SYN or SYNACK can establish the roles of both endpoints; evidence
names the observed witness, not a claim that this endpoint sent that flag.
Port 22, packet order, and a first-seen TCP direction do not establish a role.
`status` is `banner`, `complete`, or `partial`. `complete` means a fully framed,
valid initial KEXINIT was observed, even when role remains unknown. `reason`
records completion or a bounded parser/stream stop such as `kex_complete`,
`no_kex`, `missing_banner`, `incomplete`, `gap`, `malformed`, `resource_limit`,
`unsupported_version`, `newkeys_before_kex`, or `disconnect`. Envelope `partial`
independently reports incomplete capture visibility.

Ordered comma-separated name-lists are retained exactly: they are never sorted,
deduplicated, or stripped of extension markers. HASSH 1.0 computes MD5 over
`kex;encryption;mac;compression`, selecting client-to-server lists for a client
and server-to-client lists for a server, as defined by the maintained
[Corelight HASSH implementation](https://github.com/corelight/hassh/blob/main/scripts/hassh.zeek).
`hassh_algorithms` retains that exact semicolon-separated input and `hassh_version`
is `1.0`. `server_host_key_algorithms`, language lists, and the follows flag are
evidence but do not participate in this fingerprint. The fingerprint describes
the offered algorithms; it is not an authenticated endpoint identity.

Banners and partial observations have unset KEXINIT/fingerprint fields. A
complete observation with unknown/conflicting role retains the complete lists
but leaves all three HASSH fields unset. A complete empty language list is an
empty string rather than unset. `banner` excludes CR/LF. If its original bytes
contain invalid UTF-8 or control characters, `banner_escaped=true` and the field
contains the complete Go `strconv.QuoteToASCII` representation, including its
quotes, so the exact bytes can be recovered without unsafe terminal text.

SSH 2.0 and the 1.99 compatibility identification are supported. Parsing is
bounded to the initial cleartext identification and KEXINIT and stops at initial
KEX completion or NEWKEYS. Encrypted rekey traffic, authentication identities,
credentials, commands, decrypted content, and session-success inference are not
part of these events. The same handshake metadata is available to ordinary and
sensitive-authorized subscribers; requesting sensitive fields still requires
its existing authorization. Transport kind 13 is additive. Required `ssh`
streams require both that encoding and the `ssh_production` feature, which
promises observation production for eligible input. Codec support alone does
not satisfy that promise. An event relay advertising enabled SSH production
enforces the same requirement on its event-producing children, even without a
local `ssh` log. An explicitly permitted packet fallback is available only when
the receiving processor has local SSH analysis enabled. Optional unsupported
observations use compatibility-loss accounting. Relays preserve producer
identity and do not reparse SSH events.
