# Structured Protocol Log Schema v1

This document is the compatibility contract for the first structured protocol
log release. The machine-readable field order lives in
`internal/pkg/logschema`; changes to an existing field's name, type, order, or
meaning require a schema-version decision. Adding fields is append-only within a
schema version.

## Streams and compatibility

| Stream  | File        | Compatibility                                                        |
| ------- | ----------- | -------------------------------------------------------------------- |
| `conn`  | `conn.log`  | Zeek `Conn::Info` fields followed by lippycat extensions             |
| `dns`   | `dns.log`   | Zeek `DNS::Info` fields followed by lippycat extensions              |
| `ssl`   | `ssl.log`   | Zeek `SSL::Info` fields, common JA3 fields, then lippycat extensions |
| `http`  | `http.log`  | Zeek `HTTP::Info` fields followed by lippycat extensions             |
| `smtp`  | `smtp.log`  | Zeek `SMTP::Info` fields followed by lippycat extensions             |
| `files` | `files.log` | Zeek `Files::Info` fields followed by lippycat extensions            |
| `radius` | `radius.log` | Lippycat message observations |
| `dhcp` | `dhcp.log` | Opt-in DHCPv4 message observations; not transaction aggregates |
| `ntp` | `ntp.log` | Opt-in NTP time-message observations |
| `known_hosts` | `known_hosts.log` | Opt-in bounded, scoped host observations |
| `known_services` | `known_services.log` | Opt-in bounded, scoped responder/service observations |

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
`known_service`. Event kinds are stable lowercase wire labels; Go type names
and plural inventory stream names are not wire labels. `file_content` remains
local-only and is never accepted on the protocol-event transport.

### Metadata versus content

`DNSEvent`, `TLSEvent`, `ConnEvent`, and `FileMetadataEvent` are metadata-only.
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

| Field | Type |
| --- | --- |
| `ts` | `time` |
| `uid` | `string` |
| `id.orig_h` | `addr` |
| `id.orig_p` | `port` |
| `id.resp_h` | `addr` |
| `id.resp_p` | `port` |
| `proto` | `enum` |

For DHCP/NTP the endpoints retain **observed packet direction**. Each inventory
record instead retains its qualifying connection's envelope, including flow
UID, capture scope and provenance; `host` is the separate inventory subject.
The ordered suffix for all four streams is `community_id` (`string`), `node_id`
(`string`), `capture_scope` (`enum`), `partial` (`bool`). The middle fields below
are in canonical order. An absent optional value is unset, never a fabricated
zero, address or empty association. Partial decoding sets envelope `partial`;
`truncated` distinguishes an incomplete datagram/option from other invalid input.

### `dhcp.log`

| Field | Type | Meaning |
| --- | --- | --- |
| `op` | `count` | BOOTP operation 1 or 2 |
| `message_type` | `count` | DHCP option 53, numeric 1–8 |
| `transaction_id` | `count` | Unsigned 32-bit XID |
| `hardware_type` | `count` | Hardware type byte |
| `hardware_address` | `string` | Lowercase hex; at most 16 bytes |
| `client_identifier` | `string` | Optional lowercase hex, arbitrary binary identifier |
| `client_addr` | `addr` | Header ciaddr, including observed zero |
| `offered_addr` | `addr` | Header yiaddr |
| `next_server` | `addr` | Header siaddr; not DHCP server identifier |
| `relay_addr` | `addr` | Header giaddr |
| `server_identifier` | `addr` | Optional option 54 |
| `requested_addr` | `addr` | Optional option 50 |
| `hostname` | `string` | Optional bounded option 12 |
| `domain` | `string` | Optional bounded option 15 |
| `lease_seconds` | `count` | Optional unsigned seconds; present zero is distinct from absent |
| `routers` | `vector[addr]` | Ordered option 3 addresses |
| `dns_servers` | `vector[addr]` | Ordered option 6 addresses |
| `parameter_request_list` | `vector[count]` | Ordered option 55 bytes |
| `association` | `enum` | Observational association status |
| `association_id` | `string` | Opaque scoped exchange/server ID when available |
| `truncated` | `bool` | Incomplete input |

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

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | `count` | Header version |
| `mode` | `count` | Time-message mode 1–5 |
| `leap` | `count` | Leap indicator 0–3 |
| `stratum` | `count` | Exact header byte |
| `poll` | `int` | Signed exponent |
| `precision` | `int` | Signed exponent |
| `root_delay_raw` | `int` | Signed 16.16 wire value |
| `root_dispersion_raw` | `count` | Unsigned 16.16 wire value |
| `reference_id` | `string` | Exactly four bytes, lowercase hex |
| `reference_raw` | `string` | Exact 64-bit 32.32 value as 16 hex digits |
| `origin_raw` | `string` | Exact origin timestamp |
| `receive_raw` | `string` | Exact receive timestamp |
| `transmit_raw` | `string` | Exact transmit timestamp |
| `reference_time` | `time` | Capture-relative era conversion or unset |
| `origin_time` | `time` | Capture-relative era conversion or unset |
| `receive_time` | `time` | Capture-relative era conversion or unset |
| `transmit_time` | `time` | Capture-relative era conversion or unset |
| `association` | `enum` | Same finite statuses as DHCP |
| `association_id` | `string` | Opaque matched-request ID when available |
| `truncated` | `bool` | Incomplete trailing input |

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

Explicit IPv4/IPv6 local CIDRs classify inventory subjects, not capture
eligibility. Normalize mapped addresses; exclude unspecified, multicast and
broadcast subjects. Evaluate both qualifying endpoints. Do not assume private
address ranges are local. Partial capture scope remains visible despite positive
evidence. The dedup key includes origin node, producer/capture epoch, interface
or offline input identity and subject; services add port, transport and protocol.
Expiry/eviction permit later re-emission. This is bounded observation inventory,
not permanent asset identity.

### Configuration and privacy

Shared keys and finite defaults (configuration choices, not performance gates):

| Key | Default |
| --- | --- |
| `events.inventory.enabled` | `false` |
| `events.inventory.local_cidrs` | empty; enabled inventory requires an explicit nonempty policy |
| `events.inventory.max_entries` | `16384` |
| `events.inventory.max_bytes` | `8388608` |
| `events.inventory.max_entries_per_scope` | `4096` |
| `events.inventory.max_bytes_per_scope` | `2097152` |
| `events.inventory.retention` | `24h` |
| `events.dhcp.max_entries` | `4096` |
| `events.dhcp.max_bytes` | `4194304` |
| `events.dhcp.timeout` | `2m` |
| `events.ntp.max_entries` | `4096` |
| `events.ntp.max_bytes` | `4194304` |
| `events.ntp.timeout` | `30s` |

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
