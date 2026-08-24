# Structured Protocol Log Schema v1

This document is the compatibility contract for the first structured protocol
log release. The machine-readable field order lives in
`internal/pkg/logschema`; changes to an existing field's name, type, order, or
meaning require a schema-version decision. Adding fields is append-only within a
schema version.

## Streams and compatibility

| Stream | File | Compatibility |
|---|---|---|
| `conn` | `conn.log` | Zeek `Conn::Info` fields followed by lippycat extensions |
| `dns` | `dns.log` | Zeek `DNS::Info` fields followed by lippycat extensions |
| `ssl` | `ssl.log` | Zeek `SSL::Info` fields, common JA3 fields, then lippycat extensions |
| `http` | `http.log` | Zeek `HTTP::Info` fields followed by lippycat extensions |
| `smtp` | `smtp.log` | Zeek `SMTP::Info` fields followed by lippycat extensions |
| `files` | `files.log` | Zeek `Files::Info` fields followed by lippycat extensions |

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

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | timestamp | UTC observation time; packet time for replay |
| `uid` | string | `C` plus 17 base62 characters, stable for the observed flow |
| `community_id` | string | Community ID v1 for the normalized flow |
| `node_id` | string | originating capture source (`batch.SourceID`) |
| `flow` | `FlowTuple` | IP protocol, source/destination addresses and ports; ICMP type/code occupy the port slots for identity purposes |
| `partial` | bool | incomplete-visibility indicator defined above |
| `capture_scope` | enum | `full` or `filtered` |

The closed v1 event-kind set is `dns`, `smtp`, `tls`, `http`, `conn`,
`file_metadata`, and `file_content`. The corresponding concrete types are
`DNSEvent`, `SMTPEvent`, `TLSEvent`, `HTTPEvent`, `ConnEvent`,
`FileMetadataEvent`, and `FileContentEvent`. Event kinds are stable lowercase
wire labels; Go type names are not wire labels.

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

## LI profile: `internet_metadata`

The profile is metadata-only and deny-by-default. It may deliver X2 IRI derived
from `dns`, `tls`, `http`, `smtp`, and `conn` events after an active task and
target match. It may deliver `file_metadata` only when the task explicitly adds
the `file_metadata` capability. It always rejects `file_content`.

Allowed HTTP data is method, host, URI, protocol version, referrer, user agent,
status, content metadata, and byte counts. Allowed SMTP data is envelope,
routing/header metadata, replies, TLS state, and file identifiers. Arbitrary
headers, HTTP/email bodies, extracted bytes, raw payloads, RTP/media, and mirrored
packets are excluded. File/TSV/JSON configuration has no effect on authorization.

## Fixtures

- `internal/pkg/logschema/testdata/headers.golden` fixes TSV `#path`, `#fields`,
  and `#types` output for all streams.
- `internal/pkg/logschema/testdata/records.jsonl` contains one complete JSONL
  object per stream, including explicit nulls for unset data.
- `go test ./internal/pkg/logschema` verifies stream/file names, field order,
  types, fixture coverage, and duplicate fields.
