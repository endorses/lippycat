# Structured Protocol Logs

lippycat can write normalized protocol metadata beside its packet, PCAP, TUI,
virtual-interface, and LI outputs. The files use familiar Zeek stream names and
field semantics, but they are not a replacement for Zeek's analyzer and scripting
ecosystem. In particular, filtered or late-started capture produces useful
lower-bound observations rather than complete connection measurements.

## Enabling logs

Logging is off by default. Supplying `--log-dir` enables it for `process`, `tap`,
and `sniff`; the directory is created if necessary.

```bash
# Terminal processor in a distributed deployment
lc process --listen :55555 --log-dir /var/log/lippycat

# Local capture, JSONL, selected streams
sudo lc tap dns -i eth0 --insecure \
  --log-dir /var/log/lippycat --log-format json --log-streams conn,dns

# Offline or live CLI capture; packet stdout is unchanged
lc sniff http -r capture.pcap --log-dir ./logs --log-streams conn,http,files
```

The shared flags are:

| Flag | Default | Meaning |
|---|---:|---|
| `--event-queue-size` | `20000` | Normalized-event queue capacity |
| `--event-drop-policy` | `drop_new` | Overflow policy for the normalized-event queue |
| `--log-dir` | unset | Output directory; setting it enables logging |
| `--log-format` | `tsv` | `tsv` or `json` |
| `--log-streams` | all six streams | Comma-separated enabled streams |
| `--log-rotate-interval` | `1h` | Time between rotations; `0` disables periodic rotation |
| `--log-queue-size` | `10000` | Queue capacity for each stream |
| `--log-post-rotate-command` | unset | Shell command run after rotation; `%log%` is the safely quoted rotated path |
| `--log-include-http-headers` | `false` | Preserve arbitrary HTTP header maps in normalized events; fixed log columns do not change |
| `--log-include-email-body-preview` | `false` | Permit captured email body previews for file analysis; potentially sensitive |
| `--extract-files` | `false` | Write bounded HTTP/SMTP file content to disk |
| `--extract-files-dir` | unset | Extraction directory; required when extraction is enabled |
| `--extract-files-max-size` | `10 MiB` | Maximum bytes analyzed or extracted per file |
| `--extract-files-total-size` | `100 MiB` | Maximum bytes extracted during the process lifetime |
| `--log-emit-stage` | `terminal` | `process`/`tap` only: `terminal`, `all`, or `none` |

Equivalent YAML keys are `events.queue_size`, `events.drop_policy`, `logs.dir`, `logs.format`,
`logs.streams`, `logs.rotate_interval`, `logs.queue_size`, `logs.emit_stage`,
`logs.post_rotate_command`, `logs.include_http_headers`,
`logs.include_email_body_preview`, and `files.extract`,
`files.extract_dir`, `files.max_size`, and `files.total_size`.

```yaml
events:
  queue_size: 20000
  drop_policy: drop_new
logs:
  dir: /var/log/lippycat
  format: tsv
  streams: [conn, dns, ssl, http, smtp, files]
  rotate_interval: 1h
  queue_size: 10000
  emit_stage: terminal
  post_rotate_command: "gzip %log%"
  include_http_headers: false
  include_email_body_preview: false
files:
  extract: false
  extract_dir: /var/lib/lippycat/files
  max_size: 10485760
  total_size: 104857600
```

In a processor hierarchy, `terminal` prevents duplicate files by writing only on
a node that is not forwarding upstream. Use `all` deliberately to log at every
enabled stage, or `none` to suppress the file sink.

### Relationship to LI delivery

LI builds can consume the same normalized protocol events for authorized X2 IRI
delivery. This is a separate sink with separate enablement and authorization:
`--log-dir` controls local TSV/JSONL files, while `--li-metadata-events` controls
the LI metadata path. X2 delivery additionally requires a matching active task
and an enabled destination. X3 carries authorized communication content, not
structured log records. See [Normalized protocol metadata over X2](lawful-interception.md#normalized-protocol-metadata-over-x2).

## Output encodings

TSV is the default. It writes Zeek headers (`#separator`, `#set_separator`,
`#empty_field`, `#unset_field`, `#path`, `#open`, `#fields`, and `#types`) and a
`#close` footer. Times are Unix seconds with six decimals, intervals are seconds,
booleans are `T`/`F`, and vectors/sets are comma-separated. `-` means unset,
`(empty)` means present but empty, and control bytes are `\xHH` escaped.

JSON is JSON Lines: one object per row. It uses the same field names, including
keys such as `id.orig_h`; booleans, numbers, and arrays have native JSON types.
Unset values are `null`, while present empty values are `""` or `[]`. JSON files
still use the Zeek-compatible names such as `dns.log`.

## Streams and fields

All field order and types below are fixed by `internal/pkg/logschema`. `uid` is a
lippycat-generated Zeek-style connection ID. `community_id` is Community ID v1
for cross-tool joins, and `node_id` identifies the originating capture source,
not necessarily the processor writing the file. Unavailable values are unset.

### `conn.log`

One lifecycle summary per observed flow (expiry, eviction, or graceful shutdown).

| Fields | Zeek types |
|---|---|
| `ts`, `uid` | `time`, `string` |
| `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `addr`, `port`, `addr`, `port` |
| `proto`, `service`, `duration` | `enum`, `string`, `interval` |
| `orig_bytes`, `resp_bytes` | `count`, `count` |
| `conn_state`, `local_orig`, `local_resp`, `missed_bytes`, `history` | `string`, `bool`, `bool`, `count`, `string` |
| `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes` | `count`, `count`, `count`, `count` |
| `community_id`, `node_id`, `capture_scope`, `partial` | `string`, `string`, `enum`, `bool` |

Originator/responder orientation follows the TCP SYN when visible and otherwise
the first observed packet. Byte and packet values are observed counts. `service`
is detected application protocol; `conn_state` and `history` summarize visible
TCP behavior; local-address booleans may be unset when locality is unknown.

`capture_scope=full` means the source intended to observe the whole interface
stream. `filtered` means a BPF, protocol, target, or distributed filter narrowed
capture. It does not prove lossless delivery. `partial=true` means the connection
began before observation, a TCP SYN was not seen, only one direction was seen,
packets were known to be dropped, or accounting is otherwise incomplete. Treat
all counters and duration on partial rows as lower bounds. A `full` scope can
still be partial.

### `dns.log`

One DNS transaction observation. `trans_id` is the DNS transaction ID; `rtt` is
the correlated response time. Query class/type and response code appear as both
numeric and descriptive values. `AA`, `TC`, `RD`, `RA`, and `Z` are DNS header
flags; `answers` and `TTLs` are response vectors; `rejected` marks a rejected
transaction.

| Fields | Zeek types |
|---|---|
| `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto` | `time`, `string`, `addr`, `port`, `addr`, `port`, `enum` |
| `trans_id`, `rtt`, `query` | `count`, `interval`, `string` |
| `qclass`, `qclass_name`, `qtype`, `qtype_name` | `count`, `string`, `count`, `string` |
| `rcode`, `rcode_name`, `AA`, `TC`, `RD`, `RA`, `Z` | `count`, `string`, `bool`, `bool`, `bool`, `bool`, `count` |
| `answers`, `TTLs`, `rejected` | `vector[string]`, `vector[interval]`, `bool` |
| `community_id`, `node_id` | `string`, `string` |

### `ssl.log`

One TLS handshake observation. It includes negotiated `version`, `cipher`,
`curve`, SNI `server_name`, resumption/alert/ALPN state, establishment state,
certificate file IDs and identities, validation result, and JA3/JA3S/JA4
fingerprints. Fingerprints are common lippycat extensions, not base Zeek fields.

| Fields | Zeek types |
|---|---|
| `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `time`, `string`, `addr`, `port`, `addr`, `port` |
| `version`, `cipher`, `curve`, `server_name` | `string`, `string`, `string`, `string` |
| `resumed`, `last_alert`, `next_protocol`, `established` | `bool`, `string`, `string`, `bool` |
| `cert_chain_fuids`, `client_cert_chain_fuids` | `vector[string]`, `vector[string]` |
| `subject`, `issuer`, `client_subject`, `client_issuer`, `validation_status` | `string`, `string`, `string`, `string`, `string` |
| `ja3`, `ja3s`, `ja4`, `community_id`, `node_id` | `string`, `string`, `string`, `string`, `string` |

### `http.log`

One HTTP transaction observation. `trans_depth` orders transactions on a
connection. Request/response columns describe method, authority and URI,
selected standard headers, version, observed body lengths, response status and
informational response. `tags` and `proxied` carry analyzer/proxy annotations;
file vectors join to `files.log`. `password` is not collected by default.

| Fields | Zeek types |
|---|---|
| `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `time`, `string`, `addr`, `port`, `addr`, `port` |
| `trans_depth`, `method`, `host`, `uri`, `referrer`, `version` | `count`, `string`, `string`, `string`, `string`, `string` |
| `user_agent`, `origin`, `request_body_len`, `response_body_len` | `string`, `string`, `count`, `count` |
| `status_code`, `status_msg`, `info_code`, `info_msg` | `count`, `string`, `count`, `string` |
| `tags`, `username`, `password`, `proxied` | `set[enum]`, `string`, `string`, `vector[string]` |
| `orig_fuids`, `orig_filenames`, `orig_mime_types` | `vector[string]`, `vector[string]`, `vector[string]` |
| `resp_fuids`, `resp_filenames`, `resp_mime_types` | `vector[string]`, `vector[string]`, `vector[string]` |
| `community_id`, `node_id` | `string`, `string` |

### `smtp.log`

One SMTP transaction observation. It records transaction depth, HELO and envelope
sender/recipients, selected message headers and routing hops, last server reply,
TLS state, attachment file IDs, and webmail classification. It does not log the
message body.

| Fields | Zeek types |
|---|---|
| `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `time`, `string`, `addr`, `port`, `addr`, `port` |
| `trans_depth`, `helo`, `mailfrom`, `rcptto` | `count`, `string`, `string`, `set[string]` |
| `date`, `from`, `to`, `cc`, `reply_to` | `string`, `string`, `set[string]`, `set[string]`, `string` |
| `msg_id`, `in_reply_to`, `subject`, `x_originating_ip` | `string`, `string`, `string`, `addr` |
| `first_received`, `second_received`, `last_reply`, `path` | `string`, `string`, `string`, `vector[string]` |
| `user_agent`, `tls`, `fuids`, `is_webmail` | `string`, `bool`, `vector[string]`, `bool` |
| `community_id`, `node_id` | `string`, `string` |

### `files.log`

One bounded HTTP entity or SMTP attachment observation. `fuid` is the file ID;
`source` names the carrying protocol; `depth` and `parent_fuid` describe nesting;
`analyzers` describes processing. Size and loss columns report observed,
declared, missing, and overflow bytes. Hashes cover the recovered bytes;
`hash_complete` is true only when those bytes are known to represent the entire
decoded entity. A false value means the hashes identify an observed prefix and
must not be compared as whole-file hashes. `extracted` is set only when explicit
extraction succeeds.

| Fields | Zeek types |
|---|---|
| `ts`, `fuid`, `uid`, `source`, `depth`, `analyzers` | `time`, `string`, `string`, `string`, `count`, `set[string]` |
| `mime_type`, `filename`, `duration`, `local_orig`, `is_orig` | `string`, `string`, `interval`, `bool`, `bool` |
| `seen_bytes`, `total_bytes`, `missing_bytes`, `overflow_bytes`, `timedout` | `count`, `count`, `count`, `count`, `bool` |
| `parent_fuid`, `md5`, `sha1`, `sha256`, `hash_complete`, `extracted` | `string`, `string`, `string`, `string`, `bool`, `string` |
| `community_id`, `node_id` | `string`, `string` |

## Rotation and operations

Each enabled stream has a bounded, non-blocking queue and a single writer. A
full event or stream queue drops new work and increments counters; periodic
warnings summarize drops. Processor flow control considers sustained event and
log queue pressure, including each dispatcher sink queue, but no logging
configuration can guarantee lossless output. `events.drop_policy` currently
accepts `drop_new`; unsupported policies fail during initialization.

HTTP and SMTP file analysis requires body bytes at the capture analyzer. For a
distributed deployment, start the relevant hunter protocol command with
`--capture-body` and an appropriate `--max-body-size`; the processor cannot
retroactively recover bodies that a hunter omitted. SMTP MIME parsing is also
privacy-gated by `--log-include-email-body-preview`. HTTP headers and email body
previews remain disabled unless their respective opt-in flags are set.

Active files are named `conn.log`, `dns.log`, and so on. At the configured
interval, an active file is closed and renamed, for example to
`conn-2026-08-22-14-30-00.log`, then a new active file is opened on the next
record. Graceful `SIGINT`/`SIGTERM` shutdown drains queues, flushes records, and
writes TSV footers. `SIGKILL`, a crash, or a full filesystem cannot do so.

The post-rotate command is run asynchronously through `/bin/sh`; every `%log%`
placeholder is replaced by a shell-quoted path. For example:

```bash
lc process --log-dir /var/log/lippycat \
  --log-post-rotate-command 'gzip %log%'
```

The command is privileged exactly like the lippycat process. Use a fixed,
administrator-controlled command, avoid secrets in arguments, and monitor hook
failure logs. Retention and disk-space management remain operator responsibilities.

## SIEM ingestion examples

For JSONL, point an agent at `/var/log/lippycat/*.log`, parse one JSON object per
line, and use the filename as the dataset. Example Vector source/transform:

```toml
[sources.lippycat]
type = "file"
include = ["/var/log/lippycat/*.log"]
read_from = "beginning"

[transforms.lippycat_json]
type = "remap"
inputs = ["lippycat"]
source = '''
. = parse_json!(.message)
'''
```

For TSV, use an input/parser that understands Zeek headers and rotated files.
Filebeat's Zeek module or a Zeek-aware Vector/Fluent Bit pipeline is appropriate;
do not treat header lines as data. Preserve `uid`, `community_id`, and `node_id`
as exact strings. Because `uid` is local to one observed flow lifecycle,
`community_id` is the preferred cross-product join key; include time and
`node_id` when resolving collisions or repeated connections.

## Privacy and security

Structured logs can contain personal data: IP addresses, DNS names, SNI, URLs,
email addresses and subjects, user agents, filenames, certificate identities,
and stable flow identifiers. Query strings and paths may contain credentials or
tokens. Restrict directory permissions, encrypt storage and transport, define a
retention policy, and collect only streams justified by the monitoring purpose.

Conservative defaults keep logging and extraction disabled, omit arbitrary HTTP
headers, bound all file analysis/extraction, and never put packet payloads,
HTTP/email bodies, RTP/media, or extracted bytes in metadata log rows. Enabling
file extraction creates separate content files and requires correspondingly
stronger access controls. Structured file settings do not authorize LI delivery;
LI metadata remains independently gated by build, runtime, active task, target,
and delivery profile.
