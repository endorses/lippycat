# Appendix A: Command Reference {#appendix-a-command-reference}

This appendix provides a complete reference of all lippycat CLI commands, subcommands, and flags. For tutorials and usage examples, see the relevant chapters in the manual.

> **Tip:** Run `lc <command> --help` for the most up-to-date flag information for any command.

## Command Tree {#command-tree}

<!-- i18n:skip -->

```
lc
├── sniff                  Capture packets (CLI output)
│   ├── voip               VoIP-specific capture
│   ├── dns                DNS-specific capture
│   ├── tls                TLS-specific capture
│   ├── http               HTTP-specific capture
│   ├── email              Email-specific capture
│   └── radius             RADIUS UDP capture
├── tap                    Standalone capture + processor
│   ├── voip               VoIP standalone capture
│   ├── dns                DNS standalone capture
│   ├── tls                TLS standalone capture
│   ├── http               HTTP standalone capture
│   ├── email              Email standalone capture
│   └── radius             RADIUS standalone capture
├── hunt                   Distributed edge capture
│   ├── voip               VoIP hunter
│   ├── dns                DNS hunter
│   ├── tls                TLS hunter
│   ├── http               HTTP hunter
│   ├── email              Email hunter
│   └── radius             RADIUS hunter
├── process                Central aggregation node
├── watch                  Interactive TUI
│   ├── live               Live capture TUI
│   ├── file               PCAP file analysis TUI
│   └── remote             Remote node monitoring TUI
├── list                   List resources
│   ├── interfaces         List network interfaces
│   ├── hunters            List connected hunters
│   └── filters            List active filters
├── show                   Display diagnostics
│   ├── status             Processor status
│   ├── hunter             Specific hunter details
│   ├── topology           Distributed topology
│   ├── filter             Filter details
│   └── config             Local configuration
├── set                    Configure resources
│   └── filter             Create/update a filter
├── rm                     Remove resources
│   └── filter             Remove a filter
├── migrate                Offline encrypted store initialization/migration
│   ├── filter-store       Managed filters (all/cli/processor/tap builds)
│   └── li-state           Administrative state (LI builds only)
└── completion             Shell completions
    ├── bash
    ├── zsh
    ├── fish
    └── powershell
```

## Global Flags {#global-flags}

These flags apply to all commands.

| Flag        | Short | Type   | Default                              | Description               |
| ----------- | ----- | ------ | ------------------------------------ | ------------------------- |
| `--config`  | `-c`  | string | `$HOME/.config/lippycat/config.yaml` | Path to config file       |
| `--help`    | `-h`  |        |                                      | Help for the command      |
| `--version` | `-v`  |        |                                      | Print version information |

---

## Shared Flag Groups {#shared-flag-groups}

Several flag groups appear across multiple commands. They are documented here once and referenced by name in each command section.

### Capture Flags {#capture-flags}

Used by `sniff`, `hunt`, and `tap` for packet capture configuration.

| Flag                          | Short | Type   | Default    | Description                                                |
| ----------------------------- | ----- | ------ | ---------- | ---------------------------------------------------------- |
| `--interface`                 | `-i`  | string | `any`      | Network interface to capture on                            |
| `--filter`                    | `-f`  | string |            | BPF filter expression (see [Appendix C](bpf-reference.md)) |
| `--promisc` / `--promiscuous` | `-p`  | bool   | `false`    | Enable promiscuous mode                                    |
| `--pcap-buffer-size`          |       | int    | `16777216` | PCAP kernel buffer size in bytes (16 MB)                   |

### TLS Client Flags {#tls-client-flags}

Used by commands that connect to a remote processor as a client.

| Flag                | Type   | Default | Description                                           |
| ------------------- | ------ | ------- | ----------------------------------------------------- |
| `--tls-ca`          | string |         | CA certificate file for server verification           |
| `--tls-cert`        | string |         | Client certificate file (for mTLS)                    |
| `--tls-key`         | string |         | Client private key file (for mTLS)                    |
| `--tls-skip-verify` | bool   | `false` | Skip server certificate verification                  |
| `--tls-server-name` | string |         | Override server name for TLS verification             |
| `--insecure`        | bool   | `false` | Disable TLS (blocked when `LIPPYCAT_PRODUCTION=true`) |

### TLS Server Flags {#tls-server-flags}

Used by `process` and `tap` for serving gRPC with TLS.

| Flag                | Type   | Default | Description                                   |
| ------------------- | ------ | ------- | --------------------------------------------- |
| `--tls-cert`        | string |         | Server certificate file                       |
| `--tls-key`         | string |         | Server private key file                       |
| `--tls-ca`          | string |         | CA certificate for client verification (mTLS) |
| `--tls-client-auth` | bool   | `false` | Require client certificates (mTLS)            |

TLS is enabled by default for `process` and `tap` unless `--insecure` is set. Provide `--tls-cert` and `--tls-key` for encrypted serving.

### Managed Storage Flags {#managed-storage-flags}

These flags apply to `process` and every `tap` protocol. Key options contain
references to private files holding exactly 32 raw bytes.

| Flag                                     | Default        | Description                                                                                           |
| ---------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------- |
| `--filter-file`                          | Mode-dependent | Explicit snapshot path; defaults to `~/.config/lippycat/filters.yaml` or `filters.enc`.               |
| `--filter-store-mode`                    | `auto`         | `auto`, `yaml`, or `encrypted`; auto selects encryption when LI is enabled. LI rejects explicit YAML. |
| `--filter-store-key-id`                  | Empty          | Active filter key ID; required in encrypted mode.                                                     |
| `--filter-store-key-file`                | Empty          | Active filter key file; required in encrypted mode.                                                   |
| `--filter-store-read-key`                | Empty          | Repeatable prior filter key `id=path`, at most four.                                                  |
| `--li-state-file`                        | Empty          | LI builds only; encrypted administrative snapshot path, or disabled when empty.                       |
| `--li-state-key-id`                      | Empty          | Active administrative key ID; required with a state file.                                             |
| `--li-state-key-file`                    | Empty          | Independent administrative key file.                                                                  |
| `--li-state-read-key`                    | Empty          | Repeatable prior administrative key `id=path`, at most four.                                          |
| `--li-delivery-x3-spool-dir`             | Empty          | Independent encrypted X3 journal; requires encrypted state and ADMF startup reconciliation.           |
| `--li-delivery-x3-spool-max-bytes`       | `0`            | Required positive allocated disk budget when X3 persistence is enabled.                               |
| `--li-delivery-x3-spool-key-id`          | Empty          | Active X3 journal key ID.                                                                             |
| `--li-delivery-x3-spool-key-file`        | Empty          | Independent private raw 32-byte X3 key.                                                               |
| `--li-delivery-x3-spool-read-key`        | Empty          | Repeatable prior X3 `id=path`, at most four.                                                          |
| `--li-delivery-x3-max-age`               | `0`            | Original-admission retention; must be positive for persistent X3.                                     |
| `--li-delivery-x3-spool-export-manifest` | Empty          | Export exact held X3 identities to a private file.                                                    |
| `--li-delivery-x3-spool-replay-policy`   | `hold`         | Recovered X3 policy: `hold` for authorization or `purge` for durable discard.                         |
| `--li-delivery-x3-spool-replay-manifest` | Empty          | Request exact historical replay after current ADMF reconciliation.                                    |

Encrypted snapshots must already be initialized or explicitly migrated with the
node stopped. `lc migrate filter-store --init --destination PATH --key-id ID
--key-file PATH` creates an empty store. Existing YAML requires `--source-format
yaml --source PATH` instead of `--init`. LI builds provide `lc migrate li-state`
with the same initialization options and `--source-format json` for legacy state.
Same-path conversion requires `--in-place`; interruption recovery uses the
identical command with `--resume`. See the
[offline migration reference](https://github.com/endorses/lippycat/blob/main/cmd/migrate/README.md)
for source preservation and RADIUS allocator handling.

For Linux snapshot key rotation, select `--source-format encrypted`, provide the
old active `--source-key-id`/`--source-key-file` and the fresh output
`--key-id`/`--key-file`. Prior `--read-key` references then belong to the source.
Source and destination must share a private parent directory; same-path rotation
requires `--in-place`. `--max-working-bytes` caps allocated rotation workspace
(default 134217728). LI rotation preserves the optional allocator pin and rejects
`--radius-state-file`. Use the identical command with `--resume` after interruption;
update runtime configuration yourself after successful completion.

### Connection Flags {#connection-flags}

Used by `list filters`, `show`, `set filter`, and `rm filter` to connect to a processor.

| Flag          | Short | Type   | Default | Description                     |
| ------------- | ----- | ------ | ------- | ------------------------------- |
| `--processor` | `-P`  | string |         | Processor address (`host:port`) |
| `--insecure`  |       | bool   | `false` | Disable TLS                     |

Plus the [TLS Client Flags](#tls-client-flags) above.

### GPU Flags {#gpu-flags}

Used by CUDA builds of `sniff voip`, `hunt`, and `tap` for GPU-accelerated filtering. In non-CUDA builds these flags are not registered, except `watch live` has its own local GPU flags.

| Flag                   | Short | Type   | Default | Description                                                            |
| ---------------------- | ----- | ------ | ------- | ---------------------------------------------------------------------- |
| `--gpu-backend`        | `-g`  | string | `auto`  | GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd`, `disabled`          |
| `--gpu-batch-size`     |       | int    | varies  | Packets per GPU batch (default 1024 for sniff, 100 for hunt)           |
| `--gpu-enable`         |       | bool   | `true`  | Enable GPU acceleration (`sniff voip`, CUDA builds only)               |
| `--gpu-max-memory`     |       | string |         | Maximum GPU memory allocation                                          |
| `--enable-voip-filter` |       | bool   | `false` | Enable GPU-accelerated VoIP filtering on hunter/tap (CUDA builds only) |

### Virtual Interface Flags {#virtual-interface-flags}

Used by `sniff`, `process`, and `tap` for virtual network interface output.

| Flag                    | Short | Type     | Default | Description                                                    |
| ----------------------- | ----- | -------- | ------- | -------------------------------------------------------------- |
| `--virtual-interface`   | `-V`  | bool     | `false` | Enable virtual interface output                                |
| `--vif-name`            |       | string   | `lc0`   | Virtual interface name                                         |
| `--vif-type`            |       | string   | `tap`   | Interface type: `tap` or `tun`                                 |
| `--vif-buffer-size`     |       | int      | `65536` | Write buffer size in bytes                                     |
| `--vif-drop-privileges` |       | string   |         | Drop privileges to this user after interface creation          |
| `--vif-netns`           |       | string   |         | Target network namespace                                       |
| `--vif-replay-timing`   |       | bool     | `false` | Replay with original packet timing (sniff only)                |
| `--vif-startup-delay`   |       | duration | `3s`    | Delay before writing to allow consumers to attach (sniff only) |

### PCAP Output Flags {#pcap-output-flags}

Used by `tap` and `process` for writing captured packets to disk.

| Flag                         | Type     | Default   | Description                                                                   |
| ---------------------------- | -------- | --------- | ----------------------------------------------------------------------------- |
| `--write-file`               | string   |           | Write all packets to a single PCAP file                                       |
| `--per-call-pcap`            | bool     | `false`   | Write per-call PCAP files (VoIP)                                              |
| `--per-call-pcap-dir`        | string   | `./pcaps` | Directory for per-call PCAP files                                             |
| `--per-call-pcap-pattern`    | string   |           | Filename pattern for per-call PCAPs                                           |
| `--auto-rotate-pcap`         | bool     | `false`   | Enable auto-rotating PCAP files                                               |
| `--auto-rotate-pcap-dir`     | string   |           | Directory for rotated PCAP files                                              |
| `--auto-rotate-pcap-pattern` | string   |           | Filename pattern for rotated PCAPs                                            |
| `--auto-rotate-max-size`     | string   |           | Maximum file size before rotation                                             |
| `--auto-rotate-idle-timeout` | duration |           | Close file after idle period                                                  |
| `--pcap-command`             | string   |           | Command to run on completed PCAP files (`%pcap%` placeholder)                 |
| `--voip-command`             | string   |           | Command to run on completed VoIP calls (`%callid%`, `%dirname%` placeholders) |
| `--command-concurrency`      | int      | `10`      | Maximum concurrent command executions                                         |
| `--command-timeout`          | duration | `30s`     | Timeout for command execution                                                 |

### Structured Protocol Log Flags {#structured-protocol-log-flags}

Used by `sniff`, `process`, and `tap`. Logging remains disabled until
`--log-dir` is set. See [Structured Protocol Logs](../part5-advanced/structured-protocol-logs.md)
for stream schemas, completeness semantics, rotation, and privacy guidance.

| Flag                               | Type     | Default                               | Description                                            |
| ---------------------------------- | -------- | ------------------------------------- | ------------------------------------------------------ |
| `--event-queue-size`               | int      | `20000`                               | Normalized protocol-event queue capacity               |
| `--event-drop-policy`              | string   | `drop_new`                            | Normalized event overflow policy                       |
| `--log-dir`                        | string   |                                       | Directory for structured log files; enables logging    |
| `--log-format`                     | string   | `tsv`                                 | Output format: `tsv` or `json` (JSONL)                 |
| `--log-streams`                    | strings  | `conn,dns,ssl,http,smtp,files,radius` | Enabled streams                                        |
| `--log-include-http-headers`       | bool     | `false`                               | Preserve full HTTP header maps in normalized events    |
| `--log-include-email-body-preview` | bool     | `false`                               | Permit sensitive email body previews for file analysis |
| `--log-rotate-interval`            | duration | `1h`                                  | Periodic rotation interval; `0` disables it            |
| `--log-queue-size`                 | int      | `10000`                               | Queue capacity for each output stream                  |
| `--log-post-rotate-command`        | string   |                                       | Command after rotation; `%log%` is the rotated path    |
| `--log-emit-stage`                 | string   | `terminal`                            | `process`/`tap` only: `terminal`, `all`, or `none`     |
| `--extract-files`                  | bool     | `false`                               | Extract bounded HTTP and SMTP files                    |
| `--extract-files-dir`              | string   |                                       | Required output directory when extraction is enabled   |
| `--extract-files-max-size`         | int64    | `10485760`                            | Maximum bytes analyzed or extracted per file           |
| `--extract-files-total-size`       | int64    | `104857600`                           | Process-lifetime extracted-byte limit                  |

### LI Flags {#li-flags}

Used by `process` and `tap`. Requires the `li` build tag (`make processor-li`, `make tap-li`, or `make build-li`).
When `--li-enabled` is set, the X1 listen address, server certificate, server key,
and ADMF client CA are all required; incomplete X1 TLS configuration causes
startup to fail.

See [Chapter 14: Lawful Interception](../part5-advanced/lawful-interception.md) for details.

| Flag                                      | Type     | Default | Description                                                                             |
| ----------------------------------------- | -------- | ------- | --------------------------------------------------------------------------------------- |
| `--li-enabled`                            | bool     | `false` | Enable Lawful Interception support                                                      |
| `--li-x1-listen`                          | string   |         | X1 (ADMF) HTTPS listen address                                                          |
| `--li-x1-tls-cert`                        | string   |         | X1 server TLS certificate                                                               |
| `--li-x1-tls-key`                         | string   |         | X1 server TLS private key                                                               |
| `--li-x1-tls-ca`                          | string   |         | **Required when LI is enabled.** CA certificate used to verify ADMF client certificates |
| `--li-delivery-tls-cert`                  | string   |         | X2/X3 delivery client certificate                                                       |
| `--li-delivery-tls-key`                   | string   |         | X2/X3 delivery client private key                                                       |
| `--li-delivery-tls-ca`                    | string   |         | X2/X3 delivery CA certificate (MDF verification)                                        |
| `--li-delivery-queue-size`                | int      | `10000` | Maximum queued X2/X3 PDUs per destination                                               |
| `--li-delivery-send-timeout`              | duration | `5s`    | Timeout for each delivery write                                                         |
| `--li-delivery-reconnect-initial-backoff` | duration | `500ms` | Initial MDF reconnect backoff                                                           |
| `--li-delivery-reconnect-max-backoff`     | duration | `5s`    | Maximum MDF reconnect backoff                                                           |
| `--li-delivery-keepalive-idle`            | duration | `15s`   | Idle time before TCP keepalive probes                                                   |
| `--li-delivery-keepalive-interval`        | duration | `5s`    | TCP keepalive probe interval                                                            |
| `--li-delivery-keepalive-count`           | int      | `3`     | Failed probes before disconnect                                                         |
| `--li-delivery-shutdown-timeout`          | duration | `10s`   | Maximum LI queue flush time during shutdown                                             |
| `--li-admf-endpoint`                      | string   |         | ADMF HTTPS endpoint URL                                                                 |
| `--li-admf-tls-cert`                      | string   |         | Client certificate for ADMF connection                                                  |
| `--li-admf-tls-key`                       | string   |         | Client private key for ADMF connection                                                  |
| `--li-admf-tls-ca`                        | string   |         | CA certificate for ADMF server verification                                             |
| `--li-admf-keepalive`                     | duration | `30s`   | ADMF keepalive interval (0 = disabled)                                                  |
| `--li-admf-sync-on-startup`               | bool     | `true`  | Query ADMF for state on startup                                                         |
| `--li-admf-sync-timeout`                  | duration | `30s`   | Timeout for startup state sync                                                          |
| `--li-admf-reconcile-interval`            | duration | `5m`    | Periodic ADMF reconciliation interval (0 = disabled)                                    |

---

## Commands {#commands}

### `lc sniff` {#lc-sniff}

Capture and display packets from a network interface or PCAP file. Output is written to stdout in the specified format.

<!-- i18n:skip -->

```
lc sniff [flags]
```

| Flag            | Short | Type   | Default | Description                     |
| --------------- | ----- | ------ | ------- | ------------------------------- |
| `--interface`   | `-i`  | string | `any`   | Network interface to capture on |
| `--filter`      | `-f`  | string |         | BPF filter expression           |
| `--promiscuous` | `-p`  | bool   | `false` | Enable promiscuous mode         |
| `--read-file`   | `-r`  | string |         | Read packets from PCAP file     |
| `--write-file`  | `-w`  | string |         | Write packets to PCAP file      |
| `--format`      |       | string | `json`  | Output format: `json` or `text` |
| `--quiet`       | `-q`  | bool   | `false` | Suppress non-packet output      |

Plus [Virtual Interface Flags](#virtual-interface-flags) and
[Structured Protocol Log Flags](#structured-protocol-log-flags).

See [Chapter 4: CLI Capture with `lc sniff`](../part2-local-capture/sniff.md).

---

### `lc sniff voip` {#lc-sniff-voip}

VoIP-specific capture with SIP/RTP analysis, call tracking, and optional GPU acceleration.

<!-- i18n:skip -->

```
lc sniff voip [flags]
```

Inherits all `lc sniff` flags, plus:

**VoIP Filtering**

| Flag               | Short | Type   | Default | Description                            |
| ------------------ | ----- | ------ | ------- | -------------------------------------- |
| `--sip-user`       |       | string |         | Filter by SIP user                     |
| `--sip-port`       | `-S`  | string |         | SIP signaling port(s), comma-separated |
| `--rtp-port-range` | `-R`  | string |         | RTP port range (e.g., `10000-20000`)   |

`--udp-only` still exists for backward compatibility, but is hidden and deprecated in VoIP modes because it can miss TCP SIP traffic. Prefer `--sip-port` and `--rtp-port-range` for BPF narrowing.

**TCP Performance**

| Flag                     | Type   | Default    | Description                                                                            |
| ------------------------ | ------ | ---------- | -------------------------------------------------------------------------------------- |
| `--tcp-performance-mode` | string | `balanced` | TCP mode: `balanced`, `throughput`, `latency`, `memory`                                |
| `--tcp-max-goroutines`   | int    | `0`        | Advisory stream goroutine warning threshold (0 = use default); does not reject streams |
| `--tcp-*`                |        |            | Various TCP reassembly tuning flags                                                    |

**GPU Acceleration**

| Flag               | Short | Type   | Default | Description                                                   |
| ------------------ | ----- | ------ | ------- | ------------------------------------------------------------- |
| `--gpu-backend`    | `-g`  | string | `auto`  | GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd`, `disabled` |
| `--gpu-batch-size` |       | int    | `1024`  | Packets per GPU batch                                         |
| `--gpu-enable`     |       | bool   | `true`  | Enable GPU acceleration                                       |
| `--gpu-max-memory` |       | string |         | Maximum GPU memory allocation                                 |

**PCAP Output**

| Flag                  | Type     | Default | Description                                                |
| --------------------- | -------- | ------- | ---------------------------------------------------------- |
| `--pcap-grace-period` | duration | `5s`    | Grace period before closing call PCAP files after call end |

See [Chapter 4: CLI Capture with `lc sniff`](../part2-local-capture/sniff.md) and [Chapter 13: Performance Optimization](../part5-advanced/performance.md).

---

### `lc sniff dns` {#lc-sniff-dns}

DNS-specific capture with domain filtering and tunnel detection.

<!-- i18n:skip -->

```
lc sniff dns [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag                 | Type   | Default | Description                            |
| -------------------- | ------ | ------- | -------------------------------------- |
| `--dns-port`         | string | `53`    | DNS port(s) to monitor                 |
| `--domain`           | string |         | Filter by domain name                  |
| `--domains-file`     | string |         | File containing domains (one per line) |
| `--detect-tunneling` | bool   | `true`  | Enable DNS tunneling detection         |
| `--track-queries`    | bool   | `true`  | Track query/response pairs             |
| `--udp-only`         | bool   | `false` | Capture UDP only                       |

---

### `lc sniff tls` {#lc-sniff-tls}

TLS-specific capture with SNI filtering and JA3/JA4 fingerprinting.

<!-- i18n:skip -->

```
lc sniff tls [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag                  | Type   | Default | Description                            |
| --------------------- | ------ | ------- | -------------------------------------- |
| `--tls-port`          | string | `443`   | TLS port(s) to monitor                 |
| `--sni`               | string |         | Filter by SNI (Server Name Indication) |
| `--sni-file`          | string |         | File containing SNI values             |
| `--ja3`               | string |         | Filter by JA3 fingerprint              |
| `--ja3-file`          | string |         | File containing JA3 fingerprints       |
| `--ja3s`              | string |         | Filter by JA3S (server) fingerprint    |
| `--ja3s-file`         | string |         | File containing JA3S fingerprints      |
| `--ja4`               | string |         | Filter by JA4 fingerprint              |
| `--ja4-file`          | string |         | File containing JA4 fingerprints       |
| `--track-connections` | bool   | `true`  | Track TLS connection state             |

---

### `lc sniff http` {#lc-sniff-http}

HTTP-specific capture with header and content filtering.

<!-- i18n:skip -->

```
lc sniff http [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag                   | Type   | Default                  | Description                           |
| ---------------------- | ------ | ------------------------ | ------------------------------------- |
| `--http-port`          | string | `80,8080,8000,3000,8888` | HTTP port(s) to monitor               |
| `--host`               | string |                          | Filter by Host header                 |
| `--hosts-file`         | string |                          | File containing hostnames             |
| `--path`               | string |                          | Filter by URL path                    |
| `--paths-file`         | string |                          | File containing URL paths             |
| `--method`             | string |                          | Filter by HTTP method                 |
| `--status`             | string |                          | Filter by response status code        |
| `--user-agent`         | string |                          | Filter by User-Agent header           |
| `--user-agents-file`   | string |                          | File containing User-Agent patterns   |
| `--content-type`       | string |                          | Filter by Content-Type header         |
| `--content-types-file` | string |                          | File containing Content-Type values   |
| `--keywords-file`      | string |                          | File containing body keyword filters  |
| `--capture-body`       | bool   | `false`                  | Capture HTTP request/response body    |
| `--max-body-size`      | int    | `65536`                  | Maximum body size to capture (bytes)  |
| `--track-requests`     | bool   | `true`                   | Track request/response pairs          |
| `--tls-keylog`         | string |                          | TLS key log file for HTTPS decryption |
| `--tls-keylog-pipe`    | string |                          | Named pipe for TLS key log            |

---

### `lc sniff email` {#lc-sniff-email}

Email protocol capture with address and subject filtering. Supports SMTP, POP3, and IMAP.

<!-- i18n:skip -->

```
lc sniff email [flags]
```

Inherits all `lc sniff` flags, plus:

**Port Configuration**

| Flag          | Type   | Default      | Description                                    |
| ------------- | ------ | ------------ | ---------------------------------------------- |
| `--smtp-port` | string | `25,587,465` | SMTP port(s)                                   |
| `--pop3-port` | string | `110,995`    | POP3 port(s)                                   |
| `--imap-port` | string | `143,993`    | IMAP port(s)                                   |
| `--protocol`  | string | `all`        | Protocol filter: `all`, `smtp`, `pop3`, `imap` |

**Address Filtering**

| Flag                | Type   | Default | Description                                 |
| ------------------- | ------ | ------- | ------------------------------------------- |
| `--sender`          | string |         | Filter by sender address                    |
| `--senders-file`    | string |         | File containing sender addresses            |
| `--recipient`       | string |         | Filter by recipient address                 |
| `--recipients-file` | string |         | File containing recipient addresses         |
| `--address`         | string |         | Filter by any address (sender or recipient) |
| `--addresses-file`  | string |         | File containing addresses                   |

**Content Filtering**

| Flag               | Type   | Default | Description                          |
| ------------------ | ------ | ------- | ------------------------------------ |
| `--subject`        | string |         | Filter by subject                    |
| `--subjects-file`  | string |         | File containing subjects             |
| `--command`        | string |         | Filter by SMTP command               |
| `--mailbox`        | string |         | Filter by IMAP mailbox               |
| `--capture-body`   | bool   | `false` | Capture message body                 |
| `--max-body-size`  | int    | `65536` | Maximum body size to capture (bytes) |
| `--keywords-file`  | string |         | File containing body keyword filters |
| `--track-sessions` | bool   | `true`  | Track protocol sessions              |

---

### `lc sniff radius` {#lc-sniff-radius}

Capture visible UDP RADIUS authentication and accounting traffic with bounded
request/response association and exact identity criteria.

<!-- i18n:skip -->

```
lc sniff radius [flags]
```

Inherits all `lc sniff` flags and adds the
[shared RADIUS flags](../part5-advanced/radius.md#shared-flags-and-configuration).
It also supports `-w` / `--write-file` for selected-packet PCAP output.

---

### `lc tap` {#lc-tap}

Standalone capture node that combines hunter and processor capabilities. Captures packets locally, runs protocol analysis, serves a TUI interface via gRPC, and writes PCAP files -- all without requiring a separate processor.

<!-- i18n:skip -->

```
lc tap [flags]
```

**Capture**

| Flag                 | Short | Type   | Default    | Description                        |
| -------------------- | ----- | ------ | ---------- | ---------------------------------- |
| `--interface`        | `-i`  | string | `any`      | Network interface(s) to capture on |
| `--filter`           | `-f`  | string |            | BPF filter expression              |
| `--promisc`          | `-p`  | bool   | `false`    | Enable promiscuous mode            |
| `--pcap-buffer-size` |       | int    | `16777216` | PCAP kernel buffer size (bytes)    |

**Batching**

| Flag                | Short | Type     | Default | Description                                                |
| ------------------- | ----- | -------- | ------- | ---------------------------------------------------------- |
| `--buffer-size`     | `-b`  | int      | `10000` | Internal packet buffer size                                |
| `--sip-buffer-size` |       | int      | `0`     | SIP priority size; 0 automatically matches `--buffer-size` |
| `--batch-size`      |       | int      | `100`   | Packets per batch                                          |
| `--batch-timeout`   |       | duration | `100ms` | Maximum batch wait time                                    |

**Server**

| Flag                              | Short | Type   | Default       | Description                                                          |
| --------------------------------- | ----- | ------ | ------------- | -------------------------------------------------------------------- |
| `--listen`                        | `-l`  | string | `:55555`      | gRPC listen address for hunter and TUI clients                       |
| `--id`                            | `-I`  | string |               | Node identifier                                                      |
| `--max-hunters`                   |       | int    | `0`           | Maximum concurrent hunters (0 = unlimited)                           |
| `--max-subscribers`               |       | int    | `100`         | Maximum concurrent TUI subscribers (0 = unlimited)                   |
| `--event-allow-sensitive-fields`  |       | bool   | `false`       | Permit authorized requests for sensitive HTTP, SMTP, and file fields |
| `--event-allow-file-metadata`     |       | bool   | `false`       | Permit authorized file-metadata requests; never file content         |
| `--event-ingress-profile`         |       | string | `memory-only` | Downstream event acknowledgement: `memory-only` or `reliable`        |
| `--event-ingress-wal-dir`         |       | string |               | Recoverable ingress WAL; required for reliable profile               |
| `--event-ingress-wal-max-bytes`   |       | int64  | `1073741824`  | Maximum event-ingress WAL size                                       |
| `--event-ingress-max-batch-bytes` |       | int    | `4194304`     | Maximum accepted event batch size                                    |
| `--insecure`                      |       | bool   | `false`       | Disable TLS for gRPC server                                          |
| `--api-key-auth`                  |       | bool   | `false`       | Enable API key authentication                                        |
| `--debug-listen`                  |       | string |               | Enable pprof listener, loopback-only by default                      |
| `--debug-allow-non-loopback`      |       | bool   | `false`       | Permit pprof listener on non-loopback addresses                      |

**Upstream Forwarding**

| Flag                              | Short | Type     | Default                             | Description                                                     |
| --------------------------------- | ----- | -------- | ----------------------------------- | --------------------------------------------------------------- |
| `--processor`                     | `-P`  | string   |                                     | Upstream processor address for forwarding                       |
| `--forward-mode`                  |       | string   | `packets`                           | Upstream representation: `packets` or `events`                  |
| `--event-fallback-to-packets`     |       | bool     | `false`                             | Explicitly allow packet fallback after failed event negotiation |
| `--event-delivery-profile`        |       | string   | `reliable`                          | `reliable` or `memory-only` event delivery                      |
| `--event-spool-dir`               |       | string   | `/var/tmp/lippycat-tap-event-spool` | Recoverable upstream event spool                                |
| `--event-spool-max-bytes`         |       | uint     | `1073741824`                        | Spool byte limit (0 = unlimited)                                |
| `--event-spool-max-age`           |       | duration | `24h`                               | Spool age limit (0 = unlimited)                                 |
| `--event-spool-exhaustion-policy` |       | string   | `drop_oldest`                       | `drop_oldest` or `drop_new`                                     |

**Detection**

| Flag                 | Short | Type   | Default | Description                                       |
| -------------------- | ----- | ------ | ------- | ------------------------------------------------- |
| `--detect`           | `-d`  | bool   | `true`  | Enable protocol detection                         |
| `--filter-file`      |       | string |         | Filter definition file                            |
| `--no-filter-policy` |       | string | `deny`  | Behavior when no filters exist: `allow` or `deny` |

Plus [PCAP Output Flags](#pcap-output-flags), [TLS Server Flags](#tls-server-flags),
[Virtual Interface Flags](#virtual-interface-flags), [GPU Flags](#gpu-flags), and
[Structured Protocol Log Flags](#structured-protocol-log-flags).

See [Chapter 9: Standalone Mode with `lc tap`](../part3-distributed/tap.md).

---

### `lc tap voip` {#lc-tap-voip}

VoIP-specific standalone capture with SIP/RTP analysis and per-call PCAP.

<!-- i18n:skip -->

```
lc tap voip [flags]
```

Inherits all `lc tap` flags, plus:

| Flag                      | Type   | Default    | Description                                                                                  |
| ------------------------- | ------ | ---------- | -------------------------------------------------------------------------------------------- |
| `--sip-user`              | string |            | Filter by SIP user                                                                           |
| `--sip-port`              | int    | `5060`     | SIP signaling port                                                                           |
| `--rtp-port-range`        | string |            | RTP port range                                                                               |
| `--tcp-performance-mode`  | string | `balanced` | TCP mode: `minimal`, `balanced`, `high_performance`, `low_latency`                           |
| `--tcp-reassembly-shards` | int    | `1`        | Flow-sharded TCP reassembly assembler count                                                  |
| `--tcp-max-streams`       | int    | `0`        | Active buffered TCP SIP stream processor cap (0 = unlimited); positive values reject streams |
| `--pattern-algorithm`     | string | `auto`     | Pattern matching algorithm: `auto`, `linear`, `aho-corasick`                                 |
| `--pattern-buffer-mb`     | int    | `64`       | Pattern buffer size (MB)                                                                     |

`--tcp-max-streams` also uses `voip.max_streams` in configuration. A positive
value intentionally discards SIP data for rejected new or restarted streams.
Discarded connections can still occupy reassembly pool entries until they
close or are flushed. This does not cap total process memory.

---

### `lc tap dns` {#lc-tap-dns}

DNS-specific standalone capture with tunneling detection.

<!-- i18n:skip -->

```
lc tap dns [flags]
```

Inherits all `lc tap` flags, plus:

| Flag                    | Type     | Default | Description                                   |
| ----------------------- | -------- | ------- | --------------------------------------------- |
| `--dns-port`            | string   | `53`    | DNS port(s) to monitor                        |
| `--domain`              | string   |         | Filter by domain pattern                      |
| `--domains-file`        | string   |         | File containing domain patterns               |
| `--detect-tunneling`    | bool     | `true`  | Enable DNS tunneling detection                |
| `--udp-only`            | bool     | `false` | Capture UDP DNS only                          |
| `--tunneling-command`   | string   |         | Command to execute when tunneling is detected |
| `--tunneling-threshold` | float    | `0.7`   | DNS tunneling score threshold                 |
| `--tunneling-debounce`  | duration | `5m`    | Minimum time between alerts per domain        |

---

### `lc tap http` {#lc-tap-http}

HTTP-specific standalone capture.

<!-- i18n:skip -->

```
lc tap http [flags]
```

Inherits all `lc tap` flags, plus the same HTTP filtering flags as `lc sniff http`: `--http-port`, `--host`, `--path`, `--method`, `--status`, `--user-agent`, `--content-type`, pattern file flags, `--capture-body`, `--max-body-size`, `--tls-keylog`, and `--tls-keylog-pipe`.

---

### `lc tap tls` {#lc-tap-tls}

TLS-specific standalone capture.

<!-- i18n:skip -->

```
lc tap tls [flags]
```

Inherits all `lc tap` flags, plus:

| Flag         | Type   | Default | Description                  |
| ------------ | ------ | ------- | ---------------------------- |
| `--tls-port` | string | `443`   | TLS port(s) to monitor       |
| `--sni`      | string |         | Filter by SNI pattern        |
| `--sni-file` | string |         | File containing SNI patterns |

---

### `lc tap email` {#lc-tap-email}

Email-specific standalone capture.

<!-- i18n:skip -->

```
lc tap email [flags]
```

Inherits all `lc tap` flags, plus the same email filtering flags as `lc sniff email`: protocol and port flags, address/sender/recipient/subject filters, pattern file flags, `--mailbox`, `--command`, `--capture-body`, `--max-body-size`, and `--keywords-file`.

---

### `lc tap radius` {#lc-tap-radius}

Standalone RADIUS capture with processor outputs, including PCAP, structured
logs, and remote TUI display.

<!-- i18n:skip -->

```
lc tap radius [flags]
```

Inherits all `lc tap` flags and adds the
[shared RADIUS flags](../part5-advanced/radius.md#shared-flags-and-configuration).
LI builds can independently enable authorized format-11 X2 delivery.

---

### `lc hunt` {#lc-hunt}

Hunter node for distributed edge capture. Captures packets and forwards them to a processor node via gRPC.

<!-- i18n:skip -->

```
lc hunt [flags]
```

| Flag                              | Short | Type     | Default                         | Description                                                     |
| --------------------------------- | ----- | -------- | ------------------------------- | --------------------------------------------------------------- |
| `--processor`                     | `-P`  | string   | **required**                    | Processor address (`host:port`)                                 |
| `--forward-mode`                  |       | string   | `packets`                       | Upstream representation: `packets` or `events`                  |
| `--event-fallback-to-packets`     |       | bool     | `false`                         | Explicitly allow packet fallback after failed event negotiation |
| `--event-delivery-profile`        |       | string   | `reliable`                      | `reliable` or `memory-only` event delivery                      |
| `--event-spool-dir`               |       | string   | `/var/tmp/lippycat-event-spool` | Recoverable event spool                                         |
| `--event-spool-max-bytes`         |       | uint     | `1073741824`                    | Spool byte limit (0 = unlimited)                                |
| `--event-spool-max-age`           |       | duration | `24h`                           | Spool age limit (0 = unlimited)                                 |
| `--event-spool-exhaustion-policy` |       | string   | `drop_oldest`                   | `drop_oldest` or `drop_new`                                     |
| `--id`                            | `-I`  | string   |                                 | Hunter identifier                                               |
| `--interface`                     | `-i`  | string   | `any`                           | Network interface(s) to capture on                              |
| `--filter`                        | `-f`  | string   |                                 | BPF filter expression                                           |
| `--promisc`                       | `-p`  | bool     | `false`                         | Enable promiscuous mode                                         |
| `--buffer-size`                   | `-b`  | int      | `10000`                         | Internal packet buffer size                                     |
| `--sip-buffer-size`               |       | int      | `0`                             | SIP priority size; 0 automatically matches `--buffer-size`      |
| `--batch-size`                    |       | int      | `64`                            | Packets per batch                                               |
| `--batch-timeout`                 |       | duration | `100ms`                         | Maximum batch wait time                                         |
| `--batch-queue-size`              |       | int      | `1000`                          | Batch queue depth (0 defaults to 1000)                          |
| `--pcap-buffer-size`              |       | int      | `16777216`                      | PCAP kernel buffer size (bytes)                                 |
| `--disk-buffer`                   |       | bool     | `false`                         | Enable disk-based buffer for backpressure                       |
| `--disk-buffer-dir`               |       | string   |                                 | Directory for disk buffer files                                 |
| `--disk-buffer-max-mb`            |       | int      | `1024`                          | Maximum disk buffer size (MB)                                   |
| `--enable-voip-filter`            |       | bool     | `false`                         | Enable VoIP packet filtering                                    |
| `--gpu-backend`                   | `-g`  | string   | `auto`                          | GPU backend                                                     |
| `--gpu-batch-size`                |       | int      | `100`                           | Packets per GPU batch                                           |
| `--no-filter-policy`              |       | string   | `deny`                          | Behavior when no filters exist: `allow` or `deny`               |
| `--debug-listen`                  |       | string   |                                 | Enable pprof listener, loopback-only by default                 |
| `--debug-allow-non-loopback`      |       | bool     | `false`                         | Permit pprof listener on non-loopback addresses                 |
| `--insecure`                      |       | bool     | `false`                         | Disable TLS                                                     |

Plus [TLS Client Flags](#tls-client-flags) (`--tls-ca`, `--tls-cert`, `--tls-key`, `--tls-skip-verify`).

See [Chapter 7: Edge Capture with `lc hunt`](../part3-distributed/hunt.md).

---

### `lc hunt voip` {#lc-hunt-voip}

VoIP-specific hunter with SIP/RTP call filtering and buffering.

<!-- i18n:skip -->

```
lc hunt voip [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag                     | Short | Type     | Default | Description                                                                                  |
| ------------------------ | ----- | -------- | ------- | -------------------------------------------------------------------------------------------- |
| `--sip-port`             | `-S`  | int      | `5060`  | SIP signaling port                                                                           |
| `--rtp-port-range`       | `-R`  | string   |         | RTP port range                                                                               |
| `--pattern-algorithm`    |       | string   | `auto`  | Pattern matching: `auto`, `linear`, `aho-corasick`                                           |
| `--pattern-buffer-mb`    |       | int      | `64`    | Pattern buffer size (MB)                                                                     |
| `--tcp-sip-idle-timeout` |       | duration |         | Idle timeout for SIP TCP connections                                                         |
| `--tcp-max-streams`      |       | int      | `0`     | Active buffered TCP SIP stream processor cap (0 = unlimited); positive values reject streams |

`--udp-only` is hidden and deprecated for VoIP hunters; use `--sip-port` and `--rtp-port-range` instead.

`--tcp-max-streams` also uses `voip.max_streams` in configuration. A positive
value intentionally discards SIP data for rejected new or restarted streams.
Discarded connections can still occupy reassembly pool entries until they
close or are flushed. This does not cap total process memory.

---

### `lc hunt dns` {#lc-hunt-dns}

DNS-specific hunter with domain filtering.

<!-- i18n:skip -->

```
lc hunt dns [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag         | Type   | Default | Description            |
| ------------ | ------ | ------- | ---------------------- |
| `--dns-port` | string | `53`    | DNS port(s) to monitor |
| `--udp-only` | bool   | `false` | Capture UDP only       |

---

### `lc hunt http` {#lc-hunt-http}

HTTP-specific hunter with edge filtering.

<!-- i18n:skip -->

```
lc hunt http [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag                | Type   | Default                  | Description               |
| ------------------- | ------ | ------------------------ | ------------------------- |
| `--http-port`       | string | `80,8080,8000,3000,8888` | HTTP port(s) to monitor   |
| `--host`            | string |                          | Host patterns             |
| `--path`            | string |                          | Path patterns             |
| `--method`          | string |                          | HTTP methods              |
| `--status`          | string |                          | Status codes              |
| `--keywords`        | string |                          | Body/URL keywords         |
| `--capture-body`    | bool   | `false`                  | Enable body capture       |
| `--max-body-size`   | int    | `65536`                  | Maximum body capture size |
| `--tls-keylog`      | string |                          | TLS key log file          |
| `--tls-keylog-pipe` | string |                          | TLS key log named pipe    |

---

### `lc hunt tls` {#lc-hunt-tls}

TLS-specific hunter.

<!-- i18n:skip -->

```
lc hunt tls [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag         | Type   | Default | Description            |
| ------------ | ------ | ------- | ---------------------- |
| `--tls-port` | string | `443`   | TLS port(s) to monitor |

---

### `lc hunt email` {#lc-hunt-email}

Email-specific hunter with edge filtering.

<!-- i18n:skip -->

```
lc hunt email [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag              | Type   | Default      | Description                                      |
| ----------------- | ------ | ------------ | ------------------------------------------------ |
| `--protocol`      | string | `all`        | Email protocol: `smtp`, `imap`, `pop3`, or `all` |
| `--smtp-port`     | string | `25,587,465` | SMTP ports                                       |
| `--imap-port`     | string | `143,993`    | IMAP ports                                       |
| `--pop3-port`     | string | `110,995`    | POP3 ports                                       |
| `--sender`        | string |              | Sender patterns                                  |
| `--recipient`     | string |              | Recipient patterns                               |
| `--subject`       | string |              | Subject patterns                                 |
| `--mailbox`       | string |              | IMAP mailbox patterns                            |
| `--command`       | string |              | IMAP/POP3 command patterns                       |
| `--keywords`      | string |              | Body/subject keywords                            |
| `--capture-body`  | bool   | `false`      | Enable body capture                              |
| `--max-body-size` | int    | `65536`      | Maximum body capture size                        |

---

### `lc hunt radius` {#lc-hunt-radius}

Capture selected RADIUS traffic at the edge and forward packets plus validated
observation and provenance metadata to a processor. Routine display and log
output use a credential-redacted projection.

<!-- i18n:skip -->

```
lc hunt radius [flags]
```

Inherits all `lc hunt` flags and adds the
[shared RADIUS flags](../part5-advanced/radius.md#shared-flags-and-configuration).

---

### `lc process` {#lc-process}

Processor node for central aggregation. Receives packets from hunters via gRPC, performs protocol analysis, writes PCAP files, and serves TUI clients.

<!-- i18n:skip -->

```
lc process [flags]
```

**Server**

| Flag                              | Short | Type   | Default       | Description                                                          |
| --------------------------------- | ----- | ------ | ------------- | -------------------------------------------------------------------- |
| `--listen`                        | `-l`  | string | `:55555`      | gRPC listen address                                                  |
| `--id`                            | `-I`  | string |               | Processor identifier                                                 |
| `--max-hunters`                   | `-m`  | int    | `100`         | Maximum connected hunters                                            |
| `--max-subscribers`               |       | int    | `100`         | Maximum TUI subscribers                                              |
| `--event-allow-sensitive-fields`  |       | bool   | `false`       | Permit authorized requests for sensitive HTTP, SMTP, and file fields |
| `--event-allow-file-metadata`     |       | bool   | `false`       | Permit authorized file-metadata requests; never file content         |
| `--event-ingress-profile`         |       | string | `memory-only` | Event acknowledgement profile: `memory-only` or `reliable`           |
| `--event-ingress-wal-dir`         |       | string |               | Recoverable ingress WAL; required for reliable profile               |
| `--event-ingress-wal-max-bytes`   |       | int64  | `1073741824`  | Maximum event-ingress WAL size                                       |
| `--event-ingress-max-batch-bytes` |       | int    | `4194304`     | Maximum accepted event batch size                                    |
| `--insecure`                      |       | bool   | `false`       | Disable TLS                                                          |
| `--api-key-auth`                  |       | bool   | `false`       | Enable API key authentication                                        |
| `--debug-listen`                  |       | string |               | Enable pprof listener, loopback-only by default                      |
| `--debug-allow-non-loopback`      |       | bool   | `false`       | Permit pprof listener on non-loopback addresses                      |

**Detection & Filtering**

| Flag                 | Short | Type   | Default | Description               |
| -------------------- | ----- | ------ | ------- | ------------------------- |
| `--enable-detection` | `-d`  | bool   | `true`  | Enable protocol detection |
| `--filter-file`      | `-f`  | string |         | Filter definition file    |

**Upstream Forwarding**

| Flag                              | Short | Type     | Default                                   | Description                                                     |
| --------------------------------- | ----- | -------- | ----------------------------------------- | --------------------------------------------------------------- |
| `--processor`                     | `-P`  | string   |                                           | Upstream processor for hierarchical topology                    |
| `--forward-mode`                  |       | string   | `packets`                                 | Upstream representation: `packets` or `events`                  |
| `--event-fallback-to-packets`     |       | bool     | `false`                                   | Explicitly allow packet fallback after failed event negotiation |
| `--event-delivery-profile`        |       | string   | `reliable`                                | `reliable` or `memory-only` event delivery                      |
| `--event-spool-dir`               |       | string   | `/var/tmp/lippycat-processor-event-spool` | Recoverable upstream event spool                                |
| `--event-spool-max-bytes`         |       | uint     | `1073741824`                              | Spool byte limit (0 = unlimited)                                |
| `--event-spool-max-age`           |       | duration | `24h`                                     | Spool age limit (0 = unlimited)                                 |
| `--event-spool-exhaustion-policy` |       | string   | `drop_oldest`                             | `drop_oldest` or `drop_new`                                     |

**Statistics**

| Flag      | Short | Type | Default | Description                  |
| --------- | ----- | ---- | ------- | ---------------------------- |
| `--stats` | `-s`  | bool | `true`  | Enable statistics collection |

**TLS Key Logging**

| Flag               | Type   | Default | Description                                  |
| ------------------ | ------ | ------- | -------------------------------------------- |
| `--tls-keylog-dir` | string |         | Directory for TLS key log files from hunters |

Plus [PCAP Output Flags](#pcap-output-flags), [TLS Server Flags](#tls-server-flags),
[Virtual Interface Flags](#virtual-interface-flags), [Structured Protocol Log Flags](#structured-protocol-log-flags),
and [LI Flags](#li-flags).

See [Chapter 8: Central Aggregation with `lc process`](../part3-distributed/process.md).

---

### `lc watch` {#lc-watch}

Interactive terminal UI for monitoring packet capture. Defaults to live mode if no subcommand is specified.

<!-- i18n:skip -->

```
lc watch [subcommand] [flags]
```

**Persistent flags** (inherited by all subcommands):

| Flag            | Type | Default | Description                  |
| --------------- | ---- | ------- | ---------------------------- |
| `--buffer-size` | int  | `10000` | TUI packet buffer size       |
| `--max-calls`   | int  |         | Maximum displayed VoIP calls |

Plus [TLS Client Flags](#tls-client-flags).

See [Chapter 5: Interactive Capture with `lc watch`](../part2-local-capture/watch-local.md).

---

### `lc watch live` {#lc-watch-live}

Live packet capture in the TUI. Requires elevated privileges.

<!-- i18n:skip -->

```
lc watch live [flags]
```

| Flag               | Short | Type   | Default | Description                     |
| ------------------ | ----- | ------ | ------- | ------------------------------- |
| `--interface`      | `-i`  | string | `any`   | Network interface to capture on |
| `--filter`         | `-f`  | string |         | BPF filter expression           |
| `--promiscuous`    | `-p`  | bool   | `false` | Enable promiscuous mode         |
| `--enable-gpu`     |       | bool   | `false` | Enable GPU acceleration         |
| `--gpu-backend`    |       | string |         | GPU backend                     |
| `--gpu-batch-size` |       | int    |         | Packets per GPU batch           |

---

### `lc watch file` {#lc-watch-file}

Analyze PCAP files in the TUI. Accepts one or more PCAP files (merged display).

<!-- i18n:skip -->

```
lc watch file <file> [file...] [flags]
```

| Flag           | Type   | Default | Description                     |
| -------------- | ------ | ------- | ------------------------------- |
| `--tls-keylog` | string |         | TLS key log file for decryption |

---

### `lc watch remote` {#lc-watch-remote}

Monitor remote processor nodes in the TUI. Connects via gRPC.

<!-- i18n:skip -->

```
lc watch remote [flags]
```

| Flag           | Short | Type   | Default | Description                                       |
| -------------- | ----- | ------ | ------- | ------------------------------------------------- |
| `--processor`  | `-P`  | string |         | Processor address (host:port) to connect directly |
| `--nodes-file` | `-n`  | string |         | YAML file listing remote nodes                    |
| `--insecure`   |       | bool   | `false` | Disable TLS                                       |

See [Chapter 11: Remote TUI Monitoring](../part4-administration/watch-remote.md).

---

### `lc list interfaces` {#lc-list-interfaces}

List available network interfaces with their addresses and status.

<!-- i18n:skip -->

```
lc list interfaces
```

| Flag     | Type | Default | Description                   |
| -------- | ---- | ------- | ----------------------------- |
| `--json` | bool | `false` | Output interface data as JSON |

---

### `lc list filters` {#lc-list-filters}

List active filters on a processor node.

<!-- i18n:skip -->

```
lc list filters [flags]
```

| Flag          | Short | Type   | Default | Description         |
| ------------- | ----- | ------ | ------- | ------------------- |
| `--processor` | `-P`  | string |         | Processor address   |
| `--hunter`    |       | string |         | Filter by hunter ID |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

See [Chapter 10: CLI Administration](../part4-administration/cli-admin.md).

---

### `lc list hunters` {#lc-list-hunters}

List connected hunters on a processor node.

<!-- i18n:skip -->

```
lc list hunters [flags]
```

| Flag          | Short | Type   | Default | Description       |
| ------------- | ----- | ------ | ------- | ----------------- |
| `--processor` | `-P`  | string |         | Processor address |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

See [Chapter 10: CLI Administration](../part4-administration/cli-admin.md).

---

### `lc show status` {#lc-show-status}

Display processor node status.

<!-- i18n:skip -->

```
lc show status [flags]
```

| Flag          | Short | Type   | Default      | Description       |
| ------------- | ----- | ------ | ------------ | ----------------- |
| `--processor` | `-P`  | string | **required** | Processor address |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show hunter` {#lc-show-hunter}

Display details for a specific hunter.

<!-- i18n:skip -->

```
lc show hunter [flags]
```

| Flag          | Short | Type   | Default      | Description          |
| ------------- | ----- | ------ | ------------ | -------------------- |
| `--processor` | `-P`  | string | **required** | Processor address    |
| `--id`        |       | string | **required** | Hunter ID to display |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show topology` {#lc-show-topology}

Display the distributed topology (hunters, processors, connections).

<!-- i18n:skip -->

```
lc show topology [flags]
```

| Flag          | Short | Type   | Default      | Description       |
| ------------- | ----- | ------ | ------------ | ----------------- |
| `--processor` | `-P`  | string | **required** | Processor address |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show filter` {#lc-show-filter}

Display details of a specific filter.

<!-- i18n:skip -->

```
lc show filter [flags]
```

| Flag          | Short | Type   | Default      | Description          |
| ------------- | ----- | ------ | ------------ | -------------------- |
| `--processor` | `-P`  | string | **required** | Processor address    |
| `--id`        |       | string |              | Filter ID to display |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show config` {#lc-show-config}

Display the current local configuration (resolved from config file, environment, and defaults).

<!-- i18n:skip -->

```
lc show config
```

No additional flags.

---

### `lc set filter` {#lc-set-filter}

Create or update a filter on a processor node.

<!-- i18n:skip -->

```
lc set filter [flags]
```

| Flag                        | Short | Type    | Default      | Description                                      |
| --------------------------- | ----- | ------- | ------------ | ------------------------------------------------ |
| `--processor`               | `-P`  | string  | **required** | Processor address                                |
| `--id`                      |       | string  |              | Filter ID (auto-generated if omitted)            |
| `--type`                    | `-t`  | string  |              | Filter type                                      |
| `--pattern`                 |       | string  |              | Filter pattern                                   |
| `--description`             |       | string  |              | Human-readable description                       |
| `--enabled`                 |       | bool    | `true`       | Enable the filter                                |
| `--hunters`                 |       | strings |              | Target hunter IDs                                |
| `--file`                    | `-f`  | string  |              | YAML file for batch or structured RADIUS filters |
| `--revision`                |       | uint64  | `1`          | RADIUS filter revision                           |
| `--radius-mac-profile`      |       | string  |              | Subscriber MAC interpretation profile            |
| `--radius-operator-scope`   |       | string  |              | Operator/NAS deployment scope                    |
| `--radius-profile-revision` |       | string  |              | Deployment profile revision                      |
| `--radius-origin-node`      |       | string  |              | Restrict RADIUS scope to an origin node          |
| `--radius-source`           |       | string  |              | Restrict RADIUS scope to a capture source        |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

See [Chapter 10: CLI Administration](../part4-administration/cli-admin.md).

---

### `lc rm filter` {#lc-rm-filter}

Remove a filter from a processor node.

<!-- i18n:skip -->

```
lc rm filter [flags]
```

| Flag          | Short | Type   | Default      | Description               |
| ------------- | ----- | ------ | ------------ | ------------------------- |
| `--processor` | `-P`  | string | **required** | Processor address         |
| `--id`        |       | string |              | Filter ID to remove       |
| `--file`      | `-f`  | string |              | Load filter IDs from file |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc completion` {#lc-completion}

Generate shell completion scripts.

<!-- i18n:skip -->

```
lc completion [bash|zsh|fish|powershell]
```

No additional flags. Output the completion script to stdout; source it in your shell configuration.

**Examples:**

Bash:

<!-- i18n:skip -->

```bash
lc completion bash > ~/.local/share/bash-completion/completions/lc
```

Zsh:

<!-- i18n:skip -->

```bash
lc completion zsh > "${fpath[1]}/_lc"
```

Fish:

<!-- i18n:skip -->

```bash
lc completion fish > ~/.config/fish/completions/lc.fish
```

PowerShell:

<!-- i18n:skip -->

```bash
lc completion powershell > lc.ps1
```

---

## Environment Variables {#environment-variables}

| Variable              | Description                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `LIPPYCAT_PRODUCTION` | Set to `true` to enforce TLS on all gRPC connections. Blocks the `--insecure` flag.                                      |
| `SSLKEYLOGFILE`       | Path to TLS key log file for decrypting captured TLS traffic. See [Chapter 12: Security](../part5-advanced/security.md). |

---

## Exit Codes {#exit-codes}

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | Success                                                   |
| `1`  | General error (runtime failure, connection refused, etc.) |
| `2`  | Usage error (invalid flags, missing required arguments)   |
