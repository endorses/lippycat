# Appendix A: Command Reference

This appendix provides a complete reference of all lippycat CLI commands, subcommands, and flags. For tutorials and usage examples, see the relevant chapters in the manual.

> **Tip:** Run `lc <command> --help` for the most up-to-date flag information for any command.

## Command Tree

```
lc
├── sniff                  Capture packets (CLI output)
│   ├── voip               VoIP-specific capture
│   ├── dns                DNS-specific capture
│   ├── tls                TLS-specific capture
│   ├── http               HTTP-specific capture
│   └── email              Email-specific capture
├── tap                    Standalone capture + processor
│   ├── voip               VoIP standalone capture
│   ├── dns                DNS standalone capture
│   ├── tls                TLS standalone capture
│   ├── http               HTTP standalone capture
│   └── email              Email standalone capture
├── hunt                   Distributed edge capture
│   ├── voip               VoIP hunter
│   └── dns                DNS hunter
├── process                Central aggregation node
├── watch                  Interactive TUI
│   ├── live               Live capture TUI
│   ├── file               PCAP file analysis TUI
│   └── remote             Remote node monitoring TUI
├── list                   List resources
│   ├── interfaces         List network interfaces
│   └── filters            List active filters
├── show                   Display diagnostics
│   ├── status             Processor status
│   ├── hunters            Connected hunters
│   ├── topology           Distributed topology
│   ├── filter             Filter details
│   └── config             Local configuration
├── set                    Configure resources
│   └── filter             Create/update a filter
├── rm                     Remove resources
│   └── filter             Remove a filter
└── completion             Shell completions
    ├── bash
    ├── zsh
    ├── fish
    └── powershell
```

## Global Flags

These flags apply to all commands.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | `-c` | string | `$HOME/.config/lippycat/config.yaml` | Path to config file |
| `--help` | `-h` | | | Help for the command |
| `--version` | `-v` | | | Print version information |

---

## Shared Flag Groups

Several flag groups appear across multiple commands. They are documented here once and referenced by name in each command section.

### Capture Flags

Used by `sniff`, `hunt`, and `tap` for packet capture configuration.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interface` | `-i` | string | `any` | Network interface to capture on |
| `--filter` | `-f` | string | | BPF filter expression (see [Appendix C](bpf-reference.md)) |
| `--promisc` / `--promiscuous` | `-p` | bool | `false` | Enable promiscuous mode |
| `--pcap-buffer-size` | | int | `16777216` | PCAP kernel buffer size in bytes (16 MB) |

### TLS Client Flags

Used by commands that connect to a remote processor as a client.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls-ca` | string | | CA certificate file for server verification |
| `--tls-cert` | string | | Client certificate file (for mTLS) |
| `--tls-key` | string | | Client private key file (for mTLS) |
| `--tls-skip-verify` | bool | `false` | Skip server certificate verification |
| `--tls-server-name` | string | | Override server name for TLS verification |
| `--insecure` | bool | `false` | Disable TLS (blocked when `LIPPYCAT_PRODUCTION=true`) |

### TLS Server Flags

Used by `process` and `tap` for serving gRPC with TLS.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls` | bool | `false` | Enable TLS for the gRPC server |
| `--tls-cert` | string | | Server certificate file |
| `--tls-key` | string | | Server private key file |
| `--tls-ca` | string | | CA certificate for client verification (mTLS) |
| `--tls-client-auth` | bool | `false` | Require client certificates (mTLS) |

### Connection Flags

Used by `list filters`, `show`, `set filter`, and `rm filter` to connect to a processor.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | | Processor address (`host:port`) |
| `--insecure` | | bool | `false` | Disable TLS |

Plus the [TLS Client Flags](#tls-client-flags) above.

### GPU Flags

Used by `sniff voip`, `hunt`, and `tap` for GPU-accelerated filtering.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--gpu-backend` | `-g` | string | `auto` | GPU backend: `auto`, `cuda`, `opencl`, `simd`, `none` |
| `--gpu-batch-size` | | int | varies | Packets per GPU batch (default 1024 for sniff, 100 for hunt) |
| `--gpu-enable` | | bool | `true` | Enable GPU acceleration (sniff voip) |
| `--gpu-max-memory` | | string | | Maximum GPU memory allocation |
| `--enable-voip-filter` | | bool | | Enable VoIP packet filtering on hunter |

### Virtual Interface Flags

Used by `sniff`, `process`, and `tap` for virtual network interface output.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--virtual-interface` | `-V` | bool | `false` | Enable virtual interface output |
| `--vif-name` | | string | `lc0` | Virtual interface name |
| `--vif-type` | | string | `tap` | Interface type: `tap` or `tun` |
| `--vif-buffer-size` | | int | `65536` | Write buffer size in bytes |
| `--vif-drop-privileges` | | bool | `false` | Drop root privileges after interface creation |
| `--vif-netns` | | string | | Target network namespace |
| `--vif-replay-timing` | | bool | `false` | Replay with original packet timing (sniff only) |
| `--vif-startup-delay` | | duration | `3s` | Delay before writing to allow consumers to attach (sniff only) |

### PCAP Output Flags

Used by `tap` and `process` for writing captured packets to disk.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--write-file` | string | | Write all packets to a single PCAP file |
| `--per-call-pcap` | bool | `false` | Write per-call PCAP files (VoIP) |
| `--per-call-pcap-dir` | string | `./pcaps` | Directory for per-call PCAP files |
| `--per-call-pcap-pattern` | string | | Filename pattern for per-call PCAPs |
| `--auto-rotate-pcap` | bool | `false` | Enable auto-rotating PCAP files |
| `--auto-rotate-pcap-dir` | string | | Directory for rotated PCAP files |
| `--auto-rotate-pcap-pattern` | string | | Filename pattern for rotated PCAPs |
| `--auto-rotate-max-size` | string | | Maximum file size before rotation |
| `--auto-rotate-idle-timeout` | duration | | Close file after idle period |
| `--pcap-command` | string | | Command to run on completed PCAP files (`%pcap%` placeholder) |
| `--voip-command` | string | | Command to run on completed VoIP calls (`%callid%`, `%dirname%` placeholders) |
| `--command-concurrency` | int | `10` | Maximum concurrent command executions |
| `--command-timeout` | duration | `30s` | Timeout for command execution |

### LI Flags

Used by `process` only. Requires the `li` build tag (`make processor-li` or `make build-li`).

See [Chapter 14: Lawful Interception](../part5-advanced/lawful-interception.md) for details.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--li-enabled` | bool | `false` | Enable Lawful Interception support |
| `--li-x1-listen` | string | | X1 (ADMF) HTTPS listen address |
| `--li-x1-tls-cert` | string | | X1 server TLS certificate |
| `--li-x1-tls-key` | string | | X1 server TLS private key |
| `--li-x1-tls-ca` | string | | X1 CA certificate (ADMF client verification) |
| `--li-delivery-tls-cert` | string | | X2/X3 delivery client certificate |
| `--li-delivery-tls-key` | string | | X2/X3 delivery client private key |
| `--li-delivery-tls-ca` | string | | X2/X3 delivery CA certificate (MDF verification) |
| `--li-admf-*` | | | ADMF-related configuration flags |

---

## Commands

### `lc sniff`

Capture and display packets from a network interface or PCAP file. Output is written to stdout in the specified format.

```
lc sniff [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interface` | `-i` | string | `any` | Network interface to capture on |
| `--filter` | `-f` | string | | BPF filter expression |
| `--promiscuous` | `-p` | bool | `false` | Enable promiscuous mode |
| `--read-file` | `-r` | string | | Read packets from PCAP file |
| `--write-file` | `-w` | string | | Write packets to PCAP file |
| `--format` | | string | `json` | Output format: `json` or `text` |
| `--quiet` | `-q` | bool | `false` | Suppress non-packet output |

Plus [Virtual Interface Flags](#virtual-interface-flags).

See [Chapter 4: CLI Capture with `lc sniff`](../part2-local-capture/sniff.md).

---

### `lc sniff voip`

VoIP-specific capture with SIP/RTP analysis, call tracking, and optional GPU acceleration.

```
lc sniff voip [flags]
```

Inherits all `lc sniff` flags, plus:

**VoIP Filtering**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--sip-user` | | string | | Filter by SIP user |
| `--sip-user-file` | | string | | File containing SIP users (one per line) |
| `--codec` | | string | | Filter by codec name |
| `--sip-port` | `-S` | int | `5060` | SIP signaling port |
| `--rtp-port-range` | `-R` | string | | RTP port range (e.g., `10000-20000`) |
| `--udp-only` | `-U` | bool | `false` | Capture UDP only (skip TCP) |

**TCP Performance**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tcp-performance-mode` | string | `balanced` | TCP mode: `balanced`, `high_performance`, `conservative` |
| `--tcp-*` | | | Various TCP reassembly tuning flags |

**GPU Acceleration**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--gpu-backend` | `-g` | string | `auto` | GPU backend: `auto`, `cuda`, `opencl`, `simd`, `none` |
| `--gpu-batch-size` | | int | `1024` | Packets per GPU batch |
| `--gpu-enable` | | bool | `true` | Enable GPU acceleration |
| `--gpu-max-memory` | | string | | Maximum GPU memory allocation |

**PCAP Output**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--per-call-pcap` | bool | `false` | Write per-call PCAP files |
| `--per-call-pcap-dir` | string | `./pcaps` | Directory for per-call PCAPs |
| `--per-call-pcap-pattern` | string | | Filename pattern |
| `--pcap-command` | string | | Post-capture command (`%pcap%` placeholder) |
| `--voip-command` | string | | Post-call command (`%callid%`, `%dirname%` placeholders) |

See [Chapter 4: CLI Capture with `lc sniff`](../part2-local-capture/sniff.md) and [Chapter 13: Performance Optimization](../part5-advanced/performance.md).

---

### `lc sniff dns`

DNS-specific capture with domain filtering and tunnel detection.

```
lc sniff dns [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dns-port` | string | `53` | DNS port(s) to monitor |
| `--domain` | string | | Filter by domain name |
| `--domain-file` | string | | File containing domains (one per line) |
| `--detect-tunneling` | bool | `false` | Enable DNS tunneling detection |
| `--track-queries` | bool | `false` | Track query/response pairs |
| `--udp-only` | bool | `false` | Capture UDP only |

---

### `lc sniff tls`

TLS-specific capture with SNI filtering and JA3/JA4 fingerprinting.

```
lc sniff tls [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls-port` | string | `443` | TLS port(s) to monitor |
| `--sni` | string | | Filter by SNI (Server Name Indication) |
| `--sni-file` | string | | File containing SNI values |
| `--ja3` | string | | Filter by JA3 fingerprint |
| `--ja3-file` | string | | File containing JA3 fingerprints |
| `--ja3s` | string | | Filter by JA3S (server) fingerprint |
| `--ja3s-file` | string | | File containing JA3S fingerprints |
| `--ja4` | string | | Filter by JA4 fingerprint |
| `--ja4-file` | string | | File containing JA4 fingerprints |
| `--track-connections` | bool | `false` | Track TLS connection state |

---

### `lc sniff http`

HTTP-specific capture with header and content filtering.

```
lc sniff http [flags]
```

Inherits all `lc sniff` flags, plus:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--http-port` | string | `80,8080,8000,3000,8888` | HTTP port(s) to monitor |
| `--host` | string | | Filter by Host header |
| `--hosts-file` | string | | File containing hostnames |
| `--path` | string | | Filter by URL path |
| `--paths-file` | string | | File containing URL paths |
| `--method` | string | | Filter by HTTP method |
| `--status` | string | | Filter by response status code |
| `--user-agent` | string | | Filter by User-Agent header |
| `--user-agents-file` | string | | File containing User-Agent patterns |
| `--content-type` | string | | Filter by Content-Type header |
| `--content-types-file` | string | | File containing Content-Type values |
| `--keywords-file` | string | | File containing body keyword filters |
| `--capture-body` | bool | `false` | Capture HTTP request/response body |
| `--max-body-size` | int | `65536` | Maximum body size to capture (bytes) |
| `--track-requests` | bool | `false` | Track request/response pairs |
| `--tls-keylog` | string | | TLS key log file for HTTPS decryption |
| `--tls-keylog-pipe` | string | | Named pipe for TLS key log |

---

### `lc sniff email`

Email protocol capture with address and subject filtering. Supports SMTP, POP3, and IMAP.

```
lc sniff email [flags]
```

Inherits all `lc sniff` flags, plus:

**Port Configuration**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--smtp-port` | string | `25,587,465` | SMTP port(s) |
| `--pop3-port` | string | `110,995` | POP3 port(s) |
| `--imap-port` | string | `143,993` | IMAP port(s) |
| `--protocol` | string | `all` | Protocol filter: `all`, `smtp`, `pop3`, `imap` |

**Address Filtering**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sender` | string | | Filter by sender address |
| `--senders-file` | string | | File containing sender addresses |
| `--recipient` | string | | Filter by recipient address |
| `--recipients-file` | string | | File containing recipient addresses |
| `--address` | string | | Filter by any address (sender or recipient) |
| `--addresses-file` | string | | File containing addresses |

**Content Filtering**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--subject` | string | | Filter by subject |
| `--subjects-file` | string | | File containing subjects |
| `--command` | string | | Filter by SMTP command |
| `--mailbox` | string | | Filter by IMAP mailbox |
| `--capture-body` | bool | `false` | Capture message body |
| `--max-body-size` | int | `65536` | Maximum body size to capture (bytes) |
| `--keywords-file` | string | | File containing body keyword filters |
| `--track-sessions` | bool | `false` | Track protocol sessions |

---

### `lc tap`

Standalone capture node that combines hunter and processor capabilities. Captures packets locally, runs protocol analysis, serves a TUI interface via gRPC, and writes PCAP files -- all without requiring a separate processor.

```
lc tap [flags]
```

**Capture**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interface` | `-i` | string | `any` | Network interface(s) to capture on |
| `--filter` | `-f` | string | | BPF filter expression |
| `--promisc` | `-p` | bool | `false` | Enable promiscuous mode |
| `--pcap-buffer-size` | | int | `16777216` | PCAP kernel buffer size (bytes) |

**Batching**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--buffer-size` | `-b` | int | `10000` | Internal packet buffer size |
| `--batch-size` | | int | `100` | Packets per batch |
| `--batch-timeout` | | duration | `100ms` | Maximum batch wait time |

**Server**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--listen` | `-l` | string | `:50051` | gRPC listen address for TUI clients |
| `--id` | `-I` | string | | Node identifier |
| `--max-subscribers` | | int | `100` | Maximum concurrent TUI subscribers |
| `--insecure` | | bool | `false` | Disable TLS for gRPC server |

**Upstream Forwarding**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | | Upstream processor address for forwarding |

**Detection**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--enable-detection` | `-d` | bool | `true` | Enable protocol detection |
| `--filter-file` | | string | | Filter definition file |

Plus [PCAP Output Flags](#pcap-output-flags), [TLS Server Flags](#tls-server-flags), [Virtual Interface Flags](#virtual-interface-flags), and [GPU Flags](#gpu-flags).

See [Chapter 9: Standalone Mode with `lc tap`](../part3-distributed/tap.md).

---

### `lc tap voip`

VoIP-specific standalone capture with SIP/RTP analysis and per-call PCAP.

```
lc tap voip [flags]
```

Inherits all `lc tap` flags, plus:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sip-user` | string | | Filter by SIP user |
| `--sip-port` | int | `5060` | SIP signaling port |
| `--rtp-port-range` | string | | RTP port range |
| `--udp-only` | bool | `false` | Capture UDP only |
| `--tcp-performance-mode` | string | `balanced` | TCP mode: `balanced`, `high_performance`, `conservative` |
| `--pattern-algorithm` | string | `auto` | Pattern matching algorithm: `auto`, `aho-corasick`, `bloom` |
| `--pattern-buffer-mb` | int | `64` | Pattern buffer size (MB) |

---

### `lc hunt`

Hunter node for distributed edge capture. Captures packets and forwards them to a processor node via gRPC.

```
lc hunt [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address (`host:port`) |
| `--id` | `-I` | string | | Hunter identifier |
| `--interface` | `-i` | string | `any` | Network interface(s) to capture on |
| `--filter` | `-f` | string | | BPF filter expression |
| `--promisc` | `-p` | bool | `false` | Enable promiscuous mode |
| `--buffer-size` | `-b` | int | `10000` | Internal packet buffer size |
| `--batch-size` | | int | `64` | Packets per batch |
| `--batch-timeout` | | duration | `100ms` | Maximum batch wait time |
| `--batch-queue-size` | | int | `1000` | Batch queue depth (0 defaults to 1000) |
| `--pcap-buffer-size` | | int | `16777216` | PCAP kernel buffer size (bytes) |
| `--disk-buffer` | | bool | `false` | Enable disk-based buffer for backpressure |
| `--disk-buffer-dir` | | string | | Directory for disk buffer files |
| `--disk-buffer-max-mb` | | int | `1024` | Maximum disk buffer size (MB) |
| `--enable-voip-filter` | | bool | `false` | Enable VoIP packet filtering |
| `--gpu-backend` | `-g` | string | `auto` | GPU backend |
| `--gpu-batch-size` | | int | `100` | Packets per GPU batch |
| `--insecure` | | bool | `false` | Disable TLS |

Plus [TLS Client Flags](#tls-client-flags) (`--tls-ca`, `--tls-cert`, `--tls-key`, `--tls-skip-verify`).

See [Chapter 7: Edge Capture with `lc hunt`](../part3-distributed/hunt.md).

---

### `lc hunt voip`

VoIP-specific hunter with SIP/RTP call filtering and buffering.

```
lc hunt voip [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--sip-port` | `-S` | int | `5060` | SIP signaling port |
| `--rtp-port-range` | `-R` | string | | RTP port range |
| `--udp-only` | `-U` | bool | `false` | Capture UDP only |
| `--pattern-algorithm` | | string | `auto` | Pattern matching: `auto`, `aho-corasick`, `bloom` |
| `--pattern-buffer-mb` | | int | `64` | Pattern buffer size (MB) |

---

### `lc hunt dns`

DNS-specific hunter with domain filtering.

```
lc hunt dns [flags]
```

Inherits all `lc hunt` flags, plus:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dns-port` | string | `53` | DNS port(s) to monitor |
| `--udp-only` | bool | `false` | Capture UDP only |

---

### `lc process`

Processor node for central aggregation. Receives packets from hunters via gRPC, performs protocol analysis, writes PCAP files, and serves TUI clients.

```
lc process [flags]
```

**Server**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--listen` | `-l` | string | `:50051` | gRPC listen address |
| `--id` | `-I` | string | | Processor identifier |
| `--max-hunters` | `-m` | int | `100` | Maximum connected hunters |
| `--max-subscribers` | | int | `100` | Maximum TUI subscribers |
| `--insecure` | | bool | `false` | Disable TLS |
| `--api-key-auth` | | bool | `false` | Enable API key authentication |

**Detection & Filtering**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--enable-detection` | `-d` | bool | `true` | Enable protocol detection |
| `--filter-file` | `-f` | string | | Filter definition file |

**Upstream Forwarding**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | | Upstream processor for hierarchical topology |

**Statistics**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--stats` | `-s` | bool | `true` | Enable statistics collection |

**TLS Key Logging**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls-keylog-dir` | string | | Directory for TLS key log files from hunters |

Plus [PCAP Output Flags](#pcap-output-flags), [TLS Server Flags](#tls-server-flags), [Virtual Interface Flags](#virtual-interface-flags), and [LI Flags](#li-flags).

See [Chapter 8: Central Aggregation with `lc process`](../part3-distributed/process.md).

---

### `lc watch`

Interactive terminal UI for monitoring packet capture. Defaults to live mode if no subcommand is specified.

```
lc watch [subcommand] [flags]
```

**Persistent flags** (inherited by all subcommands):

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--buffer-size` | int | `10000` | TUI packet buffer size |
| `--max-calls` | int | | Maximum displayed VoIP calls |

Plus [TLS Client Flags](#tls-client-flags).

See [Chapter 5: Interactive Capture with `lc watch`](../part2-local-capture/watch-local.md).

---

### `lc watch live`

Live packet capture in the TUI. Requires elevated privileges.

```
lc watch live [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interface` | `-i` | string | `any` | Network interface to capture on |
| `--filter` | `-f` | string | | BPF filter expression |
| `--promiscuous` | `-p` | bool | `false` | Enable promiscuous mode |
| `--enable-gpu` | | bool | `false` | Enable GPU acceleration |
| `--gpu-backend` | | string | | GPU backend |
| `--gpu-batch-size` | | int | | Packets per GPU batch |

---

### `lc watch file`

Analyze PCAP files in the TUI. Accepts one or more PCAP files (merged display).

```
lc watch file <file> [file...] [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls-keylog` | string | | TLS key log file for decryption |

---

### `lc watch remote`

Monitor remote processor nodes in the TUI. Connects via gRPC.

```
lc watch remote [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | | Processor address (`host:port`) |
| `--nodes-file` | | string | | YAML file listing remote nodes |
| `--insecure` | | bool | `false` | Disable TLS |

See [Chapter 11: Remote TUI Monitoring](../part4-administration/watch-remote.md).

---

### `lc list interfaces`

List available network interfaces with their addresses and status.

```
lc list interfaces
```

No additional flags.

---

### `lc list filters`

List active filters on a processor node.

```
lc list filters [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | | Processor address |
| `--hunter` | | string | | Filter by hunter ID |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

See [Chapter 10: CLI Administration](../part4-administration/cli-admin.md).

---

### `lc show status`

Display processor node status.

```
lc show status [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show hunters`

Display connected hunters and their status.

```
lc show hunters [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |
| `--hunter` | | string | | Filter by specific hunter ID |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show topology`

Display the distributed topology (hunters, processors, connections).

```
lc show topology [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show filter`

Display details of a specific filter.

```
lc show filter [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |
| `--id` | | string | | Filter ID to display |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc show config`

Display the current local configuration (resolved from config file, environment, and defaults).

```
lc show config
```

No additional flags.

---

### `lc set filter`

Create or update a filter on a processor node.

```
lc set filter [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |
| `--id` | | string | | Filter ID (auto-generated if omitted) |
| `--type` | `-t` | string | | Filter type |
| `--pattern` | | string | | Filter pattern |
| `--description` | | string | | Human-readable description |
| `--enabled` | | bool | `true` | Enable the filter |
| `--hunters` | | string | | Comma-separated hunter IDs to apply filter to |
| `--file` | `-f` | string | | Load filter definition from file |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

See [Chapter 10: CLI Administration](../part4-administration/cli-admin.md).

---

### `lc rm filter`

Remove a filter from a processor node.

```
lc rm filter [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--processor` | `-P` | string | **required** | Processor address |
| `--id` | | string | | Filter ID to remove |
| `--file` | `-f` | string | | Load filter IDs from file |

Plus [TLS Client Flags](#tls-client-flags) and `--insecure`.

---

### `lc completion`

Generate shell completion scripts.

```
lc completion [bash|zsh|fish|powershell]
```

No additional flags. Output the completion script to stdout; source it in your shell configuration.

**Examples:**

```bash
# Bash
lc completion bash > ~/.local/share/bash-completion/completions/lc

# Zsh
lc completion zsh > "${fpath[1]}/_lc"

# Fish
lc completion fish > ~/.config/fish/completions/lc.fish

# PowerShell
lc completion powershell > lc.ps1
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LIPPYCAT_PRODUCTION` | Set to `true` to enforce TLS on all gRPC connections. Blocks the `--insecure` flag. |
| `SSLKEYLOGFILE` | Path to TLS key log file for decrypting captured TLS traffic. See [Chapter 12: Security](../part5-advanced/security.md). |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (runtime failure, connection refused, etc.) |
| `2` | Usage error (invalid flags, missing required arguments) |
