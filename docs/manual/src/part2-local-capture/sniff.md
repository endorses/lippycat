# CLI Capture with `lc sniff`

`lc sniff` is the foundation of lippycat — a CLI packet capture tool analogous to tcpdump or tshark, but with built-in protocol analysis and VoIP awareness.

## Your First Capture

### Selecting an Interface

First, find out which interfaces are available:

```bash
lc list interfaces
```

This shows all network interfaces with their addresses and status. Use `--json` for machine-readable output. Pick the interface connected to the network you want to monitor.

> **Tip**: `lc list interfaces` filters out loopback, Docker, and VM interfaces by default to show only relevant capture interfaces.

### Basic Capture

Start capturing on an interface:

```bash
sudo lc sniff -i eth0
```

The default interface is `any` (all interfaces). You can specify multiple interfaces with comma separation:

```bash
sudo lc sniff -i eth0,eth1
```

Press `Ctrl+C` to stop. lippycat prints a summary of packets captured.

### Output Format

`lc sniff` prints each captured packet to stdout as one line of JSON. This makes it easy to pipe into `jq`, `grep`, or other tools. Switch to text format for human-readable output:

```bash
sudo lc sniff -i eth0 --format text
```

Use `-q` (quiet mode) to suppress packet output for better performance when you only need PCAP file output.

### Basic Filtering

Use BPF filters with `-f` / `--filter` to focus on specific traffic (see [Appendix C: BPF Filter Reference](../appendices/bpf-reference.md) for the full syntax):

```bash
# Only DNS traffic
sudo lc sniff -i eth0 -f "port 53"

# Traffic to/from a specific host
sudo lc sniff -i eth0 -f "host 10.0.0.1"

# Only TCP traffic on port 5060 (SIP)
sudo lc sniff -i eth0 -f "tcp port 5060"

# Combine conditions
sudo lc sniff -i eth0 -f "host 10.0.0.1 and port 5060"
```

### Promiscuous Mode

By default, the interface only captures traffic destined for your machine. Enable promiscuous mode to see all traffic on the segment:

```bash
sudo lc sniff -i eth0 -p
```

### Reading from PCAP Files

Analyze existing PCAP files instead of live interfaces:

```bash
lc sniff -r capture.pcap
```

No elevated privileges needed for reading files.

### Structured protocol logs

Set `--log-dir` to write normalized protocol files while retaining the existing
packet output on stdout. These parent flags work on every protocol subcommand:

```bash
lc sniff http -r capture.pcap --log-dir ./logs --log-streams conn,http,files
```

Logging is off by default. Output is Zeek-style TSV by default, or JSONL with
`--log-format json`. Queues are bounded, so heed drop warnings and use graceful
shutdown to flush files. See [Structured Protocol Logs](../part5-advanced/structured-protocol-logs.md)
for all schemas, flags, rotation, completeness semantics, and privacy guidance.

## Protocol Modes

`lc sniff` has protocol-specific subcommands that enable deep analysis. Each adds protocol-aware filtering, correlation, and output.

### DNS Analysis

```bash
sudo lc sniff dns -i eth0
```

Captures DNS queries and responses with query/response correlation and response time tracking.

**Key flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | — | Filter by domain pattern (glob: `*.example.com`) |
| `--domains-file` | — | Load domain patterns from file |
| `--dns-port` | `53` | DNS port(s), comma-separated |
| `--udp-only` | `false` | Capture UDP DNS only (skip TCP) |
| `--track-queries` | `true` | Query/response correlation with RTT |
| `--detect-tunneling` | `true` | DNS tunneling detection via entropy analysis |

### TLS Inspection

```bash
sudo lc sniff tls -i eth0
```

Analyzes TLS handshakes without decrypting traffic. Extracts SNI, certificate details, cipher suites, and TLS fingerprints.

**Key flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--sni` | — | Filter by SNI pattern (glob: `*.example.com`) |
| `--sni-file` | — | Load SNI patterns from file |
| `--ja3` | — | Filter by JA3 fingerprint hash |
| `--ja3s` | — | Filter by JA3S fingerprint hash |
| `--ja4` | — | Filter by JA4 fingerprint |
| `--tls-port` | `443` | TLS port(s), comma-separated |
| `--track-connections` | `true` | ClientHello/ServerHello correlation |

Each fingerprint flag has a corresponding `-file` variant for bulk loading from files.

### HTTP Capture

```bash
sudo lc sniff http -i eth0
```

Reconstructs HTTP request/response pairs from TCP streams with RTT measurement.

**Key flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | — | Filter by host pattern (glob) |
| `--path` | — | Filter by URL path pattern (glob) |
| `--method` | — | Filter by HTTP methods (`GET,POST`) |
| `--status` | — | Filter by status codes (`404`, `4xx`, `400-499`) |
| `--user-agent` | — | Filter by User-Agent pattern |
| `--content-type` | — | Filter by Content-Type pattern |
| `--capture-body` | `false` | Enable body capture for keyword matching |
| `--max-body-size` | `65536` | Max body size in bytes |
| `--http-port` | `80,8080,8000,3000,8888` | HTTP port(s) |
| `--tls-keylog` | — | SSLKEYLOGFILE path for HTTPS decryption |
| `--track-requests` | `true` | Request/response correlation with RTT |

Each pattern flag has a corresponding `-file` variant for bulk loading (e.g., `--hosts-file`, `--paths-file`). Bulk keyword matching uses the Aho-Corasick algorithm via `--keywords-file`.

### Email Monitoring

```bash
sudo lc sniff email -i eth0
```

Captures SMTP, IMAP, and POP3 sessions with session tracking.

**Key flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--address` | — | Filter by email address (sender OR recipient) |
| `--sender` | — | Filter by sender address (MAIL FROM) |
| `--recipient` | — | Filter by recipient address (RCPT TO) |
| `--subject` | — | Filter by subject pattern |
| `--protocol` | `all` | Protocol: `smtp`, `imap`, `pop3`, `all` |
| `--smtp-port` | `25,587,465` | SMTP port(s) |
| `--imap-port` | `143,993` | IMAP port(s) |
| `--pop3-port` | `110,995` | POP3 port(s) |
| `--capture-body` | `false` | Enable body capture |
| `--track-sessions` | `true` | Session tracking and correlation |

### VoIP Analysis

VoIP is lippycat's most feature-rich protocol mode:

```bash
# Basic VoIP capture
sudo lc sniff voip -i eth0

# Filter by SIP user (supports wildcards)
sudo lc sniff voip -i eth0 -u alicent
sudo lc sniff voip -i eth0 -u "*456789"    # suffix match
sudo lc sniff voip -i eth0 -u "alicent,robb"  # multiple users

# Restrict to specific SIP port
sudo lc sniff voip -i eth0 -S 5060

# Custom RTP port range
sudo lc sniff voip -i eth0 -R 8000-9000
```

**Key flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--sip-user` | `-u` | — | SIP user/phone to match (wildcards, comma-separated) |
| `--sip-port` | `-S` | — | SIP port(s), comma-separated |
| `--rtp-port-range` | `-R` | `10000-32768` | RTP port range(s) |
| `--udp-only` | `-U` | `false` | Legacy UDP-only mode; hidden and deprecated |
| `--tcp-performance-mode` | `-M` | — | TCP profile: `balanced`, `throughput`, `latency`, `memory` |
| `--gpu-backend` | `-g` | `auto` | GPU backend in CUDA builds: `auto`, `cuda`, `opencl`, `cpu-simd`, `disabled` |
| `--pcap-grace-period` | — | `5s` | Grace period before closing per-call PCAPs |
| `--esp-null` | — | `false` | Decapsulate ESP via trailer/SPI validation |
| `--esp-heuristic` | — | `false` | Decapsulate ESP by sniffing payload content |
| `--esp-icv-size` | — | `-1` (auto) | ICV size in bytes: `0`, `8`, `12`, or `16` |

#### ESP-NULL Decapsulation

ESP decapsulation is off by default: without `--esp-null` or `--esp-heuristic`, ESP packets are passed through untouched and are not admitted by the VoIP BPF filter.

Enable it for VoIP traffic inside ESP-NULL tunnels (common in IPsec deployments where encryption is disabled but ESP framing remains):

```bash
sudo lc sniff voip -i eth0 --esp-null --esp-icv-size 12
```

lippycat strips the ESP header and ICV trailer, exposing the inner UDP/SIP/RTP packets for normal analysis. With `--esp-icv-size -1` (the default), the ICV size is auto-detected.

`--esp-heuristic` identifies ESP-NULL by inspecting payload content instead of the ESP trailer. Prefer `--esp-null` where the SA is known to be NULL-encrypted: on genuinely encrypted SAs the content heuristic can mistake ciphertext for inner traffic.

## PCAP File Output

### Writing PCAP Files

Save captured packets for offline analysis with `-w`:

```bash
# Write all captured packets to a single file
sudo lc sniff -i eth0 -w capture.pcap
```

The resulting file can be opened in Wireshark, analyzed with tshark, or read back with `lc watch file`.

Each protocol subcommand also supports `-w`:

```bash
sudo lc sniff dns -i eth0 -w dns-traffic.pcap
sudo lc sniff voip -i eth0 -w voip-traffic.pcap
```

### Per-Call PCAP (VoIP)

In VoIP mode, the `-w` flag automatically creates separate PCAP files per call, split by SIP signaling and RTP media:

```bash
sudo lc sniff voip -i eth0 --sip-user alicent -w /var/capture/alicent
# Creates: /var/capture/alicent_sip_<callid>.pcap
#          /var/capture/alicent_rtp_<callid>.pcap
```

For more advanced per-call PCAP features (directory organization, filename patterns, completion hooks), see [Central Aggregation with `lc process`](../part3-distributed/process.md) and [Standalone Mode with `lc tap`](../part3-distributed/tap.md).

## Performance Tuning

### TCP Performance Modes

TCP reassembly is needed for SIP-over-TCP and HTTP. lippycat offers pre-configured performance profiles via `-M` / `--tcp-performance-mode`:

| Profile | Memory Budget | Best For |
|---------|--------------|----------|
| `balanced` | 100 MB | Most use cases (default) |
| `throughput` | 500 MB | High-traffic environments |
| `latency` | 200 MB | Real-time analysis |
| `memory` | 25 MB | Embedded systems, low traffic |

```bash
sudo lc sniff voip -i eth0 -M throughput
```

For fine-grained control, individual TCP parameters can be tuned (goroutine limits, buffer sizes, timeouts). See `lc sniff voip --help` for the full list.

### Port Narrowing

On TCP-heavy networks, use explicit SIP and RTP port constraints to keep the capture focused while still allowing SIP-over-TCP when it exists:

```bash
sudo lc sniff voip -i eth0 -S 5060 -R 10000-20000
```

The older `--udp-only` VoIP flag is still accepted for compatibility but hidden and deprecated because it can miss TCP SIP traffic.

### GPU Acceleration

Offload application-filter pattern matching to CUDA for high-throughput capture:

```bash
sudo lc sniff voip -i eth0 -g auto
```

The `sniff voip` GPU flags are registered only in CUDA builds, such as binaries built with `make build-cuda`.

| Backend | Flag Value | Requirements |
|---------|-----------|-------------|
| CUDA | `cuda` | NVIDIA GPU + CUDA toolkit, `make build-cuda` |
| CPU SIMD | `cpu-simd` | AVX2 or SSE4.2 support |
| Auto-detect | `auto` | Selects best available |

OpenCL is not currently implemented. The value is accepted for configuration compatibility but falls back to CPU matching. SIP parsing and Call-ID extraction also remain CPU operations.

See [Performance Optimization](../part5-advanced/performance.md) for GPU configuration and benchmarks.

### Virtual Interface Injection

Inject filtered packets into a virtual network interface for consumption by other tools:

```bash
sudo lc sniff voip -i eth0 -V --vif-name lc0
```

This creates a `lc0` TAP interface that other tools (Wireshark, tcpdump) can capture from, seeing only the filtered traffic lippycat selected.

| Flag | Default | Description |
|------|---------|-------------|
| `-V` / `--virtual-interface` | `false` | Enable virtual interface |
| `--vif-name` | `lc0` | Interface name |
| `--vif-type` | `tap` | Type: `tap` (Layer 2) or `tun` (Layer 3) |
| `--vif-startup-delay` | `3s` | Delay before injection starts |
| `--vif-replay-timing` | `false` | Respect original PCAP packet timing |
| `--vif-buffer-size` | `65536` | Injection queue size (packets) |
| `--vif-netns` | — | Network namespace for isolation |
| `--vif-drop-privileges` | — | Drop to this user after interface creation |
