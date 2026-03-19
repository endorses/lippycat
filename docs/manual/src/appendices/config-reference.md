# Configuration Reference

This appendix documents every configuration key in lippycat's YAML configuration file. All keys shown here correspond to the output of `lc show config`, which displays the active configuration (defaults merged with any config file and CLI overrides) in JSON format.

## Configuration File Locations

lippycat searches for a configuration file in the following locations, in order of priority:

1. Path specified with `-c` / `--config` flag (highest priority)
2. `$HOME/.config/lippycat/config.yaml` (preferred)
3. `$HOME/.config/lippycat.yaml` (XDG standard)
4. `$HOME/.lippycat.yaml` (legacy)

The first file found is used. Only one configuration file is loaded.

### Precedence Rules

When the same setting is specified in multiple places, lippycat applies this precedence order (highest wins):

1. **CLI flags** — Always take priority over everything else
2. **Environment variables** — Override config file values (prefixed with `LIPPYCAT_`)
3. **Configuration file** — YAML values from the config file
4. **Defaults** — Built-in defaults shown in this reference

### Viewing Active Configuration

To see the full active configuration (with all sources merged):

```bash
lc show config
```

This outputs JSON. To convert mentally to YAML paths, replace nesting with indentation (e.g., JSON `{"voip": {"sip_ports": "5060"}}` becomes `voip.sip_ports` or in YAML file format, `voip:` / `  sip_ports: "5060"`).

### Environment Variables

Configuration keys can be set via environment variables using the pattern `LIPPYCAT_<SECTION>_<KEY>`. Nested keys use underscores:

```bash
export LIPPYCAT_VOIP_SIP_PORTS="5060,5061"
export LIPPYCAT_PROCESSOR_LISTEN_ADDR=":55555"
export LIPPYCAT_PRODUCTION=true   # Enforces TLS encryption
```

---

## Global Settings

These top-level keys apply to all commands.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `pcap_buffer_size` | integer | `16777216` (16 MB) | Kernel buffer size for packet capture in bytes. Larger values reduce packet drops under high load. |
| `pcap_timeout_ms` | integer | `200` | Timeout in milliseconds for pcap reads. Lower values decrease latency; higher values improve batching efficiency. |
| `promiscuous` | boolean | `false` | Enable promiscuous mode on capture interfaces. When true, the interface captures all traffic on the segment, not just traffic addressed to the host. |

---

## Protocol Capture Settings

These sections configure protocol-specific analysis for `lc sniff <protocol>` subcommands. They control which ports to monitor, what patterns to match, and whether to capture payload content.

### `dns` — DNS Capture

Used by `lc sniff dns`. See [CLI Capture with `lc sniff`](../part2-local-capture/sniff.md) for usage.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dns.ports` | string | `"53"` | Comma-separated list of DNS ports to monitor. |
| `dns.udp_only` | boolean | `false` | Only capture UDP DNS traffic (skip TCP DNS). |
| `dns.track_queries` | boolean | `true` | Track DNS query/response pairs for correlation. |
| `dns.detect_tunneling` | boolean | `true` | Enable DNS tunneling detection heuristics. |
| `dns.domain_pattern` | string | `""` | Regex pattern to filter by domain name. Empty means all domains. |
| `dns.domains_file` | string | `""` | Path to file containing domain patterns (one per line). |

### `email` — Email Capture

Used by `lc sniff email`. Supports SMTP, IMAP, and POP3 protocols.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `email.smtp_ports` | string | `"25,587,465"` | SMTP ports to monitor. |
| `email.imap_ports` | string | `"143,993"` | IMAP ports to monitor. |
| `email.pop3_ports` | string | `"110,995"` | POP3 ports to monitor. |
| `email.protocol` | string | `"all"` | Protocol filter: `"all"`, `"smtp"`, `"imap"`, or `"pop3"`. |
| `email.track_sessions` | boolean | `true` | Track email session state across packets. |
| `email.capture_body` | boolean | `false` | Capture email body content. |
| `email.max_body_size` | integer | `65536` | Maximum body capture size in bytes. |
| `email.sender_pattern` | string | `""` | Regex pattern to filter by sender address. |
| `email.senders_file` | string | `""` | Path to file containing sender patterns. |
| `email.recipient_pattern` | string | `""` | Regex pattern to filter by recipient address. |
| `email.recipients_file` | string | `""` | Path to file containing recipient patterns. |
| `email.address_pattern` | string | `""` | Regex pattern to match any address (sender or recipient). |
| `email.addresses_file` | string | `""` | Path to file containing address patterns. |
| `email.subject_pattern` | string | `""` | Regex pattern to filter by subject line. |
| `email.subjects_file` | string | `""` | Path to file containing subject patterns. |
| `email.command_pattern` | string | `""` | Regex pattern to filter by SMTP/IMAP command. |
| `email.mailbox_pattern` | string | `""` | Regex pattern to filter by mailbox name. |
| `email.keywords_file` | string | `""` | Path to file containing content keywords. |

### `http` — HTTP Capture

Used by `lc sniff http`. Supports HTTP/1.x with optional TLS decryption.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `http.ports` | string | `"80,8080,8000,3000,8888"` | HTTP ports to monitor. |
| `http.track_requests` | boolean | `true` | Track HTTP request/response pairs. |
| `http.capture_body` | boolean | `false` | Capture HTTP body content. |
| `http.max_body_size` | integer | `65536` | Maximum body capture size in bytes. |
| `http.methods` | string | `""` | Comma-separated HTTP methods to filter (e.g., `"GET,POST"`). Empty means all. |
| `http.status_codes` | string | `""` | Comma-separated status codes to filter (e.g., `"200,404,500"`). Empty means all. |
| `http.host_pattern` | string | `""` | Regex pattern to filter by Host header. |
| `http.hosts_file` | string | `""` | Path to file containing host patterns. |
| `http.path_pattern` | string | `""` | Regex pattern to filter by request path. |
| `http.paths_file` | string | `""` | Path to file containing path patterns. |
| `http.user_agent_pattern` | string | `""` | Regex pattern to filter by User-Agent header. |
| `http.user_agents_file` | string | `""` | Path to file containing User-Agent patterns. |
| `http.content_type_pattern` | string | `""` | Regex pattern to filter by Content-Type header. |
| `http.content_types_file` | string | `""` | Path to file containing Content-Type patterns. |
| `http.keywords_file` | string | `""` | Path to file containing content keywords. |
| `http.tls_keylog` | string | `""` | Path to TLS key log file (SSLKEYLOGFILE format) for decrypting HTTPS traffic. |
| `http.tls_keylog_pipe` | string | `""` | Path to a named pipe for streaming TLS key log data. |

### `tls` — TLS Capture

Used by `lc sniff tls`. Captures TLS handshakes and extracts fingerprints.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls.ports` | string | `"443"` | TLS ports to monitor. |
| `tls.track_connections` | boolean | `true` | Track TLS connection state. |
| `tls.sni_pattern` | string | `""` | Regex pattern to filter by SNI (Server Name Indication). |
| `tls.sni_file` | string | `""` | Path to file containing SNI patterns. |
| `tls.ja3` | string | `""` | Comma-separated JA3 hashes to match. |
| `tls.ja3_file` | string | `""` | Path to file containing JA3 hashes. |
| `tls.ja3s` | string | `""` | Comma-separated JA3S (server) hashes to match. |
| `tls.ja3s_file` | string | `""` | Path to file containing JA3S hashes. |
| `tls.ja4` | string | `""` | Comma-separated JA4 fingerprints to match. |
| `tls.ja4_file` | string | `""` | Path to file containing JA4 fingerprints. |

---

## VoIP Engine Settings

The `voip` section configures the core VoIP analysis engine used across all capture commands (`sniff voip`, `hunt voip`, `tap voip`). This is the most extensive configuration section, covering SIP/RTP analysis, TCP reassembly, GPU acceleration, and plugin management.

For TCP performance profile details, see [Performance Optimization](../part5-advanced/performance.md#tcp-performance-profiles).

### Core VoIP Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.sip_ports` | string | `""` | Comma-separated SIP ports. Empty uses default detection. |
| `voip.rtp_port_ranges` | string | `""` | RTP port ranges (e.g., `"10000-20000"`). Empty uses default detection. |
| `voip.udp_only` | boolean | `false` | Only capture UDP SIP/RTP traffic (skip TCP SIP). Significantly reduces CPU on TCP-heavy networks. |
| `voip.pattern_algorithm` | string | `"auto"` | Pattern matching algorithm: `"auto"`, `"aho-corasick"`, `"regex"`, or `"simple"`. |
| `voip.pattern_buffer_mb` | integer | `64` | Memory budget for pattern matching buffers in MB. |
| `voip.max_filename_length` | integer | `100` | Maximum length for generated PCAP filenames. |

### Call Management

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.call_expiration_time` | duration | `"1h0m0s"` | Time after which inactive calls are expired. |
| `voip.call_id_detection_timeout` | duration | `"30s"` | Timeout for call ID detection from initial packet. |
| `voip.janitor_cleanup_interval` | duration | `"30s"` | Interval for cleaning up expired calls and resources. |
| `voip.max_goroutines` | integer | `1000` | Maximum concurrent goroutines for call processing. |
| `voip.log_goroutine_limit_interval` | duration | `"30s"` | Interval for logging goroutine limit warnings. |

### TCP Reassembly

These settings control TCP stream reassembly for SIP-over-TCP. The `tcp_performance_mode` sets sensible defaults for all TCP parameters — override individual settings only when needed.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.tcp_performance_mode` | string | `"balanced"` | Performance profile: `"minimal"`, `"balanced"`, `"high_performance"`, or `"low_latency"`. See [Performance Optimization](../part5-advanced/performance.md#tcp-performance-profiles). |
| `voip.max_tcp_buffers` | integer | `10000` | Maximum TCP stream buffers. |
| `voip.tcp_memory_limit` | integer | `104857600` (100 MB) | Memory limit for TCP reassembly in bytes. |
| `voip.tcp_batch_size` | integer | `32` | Number of TCP segments to process per batch. |
| `voip.tcp_io_threads` | integer | `4` | Number of I/O threads for TCP processing. |
| `voip.tcp_buffer_pool_size` | integer | `1000` | Size of the TCP buffer pool. |
| `voip.tcp_buffer_max_age` | duration | `"5m0s"` | Maximum age of a TCP buffer before forced cleanup. |
| `voip.tcp_buffer_strategy` | string | `"adaptive"` | Buffer allocation strategy: `"fixed"`, `"adaptive"`, or `"ring"`. |
| `voip.tcp_compression_level` | integer | `1` | Compression level for TCP buffer storage (0=none, 1=fast, 9=best). |
| `voip.tcp_assembler_max_pages` | integer | `100` | Maximum assembler pages for TCP stream reassembly. |
| `voip.tcp_stream_timeout` | duration | `"10m0s"` | Timeout for idle TCP streams. |
| `voip.tcp_stream_max_queue_time` | duration | `"2m0s"` | Maximum time a packet can wait in the stream queue. |
| `voip.tcp_sip_idle_timeout` | duration | `"2m0s"` | Idle timeout specifically for SIP TCP streams. |
| `voip.tcp_opening_timeout` | duration | `"5m0s"` | Timeout for TCP connections in opening state. |
| `voip.tcp_established_timeout` | duration | `"30m0s"` | Timeout for established TCP connections. |
| `voip.tcp_closing_timeout` | duration | `"5m0s"` | Timeout for TCP connections in closing state. |
| `voip.tcp_cleanup_interval` | duration | `"1m0s"` | Interval for TCP resource cleanup. |
| `voip.tcp_latency_optimization` | boolean | `false` | Enable low-latency TCP processing (increases CPU usage). |
| `voip.stream_queue_buffer` | integer | `500` | Buffer size for the TCP stream processing queue. |
| `voip.enable_state_tcp_timeouts` | boolean | `false` | Enable state-aware TCP timeouts (different timeouts per connection state). |

### Flow Control

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.enable_backpressure` | boolean | `true` | Enable backpressure when processing falls behind capture rate. |
| `voip.enable_auto_tuning` | boolean | `true` | Automatically adjust internal parameters based on traffic patterns. |
| `voip.enable_call_aware_timeout` | boolean | `false` | Use call-aware timeouts that extend during active calls. |
| `voip.memory_optimization` | boolean | `false` | Enable aggressive memory optimization (may reduce throughput). |

### GPU Acceleration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.gpu_enable` | boolean | `true` | Enable GPU acceleration for pattern matching. Falls back to CPU if no GPU is available. |
| `voip.gpu_backend` | string | `"auto"` | GPU backend: `"auto"`, `"cuda"`, `"opencl"`, or `"simd"`. |
| `voip.gpu_batch_size` | integer | `1024` | Number of packets per GPU processing batch. |
| `voip.gpu_max_memory` | integer | `0` | Maximum GPU memory in bytes (0 = unlimited). |

### Plugins

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.plugins_enabled` | boolean | `false` | Master switch for the plugin system. |
| `voip.plugin_sip_enabled` | boolean | `true` | Enable the built-in SIP analysis plugin. |
| `voip.plugin_rtp_enabled` | boolean | `true` | Enable the built-in RTP analysis plugin. |
| `voip.plugin_generic_enabled` | boolean | `true` | Enable the generic protocol plugin. |
| `voip.plugin_watch_enabled` | boolean | `false` | Enable hot-reload watching for plugin files. |
| `voip.plugin_paths` | list | `[]` | Paths to external plugin shared libraries. |

### Metrics and Monitoring

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `voip.metrics_enabled` | boolean | `false` | Enable metrics collection. |
| `voip.monitoring_enabled` | boolean | `false` | Enable runtime monitoring. |
| `voip.monitoring_update_interval` | duration | `"30s"` | Interval for monitoring metric updates. |
| `voip.enable_plugin_metrics` | boolean | `true` | Collect per-plugin metrics. |
| `voip.enable_runtime_metrics` | boolean | `true` | Collect Go runtime metrics. |
| `voip.enable_system_metrics` | boolean | `false` | Collect system-level metrics (CPU, memory, disk). |
| `voip.tracing_enabled` | boolean | `false` | Enable distributed tracing. |

---

## Node Configuration

### `hunter` — Hunter Node

Hunter nodes capture packets at the network edge and forward them to a processor. See [Edge Capture with `lc hunt`](../part3-distributed/hunt.md) for usage.

#### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.id` | string | `""` | Hunter identifier. Auto-generated from hostname if empty. |
| `hunter.hunter_id` | string | `""` | Alias for `hunter.id`. |
| `hunter.processor_addr` | string | `""` | Address of the processor to connect to (e.g., `"processor:55555"`). |
| `hunter.interfaces` | list | `["any"]` | Network interfaces to capture from. |
| `hunter.bpf_filter` | string | `""` | BPF filter expression for kernel-level packet filtering. See [BPF Filter Reference](bpf-reference.md). |
| `hunter.buffer_size` | integer | `10000` | Internal packet buffer size (number of packets). |
| `hunter.batch_size` | integer | `64` | Number of packets per gRPC batch to the processor. |
| `hunter.batch_timeout_ms` | integer | `100` | Maximum time in ms to wait before sending an incomplete batch. |
| `hunter.batch_queue_size` | integer | `0` | Size of the batch send queue (0 = default). |

#### Hunter TLS

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.tls.enabled` | boolean | `false` | Enable TLS for the processor connection. |
| `hunter.tls.cert_file` | string | `""` | Path to client TLS certificate (for mTLS). |
| `hunter.tls.key_file` | string | `""` | Path to client TLS private key. |
| `hunter.tls.ca_file` | string | `""` | Path to CA certificate for verifying the processor. |
| `hunter.tls.skip_verify` | boolean | `false` | Skip TLS certificate verification (insecure, testing only). |
| `hunter.tls.ports` | string | `"443"` | TLS ports for protocol detection. |

#### Hunter Protocol Filters

Hunters support protocol-specific subcommands (`lc hunt dns`, `lc hunt voip`, etc.) with dedicated filter settings:

**`hunter.dns` — DNS filtering:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.dns.ports` | string | `"53"` | DNS ports. |
| `hunter.dns.udp_only` | boolean | `false` | UDP-only DNS capture. |

**`hunter.http` — HTTP filtering:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.http.ports` | string | `"80,8080,8000,3000,8888"` | HTTP ports. |
| `hunter.http.capture_body` | boolean | `false` | Capture HTTP body. |
| `hunter.http.max_body_size` | integer | `65536` | Max body size in bytes. |
| `hunter.http.host` | string | `""` | Host filter pattern. |
| `hunter.http.path` | string | `""` | Path filter pattern. |
| `hunter.http.method` | string | `""` | HTTP method filter. |
| `hunter.http.status` | string | `""` | Status code filter. |
| `hunter.http.keywords` | string | `""` | Content keywords. |
| `hunter.http.tls_keylog` | string | `""` | TLS key log file path. |
| `hunter.http.tls_keylog_pipe` | string | `""` | TLS key log pipe path. |

**`hunter.email` — Email filtering:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.email.smtp_ports` | string | `"25,587,465"` | SMTP ports. |
| `hunter.email.imap_ports` | string | `"143,993"` | IMAP ports. |
| `hunter.email.pop3_ports` | string | `"110,995"` | POP3 ports. |
| `hunter.email.protocol` | string | `"all"` | Protocol filter. |
| `hunter.email.capture_body` | boolean | `false` | Capture email body. |
| `hunter.email.max_body_size` | integer | `65536` | Max body size. |
| `hunter.email.sender` | string | `""` | Sender filter. |
| `hunter.email.recipient` | string | `""` | Recipient filter. |
| `hunter.email.subject` | string | `""` | Subject filter. |
| `hunter.email.mailbox` | string | `""` | Mailbox filter. |
| `hunter.email.command` | string | `""` | Command filter. |
| `hunter.email.keywords` | string | `""` | Content keywords. |

**`hunter.voip` — VoIP filtering:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.voip.sip_ports` | string | `""` | SIP ports. |
| `hunter.voip.rtp_port_ranges` | string | `""` | RTP port ranges. |
| `hunter.voip.udp_only` | boolean | `false` | UDP-only VoIP capture. |

**`hunter.voip_filter` — GPU-accelerated VoIP filtering:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.voip_filter.enabled` | boolean | `false` | Enable GPU-accelerated VoIP filtering at the edge. |
| `hunter.voip_filter.gpu_backend` | string | `"auto"` | GPU backend for edge filtering. |
| `hunter.voip_filter.gpu_batch_size` | integer | `100` | Batch size for GPU filter processing. |

#### Disk Buffer

When the connection to the processor is interrupted, the hunter can buffer packets to disk:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hunter.disk_buffer.enabled` | boolean | `false` | Enable disk buffering for network interruptions. |
| `hunter.disk_buffer.dir` | string | `"/var/tmp/lippycat-buffer"` | Directory for disk buffer files. |
| `hunter.disk_buffer.max_mb` | integer | `1024` | Maximum disk buffer size in MB. |

### `processor` — Processor Node

Processor nodes receive packets from hunters, perform analysis, write PCAPs, and serve TUI clients. See [Central Aggregation with `lc process`](../part3-distributed/process.md) for usage.

#### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.id` | string | `""` | Processor identifier. Auto-generated from hostname if empty. |
| `processor.processor_id` | string | `""` | Alias for `processor.id`. |
| `processor.listen_addr` | string | `":50051"` | Address to listen on for hunter and TUI connections. |
| `processor.processor_addr` | string | `""` | Alias for `processor.listen_addr`. |
| `processor.upstream_addr` | string | `""` | Address of an upstream processor for hierarchical forwarding. |
| `processor.max_hunters` | integer | `100` | Maximum concurrent hunter connections. |
| `processor.max_subscribers` | integer | `100` | Maximum TUI subscriber connections (0 = unlimited). |
| `processor.display_stats` | boolean | `true` | Display periodic statistics to stdout. |
| `processor.enable_detection` | boolean | `true` | Enable protocol detection on received packets. |
| `processor.filter_file` | string | `""` | Path to a YAML filter file for packet filtering rules. |
| `processor.write_file` | string | `""` | Path for unified PCAP output (all traffic to one file). |
| `processor.command_concurrency` | integer | `10` | Maximum concurrent command hook executions. |
| `processor.command_timeout` | duration | `"30s"` | Timeout for command hook execution. |

#### Processor TLS

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.tls.enabled` | boolean | `false` | Enable TLS for incoming connections. |
| `processor.tls.cert_file` | string | `""` | Path to server TLS certificate. |
| `processor.tls.key_file` | string | `""` | Path to server TLS private key. |
| `processor.tls.ca_file` | string | `""` | Path to CA certificate for client verification (mTLS). |
| `processor.tls.client_auth` | boolean | `false` | Require client certificates (mutual TLS). |

#### Per-Call PCAP (VoIP)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.per_call_pcap.enabled` | boolean | `false` | Write separate PCAP files per VoIP call. |
| `processor.per_call_pcap.output_dir` | string | `"./pcaps"` | Directory for per-call PCAP files. |
| `processor.per_call_pcap.file_pattern` | string | `"{timestamp}_{callid}.pcap"` | Filename pattern. Placeholders: `{timestamp}`, `{callid}`. |

#### Auto-Rotating PCAP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.auto_rotate_pcap.enabled` | boolean | `false` | Enable automatic PCAP file rotation. |
| `processor.auto_rotate_pcap.output_dir` | string | `"./auto-rotate-pcaps"` | Directory for rotated PCAP files. |
| `processor.auto_rotate_pcap.file_pattern` | string | `"{timestamp}.pcap"` | Filename pattern. Placeholder: `{timestamp}`. |
| `processor.auto_rotate_pcap.max_size` | string | `"100M"` | Maximum file size before rotation (e.g., `"100M"`, `"1G"`). |
| `processor.auto_rotate_pcap.idle_timeout` | duration | `"30s"` | Time with no packets before rotating the current file. |

#### Command Hooks

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.pcap_command` | string | `""` | Command to run when a per-call PCAP file is completed. Placeholder: `%pcap%` is replaced with the file path. |
| `processor.voip_command` | string | `""` | Command to run when a VoIP call ends. Placeholders: `%callid%`, `%dirname%`. |

#### Virtual Interface

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.virtual_interface` | boolean | `false` | Create a virtual network interface for replaying received packets. |
| `processor.vif_type` | string | `"tap"` | Virtual interface type: `"tap"` or `"tun"`. |
| `processor.vif_name` | string | `"lc0"` | Name of the virtual interface. |
| `processor.vif_buffer_size` | integer | `65536` | Buffer size for the virtual interface. |
| `processor.vif_drop_privileges` | string | `""` | User to drop privileges to after creating the virtual interface. |
| `processor.vif_netns` | string | `""` | Network namespace for the virtual interface. |

#### TLS Key Log

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.tls_keylog.output_dir` | string | `""` | Directory for TLS key log files received from hunters. |

#### Lawful Interception (LI)

These settings require the `li` build tag. See [Lawful Interception](../part5-advanced/lawful-interception.md) for details.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `processor.li.enabled` | boolean | `false` | Enable lawful interception support. |
| `processor.li.x1_listen_addr` | string | `":8443"` | Listen address for the X1 (ADMF) interface. |
| `processor.li.x1_tls_cert` | string | `""` | TLS certificate for the X1 server. |
| `processor.li.x1_tls_key` | string | `""` | TLS private key for the X1 server. |
| `processor.li.x1_tls_ca` | string | `""` | CA certificate for X1 client verification. |
| `processor.li.admf_endpoint` | string | `""` | ADMF endpoint for X1 registration. |
| `processor.li.admf_keepalive` | duration | `"30s"` | ADMF keepalive interval. |
| `processor.li.admf_tls_cert` | string | `""` | TLS certificate for ADMF connection. |
| `processor.li.admf_tls_key` | string | `""` | TLS private key for ADMF connection. |
| `processor.li.admf_tls_ca` | string | `""` | CA certificate for ADMF verification. |
| `processor.li.admf_sync_on_startup` | boolean | `true` | Query ADMF for task/destination state on startup. |
| `processor.li.admf_sync_timeout` | duration | `"30s"` | Timeout for the startup state sync request. |
| `processor.li.admf_reconcile_interval` | duration | `"0"` | Periodic ADMF reconciliation interval (0 = disabled). |
| `processor.li.delivery_tls_cert` | string | `""` | TLS certificate for X2/X3 delivery connections. |
| `processor.li.delivery_tls_key` | string | `""` | TLS private key for X2/X3 delivery. |
| `processor.li.delivery_tls_ca` | string | `""` | CA certificate for MDF verification. |
| `processor.li.delivery_tls_pinned_cert` | list | `[]` | Pinned certificates for MDF connections. |

### `tap` — Tap Node

Tap combines local capture with processor capabilities. See [Standalone Mode with `lc tap`](../part3-distributed/tap.md) for usage. Tap shares many settings with both `hunter` and `processor`.

#### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.id` | string | `""` | Tap node identifier. |
| `tap.tap_id` | string | `""` | Alias for `tap.id`. |
| `tap.interfaces` | list | `["any"]` | Network interfaces to capture from. |
| `tap.bpf_filter` | string | `""` | BPF filter expression. |
| `tap.buffer_size` | integer | `10000` | Internal packet buffer size. |
| `tap.batch_size` | integer | `100` | Packet batch size for internal processing. |
| `tap.batch_timeout_ms` | integer | `100` | Batch timeout in milliseconds. |
| `tap.promiscuous` | boolean | `false` | Promiscuous mode for capture interfaces. |
| `tap.enable_detection` | boolean | `true` | Enable protocol detection. |
| `tap.filter_file` | string | `""` | Path to filter file. |
| `tap.write_file` | string | `""` | Path for unified PCAP output. |
| `tap.command_concurrency` | integer | `10` | Max concurrent command hook executions. |
| `tap.command_timeout` | duration | `"30s"` | Command hook timeout. |

#### Tap TLS and Serving

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.listen_addr` | string | `":50051"` | Listen address for TUI client connections. |
| `tap.max_subscribers` | integer | `100` | Maximum TUI subscriber connections. |
| `tap.tls.enabled` | boolean | `false` | Enable TLS for TUI connections. |
| `tap.tls.cert_file` | string | `""` | Server TLS certificate. |
| `tap.tls.key_file` | string | `""` | Server TLS private key. |
| `tap.tls.ca_file` | string | `""` | CA certificate for client verification. |
| `tap.tls.client_auth` | boolean | `false` | Require client certificates. |

#### Tap Upstream Forwarding

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.processor_addr` | string | `""` | Upstream processor address for forwarding captured packets. |
| `tap.upstream_addr` | string | `""` | Alias for `tap.processor_addr`. |

#### Tap Per-Call PCAP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.per_call_pcap.enabled` | boolean | `false` | Write separate PCAP files per VoIP call. |
| `tap.per_call_pcap.output_dir` | string | `"./pcaps"` | Directory for per-call PCAP files. |
| `tap.per_call_pcap.file_pattern` | string | `"{timestamp}_{callid}.pcap"` | Filename pattern. |

#### Tap Auto-Rotating PCAP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.auto_rotate_pcap.enabled` | boolean | `false` | Enable PCAP file rotation. |
| `tap.auto_rotate_pcap.output_dir` | string | `"./auto-rotate-pcaps"` | Directory for rotated files. |
| `tap.auto_rotate_pcap.file_pattern` | string | `"{timestamp}.pcap"` | Filename pattern. |
| `tap.auto_rotate_pcap.max_size` | string | `"100M"` | Max file size before rotation. |
| `tap.auto_rotate_pcap.idle_timeout` | duration | `"30s"` | Idle timeout before rotation. |

#### Tap Command Hooks

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.pcap_command` | string | `""` | Command on PCAP completion. Placeholder: `%pcap%`. |
| `tap.voip_command` | string | `""` | Command on call end. Placeholders: `%callid%`, `%dirname%`. |

#### Tap Virtual Interface

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.virtual_interface` | boolean | `false` | Create a virtual network interface. |
| `tap.vif_type` | string | `"tap"` | Virtual interface type. |
| `tap.vif_name` | string | `"lc0"` | Virtual interface name. |
| `tap.vif_buffer_size` | integer | `65536` | Virtual interface buffer size. |
| `tap.vif_drop_privileges` | string | `""` | User to drop privileges to. |
| `tap.vif_netns` | string | `""` | Network namespace. |

#### Tap Protocol Filters

Tap supports the same protocol-specific subcommands as hunter. The configuration keys mirror the hunter protocol filter settings:

**`tap.dns`:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.dns.ports` | string | `"53"` | DNS ports. |
| `tap.dns.udp_only` | boolean | `false` | UDP-only DNS capture. |
| `tap.dns.domain_pattern` | string | `""` | Domain filter pattern. |
| `tap.dns.domains_file` | string | `""` | Domain patterns file. |

**`tap.voip`:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tap.voip.sip_ports` | string | `""` | SIP ports. |
| `tap.voip.sip_user` | string | `""` | Filter by SIP user. |
| `tap.voip.sipuser` | string | `""` | Alias for `tap.voip.sip_user`. |
| `tap.voip.rtp_port_ranges` | string | `""` | RTP port ranges. |
| `tap.voip.udp_only` | boolean | `false` | UDP-only VoIP capture. |
| `tap.voip.tcp_performance_mode` | string | `"balanced"` | TCP performance profile for tap VoIP. |
| `tap.voip.pattern_algorithm` | string | `"auto"` | Pattern matching algorithm. |
| `tap.voip.pattern_buffer_mb` | integer | `64` | Pattern buffer memory in MB. |

Tap also supports `tap.http` and `tap.email` sections with the same keys as `hunter.http` and `hunter.email` respectively.

---

## Command-Specific Settings

### `sniff` — Sniff Command

Settings for `lc sniff`. See [CLI Capture with `lc sniff`](../part2-local-capture/sniff.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sniff.format` | string | `"json"` | Output format: `"json"` or `"text"`. |
| `sniff.quiet` | boolean | `false` | Suppress non-packet output. |
| `sniff.virtual_interface` | boolean | `false` | Replay captured packets on a virtual interface. |
| `sniff.vif_type` | string | `"tap"` | Virtual interface type. |
| `sniff.vif_name` | string | `"lc0"` | Virtual interface name. |
| `sniff.vif_buffer_size` | integer | `65536` | Virtual interface buffer size. |
| `sniff.vif_drop_privileges` | string | `""` | User to drop privileges to. |
| `sniff.vif_netns` | string | `""` | Network namespace. |
| `sniff.vif_replay_timing` | boolean | `false` | Maintain original packet timing during replay. |
| `sniff.vif_startup_delay` | duration | `"3s"` | Delay before starting replay (allows interface setup). |

### `watch` — Watch (TUI) Settings

Settings for `lc watch`. See [Interactive Capture with `lc watch`](../part2-local-capture/watch-local.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `watch.buffer_size` | integer | `10000` | Packet display buffer size for the TUI. |
| `watch.max_calls` | integer | `5000` | Maximum VoIP calls to keep in memory. |
| `watch.theme` | string | `""` | TUI color theme (e.g., `"dark"`, `"light"`). |
| `watch.file.tls_keylog` | string | `""` | TLS key log file for PCAP file analysis. |
| `watch.tls_decryption_enabled` | boolean | `false` | Enable TLS decryption in TUI (set automatically). |
| `watch.tls_keylog` | string | `""` | Path to SSLKEYLOGFILE for TLS decryption. |
| `watch.tls.enabled` | boolean | `false` | Enable TLS for remote connections. |
| `watch.tls.ca_file` | string | `""` | CA certificate for server verification. |
| `watch.tls.cert_file` | string | `""` | Client certificate for mTLS. |
| `watch.tls.key_file` | string | `""` | Client key for mTLS. |
| `watch.tls.skip_verify` | boolean | `false` | Skip TLS certificate verification (insecure). |
| `watch.tls.server_name_override` | string | `""` | Override server name for TLS verification. |
| `watch.gpu.enabled` | boolean | `false` | Enable GPU acceleration in TUI mode. |
| `watch.gpu.backend` | string | `"auto"` | GPU backend for TUI. |
| `watch.gpu.batch_size` | integer | `100` | GPU batch size. |
| `watch.node_history` | list | `[]` | History of previously connected remote nodes (managed automatically). |
| `watch.filter_history` | list | `[]` | History of packet filter strings (managed automatically). |
| `watch.call_filter_history` | list | `[]` | History of call filter strings (managed automatically). |

---

## Remote Connection Settings

### `remote` — Remote TUI Connection

Settings for connecting `lc watch remote` to a processor or tap node. See [Remote TUI Monitoring](../part4-administration/watch-remote.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `remote.processor` | string | `""` | Processor address to connect to. |
| `remote.insecure` | boolean | `false` | Connect without TLS (blocked when `LIPPYCAT_PRODUCTION=true`). |
| `remote.tls.cert` | string | `""` | Client TLS certificate (for mTLS). |
| `remote.tls.key` | string | `""` | Client TLS private key. |
| `remote.tls.ca` | string | `""` | CA certificate for server verification. |
| `remote.tls.skip_verify` | boolean | `false` | Skip TLS certificate verification. |

---

## Security Settings

### `security` — API Security

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `security.api_keys.enabled` | boolean | `false` | Enable API key authentication for gRPC connections. |

---

## Example Configuration Files

### Minimal: Local VoIP Capture

A simple configuration for capturing VoIP traffic on a single machine:

```yaml
voip:
  sip_ports: "5060"
  udp_only: true
```

Use with: `sudo lc sniff voip -i eth0` or `sudo lc tap voip -i eth0 --insecure`

### Production: Distributed Deployment

A processor node in a production distributed deployment with TLS, per-call PCAP, and command hooks:

```yaml
processor:
  listen_addr: ":55555"
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    client_auth: true
  per_call_pcap:
    enabled: true
    output_dir: "/var/capture/calls"
    file_pattern: "{timestamp}_{callid}.pcap"
  auto_rotate_pcap:
    enabled: true
    output_dir: "/var/capture/continuous"
    max_size: "1G"
    idle_timeout: "60s"
  max_hunters: 50
  max_subscribers: 20
  filter_file: "/etc/lippycat/filters.yaml"
  pcap_command: "gzip %pcap%"
  voip_command: "/opt/scripts/process-call.sh %callid% %dirname%"
  command_concurrency: 20
  command_timeout: "60s"
```

### High-Performance: Edge Hunter

A hunter node optimized for high-throughput VoIP capture with GPU acceleration:

```yaml
hunter:
  processor_addr: "processor.internal:55555"
  interfaces:
    - "eth0"
    - "eth1"
  tls:
    enabled: true
    ca_file: "/etc/lippycat/certs/ca.crt"
  batch_size: 128
  buffer_size: 50000
  voip_filter:
    enabled: true
    gpu_backend: "cuda"
  disk_buffer:
    enabled: true
    dir: "/var/tmp/lippycat-buffer"
    max_mb: 2048

voip:
  tcp_performance_mode: "high_performance"
  udp_only: true
  sip_ports: "5060"
  gpu_enable: true
  gpu_backend: "cuda"
  gpu_batch_size: 2048

pcap_buffer_size: 67108864
promiscuous: true
```

For more on performance tuning, see [Performance Optimization](../part5-advanced/performance.md). For TLS certificate setup, see [Security](../part5-advanced/security.md).
