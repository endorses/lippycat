# Watch Command - Interactive TUI Monitoring

The `watch` command provides interactive Terminal User Interface (TUI) monitoring for packet capture. It supports live capture, PCAP file analysis, and remote node monitoring.

## Commands

### Live Capture (Default)

```bash
# Live capture on default interface
lc watch

# Explicit live mode
lc watch live

# Live capture on specific interface
lc watch live -i eth0

# With BPF filter
lc watch live -i eth0 -f "port 5060"

# Promiscuous mode
lc watch live -i eth0 -p
```

**Flags:**

- `-i, --interface` - Network interface(s) to monitor, comma separated (default: `any`)
- `-f, --filter` - BPF filter expression
- `-p, --promiscuous` - Enable promiscuous mode
- `--enable-gpu` - Enable GPU-accelerated VoIP parsing
- `--gpu-backend` - GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd`
- `--gpu-batch-size` - Batch size for GPU processing (default: 100)
- `--buffer-size` - Maximum packets in memory (default: 10000)
- `--debug-log` - Write debug logs to file (helps diagnose capture issues)

### File Analysis

```bash
# Analyze single PCAP file
lc watch file capture.pcap

# Analyze multiple PCAP files (merged display)
lc watch file sip.pcap rtp.pcap signaling.pcap

# With BPF filter
lc watch file capture.pcap -f "port 5060"

# With TLS decryption (for HTTPS, SMTPS, etc.)
lc watch file https-capture.pcap --tls-keylog sslkeys.log

# Multiple files with filter
lc watch file call1.pcap call2.pcap -f "udp"
```

**Arguments:**

- `files...` - One or more PCAP files to analyze (required)

**Flags:**

- `-f, --filter` - BPF filter expression
- `--tls-keylog` - Path to SSLKEYLOGFILE for TLS decryption
- `--buffer-size` - Live/remote packet ring and retained event capacity (default: 10000); does not limit offline packets

**Complete offline packets:** Every logical packet accepted by the source-level
`-f` BPF filter is indexed in private temporary storage before browsing starts.
Reassembly and decapsulation can change the logical packet count and effective
link type relative to the original capture. Navigation, packet details,
interactive filters (including removal and clearing), and saves cover the complete
dataset, regardless of `watch.buffer_size` or display-cache eviction. The header
shows total packets. Statistics separates global and matching counts from cached
rows/cache bytes and index bytes; the bottom area stays reserved for notifications.
Global statistics cover the dataset; matching statistics cover the last completed
query. Endpoint/cardinality estimates remain bounded and are labelled separately.

Normalized packets are ordered by timestamp, then argument order and original
source sequence, using bounded temporary disk storage before analysis. Backward
timestamps are supported without altering timestamps or deduplicating packets.
The opening modal reports reading, sorting and indexing; Escape cancels any phase.
Sorting files share the disk budget with current and replacement datasets and
queries, so opening needs additional temporary disk space. Up to 64 regular-file
sources are supported. Read errors and invalid BPF filters also fail indexing;
a failed source never publishes a successful partial dataset.
PCAP and single-section, single-interface PCAPNG files can be mixed; split
multi-interface or multi-section PCAPNG captures first. Reader records/PCAPNG
blocks are capped at 16 MiB. Per-source pending IP fragments are capped at 4,096
flows and 16 MiB, with a 30-second capture-time expiry.

Packet filtering runs as a cancellable complete summary scan. The previous query
remains installed until the new rows, description, and matching statistics are
ready together. Escape cancels without changing that query. Events and Calls
retain separate bounded histories; their filters only cover retained history.
Stateful analysis consumes the full stream and finalizes before publication,
but neither view promises complete file history.

Press `w` to save all packets matching the completed packet query, or all dataset
packets when no packet filter is active. Export streams a fixed snapshot to
nanosecond PCAP, preserving normalized raw bytes, effective link type, timestamps,
and captured/original lengths. Mixed effective link types are rejected; export
those inputs separately. Missing timestamps or timestamps outside unsigned
32-bit Unix seconds are rejected instead of altered. Empty results report no
packets to save. Escape cancels export. Only a successful export replaces the
destination atomically; failure or cancellation removes the temporary output and
preserves any existing destination. Export needs additional disk space beside
the destination, outside the offline session budget.

#### TLS Decryption

When analyzing PCAP files containing TLS-encrypted traffic (HTTPS, SMTPS, IMAPS, etc.), you can provide an SSLKEYLOGFILE to decrypt and view the plaintext content.

**Generating an SSLKEYLOGFILE:**

Most browsers and applications can export TLS session keys when the `SSLKEYLOGFILE` environment variable is set:

```bash
# Firefox / Chrome
SSLKEYLOGFILE=/tmp/sslkeys.log firefox

# curl
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://example.com

# Python requests (requires PyOpenSSL)
import sslkeylog
sslkeylog.set_keylog("sslkeys.log")
```

**Using with lc watch:**

```bash
# Capture traffic (separate terminal)
tcpdump -i eth0 -w https.pcap port 443

# Analyze with decryption
lc watch file https.pcap --tls-keylog /tmp/sslkeys.log
```

The TUI will show a "TLS" indicator in the header when decryption is enabled. In the packet details panel, decrypted content appears in a dedicated "Decrypted Content" section with HTTP syntax highlighting.

**For comprehensive documentation:** See [docs/TLS_DECRYPTION.md](../../docs/TLS_DECRYPTION.md) for key log generation, distributed key forwarding, Wireshark integration, and troubleshooting.

### Remote Monitoring

```bash
# Remote monitoring with default nodes file
lc watch remote

# Connect directly to one processor
lc watch remote --processor processor.example.com:55555 --tls-ca ca.crt

# With custom nodes file
lc watch remote --nodes-file /path/to/nodes.yaml

# With TLS (CA verification)
lc watch remote -P processor.example.com:55555 --tls-ca ca.crt

# With mutual TLS (mTLS)
lc watch remote -P processor.example.com:55555 --tls-ca ca.crt --tls-cert client.crt --tls-key client.key

# Insecure mode for testing
lc watch remote -P localhost:55555 --insecure
```

**Flags:**

- `-P, --processor` - Processor address (host:port) to connect directly
- `-n, --nodes-file` - Path to nodes YAML file (default: `~/.config/lippycat/nodes.yaml` or `./nodes.yaml`)
- `--insecure` - Allow insecure connections without TLS (testing only)
- `--tls-ca` - CA certificate for server verification
- `--tls-cert` - Client certificate for mutual TLS
- `--tls-key` - Client private key for mutual TLS
- `--tls-skip-verify` - Skip TLS certificate verification (INSECURE - testing only)
- `--tls-server-name` - Override server name for TLS verification
- `--buffer-size` - Maximum packets in memory (default: 10000)

## TUI Navigation

### Global Keys

- `Tab` - Switch between views
- `q` / `Ctrl+C` - Quit
- `?` - Help

### Packet View

- `j` / `k` / `Up` / `Down` - Navigate packets
- `g` / `Home` - Jump to first packet
- `G` / `End` - Jump to last packet
- `Enter` - View packet details
- `Ctrl+S` - Save packets to PCAP file

Live packet rows are a bounded diagnostic feed. Under load, the TUI samples
detail packets, can drop full detail batches, and evicts the oldest pending rows
so recent traffic remains visible. The Statistics view exposes **Sampled Out**,
**Batch Queue Drops**, **Pending Evictions**, and the end-to-end retained
percentage. These losses affect TUI detail visibility, not exact ingress
telemetry, upstream capture flow control, or PCAP output. Treat the displayed
packet list as incomplete whenever retention is below 100%; use PCAP output for
loss-sensitive analysis. Recognized SIP bypasses adaptive sampling but remains
subject to the later batch and ring limits. Offline PCAP replay uses a separate
preserve-all path.

### Nodes View (Remote Mode)

- `s` - Subscribe to hunters
- `d` - Unsubscribe from hunters
- `Enter` - Connect to processor

### Calls View (VoIP)

- `j` / `k` - Navigate calls
- `Enter` - View call details

## Configuration

All flags can be specified in the configuration file:

```yaml
watch:
  buffer_size: 10000
  gpu:
    enabled: false
    backend: "auto"
    batch_size: 100

tui:
  tls:
    enabled: false
    ca_file: ""
    cert_file: ""
    key_file: ""
```

## Nodes File Format

For remote monitoring, the nodes file specifies processor endpoints:

```yaml
processors:
  - name: processor-1
    address: processor1.example.com:55555
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
      cert_file: /path/to/client.crt
      key_file: /path/to/client.key

  - name: processor-2
    address: processor2.example.com:55555
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
```

## Examples

### VoIP Monitoring Setup

```bash
# Terminal 1: Start processor
lc process --listen :55555 --insecure

# Terminal 2: Start hunter
sudo lc hunt voip -i eth0 --processor localhost:55555 --insecure

# Terminal 3: Watch traffic
lc watch remote -P localhost:55555 --insecure
```

### PCAP Analysis Workflow

```bash
# Analyze captured VoIP traffic
lc watch file voip-capture.pcap

# Filter for specific SIP traffic
lc watch file voip-capture.pcap -f "port 5060"

# Analyze multiple related captures
lc watch file signaling.pcap media.pcap
```

## See Also

- [docs/TLS_DECRYPTION.md](../../docs/TLS_DECRYPTION.md) - TLS decryption guide
- [docs/TUI_REMOTE_CAPTURE.md](../../docs/TUI_REMOTE_CAPTURE.md) - Remote capture setup guide
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS configuration
- [internal/pkg/tui/CLAUDE.md](../../internal/pkg/tui/CLAUDE.md) - TUI architecture

### Offline indexing lifecycle

`watch file` indexes the complete accepted packet stream into private temporary
storage before installing the dataset. Startup, file dialogs, settings, and
restarts use the same indexing workflow. The progress modal reports phase,
source count, logical packets, scanned logical bytes, elapsed time, and disk
usage, and the frozen backing policy. Escape cancels and keeps the modal open
until cleanup finishes. A failed or cancelled replacement preserves the previous
ready dataset and its state.

Browsing loads bounded pages and selected details asynchronously. Cache eviction
does not discard logical packets or change packet/event loss counters. Events and
calls retain bounded histories independently of the complete packet dataset.

Offline resource flags (also available when switching from live/remote mode):

| Flag                         | Viper key                        | Default                |
| ---------------------------- | -------------------------------- | ---------------------- |
| `--offline-session-dir`      | `watch.offline.session_dir`      | OS temporary directory |
| `--offline-backing-policy`   | `watch.offline.backing_policy`   | `source`               |
| `--offline-max-disk-bytes`   | `watch.offline.max_disk_bytes`   | 4 GiB                  |
| `--offline-cache-bytes`      | `watch.offline.cache_bytes`      | 64 MiB                 |
| `--offline-max-record-bytes` | `watch.offline.max_record_bytes` | 8 MiB                  |
| `--offline-max-sources`      | `watch.offline.max_sources`      | 64                     |

Flags override their corresponding YAML/Viper keys. Byte settings are positive
integer byte counts; maximum record bytes must fit both cache and disk budgets.
The backing policy accepts `source` or `snapshot` and is frozen per open.
The default `source` policy keeps the original capture handles open and reads
packet bytes on demand. Keep those files unchanged until the session and its
exports finish. In-place edits or truncation cause explicit read/export errors;
opening a replacement path never substitutes new bytes into the old session.
Renamed or unlinked inputs remain readable through the original handle where
the operating system permits it. Already returned owned details remain valid.

Use `--offline-backing-policy snapshot` for independence from later input edits.
It creates and validates a private copy before indexing, charging its full size
to the session disk budget. Gzip classic PCAP uses an owned decompressed backing;
snapshot mode also temporarily charges the compressed copy. Normalized/reassembled bytes
are retained separately. There is no automatic copy after a source-change error.
`max_sources` must be between 1 and 64. The session parent directory must exist
and be writable. For example:

```yaml
watch:
  offline:
    session_dir: /var/tmp
    backing_policy: source
    max_disk_bytes: 4294967296
    cache_bytes: 67108864
    max_record_bytes: 8388608
    max_sources: 64
```

The ready dataset and replacement share disk/cache budgets. Disk accounting
includes summaries, details, offsets, manifests, and completed/in-progress query
files, source snapshots, decompressed inputs, and derived packet bytes. Allow
room for both datasets during replacement and for filtered query vectors.
All-match queries use implicit packet IDs without a per-packet query file. Normalized storage can be larger than the source capture. A configured
budget limit, physical disk exhaustion, or permission error is surfaced explicitly;
failed opens/queries preserve the previous completed dataset/query. Free space,
choose a writable session directory, or raise the disk budget before retrying.
Normal cancellation/shutdown removes owned temporary sessions; cleanup errors
remain visible and failed-open cleanup can be retried. Never delete an active
session directory manually. Resource exhaustion
fails the replacement without publishing a partial dataset. Leave offline mode
before changing budgets. These limits do not constitute a process RSS limit:
readers, analysis, retained history, and the Go runtime have separate overhead.
Offline SIP framing additionally caps active TCP streams at 4,096, total frame
buffers at 16 MiB, and SIP messages at 64 KiB; tighter configured SIP stream,
message, and content limits also apply. A framing resource limit fails indexing
explicitly. TLS key logs are read into a bounded session snapshot and are not
watched for changes during replay. Retained TLS plaintext is capped at 16 MiB
across all connections and both directions in each offline session. Exceeding
this analyzer budget fails indexing explicitly and preserves the previous ready
dataset. The plaintext budget is separate from the display cache; allocation
overhead is additional.
