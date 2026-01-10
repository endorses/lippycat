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

### File Analysis

```bash
# Analyze PCAP file
lc watch file -r capture.pcap

# With BPF filter
lc watch file -r capture.pcap -f "port 5060"

# With TLS decryption (for HTTPS, SMTPS, etc.)
lc watch file -r https-capture.pcap --tls-keylog sslkeys.log
```

**Flags:**
- `-r, --read-file` - PCAP file to analyze (required)
- `-f, --filter` - BPF filter expression
- `--tls-keylog` - Path to SSLKEYLOGFILE for TLS decryption
- `--buffer-size` - Maximum packets in memory (default: 10000)

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
lc watch file -r https.pcap --tls-keylog /tmp/sslkeys.log
```

The TUI will show a "TLS" indicator in the header when decryption is enabled. In the packet details panel, decrypted content appears in a dedicated "Decrypted Content" section with HTTP syntax highlighting.

**For comprehensive documentation:** See [docs/TLS_DECRYPTION.md](../../docs/TLS_DECRYPTION.md) for key log generation, distributed key forwarding, Wireshark integration, and troubleshooting.

### Remote Monitoring

```bash
# Remote monitoring with default nodes file
lc watch remote

# With custom nodes file
lc watch remote --nodes-file /path/to/nodes.yaml

# With TLS encryption
lc watch remote --tls --tls-ca ca.crt

# With mutual TLS (mTLS)
lc watch remote --tls --tls-ca ca.crt --tls-cert client.crt --tls-key client.key

# Insecure mode for testing
lc watch remote --insecure
```

**Flags:**
- `-n, --nodes-file` - Path to nodes YAML file (default: `~/.config/lippycat/nodes.yaml` or `./nodes.yaml`)
- `--insecure` - Allow insecure connections without TLS (testing only)
- `-T, --tls` - Enable TLS encryption
- `--tls-ca` - CA certificate for server verification
- `--tls-cert` - Client certificate for mutual TLS
- `--tls-key` - Client private key for mutual TLS
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
    address: processor1.example.com:50051
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
      cert_file: /path/to/client.crt
      key_file: /path/to/client.key

  - name: processor-2
    address: processor2.example.com:50051
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
```

## Examples

### VoIP Monitoring Setup

```bash
# Terminal 1: Start processor
lc process --listen :50051

# Terminal 2: Start hunter
sudo lc hunt voip -i eth0 --processor localhost:50051

# Terminal 3: Watch traffic
lc watch remote
```

### PCAP Analysis Workflow

```bash
# Analyze captured VoIP traffic
lc watch file -r voip-capture.pcap

# Filter for specific SIP traffic
lc watch file -r voip-capture.pcap -f "port 5060"
```

## See Also

- [docs/TLS_DECRYPTION.md](../../docs/TLS_DECRYPTION.md) - TLS decryption guide
- [docs/TUI_REMOTE_CAPTURE.md](../../docs/TUI_REMOTE_CAPTURE.md) - Remote capture setup guide
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS configuration
- [internal/pkg/tui/CLAUDE.md](../../internal/pkg/tui/CLAUDE.md) - TUI architecture
