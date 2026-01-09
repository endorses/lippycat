# TLS Decryption Guide

lippycat supports decrypting TLS-encrypted traffic (HTTPS, SMTPS, IMAPS, etc.) using SSLKEYLOGFILE format session keys. This enables viewing plaintext content from encrypted captures.

## Overview

TLS decryption requires session keys exported by the TLS client or server. These keys are stored in NSS Key Log Format (SSLKEYLOGFILE), originally created by Mozilla's NSS library and now a de facto standard supported by Wireshark.

**Key Log Format:**
```
# Each line: <label> <client_random_hex> <secret_hex>
CLIENT_RANDOM 1234...abcd 5678...efgh
```

**Key concepts:**
- Keys must be captured at runtime (forward secrecy prevents after-the-fact decryption)
- The capturing node needs access to the key log file
- In distributed mode, hunters forward keys to processors automatically

## SSLKEYLOGFILE Support Matrix

### Web Servers

| Server | Support | Version | Mechanism | Notes |
|--------|---------|---------|-----------|-------|
| **Apache** | Native | 2.4.49+ | Environment variable | Requires OpenSSL 1.1.1+ |
| **Caddy** | Native | v2.6.0+ | Environment variable | Uses Go's `KeyLogWriter` |
| **nginx Plus** | Native | R33+ | `ssl_key_log` directive | Commercial only |
| **nginx OSS** | Third-party | - | Module or LD_PRELOAD | See workarounds below |

### Programming Languages

| Language | Library | Support | Mechanism |
|----------|---------|---------|-----------|
| **Go** | crypto/tls | Native | `tls.Config.KeyLogWriter` |
| **Python** | ssl | Manual | Set env var before import |
| **Node.js** | tls | Native | `keylog` event on sockets |
| **OpenSSL** | 1.1.1+ | Native | `SSL_CTX_set_keylog_callback()` |
| **Java** | JSSE | Manual | Custom implementation required |

### Client Applications

| Application | Support | Mechanism |
|-------------|---------|-----------|
| **Firefox** | Native | `SSLKEYLOGFILE` env var |
| **Chrome/Chromium** | Native | `SSLKEYLOGFILE` env var |
| **curl** | Native | `SSLKEYLOGFILE` env var |
| **wget** | Native | `SSLKEYLOGFILE` env var |

## CLI Usage

### Live Capture

```bash
# Standalone CLI capture with key log file
sudo lc sniff http -i eth0 --tls-keylog /tmp/sslkeys.log

# Standalone tap (serves TUI, writes PCAP + keylog)
sudo lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log

# Distributed hunter (decrypts for filtering, forwards encrypted + keys)
sudo lc hunt http -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log

# Real-time key injection via named pipe
mkfifo /tmp/sslkeys.pipe
sudo lc tap http -i eth0 --tls-keylog-pipe /tmp/sslkeys.pipe &
SSLKEYLOGFILE=/tmp/sslkeys.pipe ./myserver

# Combined with content filtering (filter decrypted traffic)
sudo lc hunt http -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log \
  --host "*.example.com" --keywords-file sensitive.txt

# Processor stores encrypted PCAP + keylog for Wireshark analysis
lc process --listen :50051 \
  --per-call-pcap --per-call-pcap-dir /var/capture \
  --tls-keylog-dir /var/capture/keys

# Works for any TLS-wrapped protocol
sudo lc hunt email -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log  # SMTPS, IMAPS, POP3S
```

### Offline Analysis (PCAP + Keylog)

```bash
# CLI analysis of stored capture
lc sniff http -r capture.pcap --tls-keylog keys.log

# TUI analysis of stored capture
lc watch file -r capture.pcap --tls-keylog keys.log

# Full round-trip workflow:
# 1. Capture with keylog
sudo lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log \
  -w /var/capture/session.pcap

# 2. Later: re-analyze with same decryption capability
lc watch file -r /var/capture/session.pcap \
  --tls-keylog /var/capture/session.keys
```

## Generating Key Logs

### Web Servers

#### Apache (2.4.49+)

```bash
# Set environment variable before starting Apache
export SSLKEYLOGFILE=/var/log/apache2/sslkeys.log
systemctl start apache2

# Or in systemd unit file (/etc/systemd/system/apache2.service.d/override.conf)
[Service]
Environment="SSLKEYLOGFILE=/var/log/apache2/sslkeys.log"
```

**Note:** Requires OpenSSL 1.1.1+. Some distributions disable this feature by default.

#### Caddy (v2.6.0+)

```bash
export SSLKEYLOGFILE=/tmp/caddy-keys.log
caddy run
```

#### nginx Plus (R33+)

```nginx
server {
    listen 443 ssl;
    ssl_key_log /tmp/sslkey.log;
    # ...
}
```

Also supports `proxy_ssl_key_log`, `grpc_ssl_key_log`, and `uwsgi_ssl_key_log` for upstream connections.

#### nginx Open Source (Workarounds)

nginx OSS doesn't have native support. Options:

1. **Third-party module:** [nginx-sslkeylog](https://github.com/tiandrey/nginx-sslkeylog)
   - Requires OpenSSL 1.1.1+
   - Requires patching nginx sources for TLSv1.3

2. **LD_PRELOAD method:** Preload a shared library that intercepts OpenSSL calls
   - No patching/rebuilding required
   - Works with any OpenSSL-based application

### Browsers

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
firefox  # or chromium, chrome
```

### Command-Line Tools

```bash
# curl
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://example.com

# wget
SSLKEYLOGFILE=/tmp/sslkeys.log wget https://example.com

# OpenSSL (1.1.1+)
openssl s_client -connect example.com:443 -keylogfile /tmp/sslkeys.log
```

### Programming Languages

#### Go (crypto/tls)

```go
keylogFile, _ := os.Create("/tmp/keys.log")
config := &tls.Config{
    KeyLogWriter: keylogFile,
}
```

#### Python

```python
import os
os.environ['SSLKEYLOGFILE'] = '/tmp/sslkeys.log'
import requests  # Must import AFTER setting env var
requests.get('https://example.com')
```

#### Node.js

```javascript
// Set before importing https/tls modules
process.env.SSLKEYLOGFILE = '/tmp/sslkeys.log';
const https = require('https');
```

## Distributed Key Forwarding

In distributed mode, hunters automatically forward TLS session keys to processors:

```
┌─────────────┐                    ┌─────────────┐
│   Hunter    │  gRPC (encrypted)  │  Processor  │
│             │ ─────────────────► │             │
│ --tls-keylog│   PacketData with  │ Writes:     │
│ /tmp/keys   │   TLSSessionKeys   │ - PCAP      │
└─────────────┘                    │ - keylog    │
                                   └─────────────┘
```

**Processor flags:**
- `--tls-keylog-dir` - Directory for keylog files (one per PCAP)

The keylog files are written in NSS format, compatible with Wireshark's `ssl.keylog_file` preference.

## TUI Display

When TLS decryption is enabled:

1. **Header indicator:** Shows "TLS" badge when decryption is active
2. **Details panel:** Displays decrypted content in a dedicated section with HTTP syntax highlighting

To enable in TUI:
```bash
lc watch file -r capture.pcap --tls-keylog keys.log
```

## Wireshark Integration

lippycat's keylog files are fully compatible with Wireshark:

1. Open the PCAP file in Wireshark
2. Go to Edit → Preferences → Protocols → TLS
3. Set "(Pre)-Master-Secret log filename" to the keylog file
4. Apply - decrypted content now visible

For distributed captures, the processor writes paired files:
- `/var/capture/session.pcap` - Encrypted traffic
- `/var/capture/keys/session.keys` - Session keys

## Limitations

1. **Key log required:** Cannot decrypt without SSLKEYLOGFILE (forward secrecy)
2. **No private key decryption:** RSA key exchange is rare/obsolete
3. **Real-time sync:** Keys must arrive before or shortly after handshake
4. **Memory usage:** Session state stored until connection closes
5. **Same-machine deployment:** Key log file must be accessible to capturing node

## Security Considerations

- **Protect key log files:** They contain session secrets that can decrypt all captured traffic
- **Restricted permissions:** Use `chmod 600` on keylog files
- **Secure transport:** Forwarded keys are protected by gRPC TLS (hunter→processor)
- **Key rotation:** Clear key store on file rotation/truncation
- **Audit access:** Log access to keylog files in production

## Troubleshooting

### No decrypted content visible

1. Verify keylog file exists and has content
2. Check file permissions (must be readable by lippycat)
3. Ensure keys were captured during the TLS handshake
4. Verify the keylog contains entries for the captured sessions (match CLIENT_RANDOM)

### Keys not being forwarded (distributed mode)

1. Verify hunter has `--tls-keylog` flag set
2. Check processor logs for key reception
3. Ensure gRPC connection is healthy

### Wireshark can't decrypt

1. Verify keylog format (should start with `CLIENT_RANDOM` or `CLIENT_HANDSHAKE_TRAFFIC_SECRET`)
2. Check Wireshark TLS preferences are configured
3. Try reloading the capture after setting keylog path

## See Also

- [SECURITY.md](SECURITY.md) - TLS/mTLS configuration for gRPC connections
- [DISTRIBUTED_MODE.md](DISTRIBUTED_MODE.md) - Hunter/processor architecture
- [cmd/watch/README.md](../cmd/watch/README.md) - TUI watch command
