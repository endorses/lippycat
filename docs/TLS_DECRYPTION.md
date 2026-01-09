# TLS Decryption Guide

lippycat supports decrypting TLS-encrypted traffic (HTTPS, SMTPS, IMAPS, etc.) using SSLKEYLOGFILE format session keys. This enables viewing plaintext content from encrypted captures.

## Overview

TLS decryption requires session keys exported by the TLS client or server. These keys are stored in NSS Key Log Format (SSLKEYLOGFILE), which is also compatible with Wireshark.

**Key concepts:**
- Keys must be captured at runtime (forward secrecy prevents after-the-fact decryption)
- The capturing node needs access to the key log file
- In distributed mode, hunters forward keys to processors automatically

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

### Server-Side (Typical Deployment)

Configure your TLS server to log session keys. The capturing node runs on the same machine.

### Browsers

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
firefox  # or chromium, chrome
```

### curl

```bash
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://example.com
```

### OpenSSL (1.1.1+)

```bash
openssl s_client -connect example.com:443 -keylogfile /tmp/sslkeys.log
```

### Python (requests)

```python
import os
os.environ['SSLKEYLOGFILE'] = '/tmp/sslkeys.log'
import requests
requests.get('https://example.com')
```

### Go (crypto/tls)

```go
config := &tls.Config{
    KeyLogWriter: keylogFile,
}
```

### Node.js

```javascript
// Set before importing https/tls modules
process.env.SSLKEYLOGFILE = '/tmp/sslkeys.log';
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
