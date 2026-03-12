# Troubleshooting

When something goes wrong during a capture, you need answers quickly. This chapter organizes common problems by category, each following the same structure: what you see (symptom), why it happens (cause), and what to do about it (solution). Diagnostic commands are included so you can confirm the root cause before applying a fix.

If you have not yet read [Chapter 12: Operations Runbook](../part4-administration/operations.md), start there for health checks and monitoring scripts. This chapter goes deeper into specific failure modes.

## Capture Issues

These problems affect all capture modes — `sniff`, `hunt`, and `tap`.

### Permission Denied

**Symptom:** lippycat exits immediately with `operation not permitted` or `permission denied`.

**Cause:** Live packet capture requires the `CAP_NET_RAW` and `CAP_NET_ADMIN` Linux capabilities. Without them, the kernel refuses access to the network interface.

**Solution:**

Run with `sudo`:

```bash
sudo lc sniff voip -i eth0
```

Or grant capabilities to the binary so it can run without root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc
```

Verify the capabilities are set:

```bash
getcap /usr/local/bin/lc
# Expected: /usr/local/bin/lc cap_net_admin,cap_net_raw=eip
```

After setting capabilities, any non-root user can run captures. Note that `setcap` must be reapplied after reinstalling or upgrading the binary.

### Interface Not Found

**Symptom:** lippycat reports `no such device` or the interface name is not recognized.

**Cause:** The interface name does not match any active network device. This commonly happens after renaming (e.g., `eth0` became `enp3s0`) or when a virtual interface has not been created yet.

**Diagnosis:**

```bash
# List all interfaces with their current state
ip link show

# Or use lippycat's built-in listing
lc list interfaces
```

**Solution:**

Use the correct interface name from the listing above. If you are unsure which interface carries the traffic you want, capture on all interfaces:

```bash
sudo lc sniff voip --interface any
```

The `any` pseudo-interface captures from all active interfaces simultaneously. This is useful for diagnosis but may increase CPU load in production — switch to a specific interface once you identify the correct one.

### No Packets Captured

**Symptom:** lippycat starts without error but shows zero packets.

**Cause:** Several possibilities:

1. **Wrong interface** — traffic flows through a different interface than the one selected.
2. **BPF filter too restrictive** — the filter expression excludes the traffic you expect.
3. **Firewall rules** — iptables or nftables is dropping packets before they reach the capture layer.
4. **Promiscuous mode needed** — the traffic is not addressed to this host and the interface is not in promiscuous mode.

**Diagnosis:**

```bash
# Confirm traffic exists on the interface with tcpdump
sudo tcpdump -i eth0 -c 10 -n

# If capturing VoIP, check for SIP traffic specifically
sudo tcpdump -i eth0 -n port 5060

# Check firewall rules
sudo iptables -L -n -v
sudo nft list ruleset
```

**Solution:**

- If `tcpdump` sees traffic but lippycat does not, check your BPF filter. Start without a filter and add constraints incrementally.
- Enable promiscuous mode if capturing traffic not addressed to this host:

  ```bash
  sudo lc sniff -i eth0 --promisc
  ```

- If a firewall is dropping packets, add an exception for the capture interface or move the capture point before the firewall rules (e.g., use a TAP device or mirror port).

### PCAP File Issues

**Symptom:** PCAP files are not created, are empty, or appear corrupted.

**Cause:** Disk space exhaustion, incorrect directory permissions, or the process was killed before the file was finalized.

**Diagnosis:**

```bash
# Check disk space
df -h /var/capture/

# Check directory permissions
ls -la /var/capture/

# Verify file integrity with capinfos (Wireshark tools)
capinfos capture.pcap
```

**Solution:**

- Ensure the output directory exists and is writable by the user running lippycat.
- For per-call PCAP in VoIP mode, verify the `--per-call-pcap-dir` directory has sufficient space. Each call generates a separate file; a deployment with thousands of concurrent calls can consume disk rapidly.
- If a PCAP file appears truncated, the capture process likely crashed or was killed with `SIGKILL`. Use `SIGTERM` or `SIGINT` (Ctrl+C) for graceful shutdown, which flushes and closes all open PCAP files.
- For auto-rotating PCAP files, check that the rotation configuration does not create files faster than the disk can handle.

## TCP Reassembly Problems

TCP reassembly issues primarily affect SIP-over-TCP capture. See [Chapter 4](../part2-local-capture/sniff.md) for how TCP performance modes work.

### No TCP SIP Messages Captured

**Symptom:** Zero active TCP streams. No SIP calls detected despite TCP SIP traffic being present on the network.

**Cause:** The capture may not be seeing TCP traffic on port 5060, or the interface/filter configuration is excluding it.

**Diagnosis:**

```bash
# Verify TCP SIP traffic reaches the interface
sudo tcpdump -i eth0 -n port 5060 and tcp -c 5

# Run lippycat with debug logging to trace processing
LOG_LEVEL=debug sudo lc sniff voip -i eth0 --tcp-performance-mode latency 2> debug.log

# Search for TCP-related messages
grep -i "tcp\|sip\|stream" debug.log
```

**Solution:**

If `tcpdump` shows TCP SIP traffic:

1. Ensure you have not set `--udp-only`, which skips TCP entirely.
2. Try `--interface any` to rule out interface selection.
3. Check that no BPF filter is excluding TCP.

If `tcpdump` shows no traffic:

1. SIP may be on a non-standard port. Check your PBX configuration.
2. A firewall may be blocking port 5060. Check `iptables -L -n`.

### Streams Created but No SIP Detected

**Symptom:** TCP streams appear in metrics but no Call-IDs are extracted. Buffers accumulate without being flushed.

**Cause:** SIP messages are fragmented across TCP segments and are not reassembling correctly, or the messages have a non-standard format.

**Diagnosis:**

```bash
LOG_LEVEL=debug sudo lc sniff voip -i eth0 --tcp-performance-mode latency 2> debug.log
grep -i "fragment\|reassembl\|content-length\|malform" debug.log
```

**Solution:**

1. Increase the stream timeout to give fragmented messages more time to complete:

   ```yaml
   voip:
     tcp_stream_timeout: 120s
   ```

2. Switch to `latency` mode for faster per-segment processing:

   ```bash
   sudo lc sniff voip -i eth0 --tcp-performance-mode latency
   ```

3. Verify SIP message format with a packet capture. Check that `Content-Length` headers match the actual body size — mismatches cause the parser to wait indefinitely for more data.

### High Memory Usage During TCP Capture

**Symptom:** Memory usage grows continuously. The system becomes unresponsive or the OOM killer terminates the process.

**Cause:** Long-lived or abandoned TCP streams accumulate buffers. This is common in environments with many short-lived connections that are not cleanly terminated (no FIN/RST).

**Diagnosis:**

```bash
# Monitor memory usage
watch -n 2 'ps -o pid,rss,vsz,comm -p $(pgrep lc)'
```

**Solution:**

Switch to memory-optimized mode and set explicit limits:

```yaml
voip:
  tcp_performance_mode: "memory"
  memory_optimization: true
  tcp_memory_limit: 52428800    # 50 MB cap
  max_tcp_buffers: 1000
  tcp_buffer_max_age: 120s
  tcp_cleanup_interval: 30s
```

For environments with highly variable load, use adaptive buffering:

```yaml
voip:
  tcp_buffer_strategy: "adaptive"
```

### High CPU Usage During TCP Capture

**Symptom:** CPU usage saturates one or more cores. Packet drops begin.

**Cause:** Too many concurrent goroutines processing TCP streams, or the batch size is too small causing excessive per-packet overhead.

**Solution:**

Reduce goroutine concurrency and enable backpressure:

```yaml
voip:
  max_goroutines: 500
  enable_backpressure: true
```

For high-volume environments, switch to throughput mode with larger batches:

```yaml
voip:
  tcp_performance_mode: "throughput"
  tcp_batch_size: 64
```

### Packet Drops and Missed Calls

**Symptom:** The dropped-streams metric increases. Known calls are missing from output.

**Cause:** Processing cannot keep up with arrival rate. Queue buffers overflow.

**Solution:**

Increase queue capacity and processing throughput:

```yaml
voip:
  stream_queue_buffer: 1000
  tcp_performance_mode: "throughput"
  max_goroutines: 2000
  tcp_buffer_strategy: "ring"
```

If drops persist, consider offloading to a distributed setup with dedicated hunters ([Chapter 7](../part3-distributed/hunt.md)) so the processing load is spread across machines.

### TCP Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| TCP-001 | Stream creation failed | Reduce `max_goroutines` or increase system `ulimit -n` |
| TCP-002 | Buffer overflow | Enable `memory_optimization`, reduce `max_tcp_buffers` |
| TCP-003 | Assembly timeout | Increase `tcp_stream_timeout` |
| TCP-004 | Invalid SIP format | Inspect traffic with tcpdump; check for malformed messages |
| TCP-005 | Resource exhaustion | Restart with `tcp_performance_mode: memory` |

## Distributed Connectivity

These issues affect hunter-to-processor and processor-to-processor communication. See [Chapter 6](../part3-distributed/architecture.md) for the distributed architecture overview.

### TLS Handshake Failure

**Symptom:** Hunter fails to connect with `transport: authentication handshake failed` or `certificate verify failed`.

**Cause:** TLS certificate problems. The most common issues are:

1. **Expired certificate** — the certificate's validity period has passed.
2. **Wrong CA** — the hunter's `--tls-ca` does not match the CA that signed the processor's certificate.
3. **Missing SANs** — the processor certificate lacks a Subject Alternative Name matching the address the hunter connects to.
4. **Hostname mismatch** — the hunter connects by IP but the certificate only has DNS names (or vice versa).

**Diagnosis:**

```bash
# Check certificate expiry and SANs
openssl x509 -in server.crt -noout -dates -ext subjectAltName

# Test TLS connection manually
openssl s_client -connect processor.example.com:55555 -CAfile ca.crt

# Check if the CA matches
openssl verify -CAfile ca.crt server.crt
```

**Solution:**

For expired certificates, regenerate them. See [Chapter 13: Security](security.md) for certificate generation procedures.

For missing SANs, regenerate the server certificate with the correct entries. The SAN must include every name or IP that hunters use to connect:

```bash
# Example: certificate extensions file with SANs
cat > server-ext.conf <<EOF
subjectAltName = DNS:processor.example.com,DNS:processor,IP:10.0.1.50,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
```

For hostname mismatch, either regenerate the certificate with the correct SAN entries or change the hunter's `--processor` address to match what the certificate contains.

### Mutual TLS (mTLS) Rejection

**Symptom:** Hunter connects but is immediately disconnected. Processor logs show `client certificate required` or `bad certificate`.

**Cause:** The processor is configured for mutual TLS (`--tls-client-ca`) but the hunter did not provide a client certificate, or the client certificate was not signed by the expected CA.

**Solution:**

Provide client certificates on the hunter:

```bash
sudo lc hunt voip -i eth0 \
  --processor processor:55555 \
  --tls-cert hunter.crt \
  --tls-key hunter.key \
  --tls-ca ca.crt
```

Ensure the hunter certificate was signed by the CA specified in the processor's `--tls-client-ca`.

### Hunter Cannot Reach Processor

**Symptom:** Hunter reports `connection refused` or `context deadline exceeded`.

**Cause:** Network connectivity issue — the processor is not listening, a firewall blocks the port, or DNS resolution fails.

**Diagnosis:**

```bash
# Test basic connectivity
nc -zv processor.example.com 55555

# Check DNS resolution
dig processor.example.com

# Check if the processor is listening
ss -tlnp | grep 55555
```

**Solution:**

- Verify the processor is running and listening on the expected address and port.
- Check firewall rules on both sides. The default gRPC port is 55555.
- If using Docker or Kubernetes, verify port mappings and service discovery.

### Hunter Stalls (Flow Control)

**Symptom:** Hunter is connected but stops sending packets. Logs show flow control state changes to `PAUSE` or `SLOW`.

**Cause:** The processor is overloaded. Flow control is working as designed — the processor signals hunters to slow down or pause when its internal queues fill up. Common triggers are slow PCAP writes (disk I/O bottleneck) or upstream backlog.

**Diagnosis:**

```bash
# Check processor status
lc show status -P processor:55555 --tls-ca ca.crt

# Check disk I/O on the processor
iostat -x 1 5

# Check PCAP write queue depth in processor logs
journalctl -u lippycat-processor --since "10 minutes ago" | grep -i "queue\|flow"
```

**Solution:**

Flow control states and their thresholds:

| State | Queue Utilization | Hunter Behavior |
|-------|------------------|-----------------|
| CONTINUE | < 30% | Normal sending |
| SLOW | 30% - 70% | Reduced batch rate |
| PAUSE | 70% - 90% | Stop sending, buffer locally |
| RESUME | Drops below 30% | Resume normal sending |

To resolve:

1. **Disk bottleneck:** Move PCAP output to faster storage (SSD, tmpfs for temporary captures).
2. **Processing bottleneck:** Scale horizontally by adding processor nodes in a hierarchical topology (see [Chapter 6](../part3-distributed/architecture.md)).
3. **Temporary spike:** Wait — flow control will resume automatically when the queue drains.

Note: TUI client slowness does not cause hunter flow control. Each TUI subscriber has an independent buffer, and slow clients are handled by selective packet drops on the subscriber channel. See [Chapter 8](../part3-distributed/process.md) for the flow control architecture.

### Reconnection After Network Partition

**Symptom:** After a network outage, hunters do not reconnect, or they reconnect but miss packets during the outage.

**Cause:** Hunters have automatic reconnection with exponential backoff (target < 100 ms for fast reconnection). Packets arriving during the disconnection period are lost unless disk buffering is enabled.

**Solution:**

Enable disk buffering on hunters to survive network interruptions:

```bash
sudo lc hunt voip -i eth0 \
  --processor processor:55555 \
  --disk-buffer \
  --tls-ca ca.crt
```

With disk buffering, the hunter writes to a local overflow buffer when the processor is unreachable and drains it after reconnection.

If hunters are not reconnecting at all, check for persistent DNS or routing changes that occurred during the outage.

## GPU Troubleshooting

GPU acceleration is optional. The CPU SIMD backend is always available and provides approximately 30,000 packets/second for pattern matching. See [Chapter 14: Performance Optimization](performance.md) for GPU backend selection.

### Backend Compatibility

| Platform | CUDA | OpenCL | SIMD (CPU) |
|----------|------|--------|------------|
| NVIDIA GPU | Yes (best) | Yes | Fallback |
| AMD GPU | No | Yes (best) | Fallback |
| Intel GPU | No | Yes | Fallback |
| CPU only | No | No | Always works |

lippycat automatically falls back to SIMD if no GPU backend is available. You do not need a GPU to run lippycat.

### "No CUDA-capable device is detected"

**Symptom:** lippycat built with CUDA reports no GPU available, particularly on laptops with hybrid graphics (Intel + NVIDIA).

**Cause:** On NVIDIA Optimus laptops, the discrete GPU may be powered down by the kernel's runtime power management. The GPU exists but is not initialized.

**Diagnosis:**

```bash
# Check if NVIDIA kernel modules are loaded
lsmod | grep nvidia

# Check if device nodes exist
ls -l /dev/nvidia*

# Check PCI device visibility
lspci | grep -i nvidia

# Check GPU status (if nvidia-smi is available)
nvidia-smi
```

**Solution (quick, no reboot):**

```bash
# Force the GPU on via sysfs
echo on | sudo tee /sys/bus/pci/devices/0000:01:00.0/power/control

# Start the NVIDIA persistence daemon
sudo nvidia-persistenced --verbose

# Enable compute mode
sudo nvidia-smi -pm 1
```

Replace `0000:01:00.0` with your GPU's PCI address from `lspci`.

**Solution (permanent, requires reboot):**

Disable dynamic power management. Create `/etc/modprobe.d/nvidia-power.conf`:

```
options nvidia NVreg_DynamicPowerManagement=0x00
```

Then regenerate initramfs and reboot:

```bash
# Arch Linux / Manjaro
sudo mkinitcpio -P

# Debian / Ubuntu
sudo update-initramfs -u

sudo reboot
```

### NVIDIA GPU Detected but CUDA Fails

**Symptom:** `nvidia-smi` shows the GPU, but lippycat's CUDA backend still fails.

**Cause:** The nouveau open-source driver may be loaded instead of the proprietary NVIDIA driver, or the CUDA toolkit version is incompatible.

**Diagnosis:**

```bash
# Check if nouveau is loaded (it conflicts with nvidia)
lsmod | grep nouveau

# Check CUDA environment
echo $CUDA_VISIBLE_DEVICES
```

**Solution:**

If nouveau is loaded, blacklist it:

```bash
echo "blacklist nouveau" | sudo tee /etc/modprobe.d/blacklist-nouveau.conf
sudo mkinitcpio -P   # or update-initramfs -u
sudo reboot
```

Set CUDA environment variables:

```bash
export __NV_PRIME_RENDER_OFFLOAD=1
export __GLX_VENDOR_LIBRARY_NAME=nvidia
export CUDA_VISIBLE_DEVICES=0
```

Add these to your shell profile for persistence.

### OpenCL Backend Not Available

**Symptom:** AMD or Intel GPU is present but the OpenCL backend is not detected.

**Cause:** OpenCL runtime libraries are not installed.

**Solution:**

Install the appropriate OpenCL runtime for your GPU:

```bash
# AMD (ROCr)
sudo apt install rocm-opencl-runtime   # Debian/Ubuntu
sudo pacman -S rocm-opencl-runtime     # Arch

# Intel
sudo apt install intel-opencl-icd      # Debian/Ubuntu
sudo pacman -S intel-compute-runtime   # Arch
```

Verify with:

```bash
clinfo | head -20
```

### Falling Back to SIMD

**Symptom:** GPU backend was expected but lippycat is using CPU SIMD instead.

**Cause:** The GPU backend failed to initialize and lippycat fell back silently. This is normal behavior — SIMD is a reliable fallback.

**Diagnosis:**

```bash
# Run with debug logging to see backend selection
LOG_LEVEL=debug sudo lc sniff voip -i eth0 --gpu-backend auto 2>&1 | grep -i "gpu\|cuda\|opencl\|simd\|backend"
```

**Solution:**

If you need GPU acceleration, fix the underlying GPU issue using the sections above. If SIMD performance is sufficient (30K packets/second pattern matching), no action is needed. To explicitly force a backend and see the error:

```bash
sudo lc sniff voip -i eth0 --gpu-backend cuda
```

This will fail with a descriptive error instead of silently falling back.

## VoIP-Specific Issues

VoIP capture involves correlating SIP signaling with RTP media streams. These issues are specific to `sniff voip`, `hunt voip`, and `tap voip` modes. See [Chapter 4](../part2-local-capture/sniff.md) for VoIP capture fundamentals.

### Missing RTP Streams

**Symptom:** SIP calls are detected (INVITE, 200 OK visible) but no RTP packets are captured. Per-call PCAP files contain only signaling.

**Cause:**

1. **BPF filter too restrictive** — the filter captures SIP but excludes the RTP port range.
2. **RTP on unexpected ports** — the SDP negotiation specifies ports outside the expected range.
3. **UDP-only mode not set** — if RTP is UDP but the capture is processing TCP overhead unnecessarily.

**Diagnosis:**

```bash
# Check what ports the SDP negotiates (look at m= lines)
sudo tcpdump -i eth0 -n -A port 5060 | grep "m=audio"

# Check if RTP traffic exists on those ports
sudo tcpdump -i eth0 -n udp portrange 10000-20000 -c 10
```

**Solution:**

Ensure the RTP port range covers the ports your PBX uses:

```bash
sudo lc sniff voip -i eth0 --rtp-port-range 10000-20000
```

If you applied a custom BPF filter with `-f`, verify it does not exclude UDP traffic on the RTP port range. When in doubt, remove the BPF filter and let lippycat's protocol detection handle filtering.

### One-Way Audio (RTP in One Direction Only)

**Symptom:** Per-call PCAP shows RTP packets flowing in only one direction. The other direction is missing entirely.

**Cause:**

1. **NAT traversal** — one endpoint is behind NAT and its RTP packets have a different source IP than what the SDP advertised. lippycat correlates RTP by IP:port pairs from SDP; if NAT rewrites the source, the correlation fails.
2. **Asymmetric routing** — RTP flows through different network paths and the return traffic does not pass through the capture point.
3. **Wrong interface** — outbound RTP leaves through a different interface than the one being captured.

**Diagnosis:**

Check the SDP `c=` (connection) lines against actual packet source IPs:

```bash
# Look at SDP connection lines
sudo tcpdump -i eth0 -n -A port 5060 | grep "c=IN"

# Compare with actual RTP source IPs
sudo tcpdump -i eth0 -n udp portrange 10000-20000 | head -20
```

If the SDP says `c=IN IP4 10.0.1.100` but actual RTP comes from `203.0.113.50`, NAT is in play.

**Solution:**

- Capture on `--interface any` to cover all interfaces.
- If NAT is the issue, capture at a point in the network where both directions are visible (e.g., on the SBC or media gateway itself, or on a mirror port that sees both legs).
- In environments with complex NAT, consider deploying hunters on both sides of the NAT boundary and aggregating at a processor.

### SIP Over TCP Not Detected

**Symptom:** SIP calls using TCP transport are not detected, but UDP SIP works fine.

**Cause:** TCP SIP requires reassembly. If `--udp-only` is set, TCP is skipped entirely. Without it, the TCP reassembly engine must be functioning correctly.

**Solution:**

1. Ensure `--udp-only` is **not** set.
2. Select an appropriate TCP performance mode:

   ```bash
   sudo lc sniff voip -i eth0 --tcp-performance-mode balanced
   ```

3. If the problem persists, see the [TCP Reassembly Problems](#tcp-reassembly-problems) section above.

### High Call Volume Packet Drops

**Symptom:** In environments with hundreds of concurrent calls, some calls are missing or incomplete.

**Cause:** The packet processing pipeline cannot keep up with the arrival rate. This manifests as kernel ring buffer overflows (packets dropped before lippycat sees them) or internal queue saturation.

**Diagnosis:**

```bash
# Check kernel drop statistics
cat /proc/net/dev | grep eth0

# Check for ring buffer overflows in system logs
dmesg | grep -i "drop\|overflow"
```

**Solution:**

1. Use `--udp-only` if TCP SIP is not needed — this eliminates TCP reassembly overhead:

   ```bash
   sudo lc sniff voip -i eth0 --udp-only --sip-port 5060
   ```

2. Enable GPU acceleration for protocol detection:

   ```bash
   sudo lc sniff voip -i eth0 --gpu-backend auto
   ```

3. For sustained high volume, switch to a distributed architecture with dedicated hunters:

   ```bash
   # Hunter handles capture and filtering
   sudo lc hunt voip -i eth0 --processor central:55555 --gpu-backend auto --tls-ca ca.crt

   # Processor handles analysis and PCAP writing
   lc process --listen :55555 --per-call-pcap --per-call-pcap-dir /var/capture/calls \
     --tls-cert server.crt --tls-key server.key
   ```

4. Increase the kernel ring buffer size for the capture interface:

   ```bash
   sudo ethtool -G eth0 rx 4096
   ```

## Configuration Issues

### Configuration Not Taking Effect

**Symptom:** Changes to the config file do not change lippycat's behavior. Default values are still used.

**Cause:** lippycat loads configuration at startup from a specific set of paths. If the file is in the wrong location, has YAML syntax errors, or was modified after startup, changes will not apply.

**Diagnosis:**

```bash
# Check which config file is being loaded
lc show config

# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

**Solution:**

1. Place the config file in one of the expected locations (in priority order):
   - `$HOME/.config/lippycat/config.yaml`
   - `$HOME/.config/lippycat.yaml`
   - `$HOME/.lippycat.yaml`

2. Or specify it explicitly:

   ```bash
   sudo lc sniff voip --config /etc/lippycat/config.yaml
   ```

3. Restart lippycat after any configuration change. Configuration is read once at startup.

## Diagnostic Tools

### Debug Logging

Enable verbose logging for any lippycat command:

```bash
LOG_LEVEL=debug sudo lc sniff voip -i eth0 2> debug.log
```

Filter log output for specific subsystems:

```bash
# TCP reassembly issues
grep -i "tcp\|stream\|reassembl" debug.log

# SIP parsing
grep -i "sip\|invite\|call.id" debug.log

# gRPC / distributed connectivity
grep -i "grpc\|connect\|tls\|handshake" debug.log

# GPU backend selection
grep -i "gpu\|cuda\|opencl\|simd" debug.log
```

### System Resource Monitoring

```bash
# Monitor lippycat resource usage
watch -n 2 'ps -o pid,rss,vsz,%cpu,%mem,comm -p $(pgrep lc)'

# Monitor network interface statistics (drops, errors)
watch -n 1 'ip -s link show eth0'

# Monitor disk I/O (relevant for PCAP writing)
iostat -x 1

# Monitor open file descriptors
ls /proc/$(pgrep -f "lc ")/fd | wc -l
```

### Distributed Deployment Diagnostics

```bash
# Processor status overview
lc show status -P processor:55555 --tls-ca ca.crt

# List connected hunters
lc show hunters -P processor:55555 --tls-ca ca.crt

# View network topology
lc show topology -P processor:55555 --tls-ca ca.crt

# Check active filters
lc show filter -P processor:55555 --tls-ca ca.crt
```

### Health Check Script

A basic health check script for automated monitoring:

```bash
#!/bin/bash
# lippycat-health-check.sh

PROC_NAME="lc"

# Check if lippycat is running
if ! pgrep -f "$PROC_NAME" > /dev/null; then
    echo "CRITICAL: lippycat not running"
    exit 2
fi

PID=$(pgrep -f "$PROC_NAME" | head -1)

# Check memory usage (threshold: 500 MB)
MEM_KB=$(ps -o rss= -p "$PID" | tr -d ' ')
MEM_MB=$((MEM_KB / 1024))

if [ "$MEM_MB" -gt 500 ]; then
    echo "WARNING: High memory usage: ${MEM_MB} MB"
    exit 1
fi

# Check CPU usage (threshold: 80%)
CPU=$(ps -o pcpu= -p "$PID" | tr -d ' ' | cut -d. -f1)

if [ "$CPU" -gt 80 ]; then
    echo "WARNING: High CPU usage: ${CPU}%"
    exit 1
fi

echo "OK: lippycat healthy (Memory: ${MEM_MB} MB, CPU: ${CPU}%)"
exit 0
```

## Quick Reference

| Symptom | Section |
|---------|---------|
| `operation not permitted` | [Permission Denied](#permission-denied) |
| `no such device` | [Interface Not Found](#interface-not-found) |
| Zero packets captured | [No Packets Captured](#no-packets-captured) |
| PCAP files empty or missing | [PCAP File Issues](#pcap-file-issues) |
| No TCP SIP messages | [No TCP SIP Messages Captured](#no-tcp-sip-messages-captured) |
| TCP streams but no SIP | [Streams Created but No SIP Detected](#streams-created-but-no-sip-detected) |
| Memory growing unbounded | [High Memory Usage During TCP Capture](#high-memory-usage-during-tcp-capture) |
| CPU saturated | [High CPU Usage During TCP Capture](#high-cpu-usage-during-tcp-capture) |
| Dropped streams / missed calls | [Packet Drops and Missed Calls](#packet-drops-and-missed-calls) |
| TLS handshake failed | [TLS Handshake Failure](#tls-handshake-failure) |
| mTLS client rejected | [Mutual TLS (mTLS) Rejection](#mutual-tls-mtls-rejection) |
| Connection refused to processor | [Hunter Cannot Reach Processor](#hunter-cannot-reach-processor) |
| Hunter stops sending | [Hunter Stalls (Flow Control)](#hunter-stalls-flow-control) |
| No reconnection after outage | [Reconnection After Network Partition](#reconnection-after-network-partition) |
| No CUDA device detected | ["No CUDA-capable device is detected"](#no-cuda-capable-device-is-detected) |
| GPU detected but CUDA fails | [NVIDIA GPU Detected but CUDA Fails](#nvidia-gpu-detected-but-cuda-fails) |
| OpenCL not available | [OpenCL Backend Not Available](#opencl-backend-not-available) |
| Using SIMD instead of GPU | [Falling Back to SIMD](#falling-back-to-simd) |
| Missing RTP in captures | [Missing RTP Streams](#missing-rtp-streams) |
| One-way audio | [One-Way Audio (RTP in One Direction Only)](#one-way-audio-rtp-in-one-direction-only) |
| TCP SIP not working | [SIP Over TCP Not Detected](#sip-over-tcp-not-detected) |
| Drops at high call volume | [High Call Volume Packet Drops](#high-call-volume-packet-drops) |
| Config changes ignored | [Configuration Not Taking Effect](#configuration-not-taking-effect) |
