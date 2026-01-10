# AF_XDP Setup and Requirements

## Overview

AF_XDP (Address Family eXpress Data Path) provides ultra-fast packet capture with kernel bypass and zero-copy capabilities. This document describes requirements, setup, and usage for lippycat's AF_XDP integration.

## System Requirements

### Kernel Version
- **Minimum:** Linux kernel 4.18+
- **Recommended:** Linux kernel 5.4+ for full feature support
- **Optimal:** Linux kernel 5.10+ for best performance

Check your kernel version:
```bash
uname -r
```

### Hardware Requirements

#### Network Interface Card (NIC)
AF_XDP requires a network driver with XDP support. Compatible drivers include:

**Intel:**
- ixgbe (10GbE)
- i40e (40GbE)
- ice (100GbE)
- igb (1GbE)

**Other Vendors:**
- mlx5 (Mellanox)
- nfp (Netronome)
- bnxt (Broadcom)
- qede (QLogic)

Check driver XDP support:
```bash
ethtool -i eth0 | grep driver
```

#### CPU
- **Minimum:** 2 CPU cores
- **Recommended:** 4+ CPU cores for production
- **Optimal:** Dedicated CPU cores with CPU pinning

#### Memory
- **Minimum:** 4GB RAM
- **Recommended:** 8GB+ RAM
- **UMEM allocation:** 4-16MB per interface (configurable)

### Software Requirements

#### Kernel Configuration
Required kernel config options:
```bash
CONFIG_XDP_SOCKETS=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
```

Verify kernel configuration:
```bash
grep XDP_SOCKETS /boot/config-$(uname -r)
grep BPF /boot/config-$(uname -r)
```

#### Capabilities
AF_XDP requires elevated privileges:
```bash
# Option 1: Run as root
sudo lc

# Option 2: Grant CAP_NET_ADMIN and CAP_NET_RAW
sudo setcap cap_net_admin,cap_net_raw=eip lc
```

#### Libraries
- **libelf-dev:** For BPF program loading
- **libbpf:** BPF library (optional but recommended)

Install on Ubuntu/Debian:
```bash
sudo apt-get install libelf-dev libbpf-dev
```

Install on RHEL/CentOS:
```bash
sudo yum install elfutils-libelf-devel libbpf-devel
```

## Performance Tuning

### Interface Configuration

#### Disable Hardware Offloads
For best XDP performance:
```bash
# Disable GRO, LRO, TSO
sudo ethtool -K eth0 gro off
sudo ethtool -K eth0 lro off
sudo ethtool -K eth0 tso off
sudo ethtool -K eth0 gso off

# Verify
ethtool -k eth0 | grep -E '(gro|lro|tso|gso)'
```

#### Set Ring Buffer Sizes
Increase NIC ring buffer sizes:
```bash
# Check current sizes
ethtool -g eth0

# Set maximum sizes (example)
sudo ethtool -G eth0 rx 4096 tx 4096
```

#### Multi-Queue Configuration
Enable multiple queues for better performance:
```bash
# Check queue count
ethtool -l eth0

# Set to maximum (example: 4 queues)
sudo ethtool -L eth0 combined 4
```

### CPU Configuration

#### IRQ Affinity
Pin NIC interrupts to specific CPUs:
```bash
# Find IRQ numbers for eth0
grep eth0 /proc/interrupts

# Pin IRQ to CPU core 0
echo 1 > /proc/irq/<irq_number>/smp_affinity
```

#### CPU Governor
Set CPU to performance mode:
```bash
sudo cpupower frequency-set -g performance
```

#### NUMA Awareness
For NUMA systems, pin to same NUMA node as NIC:
```bash
# Check NIC NUMA node
cat /sys/class/net/eth0/device/numa_node

# Pin process to NUMA node 0
numactl --cpunodebind=0 --membind=0 lc
```

### Memory Configuration

#### Huge Pages
Enable huge pages for better UMEM performance:
```bash
# Enable 2MB huge pages
echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Verify
cat /proc/meminfo | grep Huge
```

#### Locked Memory Limits
Increase locked memory limit:
```bash
# Edit /etc/security/limits.conf
* soft memlock unlimited
* hard memlock unlimited

# Or set for current session
ulimit -l unlimited
```

## Configuration

### lippycat Configuration

#### Basic XDP Configuration
```yaml
capture:
  interface: eth0
  use_xdp: true
  xdp_queue_id: 0

xdp:
  umem_size: 4194304      # 4MB
  num_frames: 4096
  frame_size: 2048
  rx_ring_size: 2048
  tx_ring_size: 2048
  fill_ring_size: 2048
  comp_ring_size: 2048
  batch_size: 64
  enable_stats: true
```

#### Advanced Configuration
```yaml
capture:
  interface: eth0
  use_xdp: true
  xdp_queue_id: 0
  buffer_size: 10000
  batch_size: 64
  timeout: 100ms
  enable_stats: true
  stats_interval: 10s

xdp:
  # UMEM configuration
  umem_size: 8388608      # 8MB
  num_frames: 8192
  frame_size: 2048

  # Ring sizes (power of 2)
  rx_ring_size: 4096
  tx_ring_size: 4096
  fill_ring_size: 4096
  comp_ring_size: 4096

  # Performance tuning
  batch_size: 128
  flags: 0                # Driver decides (zerocopy/copy mode)
  bind_flags: 0           # No shared UMEM

  # Statistics
  enable_stats: true
```

### Programmatic Configuration

```go
// Create XDP configuration
config := voip.DefaultCaptureConfig("eth0")
config.UseXDP = true
config.XDPQueueID = 0
config.BufferSize = 10000
config.BatchSize = 64

// Create capture engine
engine, err := voip.NewCaptureEngine(config)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

// Check if using XDP
if engine.IsUsingXDP() {
    log.Println("AF_XDP capture active")
} else {
    log.Println("Fallback to standard capture")
}

// Start capture
if err := engine.Start(); err != nil {
    log.Fatal(err)
}

// Process packets
for pkt := range engine.Packets() {
    // Process packet
}
```

## Verification

### Check XDP Support
```bash
# Check kernel XDP support
bpftool feature probe | grep XDP

# Verify kernel version (must be 4.18+)
uname -r
```

### Monitor XDP Statistics

#### Using lippycat
```bash
# Enable verbose logging
sudo lc sniff --interface eth0 --verbose

# Check stats output:
# Capture statistics: mode=AF_XDP packets_received=X ...
```

#### Using ethtool
```bash
# Check XDP statistics
ethtool -S eth0 | grep xdp
```

#### Using bpftool
```bash
# List loaded XDP programs
sudo bpftool prog show type xdp

# Show XDP program statistics
sudo bpftool prog show id <prog_id>
```

### Performance Monitoring

#### Check Packet Drops
```bash
# Monitor interface drops
watch -n 1 "ethtool -S eth0 | grep -E '(drop|err)'"

# Monitor lippycat drops
# Look for "packets_dropped" in verbose output
```

#### CPU Usage
```bash
# Monitor CPU usage
top -H -p $(pidof lippycat)

# Check CPU affinity
taskset -p $(pidof lippycat)
```

#### Memory Usage
```bash
# Monitor memory usage
ps aux | grep lippycat

# Check UMEM allocation
cat /proc/$(pidof lippycat)/status | grep VmSize
```

## Troubleshooting

### XDP Not Available

**Symptom:** Falls back to standard capture

**Causes:**
1. Kernel too old (< 4.18)
2. Network driver doesn't support XDP
3. Missing kernel configuration

**Solutions:**
```bash
# Check kernel version
uname -r

# Check driver support
ethtool -i eth0

# Upgrade kernel if needed
sudo apt-get install linux-generic-hwe-20.04
```

### Permission Denied

**Symptom:** Error creating AF_XDP socket

**Solution:**
```bash
# Run as root
sudo lc

# Or grant capabilities
sudo setcap cap_net_admin,cap_net_raw=eip lc
```

### High Packet Loss

**Symptom:** Many packets dropped

**Causes:**
1. Insufficient ring buffer sizes
2. CPU not fast enough
3. Processing too slow

**Solutions:**
```bash
# Increase ring sizes in config
rx_ring_size: 4096
fill_ring_size: 4096

# Increase batch size
batch_size: 128

# Pin to specific CPU
taskset -c 0 lc

# Increase NIC ring buffers
sudo ethtool -G eth0 rx 4096
```

### UMEM Allocation Failed

**Symptom:** "failed to create UMEM" error

**Causes:**
1. Insufficient locked memory limit
2. Memory fragmentation
3. UMEM size too large

**Solutions:**
```bash
# Increase locked memory limit
ulimit -l unlimited

# Reduce UMEM size in config
umem_size: 2097152  # 2MB instead of 4MB

# Enable huge pages
echo 256 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Poor Performance

**Symptom:** Not achieving expected packet rates

**Causes:**
1. Hardware offloads enabled
2. CPU governor in powersave mode
3. Wrong NUMA node
4. Small batch sizes

**Solutions:**
```bash
# Disable offloads
sudo ethtool -K eth0 gro off lro off tso off gso off

# Set performance governor
sudo cpupower frequency-set -g performance

# Pin to correct NUMA node
numactl --cpunodebind=0 --membind=0 lc

# Increase batch size
batch_size: 128
```

## Performance Expectations

### Packet Rates

| Mode | Expected Rate | CPU Usage |
|------|--------------|-----------|
| Standard | 1M pps | High |
| AF_XDP | 5-10M pps | Medium |
| AF_XDP + Tuning | 10-20M pps | Low |

### Latency

| Mode | Typical Latency |
|------|----------------|
| Standard | 1-10 μs |
| AF_XDP | 100-500 ns |
| AF_XDP Zero-Copy | 50-100 ns |

### Throughput

| Mode | 64B Packets | 1500B Packets |
|------|-------------|---------------|
| Standard | ~5 Gbps | ~10 Gbps |
| AF_XDP | ~20 Gbps | ~40 Gbps |
| AF_XDP Tuned | ~40 Gbps | ~100 Gbps |

## Best Practices

### Production Deployment

1. **Dedicated Hardware:** Use dedicated CPU cores and NIC queues
2. **Monitoring:** Enable statistics and monitor drop rates
3. **Fallback:** Always configure fallback to standard capture
4. **Testing:** Test under expected load before production
5. **NUMA:** Pin to same NUMA node as NIC
6. **Huge Pages:** Enable for large UMEM allocations

### Configuration Guidelines

1. **Ring Sizes:** Use power-of-2 sizes (2048, 4096)
2. **Batch Size:** Start with 64, tune based on workload
3. **UMEM Size:** 4-16MB typically sufficient
4. **Frame Size:** 2048 bytes for standard MTU
5. **Buffer Size:** 10000+ for high packet rates

### Security Considerations

1. **Privileges:** Use capabilities instead of root when possible
2. **Isolation:** Run in dedicated namespace if available
3. **Monitoring:** Monitor for anomalous behavior
4. **Updates:** Keep kernel and drivers updated

## References

### Documentation
- [Linux XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [AF_XDP Programming Guide](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)

### Tools
- [bpftool](https://github.com/torvalds/linux/tree/master/tools/bpf/bpftool)
- [xdp-tools](https://github.com/xdp-project/xdp-tools)
- [libbpf](https://github.com/libbpf/libbpf)

### Driver Support
- [XDP Driver Support Matrix](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)

---

*Last Updated: 2025-09-30*
*lippycat AF_XDP Integration*
*Phase 2: I/O & Networking Optimizations*