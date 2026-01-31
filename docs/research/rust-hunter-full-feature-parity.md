# Rust Hunter: Full Feature Parity Implementation Analysis

**Research Document**
**Date:** 2026-01-20
**Status:** Draft
**Author:** Claude Code Analysis

## Executive Summary

This document provides a comprehensive analysis of implementing a Rust hunter node with **full feature parity** to lippycat's Go hunter. After thorough analysis of ~4,600 lines of Go hunter code plus ~8,000 lines of supporting packages (VoIP, detector, capture), we identify every component that must be reimplemented in Rust.

### Key Findings

1. **Scope**: The hunter is a complex distributed system component with 15+ major subsystems
2. **Complexity**: Full feature parity requires implementing:
   - gRPC bidirectional streaming (2 services, 15+ message types)
   - High-performance packet capture with multi-interface support
   - Protocol detection (20+ protocols) with SIMD acceleration
   - VoIP call buffering with SIP/RTP correlation
   - GPU-accelerated pattern matching (Aho-Corasick, Bloom filters, radix trees)
   - Nuclear-proof resilience (circuit breaker, disk overflow buffer)
   - TLS/mTLS with hot-reloadable certificates
3. **Performance Target**: Must exceed Go implementation (target: 40+ Gbps vs Go's ~10-15 Gbps)
4. **Estimated Effort**: 16-24 person-weeks for full implementation
5. **Recommendation**: Phased implementation, starting with core capture and gRPC

---

## Table of Contents

1. [Complete Feature Inventory](#1-complete-feature-inventory)
2. [Architecture Translation: Go → Rust](#2-architecture-translation-go--rust)
3. [Crate Selection and Dependencies](#3-crate-selection-and-dependencies)
4. [Component Implementation Details](#4-component-implementation-details)
5. [Concurrency Model Translation](#5-concurrency-model-translation)
6. [Performance Optimization Strategies](#6-performance-optimization-strategies)
7. [gRPC Protocol Implementation](#7-grpc-protocol-implementation)
8. [Resilience Patterns in Rust](#8-resilience-patterns-in-rust)
9. [Testing Strategy](#9-testing-strategy)
10. [Protocol-Specific Hunter Implementations](#10-protocol-specific-hunter-implementations)
11. [Implementation Phases](#11-implementation-phases-updated)
12. [Repository Strategy](#12-repository-strategy)
13. [Risk Assessment](#13-risk-assessment)
14. [Appendix: Complete Type Mappings](#appendix-complete-type-mappings)

---

## 1. Complete Feature Inventory

### 1.1 Command-Line Interface

| Go Feature | Description | Rust Equivalent |
|------------|-------------|-----------------|
| Cobra commands | `hunt`, `hunt voip`, `hunt dns`, etc. | `clap` with subcommands |
| Viper config | YAML config + env vars + flags | `config-rs` or `figment` |
| Persistent flags | Inherited by subcommands | `clap` global args |
| Build tags | `//go:build hunter` | Cargo features |

**Flags to Implement (Base Hunter):**
```
--processor/-P string         REQUIRED: Processor address
--id/-I string               Hunter ID (default: hostname)
--interface/-i strings       Network interfaces (multiple)
--filter/-f string           BPF filter expression
--promisc/-p                 Promiscuous mode
--pcap-buffer-size int       Kernel buffer (16MB default)
--buffer-size/-b int         Packet buffer (10000)
--batch-size int             Batch size (64)
--batch-timeout int          Batch timeout ms (100)
--batch-queue-size int       Memory queue (1000)
--disk-buffer bool           Enable disk overflow
--disk-buffer-dir string     Overflow directory
--disk-buffer-max-mb int     Max disk usage (1024)
--tls-cert string            Client certificate
--tls-key string             Client key
--tls-ca string              CA certificate
--tls-skip-verify            Skip verification
--insecure                   Disable TLS
--no-filter-policy string    "allow" or "deny"
```

**VoIP-Specific Flags:**
```
--udp-only/-U               UDP-only SIP
--sip-port/-S string        SIP ports
--rtp-port-range/-R string  RTP port ranges
--pattern-algorithm string  auto|linear|aho-corasick
--pattern-buffer-mb int     Pattern buffer (64MB)
```

**DNS-Specific Flags:**
```
--dns-port string           DNS ports (default: "53")
--udp-only                  UDP-only DNS capture
--detect-tunneling          Enable DNS tunneling detection (default: true)
```

**HTTP-Specific Flags:**
```
--http-port string          HTTP ports (default: "80,8080,8000,3000,8888")
--host string               Host patterns (glob-style, comma-separated)
--path string               Path patterns (glob-style, comma-separated)
--method string             HTTP methods to filter (comma-separated)
--status string             Status codes to filter (e.g., "4xx", "500-599")
--keywords string           Body/URL keywords for Aho-Corasick matching
--capture-body              Enable body content capture
--max-body-size int         Max body size (default: 65536)
--tls-keylog string         SSLKEYLOGFILE path for HTTPS decryption
--tls-keylog-pipe string    Named pipe for real-time TLS key injection
```

**TLS-Specific Flags:**
```
--tls-port string           TLS ports (default: "443")
```
(SNI/JA3/JA3S/JA4 filtering is processor-managed via filter subscription)

**Email-Specific Flags:**
```
--protocol string           smtp|imap|pop3|all (default: "all")
--smtp-port string          SMTP ports (default: "25,587,465")
--imap-port string          IMAP ports (default: "143,993")
--pop3-port string          POP3 ports (default: "110,995")
--sender string             Sender address patterns (glob)
--recipient string          Recipient address patterns (glob)
--subject string            Subject patterns (glob)
--keywords string           Body keywords for Aho-Corasick matching
--mailbox string            IMAP mailbox patterns (glob)
--command string            IMAP/POP3 command patterns (glob)
--capture-body              Enable body capture
--max-body-size int         Max body size (default: 65536)
```

### 1.2 Core Hunter Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| Hunter lifecycle | `hunter/hunter.go` | 500 | P0 |
| Connection manager | `hunter/connection/manager.go` | 600 | P0 |
| Forwarding manager | `hunter/forwarding/manager.go` | 700 | P0 |
| Packet capture | `capture/capture.go` | 400 | P0 |
| Statistics collector | `hunter/stats/collector.go` | 200 | P0 |
| Circuit breaker | `hunter/circuitbreaker/breaker.go` | 300 | P1 |
| Disk buffer | `hunter/buffer/disk_buffer.go` | 400 | P1 |
| Filter manager | `hunter/filtering/manager.go` | 350 | P0 |
| Capture manager | `hunter/capture/manager.go` | 250 | P0 |

### 1.3 VoIP Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| Buffer manager | `voip/buffermanager.go` | 300 | P1 |
| Call buffer | `voip/callbuffer.go` | 200 | P1 |
| Call tracker | `voip/calltracker.go` | 600 | P1 |
| Call aggregator | `voip/call_aggregator.go` | 600 | P1 |
| Lock-free tracker | `voip/lockfree_calltracker.go` | 400 | P2 |
| SIP parsing | `voip/sip.go` | 250 | P1 |
| RTP detection | `voip/rtp.go` | 150 | P1 |
| TCP reassembly | `voip/tcp_stream.go` | 600 | P1 |
| TCP buffer | `voip/tcp_buffer.go` | 300 | P1 |
| TCP handler (hunter) | `voip/tcp_handler_hunter.go` | 200 | P1 |
| TCP handler (tap) | `voip/tcp_handler_tap.go` | 130 | P1 |
| TCP handler (local) | `voip/tcp_handler_local.go` | 100 | P1 |
| TCP config | `voip/tcp_config.go` | 200 | P2 |
| VoIP config | `voip/config.go` | 225 | P1 |
| BPF filter builder | `voip/filter.go` | 150 | P1 |
| VoIP processor | `voip/processor/*.go` | 800 | P1 |

### 1.4 DNS Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| DNS parser | `dns/parser.go` | 400 | P2 |
| DNS filter builder | `dns/filter.go` | 150 | P2 |
| Query tracker | `dns/tracker.go` | 250 | P2 |
| Tunneling detector | `dns/tunneling.go` | 500 | P2 |
| DNS processor | `dns/processor.go` | 300 | P2 |
| Hunter DNS processor | `hunter/dns_processor.go` | 200 | P2 |

### 1.5 HTTP Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| HTTP parser | `http/parser.go` | 350 | P2 |
| Content filter | `http/content_filter.go` | 400 | P2 |
| HTTP filter builder | `http/filter.go` | 150 | P2 |
| TCP stream handler | `http/tcp_stream.go` | 500 | P2 |
| TCP factory | `http/tcp_factory.go` | 350 | P2 |
| Request tracker | `http/tracker.go` | 300 | P2 |
| Request aggregator | `http/aggregator.go` | 250 | P2 |
| HTTP processor | `http/processor.go` | 200 | P2 |

### 1.6 TLS Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| TLS parser | `tls/parser.go` | 600 | P2 |
| JA3/JA3S/JA4 fingerprinting | `tls/ja3.go` | 400 | P2 |
| TLS filter builder | `tls/filter.go` | 150 | P2 |
| Connection tracker | `tls/tracker.go` | 300 | P2 |
| Content filter | `tls/content_filter.go` | 250 | P2 |

### 1.7 Email Components

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| SMTP parser | `email/parser.go` | 400 | P3 |
| IMAP parser | `email/imap_parser.go` | 500 | P3 |
| POP3 parser | `email/pop3_parser.go` | 350 | P3 |
| Email filter builder | `email/filter.go` | 150 | P3 |
| Content filter | `email/content_filter.go` | 400 | P3 |
| SMTP TCP factory | `email/tcp_factory.go` | 350 | P3 |
| IMAP TCP factory | `email/imap_tcp_factory.go` | 350 | P3 |
| POP3 TCP factory | `email/pop3_tcp_factory.go` | 350 | P3 |
| Session tracker | `email/tracker.go` | 400 | P3 |
| IMAP tracker | `email/imap_tracker.go` | 300 | P3 |
| POP3 tracker | `email/pop3_tracker.go` | 300 | P3 |
| Email packet processor | `email/email_packet_processor.go` | 400 | P3 |

### 1.8 Pattern Matching (Shared)

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| Aho-Corasick | `ahocorasick/ahocorasick.go` | 400 | P1 |
| Buffered matcher | `ahocorasick/buffered.go` | 200 | P1 |
| Phone matcher | `phonematcher/matcher.go` | 300 | P1 |
| Pattern parsing | `filtering/pattern.go` | 150 | P1 |
| SIP user filter | `voip/sipusers/sipusers.go` | 250 | P1 |

### 1.9 Protocol Detection

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| Detector core | `detector/detector.go` | 400 | P1 |
| Detection cache | `detector/cache.go` | 200 | P2 |
| Flow tracker | `detector/flow.go` | 250 | P2 |
| SIP signature | `detector/signatures/voip/sip.go` | 150 | P1 |
| RTP signature | `detector/signatures/voip/rtp.go` | 200 | P1 |
| DNS signature | `detector/signatures/dns/dns.go` | 150 | P2 |
| TLS signature | `detector/signatures/tls/tls.go` | 200 | P2 |
| HTTP signature | `detector/signatures/http/http.go` | 200 | P2 |
| 15+ other protocols | Various | 1500 | P3 |

### 1.10 Application Filter (GPU-Accelerated)

| Component | Go Location | Lines | Priority |
|-----------|-------------|-------|----------|
| Application filter | `hunter/application_filter.go` | 1200 | P1 |
| GPU accelerator | `voip/gpu_accel.go` | 400 | P2 |
| GPU backend interface | `voip/gpu_backend.go` | 150 | P2 |
| CUDA backend | `voip/gpu_cuda_backend_impl.go` | 600 | P3 |
| SIMD utilities | `simd/simd.go` | 300 | P1 |

### 1.11 gRPC Protocol

| Service | Methods | Message Types |
|---------|---------|---------------|
| DataService | StreamPackets, SubscribePackets | PacketBatch, CapturedPacket, StreamControl |
| ManagementService | RegisterHunter, SubscribeFilters, Heartbeat | HunterRegistration, Filter, FilterUpdate, Heartbeat |

---

## 2. Architecture Translation: Go → Rust

### 2.1 Concurrency Model

| Go Pattern | Rust Equivalent | Notes |
|------------|-----------------|-------|
| `goroutine` | `tokio::spawn` | Async tasks |
| `chan T` | `tokio::sync::mpsc` | Bounded channels |
| `sync.Mutex` | `tokio::sync::Mutex` or `parking_lot::Mutex` | Async vs sync |
| `sync.RWMutex` | `tokio::sync::RwLock` or `parking_lot::RwLock` | Read-heavy use parking_lot |
| `sync.WaitGroup` | `tokio::task::JoinSet` or futures | Task tracking |
| `atomic.Int32` | `std::sync::atomic::AtomicI32` | Lock-free |
| `context.Context` | `tokio_util::sync::CancellationToken` | Cancellation |
| `select {}` | `tokio::select!` | Multiplexing |

### 2.2 Error Handling

| Go Pattern | Rust Equivalent |
|------------|-----------------|
| `error` interface | `thiserror` custom errors |
| `fmt.Errorf("...: %w", err)` | `anyhow` or custom error types |
| Panic recovery | `std::panic::catch_unwind` (rare) |
| `defer cleanup()` | `Drop` trait / RAII |

### 2.3 Struct Organization

**Go Hunter struct:**
```go
type Hunter struct {
    config          Config
    captureManager  *capture.Manager
    filterManager   *filtering.Manager
    connectionMgr   *connection.Manager
    applicationFilter *ApplicationFilter
    dnsProcessor    *dns.Processor
    packetProcessor PacketProcessor
    batchQueue      chan *data.PacketBatch
    statsCollector  *stats.Collector
    ctx             context.Context
    cancel          context.CancelFunc
    wg              sync.WaitGroup
}
```

**Rust equivalent:**
```rust
pub struct Hunter {
    config: HunterConfig,
    capture_manager: Arc<CaptureManager>,
    filter_manager: Arc<RwLock<FilterManager>>,
    connection_manager: Arc<ConnectionManager>,
    application_filter: Arc<RwLock<ApplicationFilter>>,
    dns_processor: Option<Arc<DnsProcessor>>,
    packet_processor: Option<Arc<dyn PacketProcessor>>,
    batch_queue: mpsc::Sender<PacketBatch>,
    stats: Arc<StatsCollector>,
    cancel_token: CancellationToken,
    task_tracker: JoinSet<Result<(), HunterError>>,
}
```

### 2.4 Ownership and Borrowing

**Key decisions:**

1. **Shared state across tasks:** Use `Arc<T>` or `Arc<RwLock<T>>`
2. **Mutable configuration:** Use `Arc<RwLock<Config>>` for hot-reload
3. **Packet buffers:** Use `bytes::Bytes` for zero-copy sharing
4. **Statistics:** Use `AtomicU64` for lock-free counters
5. **gRPC streams:** Use `tokio_stream::wrappers` for async iterators

### 2.5 Interface/Trait Translation

| Go Interface | Rust Trait |
|--------------|------------|
| `PacketProcessor` | `trait PacketProcessor: Send + Sync` |
| `ApplicationFilter` | `trait ApplicationFilter: Send + Sync` |
| `GPUBackend` | `trait GpuBackend: Send + Sync` |
| `Signature` | `trait ProtocolSignature: Send + Sync` |

---

## 3. Crate Selection and Dependencies

### 3.1 Core Dependencies

```toml
[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["rt"] }
tokio-stream = "0.1"

# gRPC
tonic = "0.12"
prost = "0.13"
prost-types = "0.13"

# CLI
clap = { version = "4", features = ["derive", "env"] }

# Configuration
figment = { version = "0.10", features = ["toml", "yaml", "env"] }
serde = { version = "1", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
thiserror = "2"
anyhow = "1"

# Networking / Packet capture
pcap = "2"  # libpcap bindings
etherparse = "0.15"  # Zero-copy packet parsing
pnet = "0.35"  # Alternative for raw sockets

# TLS
rustls = "0.23"
rustls-pemfile = "2"
tokio-rustls = "0.26"

# Async utilities
async-trait = "0.1"
futures = "0.3"
pin-project = "1"

# Synchronization
parking_lot = "0.12"
crossbeam = "0.8"

# Data structures
bytes = "1"
dashmap = "6"  # Concurrent hashmap
```

### 3.2 Pattern Matching Dependencies

```toml
# Aho-Corasick (native Rust, highly optimized)
aho-corasick = "1"

# Regex (for complex patterns)
regex = "1"

# IP address handling
ipnet = "2"

# Radix tree for CIDR matching
ip_network_table = "0.2"
# Alternative: cidr-utils = "0.6"

# Bloom filter
bloomfilter = "1"
```

### 3.3 SIMD and Performance

```toml
# SIMD intrinsics (stable Rust)
# Use std::arch directly for AVX2/SSE

# Or use portable SIMD (nightly or polyfill)
# wide = "0.7"  # Portable SIMD

# Memory-mapped I/O (for disk buffer)
memmap2 = "0.9"
```

### 3.4 GPU Acceleration (Optional)

```toml
[features]
cuda = ["dep:cust", "dep:cuda-sys"]

[dependencies]
# CUDA (conditional)
cust = { version = "0.3", optional = true }  # Safe CUDA bindings
cuda-sys = { version = "0.2", optional = true }

# OpenCL (alternative)
# opencl3 = { version = "0.9", optional = true }
```

### 3.5 Build Dependencies

```toml
[build-dependencies]
tonic-build = "0.12"
prost-build = "0.13"
```

---

## 4. Component Implementation Details

### 4.1 Packet Capture

**Go implementation uses:** `github.com/google/gopacket` with libpcap

**Rust implementation:**

```rust
use pcap::{Capture, Active, Device};
use tokio::sync::mpsc;
use bytes::Bytes;

pub struct PacketCapture {
    handles: Vec<Capture<Active>>,
    sender: mpsc::Sender<PacketInfo>,
}

pub struct PacketInfo {
    pub data: Bytes,
    pub timestamp: i64,
    pub caplen: u32,
    pub origlen: u32,
    pub interface: String,
    pub link_type: u32,
}

impl PacketCapture {
    pub async fn capture_loop(
        handle: Capture<Active>,
        sender: mpsc::Sender<PacketInfo>,
        cancel: CancellationToken,
    ) {
        // Use pcap's nonblock mode with tokio
        handle.setnonblock().unwrap();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = tokio::task::spawn_blocking({
                    let handle = handle.clone();
                    move || handle.next_packet()
                }) => {
                    match result {
                        Ok(Ok(packet)) => {
                            let info = PacketInfo {
                                data: Bytes::copy_from_slice(packet.data),
                                timestamp: packet.header.ts.tv_sec * 1_000_000_000
                                         + packet.header.ts.tv_usec as i64 * 1_000,
                                caplen: packet.header.caplen,
                                origlen: packet.header.len,
                                interface: "eth0".to_string(), // from config
                                link_type: handle.get_datalink().0 as u32,
                            };
                            let _ = sender.try_send(info);
                        }
                        Ok(Err(pcap::Error::TimeoutExpired)) => continue,
                        _ => break,
                    }
                }
            }
        }
    }
}
```

**Alternative: AF_XDP for maximum performance:**

```rust
// Using xsk-rs for AF_XDP
use xsk_rs::{Socket, Umem, RxQueue, TxQueue};

pub struct XdpCapture {
    socket: Socket,
    umem: Umem,
    rx_queue: RxQueue,
}
```

### 4.2 Protocol Detection

**Rust implementation:**

```rust
use etherparse::{SlicedPacket, TransportSlice};

pub trait ProtocolSignature: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> i32;
    fn detect(&self, ctx: &DetectionContext) -> Option<DetectionResult>;
}

pub struct SipSignature {
    methods: &'static [&'static [u8]],
}

impl SipSignature {
    const METHODS: &'static [&'static [u8]] = &[
        b"INVITE ", b"ACK ", b"BYE ", b"CANCEL ",
        b"REGISTER ", b"OPTIONS ", b"SIP/2.0 ",
    ];

    pub fn new() -> Self {
        Self { methods: Self::METHODS }
    }
}

impl ProtocolSignature for SipSignature {
    fn name(&self) -> &'static str { "SIP" }
    fn priority(&self) -> i32 { 150 }

    fn detect(&self, ctx: &DetectionContext) -> Option<DetectionResult> {
        let payload = ctx.payload;
        if payload.len() < 7 {
            return None;
        }

        for method in self.methods {
            if payload.starts_with(method) {
                return Some(DetectionResult {
                    protocol: "SIP".to_string(),
                    confidence: 0.95,
                    metadata: HashMap::new(),
                });
            }
        }
        None
    }
}
```

### 4.3 Aho-Corasick Pattern Matching

**Use the `aho-corasick` crate (highly optimized):**

```rust
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

pub struct PatternMatcher {
    ac: AhoCorasick,
    pattern_ids: Vec<String>,
}

impl PatternMatcher {
    pub fn new(patterns: &[(String, String)]) -> Self {
        let (ids, pats): (Vec<_>, Vec<_>) = patterns
            .iter()
            .map(|(id, pat)| (id.clone(), pat.as_bytes().to_vec()))
            .unzip();

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(&pats)
            .unwrap();

        Self { ac, pattern_ids: ids }
    }

    pub fn find_matches(&self, input: &[u8]) -> Vec<&str> {
        self.ac
            .find_overlapping_iter(input)
            .map(|m| self.pattern_ids[m.pattern().as_usize()].as_str())
            .collect()
    }
}
```

### 4.4 VoIP Call Buffering

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use bytes::Bytes;

pub struct CallBuffer {
    call_id: String,
    sip_packets: Vec<BufferedPacket>,
    rtp_packets: Vec<BufferedPacket>,
    rtp_ports: HashSet<String>,
    metadata: Option<CallMetadata>,
    created: Instant,
    matched: bool,
}

pub struct BufferManager {
    buffers: RwLock<HashMap<String, CallBuffer>>,
    max_age: Duration,
    max_size: usize,
}

impl BufferManager {
    pub fn new(max_age: Duration, max_size: usize) -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            max_age,
            max_size,
        }
    }

    pub fn add_sip_packet(&self, call_id: &str, packet: BufferedPacket) {
        let mut buffers = self.buffers.write();
        let buffer = buffers.entry(call_id.to_string())
            .or_insert_with(|| CallBuffer::new(call_id));

        if buffer.sip_packets.len() < self.max_size {
            buffer.sip_packets.push(packet);
        }
    }

    pub fn add_rtp_packet(&self, port: &str, packet: BufferedPacket) {
        let buffers = self.buffers.read();
        // Find call by RTP port
        for buffer in buffers.values() {
            if buffer.rtp_ports.contains(port) {
                // Need to upgrade to write lock
                drop(buffers);
                let mut buffers = self.buffers.write();
                if let Some(buf) = buffers.get_mut(&buffer.call_id) {
                    if buf.rtp_packets.len() < self.max_size {
                        buf.rtp_packets.push(packet);
                    }
                }
                return;
            }
        }
    }

    pub fn flush_matched(&self, call_id: &str) -> Option<Vec<BufferedPacket>> {
        let mut buffers = self.buffers.write();
        if let Some(mut buffer) = buffers.remove(call_id) {
            let mut all_packets = buffer.sip_packets;
            all_packets.append(&mut buffer.rtp_packets);
            // Sort by timestamp
            all_packets.sort_by_key(|p| p.timestamp);
            return Some(all_packets);
        }
        None
    }

    pub async fn cleanup_expired(&self) {
        let mut buffers = self.buffers.write();
        let now = Instant::now();
        buffers.retain(|_, buf| now.duration_since(buf.created) < self.max_age);
    }
}
```

### 4.5 SIP Parsing

```rust
pub struct SipParser;

impl SipParser {
    /// Extract username from SIP URI header
    /// "Alicent <sip:alicent@domain.com>" -> "alicent"
    /// "sip:+49123456789@domain.com" -> "+49123456789"
    pub fn extract_user(header: &str) -> Option<&str> {
        // Find sip: or sips: prefix
        let start = header.find("sip:")
            .or_else(|| header.find("sips:"))
            .map(|i| i + if header[i..].starts_with("sips:") { 5 } else { 4 })?;

        // Find @ to get end of user part
        let remaining = &header[start..];
        let end = remaining.find('@')?;

        Some(&remaining[..end])
    }

    /// Extract Call-ID from SIP message
    pub fn extract_call_id(message: &[u8]) -> Option<String> {
        let msg = std::str::from_utf8(message).ok()?;

        for line in msg.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("call-id:") || lower.starts_with("i:") {
                let value = line.split_once(':')?.1.trim();
                // Validate length (DoS protection)
                if value.len() > 1024 {
                    return None;
                }
                return Some(value.to_string());
            }
        }
        None
    }

    /// Extract RTP ports from SDP body
    pub fn extract_rtp_ports(sdp: &str) -> Vec<(String, u16)> {
        let mut results = Vec::new();
        let mut connection_ip = None;

        for line in sdp.lines() {
            if line.starts_with("c=IN IP4 ") {
                connection_ip = line.strip_prefix("c=IN IP4 ")
                    .and_then(|s| s.split_whitespace().next())
                    .map(|s| s.to_string());
            } else if line.starts_with("m=audio ") {
                if let Some(port_str) = line.strip_prefix("m=audio ")
                    .and_then(|s| s.split_whitespace().next())
                {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if let Some(ref ip) = connection_ip {
                            results.push((ip.clone(), port));
                        }
                    }
                }
            }
        }
        results
    }
}
```

### 4.6 RTP Detection

```rust
pub struct RtpDetector;

impl RtpDetector {
    /// Detect RTP packet using header heuristics
    pub fn detect(payload: &[u8], is_udp: bool) -> Option<RtpInfo> {
        // RTP requires at least 12 bytes header
        if payload.len() < 12 || !is_udp {
            return None;
        }

        // Version must be 2
        let version = (payload[0] >> 6) & 0x03;
        if version != 2 {
            return None;
        }

        // Extract fields
        let padding = (payload[0] >> 5) & 0x01;
        let extension = (payload[0] >> 4) & 0x01;
        let csrc_count = payload[0] & 0x0F;
        let marker = (payload[1] >> 7) & 0x01;
        let payload_type = payload[1] & 0x7F;
        let sequence = u16::from_be_bytes([payload[2], payload[3]]);
        let timestamp = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

        // Validate payload type (0-34 or 96-127)
        if payload_type > 34 && payload_type < 96 {
            return None;
        }

        // Validate CSRC count
        if csrc_count > 15 {
            return None;
        }

        // Validate header size
        let header_size = 12 + (csrc_count as usize * 4) + if extension == 1 { 4 } else { 0 };
        if payload.len() < header_size {
            return None;
        }

        // Reject pathological cases
        if ssrc == 0 || ssrc == 0xFFFFFFFF || timestamp == 0xFFFFFFFF {
            return None;
        }

        Some(RtpInfo {
            version,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            marker: marker == 1,
        })
    }
}

pub struct RtpInfo {
    pub version: u8,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub marker: bool,
}
```

---

## 5. Concurrency Model Translation

### 5.1 Hunter Task Structure

**Go goroutine hierarchy:**
```
Hunter.Start(ctx)
├─ System metrics collection (1)
├─ Connection manager (1)
│  ├─ connectAndRegister() → gRPC setup
│  ├─ Forwarding manager (1)
│  │  ├─ ForwardPackets() (1)
│  │  └─ batchSender() (1)
│  ├─ handleStreamControl() (1)
│  ├─ subscribeToFilters() (1)
│  └─ sendHeartbeats() (1)
├─ Packet capture (1 per interface)
├─ DNS processor janitor (optional, 1)
└─ Application filter janitor (optional, 1)
```

**Rust task hierarchy:**
```rust
impl Hunter {
    pub async fn start(&self) -> Result<(), HunterError> {
        let mut tasks = JoinSet::new();

        // System metrics
        tasks.spawn(self.collect_metrics(self.cancel.clone()));

        // Connection manager (spawns child tasks)
        tasks.spawn(self.connection_manager.run(self.cancel.clone()));

        // Packet capture (one per interface)
        for iface in &self.config.interfaces {
            tasks.spawn(self.capture_packets(
                iface.clone(),
                self.cancel.clone()
            ));
        }

        // Optional components
        if let Some(ref dns) = self.dns_processor {
            tasks.spawn(dns.janitor(self.cancel.clone()));
        }

        // Wait for cancellation or error
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                Some(result) = tasks.join_next() => {
                    if let Err(e) = result? {
                        tracing::error!("Task failed: {}", e);
                    }
                }
            }
        }

        // Graceful shutdown
        self.flush_batches().await?;
        tasks.shutdown().await;
        Ok(())
    }
}
```

### 5.2 Channel Usage

| Go Channel | Rust Equivalent | Bounded |
|------------|-----------------|---------|
| `chan PacketInfo` (10000) | `mpsc::channel(10000)` | Yes |
| `chan *PacketBatch` (1000) | `mpsc::channel(1000)` | Yes |
| `chan error` (1) | `oneshot::channel()` | N/A |
| `chan struct{}` (signal) | `tokio::sync::Notify` | N/A |

### 5.3 Synchronization Primitives

```rust
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

pub struct SynchronizationPrimitives {
    // Fast mutex (no async, just blocking)
    batch_lock: Mutex<Vec<CapturedPacket>>,

    // RwLock for read-heavy (filters)
    filters: RwLock<FilterSet>,

    // Atomic for statistics
    packets_captured: AtomicU64,
    packets_forwarded: AtomicU64,

    // Cancellation
    shutdown: CancellationToken,

    // State flags
    paused: AtomicBool,
    reconnecting: AtomicBool,
}
```

---

## 6. Performance Optimization Strategies

### 6.1 Zero-Copy Packet Handling

```rust
use bytes::{Bytes, BytesMut};

// Packet data is Bytes (reference counted, zero-copy clone)
pub struct PacketInfo {
    data: Bytes,  // Cheap to clone
    // ...
}

// For mutable packet assembly
pub struct BatchBuilder {
    buffer: BytesMut,  // Growable buffer
}

impl BatchBuilder {
    pub fn add_packet(&mut self, packet: &PacketInfo) {
        // Protobuf encoding directly into buffer
        prost::Message::encode(&packet.to_proto(), &mut self.buffer).unwrap();
    }

    pub fn finish(self) -> Bytes {
        self.buffer.freeze()  // Zero-copy conversion to Bytes
    }
}
```

### 6.2 SIMD Acceleration

```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub struct SimdMatcher;

impl SimdMatcher {
    /// AVX2 accelerated byte search
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn contains_avx2(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return needle.is_empty();
        }

        let first = _mm256_set1_epi8(needle[0] as i8);
        let chunks = haystack.chunks_exact(32);

        for chunk in chunks {
            let data = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let cmp = _mm256_cmpeq_epi8(data, first);
            let mask = _mm256_movemask_epi8(cmp) as u32;

            if mask != 0 {
                // Found potential match, verify full needle
                for bit in 0..32 {
                    if mask & (1 << bit) != 0 {
                        let start = chunk.as_ptr().offset_from(haystack.as_ptr()) as usize + bit;
                        if start + needle.len() <= haystack.len()
                            && &haystack[start..start + needle.len()] == needle {
                            return true;
                        }
                    }
                }
            }
        }

        // Handle remainder
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Portable fallback
    pub fn contains_scalar(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Runtime dispatch
    pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") && needle.len() >= 8 {
            return unsafe { Self::contains_avx2(haystack, needle) };
        }
        Self::contains_scalar(haystack, needle)
    }
}
```

### 6.3 Lock-Free Statistics

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Stats {
    packets_captured: AtomicU64,
    packets_matched: AtomicU64,
    packets_forwarded: AtomicU64,
    packets_dropped: AtomicU64,
    bytes_captured: AtomicU64,
}

impl Stats {
    pub fn increment_captured(&self, bytes: u64) {
        self.packets_captured.fetch_add(1, Ordering::Relaxed);
        self.bytes_captured.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        // Use Acquire for consistent reads
        StatsSnapshot {
            packets_captured: self.packets_captured.load(Ordering::Acquire),
            packets_matched: self.packets_matched.load(Ordering::Acquire),
            packets_forwarded: self.packets_forwarded.load(Ordering::Acquire),
            packets_dropped: self.packets_dropped.load(Ordering::Acquire),
            bytes_captured: self.bytes_captured.load(Ordering::Acquire),
        }
    }
}
```

### 6.4 Memory Pool

```rust
use crossbeam::queue::ArrayQueue;
use bytes::BytesMut;

pub struct PacketPool {
    pool: ArrayQueue<BytesMut>,
    packet_size: usize,
}

impl PacketPool {
    pub fn new(capacity: usize, packet_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        // Pre-allocate
        for _ in 0..capacity {
            let _ = pool.push(BytesMut::with_capacity(packet_size));
        }
        Self { pool, packet_size }
    }

    pub fn get(&self) -> BytesMut {
        self.pool.pop().unwrap_or_else(|| BytesMut::with_capacity(self.packet_size))
    }

    pub fn put(&self, mut buf: BytesMut) {
        buf.clear();
        let _ = self.pool.push(buf);  // Ignore if full
    }
}
```

### 6.5 Batch Processing

```rust
pub struct BatchProcessor {
    batch: Vec<CapturedPacket>,
    batch_size: usize,
    timeout: Duration,
    last_send: Instant,
}

impl BatchProcessor {
    pub async fn process(
        &mut self,
        receiver: &mut mpsc::Receiver<PacketInfo>,
        sender: &mpsc::Sender<PacketBatch>,
        cancel: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(self.timeout);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,

                Some(packet) = receiver.recv() => {
                    self.batch.push(packet.into());
                    if self.batch.len() >= self.batch_size {
                        self.flush(sender).await;
                    }
                }

                _ = interval.tick() => {
                    if !self.batch.is_empty() {
                        self.flush(sender).await;
                    }
                }
            }
        }
    }

    async fn flush(&mut self, sender: &mpsc::Sender<PacketBatch>) {
        let batch = PacketBatch {
            packets: std::mem::take(&mut self.batch),
            sequence: self.next_sequence(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            ..Default::default()
        };
        let _ = sender.send(batch).await;
        self.last_send = Instant::now();
    }
}
```

---

## 7. gRPC Protocol Implementation

### 7.1 Proto Compilation

**build.rs:**
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)  // Hunter is client only
        .build_client(true)
        .out_dir("src/proto")
        .compile(
            &["proto/data.proto", "proto/management.proto"],
            &["proto"],
        )?;
    Ok(())
}
```

### 7.2 Client Implementation

```rust
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use proto::data::{data_service_client::DataServiceClient, PacketBatch, StreamControl};
use proto::management::{
    management_service_client::ManagementServiceClient,
    HunterRegistration, FilterRequest, FilterUpdate,
};

pub struct GrpcClient {
    data_client: DataServiceClient<Channel>,
    mgmt_client: ManagementServiceClient<Channel>,
}

impl GrpcClient {
    pub async fn connect(config: &TlsConfig) -> Result<Self, GrpcError> {
        let tls = if config.enabled {
            let ca_cert = std::fs::read(&config.ca_file)?;
            let ca = Certificate::from_pem(ca_cert);

            let mut tls_config = ClientTlsConfig::new().ca_certificate(ca);

            // mTLS if client cert provided
            if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
                let cert = std::fs::read(cert_file)?;
                let key = std::fs::read(key_file)?;
                let identity = Identity::from_pem(cert, key);
                tls_config = tls_config.identity(identity);
            }

            Some(tls_config)
        } else {
            None
        };

        let endpoint = Channel::from_shared(format!("https://{}", config.address))?;
        let endpoint = if let Some(tls) = tls {
            endpoint.tls_config(tls)?
        } else {
            Channel::from_shared(format!("http://{}", config.address))?
        };

        let channel = endpoint
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .connect()
            .await?;

        Ok(Self {
            data_client: DataServiceClient::new(channel.clone()),
            mgmt_client: ManagementServiceClient::new(channel),
        })
    }

    pub async fn stream_packets(
        &mut self,
        receiver: mpsc::Receiver<PacketBatch>,
    ) -> Result<impl Stream<Item = StreamControl>, GrpcError> {
        let request_stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let response = self.data_client.stream_packets(request_stream).await?;
        Ok(response.into_inner())
    }

    pub async fn subscribe_filters(
        &mut self,
        hunter_id: &str,
    ) -> Result<impl Stream<Item = FilterUpdate>, GrpcError> {
        let request = FilterRequest {
            hunter_id: hunter_id.to_string(),
            filter_types: vec![], // All types
        };
        let response = self.mgmt_client.subscribe_filters(request).await?;
        Ok(response.into_inner())
    }
}
```

### 7.3 Bidirectional Streaming

```rust
impl ConnectionManager {
    pub async fn run_streams(
        &self,
        mut client: GrpcClient,
        cancel: CancellationToken,
    ) -> Result<(), ConnectionError> {
        // Start packet streaming
        let (batch_tx, batch_rx) = mpsc::channel(1000);
        let control_stream = client.stream_packets(batch_rx).await?;

        // Start filter subscription
        let filter_stream = client.subscribe_filters(&self.hunter_id).await?;

        // Spawn handlers
        let mut tasks = JoinSet::new();

        // Batch sender
        tasks.spawn({
            let cancel = cancel.clone();
            let tx = batch_tx.clone();
            async move {
                self.forward_packets(tx, cancel).await
            }
        });

        // Control receiver
        tasks.spawn({
            let cancel = cancel.clone();
            async move {
                self.handle_control(control_stream, cancel).await
            }
        });

        // Filter receiver
        tasks.spawn({
            let cancel = cancel.clone();
            async move {
                self.handle_filters(filter_stream, cancel).await
            }
        });

        // Heartbeat sender
        tasks.spawn({
            let cancel = cancel.clone();
            let mut client = client.clone();
            async move {
                self.send_heartbeats(&mut client, cancel).await
            }
        });

        // Wait for any task to complete (usually due to error or cancellation)
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result? {
                return Err(e);
            }
        }

        Ok(())
    }
}
```

---

## 8. Resilience Patterns in Rust

### 8.1 Circuit Breaker

```rust
use std::sync::atomic::{AtomicU32, AtomicI32, AtomicI64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

pub struct CircuitBreaker {
    state: AtomicI32,
    consecutive_failures: AtomicU32,
    last_failure_time: AtomicI64,
    half_open_calls: AtomicU32,

    max_failures: u32,
    reset_timeout: Duration,
    half_open_max_calls: u32,

    // Metrics
    total_attempts: AtomicU64,
    total_successes: AtomicU64,
    total_failures: AtomicU64,
    total_rejections: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(max_failures: u32, reset_timeout: Duration, half_open_max_calls: u32) -> Self {
        Self {
            state: AtomicI32::new(CircuitState::Closed as i32),
            consecutive_failures: AtomicU32::new(0),
            last_failure_time: AtomicI64::new(0),
            half_open_calls: AtomicU32::new(0),
            max_failures,
            reset_timeout,
            half_open_max_calls,
            total_attempts: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            total_rejections: AtomicU64::new(0),
        }
    }

    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: Future<Output = Result<T, E>>,
    {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);

        let state = self.get_state();

        match state {
            CircuitState::Open => {
                let last_fail = self.last_failure_time.load(Ordering::Acquire);
                let elapsed = Duration::from_nanos((Instant::now().elapsed().as_nanos() - last_fail as u128) as u64);

                if elapsed >= self.reset_timeout {
                    self.transition_to_half_open();
                } else {
                    self.total_rejections.fetch_add(1, Ordering::Relaxed);
                    return Err(CircuitBreakerError::Open);
                }
            }
            CircuitState::HalfOpen => {
                let calls = self.half_open_calls.fetch_add(1, Ordering::AcqRel);
                if calls >= self.half_open_max_calls {
                    self.total_rejections.fetch_add(1, Ordering::Relaxed);
                    return Err(CircuitBreakerError::Open);
                }
            }
            CircuitState::Closed => {}
        }

        match f.await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }

    fn record_success(&self) {
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Release);

        if self.get_state() == CircuitState::HalfOpen {
            self.state.store(CircuitState::Closed as i32, Ordering::Release);
            self.half_open_calls.store(0, Ordering::Release);
            tracing::info!("Circuit breaker closed - service recovered");
        }
    }

    fn record_failure(&self) {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        self.last_failure_time.store(
            Instant::now().elapsed().as_nanos() as i64,
            Ordering::Release,
        );

        if failures >= self.max_failures && self.get_state() == CircuitState::Closed {
            self.state.store(CircuitState::Open as i32, Ordering::Release);
            tracing::warn!(
                failures = failures,
                threshold = self.max_failures,
                "Circuit breaker opened"
            );
        } else if self.get_state() == CircuitState::HalfOpen {
            self.state.store(CircuitState::Open as i32, Ordering::Release);
            self.half_open_calls.store(0, Ordering::Release);
        }
    }

    fn get_state(&self) -> CircuitState {
        match self.state.load(Ordering::Acquire) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    fn transition_to_half_open(&self) {
        self.state.store(CircuitState::HalfOpen as i32, Ordering::Release);
        self.half_open_calls.store(0, Ordering::Release);
        tracing::info!("Circuit breaker half-open - testing recovery");
    }
}
```

### 8.2 Disk Overflow Buffer

```rust
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use parking_lot::Mutex;
use prost::Message;

pub struct DiskOverflowBuffer {
    dir: PathBuf,
    max_bytes: u64,
    current_size: AtomicU64,
    write_sequence: AtomicU64,
    read_sequence: AtomicU64,
    lock: Mutex<()>,
}

impl DiskOverflowBuffer {
    pub fn new(dir: PathBuf, max_bytes: u64) -> Result<Self, DiskBufferError> {
        fs::create_dir_all(&dir)?;

        // Cleanup old files from previous run
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("batch-") {
                fs::remove_file(entry.path())?;
            }
        }

        Ok(Self {
            dir,
            max_bytes,
            current_size: AtomicU64::new(0),
            write_sequence: AtomicU64::new(0),
            read_sequence: AtomicU64::new(0),
            lock: Mutex::new(()),
        })
    }

    pub fn write(&self, batch: &PacketBatch) -> Result<bool, DiskBufferError> {
        let _guard = self.lock.lock();

        // Serialize
        let mut buf = Vec::new();
        batch.encode(&mut buf)?;
        let needed = buf.len() as u64 + 4; // + length prefix

        // Check capacity
        let current = self.current_size.load(Ordering::Acquire);
        if current + needed > self.max_bytes {
            return Ok(false); // Disk full
        }

        // Write file
        let seq = self.write_sequence.fetch_add(1, Ordering::AcqRel);
        let path = self.dir.join(format!("batch-{:010}.pb", seq));

        let mut file = File::create(&path)?;
        file.write_all(&(buf.len() as u32).to_be_bytes())?;
        file.write_all(&buf)?;
        file.sync_all()?;

        self.current_size.fetch_add(needed, Ordering::Release);
        Ok(true)
    }

    pub fn read(&self) -> Result<Option<PacketBatch>, DiskBufferError> {
        let _guard = self.lock.lock();

        // Find oldest file
        let seq = self.read_sequence.load(Ordering::Acquire);
        let path = self.dir.join(format!("batch-{:010}.pb", seq));

        if !path.exists() {
            return Ok(None);
        }

        // Read file
        let mut file = File::open(&path)?;
        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Sanity check
        if len > 10_000_000 {
            fs::remove_file(&path)?;
            return Err(DiskBufferError::CorruptedFile);
        }

        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;

        let batch = PacketBatch::decode(&*buf)?;

        // Cleanup
        fs::remove_file(&path)?;
        self.read_sequence.fetch_add(1, Ordering::Release);
        self.current_size.fetch_sub(len as u64 + 4, Ordering::Release);

        Ok(Some(batch))
    }

    pub fn is_empty(&self) -> bool {
        self.read_sequence.load(Ordering::Acquire) >= self.write_sequence.load(Ordering::Acquire)
    }
}
```

### 8.3 Exponential Backoff

```rust
use std::time::Duration;
use rand::Rng;

pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    attempt: u32,
    jitter: bool,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, max: Duration, jitter: bool) -> Self {
        Self { base, max, attempt: 0, jitter }
    }

    pub fn next_delay(&mut self) -> Duration {
        let exp = 2u64.saturating_pow(self.attempt.min(6));
        let delay = self.base.saturating_mul(exp as u32);
        let delay = delay.min(self.max);

        self.attempt = self.attempt.saturating_add(1);

        if self.jitter {
            let jitter = rand::thread_rng().gen_range(0..=delay.as_millis() / 4) as u64;
            delay + Duration::from_millis(jitter)
        } else {
            delay
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}
```

---

## 9. Testing Strategy

### 9.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sip_user_extraction() {
        assert_eq!(
            SipParser::extract_user("Alicent <sip:alicent@domain.com>"),
            Some("alicent")
        );
        assert_eq!(
            SipParser::extract_user("sip:+49123456789@domain.com"),
            Some("+49123456789")
        );
        assert_eq!(
            SipParser::extract_user("invalid"),
            None
        );
    }

    #[test]
    fn test_rtp_detection() {
        // Valid RTP packet (version 2, PT 0, etc.)
        let valid_rtp = [
            0x80, 0x00, // V=2, P=0, X=0, CC=0, M=0, PT=0
            0x00, 0x01, // Sequence number
            0x00, 0x00, 0x00, 0x10, // Timestamp
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00, // Payload
        ];
        assert!(RtpDetector::detect(&valid_rtp, true).is_some());

        // Invalid version
        let invalid = [0x00; 16];
        assert!(RtpDetector::detect(&invalid, true).is_none());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(100), 2);

        // 3 failures should open circuit
        for _ in 0..3 {
            let _ = cb.call(async { Err::<(), _>("error") }).await;
        }

        // Next call should be rejected
        let result = cb.call(async { Ok::<_, &str>(()) }).await;
        assert!(matches!(result, Err(CircuitBreakerError::Open)));

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be half-open now, success should close
        let result = cb.call(async { Ok::<_, &str>(()) }).await;
        assert!(result.is_ok());
    }
}
```

### 9.2 Integration Tests

```rust
#[tokio::test]
async fn test_hunter_processor_integration() {
    // Start mock processor
    let mock_processor = MockProcessor::start(50051).await;

    // Create hunter
    let config = HunterConfig {
        processor_addr: "127.0.0.1:50051".to_string(),
        hunter_id: "test-hunter".to_string(),
        interfaces: vec!["lo".to_string()],
        ..Default::default()
    };

    let hunter = Hunter::new(config).await.unwrap();

    // Start hunter
    let handle = tokio::spawn(async move {
        hunter.start().await
    });

    // Wait for registration
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify hunter registered
    assert!(mock_processor.has_hunter("test-hunter").await);

    // Send some packets via loopback
    // Verify they arrive at processor

    // Shutdown
    hunter.cancel();
    handle.await.unwrap().unwrap();
}
```

### 9.3 Benchmark Tests

```rust
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn benchmark_sip_detection(c: &mut Criterion) {
    let detector = SipSignature::new();
    let sip_packet = b"INVITE sip:alice@example.com SIP/2.0\r\n...";

    let mut group = c.benchmark_group("sip_detection");
    group.throughput(Throughput::Elements(1));

    group.bench_function("detect", |b| {
        b.iter(|| {
            let ctx = DetectionContext::new(sip_packet);
            detector.detect(&ctx)
        })
    });

    group.finish();
}

fn benchmark_aho_corasick(c: &mut Criterion) {
    let patterns: Vec<_> = (0..1000)
        .map(|i| (format!("id{}", i), format!("user{}", i)))
        .collect();
    let matcher = PatternMatcher::new(&patterns);
    let input = b"This message is from user500@domain.com to user750@domain.com";

    let mut group = c.benchmark_group("aho_corasick");
    group.throughput(Throughput::Bytes(input.len() as u64));

    group.bench_function("match_1000_patterns", |b| {
        b.iter(|| matcher.find_matches(input))
    });

    group.finish();
}

criterion_group!(benches, benchmark_sip_detection, benchmark_aho_corasick);
criterion_main!(benches);
```

---

## 10. Protocol-Specific Hunter Implementations

Beyond the base hunter and VoIP mode, lippycat supports four additional protocol-specific hunters that must be implemented in Rust for full feature parity.

### 10.1 DNS Hunter (`lc hunt dns`)

**Purpose:** Edge DNS capture with tunneling detection.

**Key Features:**
- DNS packet parsing (questions, answers, authority, additional)
- Query/response correlation by transaction ID
- DNS tunneling detection via entropy analysis
- Domain pattern filtering (glob-style)
- BPF filter optimization for DNS ports

**Supported Filter Types:** `bpf`, `ip_address`, `dns_domain`

**Tunneling Detection Algorithm:**
```rust
pub struct TunnelingDetector {
    entropy_threshold: f64,     // Default: 3.5 bits
    max_unique_subdomains: u32, // Default: 100
    domain_stats: HashMap<String, DomainStats>,
}

pub struct DomainStats {
    query_count: u64,
    unique_subdomains: HashSet<String>,
    high_entropy_queries: u64,
    txt_queries: u64,
    avg_query_length: f64,
}

impl TunnelingDetector {
    /// Calculate tunneling probability (0.0 - 1.0)
    pub fn calculate_score(&self, domain: &str) -> f64 {
        let stats = self.domain_stats.get(domain)?;

        let entropy_factor = self.calculate_entropy_factor(stats);      // 0-0.3
        let subdomain_factor = self.calculate_subdomain_factor(stats);  // 0-0.25
        let entropy_ratio = self.calculate_entropy_ratio(stats);        // 0-0.2
        let suspicious_ratio = self.calculate_suspicious_ratio(stats);  // 0-0.15
        let length_factor = self.calculate_length_factor(stats);        // 0-0.1

        (entropy_factor + subdomain_factor + entropy_ratio +
         suspicious_ratio + length_factor).min(1.0)
    }

    /// Shannon entropy calculation
    fn calculate_entropy(&self, subdomain: &str) -> f64 {
        let mut freq = HashMap::new();
        for c in subdomain.to_lowercase().chars().filter(|&c| c != '.') {
            *freq.entry(c).or_insert(0) += 1;
        }
        let len = subdomain.len() as f64;
        -freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                p * p.log2()
            })
            .sum::<f64>()
    }
}
```

**Rust Implementation Notes:**
- Use `trust-dns-proto` or custom DNS parsing for efficiency
- Entropy calculation with SIMD for batch processing
- Concurrent `DashMap` for domain stats tracking

### 10.2 HTTP Hunter (`lc hunt http`)

**Purpose:** HTTP request/response capture with content filtering.

**Key Features:**
- TCP reassembly for HTTP streams
- Request/response correlation
- Host, path, method, status filtering (glob patterns)
- Keyword matching (Aho-Corasick) in body/URL
- Body capture with configurable max size
- TLS decryption via SSLKEYLOGFILE

**Supported Filter Types:** `bpf`, `ip_address`, `http_host`, `http_path`

**Content Filter Logic:**
```rust
pub struct HttpContentFilter {
    host_patterns: Vec<GlobPattern>,
    path_patterns: Vec<GlobPattern>,
    methods: HashSet<String>,           // Uppercase (GET, POST, etc.)
    status_codes: Vec<StatusCodeFilter>, // Exact, range, or wildcard (4xx)
    keywords: Option<AhoCorasick>,       // For body/URL keyword matching
}

pub enum StatusCodeFilter {
    Exact(u16),
    Range { start: u16, end: u16 },
}

impl HttpContentFilter {
    /// AND between groups, OR within groups
    pub fn matches(&self, metadata: &HttpMetadata) -> bool {
        if !self.has_filters() {
            return true; // No filters = pass all
        }

        // Each configured filter group must match
        if !self.host_patterns.is_empty()
            && !self.match_any_glob(&self.host_patterns, &metadata.host) {
            return false;
        }
        if !self.path_patterns.is_empty()
            && !self.match_any_glob(&self.path_patterns, &metadata.path) {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.contains(&metadata.method) {
            return false;
        }
        if !self.status_codes.is_empty() && metadata.status_code > 0 {
            if !self.match_status_code(metadata.status_code) {
                return false;
            }
        }
        if let Some(ref ac) = self.keywords {
            let search_text = format!("{} {} {}",
                metadata.path, metadata.query_string, metadata.body_preview);
            if ac.find(&search_text.to_lowercase()).is_none() {
                return false;
            }
        }
        true
    }
}
```

**TCP Reassembly:**
```rust
// Use smoltcp or custom reassembly
pub struct HttpStreamHandler {
    buffer: BytesMut,
    state: HttpParseState,
    metadata: HttpMetadata,
    body_buffer: Vec<u8>,
    max_body_size: usize,
}

pub enum HttpParseState {
    AwaitingRequestLine,
    ReadingHeaders,
    ReadingBody { remaining: usize },
    ReadingChunked,
    Complete,
}
```

**Rust Implementation Notes:**
- `httparse` crate for zero-copy HTTP parsing
- Custom TCP reassembly or integration with `smoltcp`
- Chunked encoding support for body capture

### 10.3 TLS Hunter (`lc hunt tls`)

**Purpose:** TLS handshake capture with fingerprinting.

**Key Features:**
- ClientHello/ServerHello parsing
- SNI extraction for domain identification
- JA3 fingerprinting (MD5 of ClientHello fields)
- JA3S fingerprinting (MD5 of ServerHello fields)
- JA4 fingerprinting (modern format with sorted hashes)
- Connection tracking (correlate ClientHello + ServerHello)

**Supported Filter Types:** `bpf`, `ip_address`, `tls_sni`, `tls_ja3`, `tls_ja3s`, `tls_ja4`

**JA3 Fingerprinting Algorithm:**
```rust
pub struct Ja3Calculator;

impl Ja3Calculator {
    /// JA3 = MD5(version,ciphers,extensions,groups,formats)
    pub fn calculate_ja3(ch: &ClientHello) -> (String, String) {
        let version = ch.version_raw.to_string();

        let ciphers = ch.cipher_suites.iter()
            .filter(|&&c| !Self::is_grease(c))
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions = ch.extensions.iter()
            .filter(|&&e| !Self::is_grease(e))
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let groups = ch.supported_groups.iter()
            .filter(|&&g| !Self::is_grease(g))
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let formats = ch.ec_point_formats.iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3_string = format!("{},{},{},{},{}",
            version, ciphers, extensions, groups, formats);
        let ja3_hash = format!("{:x}", md5::compute(&ja3_string));

        (ja3_string, ja3_hash)
    }

    /// JA4 = t<ver><sni><count><count><alpn>_<cipher_hash>_<ext_hash>
    pub fn calculate_ja4(ch: &ClientHello) -> String {
        let version_code = match ch.version_raw {
            0x0300 => "s3",
            0x0301 => "10",
            0x0302 => "11",
            0x0303 => "12",
            0x0304 => "13",
            _ => "00",
        };

        let sni_indicator = if ch.sni.is_some() { "d" } else { "i" };

        let cipher_count = ch.cipher_suites.iter()
            .filter(|&&c| !Self::is_grease(c))
            .count()
            .min(99);

        let ext_count = ch.extensions.iter()
            .filter(|&&e| !Self::is_grease(e))
            .count()
            .min(99);

        let alpn = ch.alpn_protocols.first()
            .map(|s| &s[..2.min(s.len())])
            .unwrap_or("00");

        let ja4_a = format!("t{}{}{:02}{:02}{}",
            version_code, sni_indicator, cipher_count, ext_count, alpn);

        // Sorted cipher hash (12 hex chars)
        let mut sorted_ciphers: Vec<_> = ch.cipher_suites.iter()
            .filter(|&&c| !Self::is_grease(c))
            .collect();
        sorted_ciphers.sort();
        let cipher_str = sorted_ciphers.iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let cipher_hash = &format!("{:x}", md5::compute(&cipher_str))[..12];

        // Sorted extensions hash (excluding SNI, ALPN)
        let mut sorted_exts: Vec<_> = ch.extensions.iter()
            .filter(|&&e| !Self::is_grease(e) && e != 0 && e != 16)
            .collect();
        sorted_exts.sort();
        let ext_str = sorted_exts.iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let ext_hash = &format!("{:x}", md5::compute(&ext_str))[..12];

        format!("{}_{}_{}",ja4_a, cipher_hash, ext_hash)
    }

    /// GREASE values are filtered from fingerprints
    fn is_grease(value: u16) -> bool {
        matches!(value,
            0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a |
            0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a |
            0x8a8a | 0x9a9a | 0xaaaa | 0xbaba |
            0xcaca | 0xdada | 0xeaea | 0xfafa)
    }
}
```

**TLS Parsing:**
```rust
pub struct TlsParser;

impl TlsParser {
    pub fn parse_record(data: &[u8]) -> Option<TlsRecord> {
        if data.len() < 5 {
            return None;
        }

        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return None;
        }

        let payload = &data[5..5 + length];

        match content_type {
            22 => Self::parse_handshake(payload, version),
            _ => None,
        }
    }

    fn parse_client_hello(payload: &[u8]) -> Option<ClientHello> {
        // Skip: handshake type (1) + length (3)
        let mut pos = 4;

        // Version (2 bytes)
        let version = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        let session_id_len = payload[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites
        let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let cipher_suites = payload[pos..pos + cipher_len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        pos += cipher_len;

        // Compression methods
        let comp_len = payload[pos] as usize;
        pos += 1 + comp_len;

        // Extensions
        let (extensions, sni, alpn, groups, formats) =
            Self::parse_extensions(&payload[pos..])?;

        Some(ClientHello {
            version_raw: version,
            cipher_suites,
            extensions,
            sni,
            alpn_protocols: alpn,
            supported_groups: groups,
            ec_point_formats: formats,
        })
    }
}
```

**Rust Implementation Notes:**
- Use `rustls` types for parsing or custom implementation
- Connection tracking with `DashMap<FlowKey, ConnectionRecord>`
- 30-second timeout for stale connections

### 10.4 Email Hunter (`lc hunt email`)

**Purpose:** Email protocol capture (SMTP/IMAP/POP3) with content filtering.

**Key Features:**
- TCP reassembly for email streams
- SMTP envelope extraction (MAIL FROM, RCPT TO)
- IMAP command/response parsing (SELECT, FETCH, SEARCH)
- POP3 command parsing (RETR, LIST, DELE)
- Sender/recipient filtering (glob patterns)
- Subject and keyword filtering (Aho-Corasick)
- Session tracking per protocol

**Supported Filter Types:** `bpf`, `ip_address`, `email_address`, `email_subject`

**SMTP State Machine:**
```rust
pub enum SmtpState {
    Initial,
    Connected,
    HeloReceived { hostname: String },
    MailFromReceived { sender: String },
    RcptToReceived { recipients: Vec<String> },
    DataMode,
    DataComplete,
}

pub struct SmtpSession {
    state: SmtpState,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    subject: Option<String>,
    message_id: Option<String>,
    body_preview: String,
    starttls_offered: bool,
    starttls_requested: bool,
}

impl SmtpSession {
    pub fn process_line(&mut self, line: &str, is_server: bool) -> Option<SmtpEvent> {
        if is_server {
            self.process_server_response(line)
        } else {
            self.process_client_command(line)
        }
    }

    fn process_client_command(&mut self, line: &str) -> Option<SmtpEvent> {
        let upper = line.to_uppercase();

        if upper.starts_with("HELO ") || upper.starts_with("EHLO ") {
            let hostname = line[5..].trim().to_string();
            self.state = SmtpState::HeloReceived { hostname };
            return Some(SmtpEvent::Helo);
        }

        if upper.starts_with("MAIL FROM:") {
            let sender = Self::extract_email(&line[10..]);
            self.mail_from = sender.clone();
            self.state = SmtpState::MailFromReceived { sender: sender? };
            return Some(SmtpEvent::MailFrom);
        }

        if upper.starts_with("RCPT TO:") {
            if let Some(recipient) = Self::extract_email(&line[8..]) {
                self.rcpt_to.push(recipient);
                return Some(SmtpEvent::RcptTo);
            }
        }

        if upper == "DATA" {
            self.state = SmtpState::DataMode;
            return Some(SmtpEvent::DataStart);
        }

        if upper == "STARTTLS" {
            self.starttls_requested = true;
            return Some(SmtpEvent::StartTls);
        }

        if upper == "RSET" {
            self.reset();
            return Some(SmtpEvent::Reset);
        }

        None
    }

    fn extract_email(s: &str) -> Option<String> {
        // Extract from <email@domain.com> or bare address
        let s = s.trim();
        if let Some(start) = s.find('<') {
            if let Some(end) = s.find('>') {
                return Some(s[start + 1..end].to_string());
            }
        }
        // Bare address
        let addr = s.split_whitespace().next()?;
        if addr.contains('@') {
            Some(addr.to_string())
        } else {
            None
        }
    }
}
```

**Email Content Filter:**
```rust
pub struct EmailContentFilter {
    sender_patterns: Vec<GlobPattern>,
    recipient_patterns: Vec<GlobPattern>,
    subject_patterns: Vec<GlobPattern>,
    keywords: Option<AhoCorasick>,
    mailbox_patterns: Vec<GlobPattern>,  // IMAP
    command_patterns: Vec<GlobPattern>,  // IMAP/POP3
}

impl EmailContentFilter {
    /// AND between groups, OR within groups
    pub fn matches(&self, metadata: &EmailMetadata) -> bool {
        if !self.has_filters() {
            return true;
        }

        if !self.sender_patterns.is_empty() {
            if !self.match_any_glob(&self.sender_patterns, &metadata.mail_from) {
                return false;
            }
        }

        if !self.recipient_patterns.is_empty() {
            let any_match = metadata.rcpt_to.iter()
                .any(|r| self.match_any_glob(&self.recipient_patterns, r));
            if !any_match {
                return false;
            }
        }

        if !self.subject_patterns.is_empty() {
            if !self.match_any_glob(&self.subject_patterns, &metadata.subject) {
                return false;
            }
        }

        if let Some(ref ac) = self.keywords {
            let search = format!("{} {}", metadata.subject, metadata.body_preview);
            if ac.find(&search.to_lowercase()).is_none() {
                return false;
            }
        }

        if !self.mailbox_patterns.is_empty() && metadata.imap_mailbox.is_some() {
            if !self.match_any_glob(&self.mailbox_patterns,
                    metadata.imap_mailbox.as_ref().unwrap()) {
                return false;
            }
        }

        true
    }
}
```

**Rust Implementation Notes:**
- Separate TCP factories for SMTP, IMAP, POP3 (port-based routing)
- Session buffers with timeouts (5 minutes default)
- IMAP requires tagged command/response correlation
- POP3 requires multiline response detection (`.` terminator)

### 10.5 Protocol Hunter Summary

| Hunter Mode | Primary Use Case | Key Algorithms | Estimated Lines |
|-------------|------------------|----------------|-----------------|
| `hunt voip` | VoIP/SIP/RTP | Call buffering, SIP parsing, RTP correlation | ~4,000 |
| `hunt dns` | DNS monitoring | Query tracking, Shannon entropy, tunneling detection | ~1,800 |
| `hunt http` | Web traffic | TCP reassembly, HTTP parsing, content filtering | ~2,500 |
| `hunt tls` | TLS monitoring | JA3/JA3S/JA4 fingerprinting, SNI extraction | ~1,700 |
| `hunt email` | Email capture | SMTP/IMAP/POP3 parsing, session tracking | ~3,500 |

**Total for all protocols:** ~13,500 lines (in addition to core hunter)

### 10.6 Shared Protocol Infrastructure

All protocol hunters share these components:

```rust
// Shared TCP reassembly framework
pub trait TcpStreamFactory: Send + Sync {
    fn new_stream(
        &self,
        net_flow: Flow,
        transport_flow: Flow,
        direction: Direction,
    ) -> Box<dyn TcpStream>;
}

pub trait TcpStream: Send {
    fn reassembled(&mut self, data: &[u8], timestamp: i64);
    fn reassembly_complete(&mut self);
}

// Shared content filter interface
pub trait ContentFilter: Send + Sync {
    fn matches(&self, metadata: &dyn Any) -> bool;
    fn has_filters(&self) -> bool;
}

// Shared session tracker interface
pub trait SessionTracker: Send + Sync {
    fn update(&self, session_id: &str, metadata: &dyn Any);
    fn correlate(&self, session_id: &str, response: &dyn Any) -> bool;
    fn cleanup_expired(&self);
}

// Shared packet buffer (per-session TCP packet accumulation)
pub struct SessionPacketBuffer {
    sessions: DashMap<String, Vec<BufferedPacket>>,
    max_age: Duration,
    max_packets: usize,
}
```

---

## 11. Implementation Phases (Updated)

### Phase 1: Core Foundation (4-5 weeks)

**Deliverables:**
- [ ] Project scaffold with Cargo workspace
- [ ] CLI argument parsing with clap
- [ ] Configuration system with figment
- [ ] Logging with tracing
- [ ] Basic packet capture (single interface)
- [ ] gRPC client (DataService.StreamPackets)
- [ ] Basic batching and forwarding
- [ ] Unit tests for core components

**Milestone:** Hunter can connect to processor and stream raw packets

### Phase 2: Protocol Detection (3-4 weeks)

**Deliverables:**
- [ ] Protocol signature framework
- [ ] SIP detection (SIMD-accelerated)
- [ ] RTP detection
- [ ] DNS, TLS, HTTP signatures
- [ ] Detection caching
- [ ] Integration with packet pipeline

**Milestone:** Hunter identifies VoIP traffic and adds metadata

### Phase 3: VoIP Call Handling (3-4 weeks)

**Deliverables:**
- [ ] Call buffer manager
- [ ] SIP parsing (Call-ID, From, To, SDP)
- [ ] RTP port correlation
- [ ] Per-call buffering
- [ ] Filter matching integration
- [ ] TCP reassembly for SIP

**Milestone:** Hunter buffers and correlates VoIP calls

### Phase 4: Pattern Matching (2-3 weeks)

**Deliverables:**
- [ ] Aho-Corasick integration
- [ ] Phone number normalization
- [ ] Wildcard pattern support
- [ ] IP/CIDR matching (radix tree)
- [ ] Hot-reload filter updates
- [ ] GPU backend interface (stubs)

**Milestone:** Hunter performs efficient multi-pattern matching

### Phase 5: Resilience & Management (2-3 weeks)

**Deliverables:**
- [ ] Circuit breaker
- [ ] Exponential backoff
- [ ] Disk overflow buffer
- [ ] Flow control handling
- [ ] Heartbeat reporting
- [ ] Filter subscription
- [ ] Graceful shutdown

**Milestone:** Hunter survives extended disconnections

### Phase 6: Performance & Optimization (2-3 weeks)

**Deliverables:**
- [ ] AF_XDP capture backend (optional)
- [ ] Memory pool
- [ ] Zero-copy packet handling
- [ ] SIMD byte operations
- [ ] Benchmark suite
- [ ] Profiling and optimization

**Milestone:** Hunter achieves target throughput (40+ Gbps)

### Phase 7: GPU Acceleration (Optional, 3-4 weeks)

**Deliverables:**
- [ ] CUDA backend implementation
- [ ] GPU Aho-Corasick
- [ ] Batch GPU transfers
- [ ] Fallback to CPU

**Milestone:** GPU-accelerated pattern matching

---

## 12. Repository Strategy

### 12.1 Recommendation: Monorepo

The Rust hunter should be developed **within the existing lippycat repository** rather than as a separate repository. This decision is driven by the tight coupling between hunter and processor components.

### 12.2 Rationale

#### Shared Protocol Contract

The gRPC protocol definitions in `api/proto/` are the critical interface between hunter and processor. A monorepo ensures:

- **Single source of truth** for proto files
- Both implementations always use the same message definitions
- Breaking changes are immediately visible to both codebases
- No synchronization overhead between repositories

#### Integration Testing

Integration testing with the Go processor is essential for correctness (see Section 9.2). A monorepo enables:

```bash
# Single command to test interoperability
make test-integration  # Tests Go processor ↔ Rust hunter
```

Separate repositories would require complex CI coordination, git submodules, or version pinning—all of which introduce synchronization risks.

#### Coordinated Releases

The risk assessment (Section 13.3) identifies protocol compatibility as a key risk. A monorepo naturally enforces coordinated releases:

- A single commit can update both processor expectations and hunter implementation
- Version compatibility is guaranteed at the commit level
- No need for compatibility matrices between repository versions

#### Shared Assets

Multiple resources benefit from co-location:

| Asset | Benefit |
|-------|---------|
| `api/proto/` | Single proto definition, no drift |
| `captures/` | Shared test PCAP files |
| `docs/` | Unified documentation |
| `Makefile` | Integrated build targets |
| CI/CD | Single pipeline for full system testing |

### 12.3 Recommended Directory Structure

```
lippycat/
├── cmd/                     # Go CLI commands
├── internal/pkg/            # Go packages
├── api/
│   ├── proto/               # Shared gRPC definitions (source of truth)
│   └── gen/                 # Generated Go code
├── rust/                    # Rust workspace root
│   ├── Cargo.toml           # Workspace manifest
│   ├── hunter/              # Rust hunter crate
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── capture/
│   │   │   ├── grpc/
│   │   │   ├── filter/
│   │   │   └── voip/
│   │   └── build.rs         # Proto compilation
│   ├── proto/               # Generated Rust proto code
│   └── common/              # Shared Rust utilities (optional)
├── captures/                # Shared test PCAPs
├── scripts/
│   └── integration-test.sh  # Cross-implementation testing
├── Makefile                 # Unified build system
└── CLAUDE.md
```

### 12.4 Makefile Integration

```makefile
# Rust targets (add to existing Makefile)
.PHONY: rust-hunter rust-hunter-release rust-test rust-bench rust-fmt

# Development build
rust-hunter:
	cd rust && cargo build -p hunter

# Release build (optimized, stripped)
rust-hunter-release:
	cd rust && cargo build --release -p hunter
	strip rust/target/release/hunter

# Testing
rust-test:
	cd rust && cargo test

rust-bench:
	cd rust && cargo bench

rust-fmt:
	cd rust && cargo fmt

# Integration tests (both implementations)
test-integration: build rust-hunter
	./scripts/integration-test.sh

# Build all variants including Rust
binaries-all: binaries rust-hunter-release
```

### 12.5 CI/CD Considerations

The monorepo CI pipeline should:

1. **Detect changes** - Only run Rust CI when `rust/` or `api/proto/` changes
2. **Cache dependencies** - Separate caches for Go modules and Cargo
3. **Integration matrix** - Test Go processor with both Go and Rust hunters
4. **Artifact publishing** - Publish both hunter binaries

```yaml
# Example GitHub Actions workflow structure
jobs:
  go-build:
    # Existing Go build/test

  rust-build:
    if: contains(github.event.paths, 'rust/') || contains(github.event.paths, 'api/proto/')
    steps:
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cd rust && cargo build --release
      - run: cd rust && cargo test

  integration-test:
    needs: [go-build, rust-build]
    steps:
      - run: ./scripts/integration-test.sh
```

### 12.6 When Separate Repos Might Be Preferred

A separate repository would be more appropriate if:

| Condition | Why |
|-----------|-----|
| Protocol is stable and rarely changes | Loose coupling becomes acceptable |
| Different maintainer teams | Organizational separation |
| Different release cadences | Hunter releases independently |
| Community-driven Rust development | External contributors prefer focused repo |
| Rust-only CI requirements | Avoid Go toolchain in Rust CI |

**Current assessment:** None of these conditions apply. The project is in active development with frequent protocol evolution, making monorepo the clear choice.

### 12.7 Migration Path

If a separate repository becomes desirable later:

1. Extract `rust/` to new repository
2. Set up proto file synchronization (git submodule or CI copy)
3. Establish version compatibility contract
4. Update CI to test across repositories

The monorepo structure proposed here supports this future extraction without requiring code changes—only build system and CI adjustments.

---

## 13. Risk Assessment

### 13.1 Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| libpcap performance ceiling | High | Medium | Implement AF_XDP backend as alternative |
| gRPC streaming complexity | Medium | Medium | Extensive testing, use proven patterns |
| TCP reassembly correctness | High | Medium | Port gopacket logic carefully, comprehensive tests |
| SIMD portability | Low | Low | Runtime feature detection, scalar fallbacks |
| Memory safety in unsafe blocks | High | Low | Minimize unsafe, audit carefully, use miri |

### 13.2 Schedule Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Scope creep | High | High | Strict phase boundaries, feature flags |
| Protocol edge cases | Medium | High | Fuzz testing, real-world PCAP corpus |
| Performance regression | Medium | Medium | Continuous benchmarking, profiling |
| Integration issues | Medium | Medium | Early integration testing with Go processor |

### 13.3 Compatibility Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Proto message evolution | Medium | Low | Versioned proto, backward compat |
| Go processor changes | Medium | Medium | Coordinated releases, integration tests |
| OS-specific capture | Medium | Medium | Test on Linux, macOS; document requirements |

---

## Appendix: Complete Type Mappings

### A.1 Configuration Types

| Go Type | Rust Type |
|---------|-----------|
| `hunter.Config` | `HunterConfig` |
| `forwarding.Config` | `ForwardingConfig` |
| `buffer.Config` | `DiskBufferConfig` |
| `voip.CaptureConfig` | `VoipCaptureConfig` |

### A.2 Packet Types

| Go Type | Rust Type |
|---------|-----------|
| `capture.PacketInfo` | `PacketInfo` |
| `data.CapturedPacket` | `CapturedPacket` (prost-generated) |
| `data.PacketBatch` | `PacketBatch` (prost-generated) |
| `data.PacketMetadata` | `PacketMetadata` (prost-generated) |

### A.3 Filter Types

| Go Type | Rust Type |
|---------|-----------|
| `management.Filter` | `Filter` (prost-generated) |
| `management.FilterType` | `FilterType` (prost-generated enum) |
| `ahocorasick.Pattern` | `Pattern` |
| `filtering.PatternType` | `PatternType` enum |

### A.4 State Types

| Go Type | Rust Type |
|---------|-----------|
| `circuitbreaker.State` | `CircuitState` enum |
| `data.FlowControl` | `FlowControl` (prost-generated enum) |
| `management.HunterStatus` | `HunterStatus` (prost-generated enum) |

---

## Addendum: Codebase Updates (2026-01-31)

Since the initial research (2026-01-20), the Go codebase has evolved with significant VoIP and TCP handling improvements. The Rust implementation must incorporate these patterns.

### A. TCP Handler Architecture (New)

Build-tagged handlers now separate concerns for different modes:

| File | Build Tag | Purpose |
|------|-----------|---------|
| `tcp_handler_hunter.go` | `hunter \|\| all` | Forward to processor with metadata |
| `tcp_handler_tap.go` | `tap \|\| all` | Channel-based local processing |
| `tcp_handler_local.go` | `all` | TUI/local packet injection |

**Rust Impact:** Implement `SIPMessageHandler` trait with mode-specific implementations via Cargo features.

```rust
pub trait SIPMessageHandler: Send + Sync {
    fn handle_sip_message(
        &self,
        sip_message: &[u8],
        call_id: &str,
        src_endpoint: &str,
        dst_endpoint: &str,
        net_flow: &Flow,
    ) -> bool;
}
```

### B. Buffered TCP Stream (New Pattern)

The `bufferedSIPStream` replaces `tcpreader.ReaderStream` to prevent packet capture freezes:

| Go Pattern | Rust Equivalent |
|------------|-----------------|
| `chan []byte` (buffered, 64) | `tokio::sync::mpsc::channel(64)` |
| Non-blocking `select` send | `try_send()` with drop on full |
| `discard` atomic flag | `AtomicBool` to skip non-SIP streams |
| State-based timeouts | `tokio::time::timeout` per state |

**Key invariant:** `Reassembled()` must never block the capture loop.

### C. TCP Buffer Strategies (New)

Three buffer strategies for TCP packet accumulation:

```rust
pub enum TCPBufferStrategy {
    Fixed,    // Drop new packets when full
    Ring,     // Circular overwrite oldest
    Adaptive, // Remove 25% oldest when full
}
```

**Buffer Pool Pattern:** Reuse `TCPPacketBuffer` instances to reduce allocation:

```rust
pub struct TCPBufferPool {
    buffers: ArrayQueue<TCPPacketBuffer>,
    max_size: usize,
}
```

### D. State-Based TCP Timeouts (New Feature)

TCP streams now support per-state timeout configuration:

| TCP State | Default Timeout | Purpose |
|-----------|-----------------|---------|
| Opening | 5s | No SIP detected yet |
| Established | 300s | Valid SIP session |
| Closing | 30s | FIN received |

```rust
pub enum TCPState {
    Opening,
    Established,
    Closing,
}

pub struct StatefulStream {
    state: AtomicU8,
    state_change_notify: tokio::sync::Notify,
}
```

Call-aware timeout option keeps streams open for active calls.

### E. LRU Eviction (Changed)

`CallTracker` and `CallAggregator` now use **LRU eviction** instead of FIFO:

```rust
// Use linked-hash-map or lru crate
pub struct CallTracker {
    calls: LinkedHashMap<String, CallState>, // LRU order
    max_calls: usize,
}

impl CallTracker {
    pub fn get(&mut self, call_id: &str) -> Option<&CallState> {
        // Move to back (most recent) on access
        self.calls.get_refresh(call_id)
    }
}
```

### F. RTP-Only Calls (New Feature)

Calls can now be created from RTP streams before SIP arrives:

```rust
pub enum CallState {
    // ... existing states ...
    RTPOnly, // RTP detected without SIP signaling
}
```

When SIP arrives, the synthetic call is merged with the real call.

### G. Other Changes

| Change | Impact on Rust Implementation |
|--------|-------------------------------|
| Default gRPC port: 55555 | Update default in config |
| `--no-filter-policy` default: deny | Match in CLI defaults |
| DNS tunneling at hunter edge | Include in Phase 7 DNS hunter |
| System metrics integration | Add sysinfo crate for Phase 5 |

### H. Updated Component Lines

| Component | Previous | Current | Notes |
|-----------|----------|---------|-------|
| `tcp_stream.go` | ~400 | ~600 | Buffered stream, state timeouts |
| `tcp_buffer.go` | (new) | ~300 | Buffer pool, strategies |
| `tcp_handler_*.go` | (new) | ~400 | Build-tagged handlers |
| `config.go` | ~100 | ~225 | Many new TCP options |
| `call_aggregator.go` | ~400 | ~600 | LRU, RTP-only, merge |

---

## Conclusion

Full feature parity with lippycat's Go hunter is achievable but represents a significant engineering effort (~16-24 person-weeks). The Rust implementation offers several advantages:

1. **Performance:** Potential 2-4x throughput improvement via zero-copy, SIMD, and AF_XDP
2. **Memory safety:** Compile-time guarantees eliminate entire classes of bugs
3. **Concurrency:** Rust's ownership model prevents data races
4. **Binary size:** Smaller, more efficient binaries

The phased approach allows incremental delivery of value while managing technical risk. Phase 1-3 (core + VoIP) delivers the most critical functionality in ~10-13 weeks.

**Recommendation:** Proceed with implementation, starting with Phase 1. Maintain close integration testing with the Go processor throughout development.

---

*Document Version: 1.1*
*Last Updated: 2026-01-31*
*Changes: Added Addendum with codebase updates (TCP handlers, buffer strategies, LRU eviction, RTP-only calls)*
