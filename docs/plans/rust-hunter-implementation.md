# Rust Hunter Implementation Plan

**Date:** 2026-01-31
**Status:** Planning
**Research:** `docs/research/rust-hunter-full-feature-parity.md`
**Branch:** `feature/rust-hunter`

## Overview

Implement a Rust hunter node with full feature parity to lippycat's Go hunter. The Rust hunter provides high-performance packet capture, protocol detection, and VoIP call handling at the network edge.

**Target Performance:** 40+ Gbps (vs Go's ~10-15 Gbps)
**Repository Strategy:** Monorepo under `rust/` directory

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                        Rust Hunter                              │
│  ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────────┐   │
│  │ Capture  │─→│  Protocol   │─→│ App      │─→│ gRPC        │   │
│  │ Manager  │  │  Detection  │  │ Filter   │  │ Forwarding  │   │
│  └──────────┘  └─────────────┘  └──────────┘  └─────────────┘   │
│       │              │              │                           │
│       │         ┌────┴────┐    ┌────┴────┐                      │
│       │         │ VoIP    │    │ Pattern │                      │
│       │         │ Buffer  │    │ Matcher │                      │
│       │         └─────────┘    └─────────┘                      │
└───────┼─────────────────────────────────────────────────────────┘
        ↓
   [libpcap/AF_XDP]
```

## Phase 1: Core Foundation (4-5 weeks)

Project scaffold, configuration, basic capture and gRPC streaming.

### Step 1.1: Project Structure
- [ ] Create `rust/Cargo.toml` workspace manifest
- [ ] Create `rust/hunter/Cargo.toml` crate
- [ ] Add dependencies: tokio, tonic, clap, tracing, pcap, bytes
- [ ] Create `rust/hunter/build.rs` for proto compilation

### Step 1.2: CLI Framework
- [ ] Implement clap command structure matching Go:
  - `lc-hunt` base command
  - `lc-hunt voip` subcommand
  - `lc-hunt dns`, `http`, `tls`, `email` stubs
- [ ] Implement flag parsing:
  - `--processor/-P` (required)
  - `--id/-I`, `--interface/-i`, `--filter/-f`
  - `--batch-size`, `--batch-timeout`, `--buffer-size`
  - TLS flags: `--tls-cert`, `--tls-key`, `--tls-ca`, `--insecure`

### Step 1.3: Configuration System
- [ ] Implement figment-based config loading
- [ ] Support: YAML file, environment variables, CLI flags
- [ ] Config file search paths matching Go
- [ ] Define `HunterConfig` struct with all options

### Step 1.4: Logging Infrastructure
- [ ] Set up tracing with structured logging
- [ ] JSON format for production
- [ ] Log level filtering via RUST_LOG

### Step 1.5: Packet Capture
- [ ] Implement `CaptureManager` using pcap crate
- [ ] Multi-interface support via spawn per interface
- [ ] BPF filter compilation and application
- [ ] Promiscuous mode support
- [ ] Buffer size configuration
- [ ] PacketInfo struct with metadata

### Step 1.6: gRPC Client
- [ ] Compile protos from `api/proto/` via tonic-build
- [ ] Implement DataService.StreamPackets client
- [ ] Implement ManagementService.RegisterHunter client
- [ ] TLS/mTLS support via rustls
- [ ] Connection manager with reconnect logic

### Step 1.7: Batch Forwarding
- [ ] Implement `ForwardingManager`
- [ ] Packet → CapturedPacket conversion
- [ ] Batching with size and timeout triggers
- [ ] mpsc channel pipeline

**Milestone:** Hunter connects to processor and streams raw packets

## Phase 2: Protocol Detection (3-4 weeks)

Signature-based detection with SIMD optimization.

### Step 2.1: Detection Framework
- [ ] Define `ProtocolSignature` trait
- [ ] `DetectionContext` struct with packet metadata
- [ ] `DetectionResult` with protocol, confidence, metadata
- [ ] Priority-based signature ordering

### Step 2.2: Core Signatures
- [ ] SIP detection (7 methods: INVITE, ACK, BYE, etc.)
- [ ] RTP detection (header validation)
- [ ] DNS detection (port + header checks)
- [ ] TLS detection (handshake recognition)
- [ ] HTTP detection (method recognition)

### Step 2.3: SIMD Acceleration
- [ ] AVX2/SSE4.2 byte search using std::arch
- [ ] Portable fallback for non-x86
- [ ] Runtime feature detection
- [ ] Batch detection interface

### Step 2.4: Detection Cache
- [ ] Flow-keyed cache with DashMap
- [ ] TTL-based expiration
- [ ] Cache hit statistics

**Milestone:** Hunter identifies VoIP traffic and adds metadata

## Phase 3: VoIP Call Handling (3-4 weeks)

SIP/RTP correlation with TCP reassembly.

### Step 3.1: SIP Parsing
- [ ] Call-ID extraction
- [ ] From/To header parsing
- [ ] SDP body extraction
- [ ] RTP port discovery from SDP
- [ ] Method and response code detection

### Step 3.2: RTP Detection
- [ ] RTP header validation (version, PT, SSRC)
- [ ] SSRC tracking for stream correlation
- [ ] Sequence number tracking

### Step 3.3: Call Buffer Manager
- [ ] Per-call packet buffering
- [ ] SIP packet accumulation
- [ ] RTP port correlation via SDP
- [ ] RTP packet association
- [ ] LRU eviction (matching Go implementation)
- [ ] RTP-only call support with SIP merge

### Step 3.4: TCP Reassembly
- [ ] Implement `SIPMessageHandler` trait
- [ ] Build-tagged handlers (hunter, tap, local pattern)
- [ ] Buffered stream with non-blocking channel
- [ ] Discard flag for non-SIP streams
- [ ] Buffer strategies: fixed, ring, adaptive
- [ ] Buffer pooling for memory efficiency

### Step 3.5: TCP Handler (Hunter Mode)
- [ ] Filter matching integration
- [ ] Metadata extraction
- [ ] Packet forwarding with metadata
- [ ] Termination message handling (BYE/CANCEL)

### Step 3.6: State-Based Timeouts
- [ ] TCPState enum: Opening, Established, Closing
- [ ] Per-state configurable timeouts
- [ ] Call-aware timeout option

**Milestone:** Hunter buffers and correlates VoIP calls

## Phase 4: Pattern Matching (2-3 weeks)

High-performance multi-pattern matching.

### Step 4.1: Aho-Corasick Integration
- [ ] Use `aho-corasick` crate
- [ ] Pattern compilation from filters
- [ ] Case-insensitive matching
- [ ] Overlapping match support

### Step 4.2: Application Filter
- [ ] `ApplicationFilter` trait definition
- [ ] SIP user matching
- [ ] Phone number normalization and matching
- [ ] IP address matching (HashMap O(1))
- [ ] IP CIDR matching (radix tree)

### Step 4.3: Filter Subscription
- [ ] ManagementService.SubscribeFilters client
- [ ] Hot-reload filter updates
- [ ] Filter type routing
- [ ] Default filter policy (allow/deny)

**Milestone:** Hunter performs efficient multi-pattern matching

## Phase 5: Resilience & Management (2-3 weeks)

Production-grade fault tolerance.

### Step 5.1: Circuit Breaker
- [ ] State machine: Closed, Open, HalfOpen
- [ ] Configurable failure threshold
- [ ] Reset timeout with jitter
- [ ] Half-open call limit

### Step 5.2: Backoff Strategy
- [ ] Exponential backoff implementation
- [ ] Configurable base and max delay
- [ ] Jitter support

### Step 5.3: Disk Overflow Buffer
- [ ] Memory-mapped file buffer
- [ ] Protobuf serialization
- [ ] Size-limited with cleanup
- [ ] Recovery on restart

### Step 5.4: Flow Control
- [ ] Handle StreamControl messages
- [ ] SLOW/PAUSE/RESUME states
- [ ] Backpressure to capture

### Step 5.5: Heartbeat & Stats
- [ ] Periodic heartbeat sending
- [ ] Statistics collection (packets, bytes, drops)
- [ ] Hunter status reporting

### Step 5.6: Graceful Shutdown
- [ ] CancellationToken propagation
- [ ] Flush pending batches
- [ ] Clean gRPC disconnect

**Milestone:** Hunter survives extended disconnections

## Phase 6: Performance Optimization (2-3 weeks)

Target 40+ Gbps throughput.

### Step 6.1: Zero-Copy
- [ ] Use bytes::Bytes for packet data
- [ ] Minimize allocations in hot path
- [ ] Direct protobuf encoding to buffer

### Step 6.2: Memory Pool
- [ ] ArrayQueue-based packet pool
- [ ] Pre-allocated buffers
- [ ] Pool statistics

### Step 6.3: SIMD Operations
- [ ] Vectorized byte operations
- [ ] Batch protocol detection
- [ ] memchr-based searches

### Step 6.4: AF_XDP Backend (Optional)
- [ ] xsk-rs integration
- [ ] UMEM setup
- [ ] Zero-copy receive

### Step 6.5: Benchmarking
- [ ] Criterion benchmark suite
- [ ] Throughput tests
- [ ] Latency profiling

**Milestone:** Hunter achieves 40+ Gbps

## Phase 7: Protocol Hunters (4-5 weeks)

Complete protocol-specific implementations.

### Step 7.1: DNS Hunter
- [ ] DNS packet parsing
- [ ] Query/response correlation
- [ ] Tunneling detection (entropy analysis)
- [ ] Domain pattern filtering

### Step 7.2: HTTP Hunter
- [ ] TCP reassembly for HTTP
- [ ] Request/response correlation
- [ ] Content filtering (host, path, method, status)
- [ ] Body capture with limits

### Step 7.3: TLS Hunter
- [ ] ClientHello/ServerHello parsing
- [ ] SNI extraction
- [ ] JA3/JA3S/JA4 fingerprinting
- [ ] Connection tracking

### Step 7.4: Email Hunter
- [ ] SMTP state machine
- [ ] IMAP command parsing
- [ ] POP3 command parsing
- [ ] Sender/recipient filtering

**Milestone:** Full protocol parity

## Phase 8: GPU Acceleration (Optional, 3-4 weeks)

CUDA-based pattern matching.

### Step 8.1: CUDA Backend
- [ ] cust crate integration
- [ ] GPU Aho-Corasick kernel
- [ ] Batch GPU transfers
- [ ] Fallback to CPU

**Milestone:** GPU-accelerated filtering

## Makefile Integration

```makefile
# Add to existing Makefile
rust-hunter:
	cd rust && cargo build -p hunter

rust-hunter-release:
	cd rust && cargo build --release -p hunter
	strip rust/target/release/lc-hunt

rust-test:
	cd rust && cargo test

rust-bench:
	cd rust && cargo bench

test-integration: build rust-hunter
	./scripts/integration-test.sh
```

## Success Criteria

1. **Compatibility:** Passes integration tests with Go processor
2. **Performance:** Achieves 40+ Gbps on test hardware
3. **Feature Parity:** All Go hunter features implemented
4. **Reliability:** Circuit breaker and disk buffer tested
5. **Documentation:** README and inline docs complete

## Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| 1. Core Foundation | 4-5 weeks | Basic capture + gRPC |
| 2. Protocol Detection | 3-4 weeks | SIMD detection |
| 3. VoIP Handling | 3-4 weeks | Call buffering + TCP |
| 4. Pattern Matching | 2-3 weeks | Aho-Corasick filters |
| 5. Resilience | 2-3 weeks | Circuit breaker + disk buffer |
| 6. Performance | 2-3 weeks | 40+ Gbps |
| 7. Protocol Hunters | 4-5 weeks | DNS/HTTP/TLS/Email |
| 8. GPU (Optional) | 3-4 weeks | CUDA acceleration |

**Total:** 24-31 weeks (P1-P7), +3-4 weeks for GPU

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| libpcap ceiling | AF_XDP backend as alternative |
| TCP reassembly bugs | Port Go logic carefully, fuzz testing |
| Proto compatibility | Monorepo, integration tests |
| Performance regression | Continuous benchmarking |
