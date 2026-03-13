# User Manual — Full Guide Implementation Plan

## Overview

Expand the user manual from the focused guide (Parts I-II, ~50 pages) to the full manual (Parts III-V + Appendices, ~110 additional pages). All stub files are already in place with placeholder content.

**Predecessor**: [user-manual-implementation.md](user-manual-implementation.md) (completed)
**Research**: [../research/user-manual-design.md](../research/user-manual-design.md)

## Source Material

~12,400 lines across 24 existing docs feed into the remaining chapters:

| Chapter | Primary Sources | Lines |
|---------|----------------|-------|
| Ch 6: Architecture | `docs/DISTRIBUTED_MODE.md` | 1,508 |
| Ch 7: Hunt | `cmd/hunt/README.md`, `cmd/hunt/CLAUDE.md` | 1,122 |
| Ch 8: Process | `cmd/process/README.md`, `cmd/process/CLAUDE.md` | 1,769 |
| Ch 9: Tap | `cmd/tap/README.md`, `cmd/tap/CLAUDE.md` | 1,249 |
| Ch 10: CLI Admin | `cmd/show/README.md`, `cmd/list/README.md`, `cmd/show/CLAUDE.md`, `cmd/list/CLAUDE.md` | 483 |
| Ch 11: Watch Remote | `cmd/watch/README.md`, `docs/TUI_REMOTE_CAPTURE.md` | 785 |
| Ch 12: Operations | `docs/operational-procedures.md` | 426 |
| Ch 13: Security | `docs/SECURITY.md`, `docs/TLS_DECRYPTION.md` | 1,797 |
| Ch 14: Performance | `docs/PERFORMANCE.md`, `docs/GPU_ACCELERATION.md`, `docs/AF_XDP_SETUP.md` | 1,662 |
| Ch 15: Protocol Dives | `cmd/sniff/CLAUDE.md`, protocol analyzer sources | ~850 |
| Ch 16: LI | `docs/LI_INTEGRATION.md`, `docs/LI_CERTIFICATES.md`, `internal/pkg/li/CLAUDE.md` | 790+ |
| Ch 17: Troubleshooting | `docs/tcp-troubleshooting.md`, `docs/GPU_TROUBLESHOOTING.md` | 634 |
| Appendices | All command `--help` output, config sources, glossary | — |

## Phase 1: Part III — Distributed Capture

The core of lippycat's value proposition. This is the largest and most important remaining part.

### Chapter 6: Distributed Architecture Overview (`part3-distributed/architecture.md`)

- [x] Why distribute capture? (multi-segment visibility, scalability, separation of concerns)
- [x] Hunter/processor model explained (roles, responsibilities, data flow)
- [x] Mermaid diagram already added (full README diagram with hunters, processor, outputs)
- [x] Network topologies with mermaid diagrams:
  - [x] Hub-and-spoke (simple)
  - [x] Hierarchical (processor-to-processor forwarding)
  - [x] Multi-processor
- [x] Security model overview (TLS by default, mTLS, production mode)
- [x] Decision framework: when to use hunt+process vs tap vs sniff
- [x] Capacity planning basics (hunters per processor, bandwidth considerations)

**Sources**: `docs/DISTRIBUTED_MODE.md`, `docs/SECURITY.md`

### Chapter 7: Edge Capture with `lc hunt` (`part3-distributed/hunt.md`)

- [x] **7.1 From sniff to hunt** — the bridge (critical section per research doc)
  - [x] Side-by-side comparison: `sniff` vs `hunt` flags
  - [x] What changes (processor connection) and what doesn't (most flags)
  - [x] Connecting to a processor (TLS, CA verification)
  - [x] First distributed capture walkthrough
- [x] **7.2 Protocol-specific hunters**
  - [x] VoIP hunter (`hunt voip`) — SIP user filtering, call buffering
  - [x] DNS hunter (`hunt dns`) — domain filtering
  - [x] HTTP, TLS, Email hunters — brief coverage
- [x] **7.3 Resilience and flow control**
  - [x] Flow control states (CONTINUE, SLOW, PAUSE, RESUME)
  - [x] Disk overflow buffer
  - [x] Circuit breaker pattern
  - [x] Reconnection behavior
- [x] **7.4 Performance tuning**
  - [x] Batch sizing
  - [x] GPU acceleration for edge filtering
  - [x] BPF filter optimization (`--udp-only`, `--sip-port`)

**Sources**: `cmd/hunt/README.md`, `cmd/hunt/CLAUDE.md`

### Chapter 8: Central Aggregation with `lc process` (`part3-distributed/process.md`)

- [x] **8.1 Processor basics**
  - [x] Starting a processor (`--listen`, TLS cert/key)
  - [x] Receiving from hunters (auto-discovery, hunter management)
  - [x] Hunter status monitoring
- [x] **8.2 PCAP writing modes**
  - [x] Unified PCAP (`--write-file`)
  - [x] Per-call PCAP for VoIP (`--per-call-pcap`, `--per-call-pcap-dir`)
  - [x] Auto-rotating PCAP (`--pcap-rotation-interval`, `--pcap-rotation-size`)
- [x] **8.3 Command hooks**
  - [x] PCAP completion hooks (`--pcap-command`)
  - [x] VoIP call completion hooks (`--voip-command`)
  - [x] Placeholder reference (`%pcap%`, `%callid%`, `%dirname%`)
- [x] **8.4 Filter management**
  - [x] Static filters (CLI flags)
  - [x] Dynamic filter updates (via management gRPC)
  - [x] Filter distribution to hunters
- [x] **8.5 Advanced topologies**
  - [x] Hierarchical mode (upstream forwarding)
  - [x] Virtual interface injection for external tools

**Sources**: `cmd/process/README.md`, `cmd/process/CLAUDE.md`, `docs/DISTRIBUTED_MODE.md`

### Chapter 9: Standalone Mode with `lc tap` (`part3-distributed/tap.md`)

- [x] When to use tap vs hunt+process (decision framework)
- [x] Tap = hunt + process − gRPC (conceptual model)
- [x] Configuration and usage examples
- [x] TUI serving from tap (local gRPC loopback)
- [x] Upstream forwarding to a processor
- [x] Per-call PCAP in tap mode

**Sources**: `cmd/tap/README.md`, `cmd/tap/CLAUDE.md`

## Phase 2: Part IV — Administration & Monitoring

### Chapter 10: CLI Administration (`part4-administration/cli-admin.md`)

- [x] `lc show` commands (all require `-P` processor address except `show config`)
  - [x] `show status` — processor health and statistics
  - [x] `show hunter` — specific hunter details
  - [x] `list hunters` — connected hunter list
  - [x] `show topology` — distributed topology visualization
  - [x] `show filter` — active filter details
  - [x] `show config` — local configuration display (no `-P` needed)
- [x] `lc list` commands
  - [x] `list interfaces` — network interface discovery
  - [x] `list filters` — filter listing on processor
- [x] `lc set` commands
  - [x] `set filter` — create or update a filter (upsert)
  - [x] Inline mode (--type, --pattern) vs file mode (-f filters.yaml)
  - [x] Filter types reference (VoIP, DNS, Email, TLS, HTTP, Universal)
- [x] `lc rm` commands
  - [x] `rm filter` — delete a filter by ID
  - [x] Batch deletion from file (-f filter-ids.txt)
- [x] Connection flags reference (shared across all remote commands)
- [x] JSON output format and exit codes

**Sources**: `cmd/show/README.md`, `cmd/show/CLAUDE.md`, `cmd/list/README.md`, `cmd/list/CLAUDE.md`, `cmd/set/set.go`, `cmd/rm/rm.go`, `cmd/filter/`

### Chapter 11: Remote TUI Monitoring (`part4-administration/watch-remote.md`)

- [x] Connecting to a remote processor (`lc watch remote`)
- [x] Node file configuration (`nodes.yaml` format)
- [x] Multi-node monitoring (aggregated view)
- [x] Hunter subscription management (selective monitoring)
- [x] Filter management via TUI
- [x] TLS configuration for remote connections

**Sources**: `cmd/watch/README.md`, `docs/TUI_REMOTE_CAPTURE.md`

### Chapter 12: Operations Runbook (`part4-administration/operations.md`)

- [x] Health checks and monitoring
- [x] Log analysis and structured logging
- [x] Common operational issues and resolution
- [x] Capacity planning guidelines
- [x] Deployment checklists

**Sources**: `docs/operational-procedures.md`

## Phase 3: Part V — Production & Advanced

### Chapter 13: Security (`part5-advanced/security.md`)

- [x] TLS configuration for distributed mode
  - [x] Certificate requirements per node type
  - [x] Generating certificates (OpenSSL commands)
- [x] Mutual TLS (mTLS) setup
  - [x] CA setup, client certs, trust model
- [x] Certificate management lifecycle
- [x] Production mode enforcement (`LIPPYCAT_PRODUCTION=true`)
- [x] TLS decryption for captured traffic (`SSLKEYLOGFILE`, Wireshark integration)

**Sources**: `docs/SECURITY.md`, `docs/TLS_DECRYPTION.md`

### Chapter 14: Performance Optimization (`part5-advanced/performance.md`)

- [x] TCP performance profiles (`--tcp-performance-mode`)
  - [x] balanced, high_performance, max_throughput
  - [x] When to use each
- [x] GPU acceleration
  - [x] Backend selection (CUDA, OpenCL, SIMD auto-detection)
  - [x] Benchmarks and expected throughput
  - [x] Hardware requirements
- [x] AF_XDP high-speed capture
  - [x] Kernel requirements, NIC support
  - [x] Setup and configuration
- [x] Distributed scaling patterns

**Sources**: `docs/PERFORMANCE.md`, `docs/GPU_ACCELERATION.md`, `docs/AF_XDP_SETUP.md`

### Chapter 15: Protocol Deep Dives (`part5-advanced/protocol-deep-dives.md`)

- [x] VoIP deep dive
  - [x] SIP signaling flow (mermaid diagram)
  - [x] RTP/SRTP media streams
  - [x] Call quality metrics (MOS, jitter, packet loss)
  - [x] Per-call PCAP workflow
- [x] DNS analysis patterns
  - [x] Query/response correlation
  - [x] Common DNS investigations
- [x] TLS inspection
  - [x] JA3/JA3S fingerprinting
  - [x] Certificate extraction
  - [x] SNI filtering
- [x] HTTP/Email analysis patterns

**Sources**: Protocol analyzer source code, `cmd/sniff/CLAUDE.md`, existing protocol docs

### Chapter 16: Lawful Interception (`part5-advanced/lawful-interception.md`)

- [x] ETSI X1/X2/X3 interface overview
  - [x] Mermaid diagram of ADMF → NE → MDF flow
- [x] Build requirements (`-tags li`)
- [x] Configuration and deployment
  - [x] X1 server setup
  - [x] X2/X3 delivery configuration
  - [x] Certificate setup for LI interfaces
- [x] Filter integration (how LI tasks map to capture filters)
- [x] Operational considerations

**Sources**: `docs/LI_INTEGRATION.md`, `docs/LI_CERTIFICATES.md`, `internal/pkg/li/CLAUDE.md`

### Chapter 17: Troubleshooting (`part5-advanced/troubleshooting.md`)

- [x] Capture issues (permissions, interface selection, no packets)
- [x] TCP reassembly problems (SIP over TCP, stream handling)
- [x] Distributed connectivity (TLS handshake failures, flow control stalls)
- [x] GPU troubleshooting (driver issues, fallback, diagnostics)
- [x] VoIP-specific issues (missing RTP, one-way audio, codec handling)

**Sources**: `docs/tcp-troubleshooting.md`, `docs/GPU_TROUBLESHOOTING.md`

## Phase 4: Appendices

### Appendix A: Command Reference (`appendices/command-reference.md`)

- [x] Complete command tree with all flags (generated from `--help` output)
- [x] Environment variables reference
- [x] Exit codes

### Appendix B: Configuration Reference (`appendices/config-reference.md`)

- [x] Full YAML schema with all fields
- [x] Configuration precedence order
- [x] Example configuration files (minimal, production, distributed)

### Appendix C: BPF Filter Reference (`appendices/bpf-reference.md`)

- [x] BPF syntax quick reference
- [x] Common filter patterns by use case (VoIP, DNS, HTTP, security)
- [x] Performance implications of filter complexity
- [x] lippycat-specific filter optimizations (`--udp-only`, `--sip-port`)

### Appendix D: Glossary (`appendices/glossary.md`)

- [x] Expand existing 8 terms to comprehensive glossary
- [x] Include all lippycat-specific terminology
- [x] Cross-reference to chapters where terms are defined

## Phase 5: Polish & Cross-References

- [ ] Add mermaid diagrams throughout (architecture, protocol flows, topologies)
- [ ] Verify all CLI examples against current `--help` output
- [ ] Add cross-references between chapters (forward/back links)
- [ ] Review for consistent voice, terminology, and progressive disclosure
- [ ] Update SUMMARY.md if any chapter structure changed
- [ ] Test `mdbook build` for clean output
- [ ] Update the focused guide plan as complete

## Implementation Notes

- **Verify flags**: Before documenting any command, run `lc <cmd> --help` to verify current flags
- **Don't duplicate**: Link to existing docs for deep operational details, don't copy wholesale
- **Progressive disclosure**: Each chapter builds on previous — reference earlier concepts, don't re-explain
- **Mermaid diagrams**: Use for all architecture/topology/flow visualizations (support added)
- **Runnable examples**: Every `lc` command shown should work against the current binary
- **Phase order matters**: Part III first (most important), then IV (depends on III), then V (advanced), then Appendices
