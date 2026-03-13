# User Manual Design Research

## Executive Summary

This document explores the design of a comprehensive user manual for lippycat. While the project has extensive documentation (84+ markdown files, ~15,000 lines), it lacks a cohesive, didactic resource that teaches users the system in a logical progression.

**Problem**: Documentation is fragmented across README files, CLAUDE.md architecture docs, and operational guides in `docs/`. Users must piece together knowledge from multiple sources.

**Proposed Solution**: A structured manual that teaches concepts progressively, following the natural command hierarchy: `sniff` → `hunt` → `process` → `tap`.

**Target Audiences**:
- New users learning lippycat
- Operators deploying in production

## Current Documentation Inventory

### Documentation by Type

| Type | Count | Purpose | Audience |
|------|-------|---------|----------|
| README.md | 9 | User guides, usage examples | End users |
| CLAUDE.md | 9 | Architecture, patterns | AI assistants, developers |
| docs/*.md | 15 | Operational guides | Operators |
| docs/research/*.md | 30+ | Design exploration | Internal |
| docs/plans/*.md | 35+ | Implementation roadmaps | Internal |

### Documentation by Command

| Command | README | CLAUDE.md | Combined Lines |
|---------|--------|-----------|----------------|
| sniff | 420 | 850 | ~1,270 |
| hunt | 520 | 550 | ~1,070 |
| process | 720 | 900 | ~1,620 |
| tap | 150 | 600 | ~750 |
| watch | 220 | 100 | ~320 |
| list | 80 | 100 | ~180 |
| show | 100 | 100 | ~200 |

### Identified Gaps

1. **No learning path**: Documentation is reference-oriented, not tutorial-oriented
2. **No conceptual foundation**: Assumes prior knowledge of packet capture, distributed systems
3. **Fragmented topics**: Same concepts (TLS, VoIP, filters) explained in multiple places
4. **No decision frameworks**: Users don't know when to use sniff vs hunt vs tap
5. **Missing quick reference**: No single-page command cheat sheet

### Overlapping Content

The following topics are documented in 3+ places:

- Distributed architecture (CLAUDE.md, DISTRIBUTED_MODE.md, README.md, command READMEs)
- TLS/security (SECURITY.md, README.md, each command README)
- VoIP capture (sniff README, hunt README, tap README, PERFORMANCE.md, tcp-troubleshooting.md)
- BPF filters (sniff README, hunt README, CLAUDE.md)

## Proposed Manual Structure

### Design Principles

1. **Progressive disclosure**: Start simple, add complexity gradually
2. **Concept-first**: Explain *why* before *how*
3. **Build on familiar tools**: Reference tcpdump, Wireshark, tshark where applicable
4. **Single source of truth**: Define concepts once, reference thereafter
5. **Practical examples**: Every concept demonstrated with runnable commands

### Learning Path Rationale

The command progression follows natural complexity:

```
sniff (local CLI) → watch live/file (local TUI) → hunt → process → tap → watch remote
```

**Why this order?**

1. **`lc sniff`** is the foundation
   - Analogous to tcpdump/tshark (familiar mental model)
   - Introduces: interfaces, BPF filters, protocols, PCAP output, packet injection to virtual interface
   - No distributed concepts to confuse newcomers
   - Most flags carry forward to other commands

2. **`lc watch live/file`** reinforces sniff concepts visually
   - Same capture concepts, interactive interface
   - Analogous to Wireshark (familiar to many users)
   - Teaches TUI navigation before remote complexity

3. **`lc hunt`** introduces distribution
   - "sniff that forwards instead of writes locally"
   - Most sniff flags carry over
   - New concept: processor connection
   - Teaches: flow control, resilience, buffering

4. **`lc process`** completes the distributed picture
   - Receives what hunters send
   - Introduces: aggregation, per-call PCAP, command hooks
   - Makes hunt's purpose concrete

5. **`lc tap`** synthesizes understanding
   - "hunt + process − gRPC"
   - Only makes sense after understanding both components
   - Shows when distribution is/isn't needed

6. **`lc watch remote`** completes the TUI story
   - Requires distributed concepts
   - Multi-node monitoring
   - Natural endpoint of the learning path

### The "sniff → hunt" Bridge

This transition is critical. The manual should explicitly show the relationship:

```bash
# What you learned with sniff:
lc sniff voip -i eth0 --sip-user alice --pcap calls.pcap

# Same thing, but now it goes to a processor:
lc hunt voip -i eth0 --sip-user alice --processor central:50051
                                       ^^^^^^^^^^^^^^^^^^^^^^^^
                                       This is the only new part
```

Most flags carry over. The mental model: *"hunt is sniff that forwards instead of writes locally."*

## Proposed Table of Contents

```
lippycat Manual

PART I: FOUNDATIONS
├── Chapter 1: Introduction
│   ├── What is lippycat?
│   ├── Use cases (network monitoring, VoIP analysis, security)
│   ├── Comparison with similar tools (tcpdump, Wireshark, tshark)
│   └── When to use lippycat
│
├── Chapter 2: Core Concepts
│   ├── Packets and protocols
│   ├── Network interfaces and capture
│   ├── BPF filters (Berkeley Packet Filter)
│   ├── PCAP format
│   └── Protocol analysis basics
│
└── Chapter 3: Installation & Setup
    ├── Binary installation
    ├── Building from source
    ├── Permissions (CAP_NET_RAW, sudo)
    └── Configuration file

PART II: LOCAL CAPTURE
├── Chapter 4: CLI Capture with `lc sniff`
│   ├── 4.1 Your first capture
│   │   ├── Selecting an interface
│   │   ├── Basic filtering
│   │   └── Reading output
│   │
│   ├── 4.2 Protocol modes
│   │   ├── DNS analysis (lc sniff dns)
│   │   ├── TLS inspection (lc sniff tls)
│   │   ├── HTTP capture (lc sniff http)
│   │   ├── Email monitoring (lc sniff email)
│   │   └── VoIP analysis (lc sniff voip)
│   │
│   ├── 4.3 Output and PCAP
│   │   ├── CLI output formats
│   │   ├── Writing PCAP files
│   │   └── Per-call PCAP (VoIP)
│   │
│   └── 4.4 Performance tuning
│       ├── TCP reassembly modes
│       ├── Buffer sizing
│       └── GPU acceleration
│
├── Chapter 5: Interactive Capture with `lc watch`
│   ├── 5.1 Live capture mode
│   │   ├── Starting live capture
│   │   ├── TUI navigation
│   │   ├── Filtering packets
│   │   └── Keybindings reference
│   │
│   ├── 5.2 PCAP file analysis
│   │   ├── Opening PCAP files
│   │   ├── Multi-file analysis
│   │   └── Searching and filtering
│   │
│   └── 5.3 TUI features
│       ├── Tabs and views
│       ├── Statistics
│       └── Help system

PART III: DISTRIBUTED CAPTURE
├── Chapter 6: Distributed Architecture Overview
│   ├── Why distribute capture?
│   ├── Hunter/processor model
│   ├── Network topologies
│   └── Security considerations
│
├── Chapter 7: Edge Capture with `lc hunt`
│   ├── 7.1 From sniff to hunt
│   │   ├── What changes (and what doesn't)
│   │   ├── Connecting to a processor
│   │   └── Your first distributed capture
│   │
│   ├── 7.2 Protocol-specific hunters
│   │   ├── VoIP hunter
│   │   ├── DNS hunter
│   │   └── Other protocol modes
│   │
│   ├── 7.3 Resilience and flow control
│   │   ├── Flow control states
│   │   ├── Disk overflow buffer
│   │   ├── Circuit breaker
│   │   └── Reconnection behavior
│   │
│   └── 7.4 Performance tuning
│       ├── Batch sizing
│       ├── GPU acceleration
│       └── BPF optimization
│
├── Chapter 8: Central Aggregation with `lc process`
│   ├── 8.1 Processor basics
│   │   ├── Starting a processor
│   │   ├── Receiving from hunters
│   │   └── Hunter management
│   │
│   ├── 8.2 PCAP writing modes
│   │   ├── Unified PCAP
│   │   ├── Per-call PCAP (VoIP)
│   │   └── Auto-rotating PCAP
│   │
│   ├── 8.3 Command hooks
│   │   ├── PCAP completion hooks
│   │   ├── VoIP call completion hooks
│   │   └── Placeholder reference
│   │
│   ├── 8.4 Filter management
│   │   ├── Static filters
│   │   ├── Dynamic filter updates
│   │   └── Filter distribution to hunters
│   │
│   └── 8.5 Advanced topologies
│       ├── Hierarchical mode
│       └── Multi-processor deployments
│
└── Chapter 9: Standalone Mode with `lc tap`
    ├── When to use tap vs hunt+process
    ├── Tap as "hunt + process − gRPC"
    ├── Configuration
    └── Upstream forwarding

PART IV: ADMINISTRATION & MONITORING
├── Chapter 10: CLI Administration
│   ├── lc show commands
│   │   ├── show status
│   │   ├── show hunter
│   │   ├── show topology
│   │   └── show filter
│   │
│   ├── lc list commands
│   │   ├── list interfaces
│   │   ├── list hunters
│   │   └── list filters
│   │
│   └── lc set/rm commands (filter management)
│       ├── set filter (add/update filters)
│       ├── rm filter (remove filters)
│       └── Filter lifecycle management
│
├── Chapter 11: Remote TUI Monitoring
│   ├── Connecting to remote processors
│   ├── Multi-node monitoring
│   ├── Node file configuration
│   ├── Hunter subscription management
│   └── Filter management in TUI
│       ├── Viewing active filters
│       ├── Adding/removing filters
│       └── Filter propagation to hunters
│
└── Chapter 12: Operations Runbook
    ├── Health checks
    ├── Log analysis
    ├── Common issues
    └── Capacity planning

PART V: PRODUCTION & ADVANCED
├── Chapter 13: Security
│   ├── TLS configuration
│   ├── Mutual TLS (mTLS)
│   ├── Certificate management
│   └── Production mode enforcement
│
├── Chapter 14: Performance Optimization
│   ├── TCP performance profiles
│   ├── GPU acceleration
│   ├── High-speed capture (AF_XDP)
│   └── Distributed scaling
│
├── Chapter 15: Protocol Deep Dives
│   ├── VoIP (SIP/RTP/SRTP)
│   ├── DNS analysis
│   ├── TLS inspection
│   └── HTTP/Email
│
├── Chapter 16: Lawful Interception
│   ├── ETSI X1/X2/X3 overview
│   ├── Build requirements
│   ├── Configuration
│   └── Certificate setup
│
└── Chapter 17: Troubleshooting
    ├── Capture issues
    ├── TCP reassembly problems
    ├── Distributed connectivity
    └── GPU troubleshooting

APPENDICES
├── Appendix A: Command Reference
│   ├── All commands with flags
│   └── Environment variables
│
├── Appendix B: Configuration Reference
│   ├── YAML schema
│   └── Configuration precedence
│
├── Appendix C: BPF Filter Reference
│   └── Common filter patterns
│
└── Appendix D: Glossary
    └── Terms and definitions
```

## TUI Placement Decision

### Option Analysis

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| TUI before sniff | Start visual | Familiar to Wireshark users | Assumes TUI comfort |
| TUI after sniff | CLI first, then visual | Reinforces concepts | Interrupts CLI flow |
| TUI split | Local early, remote later | Logical progression | More complex TOC |

### Recommendation: Split TUI Coverage

Introduce TUI in two phases:

1. **Chapter 5** (after sniff): Local TUI modes
   - `lc watch live` — same as sniff, visual interface
   - `lc watch file` — PCAP analysis, like Wireshark

2. **Chapter 11** (after process): Remote TUI
   - `lc watch remote` — requires distributed knowledge
   - Multi-node monitoring

**Rationale**: The local TUI modes reinforce sniff concepts with visual feedback, while remote monitoring only makes sense after understanding hunters and processors.

## Format Considerations

### Recommended: mdBook

**Why mdBook?**
- Rust-based static site generator (fits project ecosystem)
- Beautiful web output with search
- Table of contents navigation
- Code syntax highlighting
- Can be hosted on GitHub Pages
- Source is plain markdown (Git-friendly)

**Alternative Formats Considered**:

| Format | Pros | Cons |
|--------|------|------|
| Single markdown | Simple, searchable | Hard to navigate at scale |
| GitBook | Feature-rich | Commercial, external dependency |
| Man pages | Unix tradition, offline | Limited formatting |
| Docusaurus | React-based, versioning | Heavy dependency |

### Directory Structure

```
docs/manual/
├── book.toml              # mdBook configuration
├── src/
│   ├── SUMMARY.md         # Table of contents
│   ├── part1-foundations/
│   │   ├── introduction.md
│   │   ├── core-concepts.md
│   │   └── installation.md
│   ├── part2-local-capture/
│   │   ├── sniff.md
│   │   └── watch-local.md
│   ├── part3-distributed/
│   │   ├── architecture.md
│   │   ├── hunt.md
│   │   ├── process.md
│   │   └── tap.md
│   ├── part4-administration/
│   │   ├── cli-admin.md
│   │   └── watch-remote.md
│   ├── part5-advanced/
│   │   ├── security.md
│   │   ├── performance.md
│   │   └── troubleshooting.md
│   └── appendices/
│       ├── command-reference.md
│       ├── config-reference.md
│       └── glossary.md
└── theme/                 # Custom styling (optional)
```

## Implementation Considerations

### Content Strategy

1. **Don't duplicate**: Reference existing docs where appropriate
   - Link to SECURITY.md for certificate generation details
   - Link to PERFORMANCE.md for tuning specifics

2. **Consolidate**: Move scattered explanations into the manual
   - BPF filter syntax (currently in 3+ places)
   - VoIP capture patterns (currently in 5+ places)

3. **Canonical definitions**: Define terms once in the manual, reference thereafter
   - "Hunter" defined in Chapter 6, used throughout
   - "Per-call PCAP" defined in Chapter 8.2, referenced elsewhere

### Relationship to Existing Docs

| Doc Type | Future Role |
|----------|-------------|
| README.md files | Quick start, link to manual |
| CLAUDE.md files | Architecture reference (unchanged) |
| docs/*.md | Deep-dive supplements to manual |
| Manual | Primary learning resource |

### Estimated Scope

| Part | Chapters | Estimated Pages |
|------|----------|-----------------|
| Foundations | 3 | 15-20 |
| Local Capture | 2 | 25-30 |
| Distributed | 4 | 40-50 |
| Administration | 3 | 20-25 |
| Advanced | 5 | 35-40 |
| Appendices | 4 | 20-25 |
| **Total** | **21** | **~160** |

## Open Questions (Resolved)

1. **Scope for v1**: Full manual (~160 pages) or focused guide (~50 pages)?

   **Decision**: Focused guide (~50 pages). Start with Parts I-II (Foundations + Local Capture) — this covers what 80% of new users need first. Ship something useful quickly and expand incrementally. mdBook makes adding chapters easy since each is its own file.

2. **Code examples**: Should examples be runnable scripts or embedded snippets?

   **Decision**: Embedded snippets. Runnable scripts add maintenance overhead (need test infrastructure to stay correct) and most users will adapt commands to their own environment. The existing README examples already follow this pattern.

3. **Screenshots**: Include TUI screenshots? (maintenance burden vs clarity)

   **Decision**: Yes, but sparingly — only for the initial TUI introduction (Chapter 5) to orient new users. After that, text descriptions suffice. Screenshots rot fast when UI changes, so keep them to stable, high-level views. Consider using `vhs` or `terminalizer` to generate them from scripts for easier updates.

4. **Versioning**: Track manual version separately from software version?

   **Decision**: No separate versioning. Tie the manual to the software version. Separate versioning creates confusion ("which manual version matches my binary?") and doubles the release checklist. The manual lives in the same repo — it should move with the code.

5. **Localization**: English-only or plan for translations?

   **Decision**: English-only. Translations are a massive ongoing maintenance burden and the target audience (network engineers, security professionals) overwhelmingly works in English. mdBook supports multi-language books if demand appears later.

## Next Steps

- [x] Decide on scope (focused guide, Parts I-II first)
- [x] Choose format (mdBook)
- [ ] Create directory structure
- [ ] Draft Part I (Foundations) as proof of concept
- [ ] Review and iterate
- [ ] Integrate with existing documentation
- [ ] Set up build/publish pipeline

## References

- Existing documentation inventory (see agent exploration above)
- mdBook documentation: https://rust-lang.github.io/mdBook/
- tcpdump manual (reference for CLI capture docs): https://www.tcpdump.org/manpages/tcpdump.1.html
- Wireshark User's Guide (reference for TUI/analysis docs): https://www.wireshark.org/docs/wsug_html/
