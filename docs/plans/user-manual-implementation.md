# User Manual Implementation Plan

## Overview

Implement the user manual for lippycat using mdBook, starting with the focused scope (Parts I-II: Foundations + Local Capture, ~50 pages) as decided in the research document.

**Research**: [docs/research/user-manual-design.md](../research/user-manual-design.md)

## Phase 1: Project Setup

- [x] Install mdBook (`cargo install mdbook` or download binary)
- [x] Create directory structure under `docs/manual/`
- [x] Create `book.toml` with project metadata (title, authors, language, build output dir)
- [x] Create `src/SUMMARY.md` with the full TOC skeleton (Parts I-V + Appendices), marking future chapters as draft/commented
- [x] Create placeholder `.md` files for Parts I-II chapters
- [x] Add mdBook build commands to `Makefile` (`make manual`, `make manual-serve`)
- [x] Add `docs/manual/book/` to `.gitignore` (built output)
- [x] Verify `mdbook build` and `mdbook serve` work

## Phase 2: Part I — Foundations

### Chapter 1: Introduction (`src/part1-foundations/introduction.md`)

- [x] "What is lippycat?" — positioning as a network traffic analysis tool
- [x] Use cases: network monitoring, VoIP analysis, security monitoring, distributed capture
- [x] Comparison table with tcpdump, Wireshark, tshark (what lippycat adds)
- [x] "When to use lippycat" decision framework
- [x] Command overview diagram showing the verb hierarchy (`sniff`, `watch`, `hunt`, `process`, `tap`)

### Chapter 2: Core Concepts (`src/part1-foundations/core-concepts.md`)

- [x] Packets and protocols primer (just enough for context, not a networking textbook)
- [x] Network interfaces and capture mechanics (promiscuous mode, `CAP_NET_RAW`)
- [x] BPF filters — what they are, why they matter, basic syntax
- [x] PCAP format — what it is, tools that consume it
- [x] Protocol analysis basics — how lippycat dissects packets
- [x] The distributed model at a high level (hunter/processor/tap — conceptual only, details in Part III)

### Chapter 3: Installation & Setup (`src/part1-foundations/installation.md`)

- [x] ~~Binary installation (download pre-built binaries)~~ Removed — no releases page exists
- [x] Building from source (`make build`, `make binaries`, build tags explanation)
- [x] Specialized builds table (hunter, processor, tap, cli, tui)
- [x] Permissions setup: `CAP_NET_RAW` vs `sudo`, security implications
- [x] Configuration file: locations, YAML schema basics, precedence order
- [x] Environment variables (`LIPPYCAT_PRODUCTION`)
- [x] Verifying installation: `lc list interfaces`, `lc show config`

## Phase 3: Part II — Local Capture

### Chapter 4: CLI Capture with `lc sniff` (`src/part2-local-capture/sniff.md`)

- [x] **4.1 Your first capture**
  - [x] Selecting an interface (`lc list interfaces`)
  - [x] Basic capture: `sudo lc sniff -i eth0`
  - [x] Reading CLI output (columns, fields)
  - [x] Stopping capture (Ctrl+C), packet count summary
  - [x] Basic BPF filtering: `-f "port 53"`, `-f "host 10.0.0.1"`

- [x] **4.2 Protocol modes**
  - [x] Overview: protocol subcommands and when to use each
  - [x] DNS analysis: `lc sniff dns` — flags, output, use cases
  - [x] TLS inspection: `lc sniff tls` — what's visible without decryption
  - [x] HTTP capture: `lc sniff http` — request/response logging
  - [x] Email monitoring: `lc sniff email` — SMTP/IMAP/POP3 capture
  - [x] VoIP analysis: `lc sniff voip` — SIP/RTP, `--sip-user`, per-call tracking

- [x] **4.3 Output and PCAP**
  - [x] CLI output format and verbosity flags
  - [x] Writing PCAP files: `-w output.pcap`
  - [x] Per-call PCAP for VoIP (noted as processor/tap feature)
  - [x] ESP-NULL decapsulation flags
  - [x] Integrating with Wireshark/tshark (opening lippycat PCAPs)

- [x] **4.4 Performance tuning**
  - [x] TCP reassembly modes (`--tcp-performance-mode`)
  - [x] UDP-only mode for VoIP (`-U`)
  - [x] GPU acceleration overview (brief, link to Chapter 14 for details)
  - [x] Virtual interface injection (`-V` / `--virtual-interface`)

### Chapter 5: Interactive Capture with `lc watch` (`src/part2-local-capture/watch-local.md`)

- [x] **5.1 Live capture mode**
  - [x] Starting live capture: `sudo lc watch` / `sudo lc watch live`
  - [x] TUI layout orientation (tabs table)
  - [x] Navigation: scrolling, selecting packets
  - [x] Keybindings reference table

- [x] **5.2 PCAP file analysis**
  - [x] Opening a single PCAP: `lc watch file capture.pcap`
  - [x] Multi-file analysis: `lc watch file sip.pcap rtp.pcap`
  - [x] Searching and filtering within TUI

- [x] **5.3 TUI features**
  - [x] Tabs and views
  - [x] Statistics display
  - [x] Help system (`?` key)
  - [x] Toast notifications

## Phase 4: Skeleton for Parts III-V & Appendices

Create stub files with section headers and "Coming soon" markers so the TOC is navigable and the structure is clear for future expansion.

- [x] Part III stubs: `architecture.md`, `hunt.md`, `process.md`, `tap.md`
- [x] Part IV stubs: `cli-admin.md`, `watch-remote.md`, `operations.md`
- [x] Part V stubs: `security.md`, `performance.md`, `protocol-deep-dives.md`, `lawful-interception.md`, `troubleshooting.md`
- [x] Appendix stubs: `command-reference.md`, `config-reference.md`, `bpf-reference.md`, `glossary.md`

## Phase 5: Build Integration & Polish

- [x] Review all chapters for consistent voice and terminology
- [x] Ensure all code examples are accurate against current CLI flags (verify with `lc <cmd> --help`)
- [x] Add cross-references between chapters (mdBook link syntax)
- [ ] Add any TUI screenshots for Chapter 5 (`vhs` not available; deferred)
- [x] Test `mdbook build` produces clean output with no broken links
- [x] Fix external links in stub files (converted to repo-relative code references)
- [x] Add GPU flags to watch live documentation
- [ ] Test `mdbook serve` for local preview (manual step)
- [x] Add CI step to build manual (added to integration-tests.yml)

## Directory Structure

```
docs/manual/
├── book.toml
├── src/
│   ├── SUMMARY.md
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
│   │   ├── watch-remote.md
│   │   └── operations.md
│   ├── part5-advanced/
│   │   ├── security.md
│   │   ├── performance.md
│   │   ├── protocol-deep-dives.md
│   │   ├── lawful-interception.md
│   │   └── troubleshooting.md
│   └── appendices/
│       ├── command-reference.md
│       ├── config-reference.md
│       ├── bpf-reference.md
│       └── glossary.md
└── theme/                    # Optional custom styling
```

## Content Sources

When writing each chapter, pull from these existing docs:

| Chapter | Primary Sources |
|---------|----------------|
| Ch 1: Introduction | `README.md`, `CLAUDE.md` |
| Ch 2: Core Concepts | `CLAUDE.md`, `docs/DISTRIBUTED_MODE.md` |
| Ch 3: Installation | `README.md`, `Makefile`, `CLAUDE.md` build section |
| Ch 4: Sniff | `cmd/sniff/README.md`, `cmd/sniff/CLAUDE.md`, `docs/PERFORMANCE.md` |
| Ch 5: Watch Local | `cmd/watch/README.md`, `cmd/watch/CLAUDE.md`, `internal/pkg/tui/CLAUDE.md` |

## Notes

- **Don't duplicate operational docs**: Link to `docs/SECURITY.md`, `docs/PERFORMANCE.md`, etc. for deep dives
- **Keep examples runnable**: Every `lc` command shown should work against the current binary
- **Manual version = software version**: No separate versioning
- **English only**: No localization planned
