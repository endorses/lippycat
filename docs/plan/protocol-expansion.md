# Protocol Expansion Implementation Plan

**Date:** 2026-01-03
**Status:** Phase 1-2 Protocol Support Complete, Phase 1 Content Filtering Complete
**Research:** [docs/research/protocol-expansion-roadmap.md](../research/protocol-expansion-roadmap.md)

## Overview

Expand lippycat beyond VoIP to support additional protocols. Detection signatures already exist for most protocols; the work is creating deep analysis plugins and command variants for the distributed capture architecture.

**Priority:** Hunt/tap (distributed capture) are the primary deployment modes. Sniff is secondary.

## Design Decisions

### Protocol Naming

Unified commands per protocol with optional `--protocol` flag for sub-protocol filtering:

```bash
lc hunt email              # All email protocols (SMTP, IMAP, POP3)
lc hunt email --protocol smtp   # SMTP only
lc tap dns
lc sniff tls
```

### TUI Integration

Follow existing VoIP pattern:
- `p` → Select protocol (DNS, Email, VoIP, TLS, HTTP)
- `v` → Toggle between protocol-specific view and packet list

Each protocol implements its own detail view (like VoIP call list).

### LI Mapping (ETSI X2/X3)

| Protocol | Data Type | ETSI Interface |
|----------|-----------|----------------|
| DNS | Query/response | X2 (IRI) |
| Email | Envelope (FROM, TO, Subject) | X2 (IRI) |
| Email | Body/attachments | X3 (CC) |
| HTTP | URL, headers, method | X2 (IRI) |
| HTTP | Request/response body | X3 (CC) |
| TLS | SNI, fingerprints | X2 (IRI) |

### Filter Syntax

Glob-style wildcards compile to existing AC pattern types:

| Syntax | Pattern Type | Example |
|--------|--------------|---------|
| `*foo` | Suffix | `*.malware.com` |
| `foo*` | Prefix | `admin@*` |
| `*foo*` or `foo` | Contains | `confidential` |

### Filter Configuration

Layered (lowest to highest priority):
1. CLI flags: `--keywords-file ./keywords.txt`
2. Config file: `filters.email.keywords_file`
3. X1 task activation (LI mode, overrides all)

### Output Architecture

All commands (sniff/tap/hunt) use existing output mechanisms:

| Output | sniff | tap | hunt |
|--------|-------|-----|------|
| CLI stdout | ✓ | ✓ | ✓ |
| PCAP file | ✓ | ✓ (per-session) | - |
| Virtual interface | ✓ | ✓ | - |
| gRPC upstream | - | ✓ (optional) | ✓ |
| gRPC to TUI | - | ✓ | - |
| X2/X3 delivery | - | ✓ | - |

New protocols plug into these existing paths—no new output mechanisms needed.

## Phase 1: DNS (2-3 days) - Complete ✅

**Priority:** Highest - Low effort, high value, strong LI relevance

### Protocol Support ✅
- [x] Create `internal/pkg/dns/` package (parser, tracker, plugin)
- [x] Add `DNSMetadata` type in `internal/pkg/types/`
- [x] Create `cmd/hunt/dns.go` (hunter node)
- [x] Create `cmd/tap/dns.go` (standalone capture)
- [x] Create `cmd/sniff/dns.go` (CLI mode)
- [x] Add DNS protocol view in TUI (toggle with `v`)
- [x] Query/response correlation via transaction ID
- [x] DNS tunneling detection (entropy analysis)

### Content Filtering ✅
- [x] Glob pattern matching implementation (extracted to `internal/pkg/filtering/glob.go`)
- [x] Wire `--domain` flag to sniff mode (`core.go` reads `dns.domain_pattern` from viper)
- [x] Add `--domain` flag to hunt command (creates DNS processor with domain patterns)
- [x] Add `--domain` flag to tap command (stores in viper for processor-level filtering)
- [x] Add `--domains-file` flag for bulk domain lists (load patterns from file)
- [x] GlobMatcher type with O(1) exact match lookup and AC integration foundation

## Phase 2: Email - SMTP (3-4 days) - Protocol Complete, Filtering Incomplete

**Priority:** High - Major LI use case

### Protocol Support ✅
- [x] Create `internal/pkg/email/` package
- [x] Add `EmailMetadata` type (envelope: MAIL FROM, RCPT TO, Subject)
- [x] SMTP parser using TCP reassembly (already working from SIP)
- [x] Create `cmd/hunt/email.go` (hunter node)
- [x] Create `cmd/tap/email.go` (standalone capture)
- [x] Create `cmd/sniff/email.go` (CLI mode)
- [x] Add Email protocol view in TUI (toggle with `v`)
- [x] STARTTLS detection
- [x] Message-ID correlation

### Content Filtering ⚠️ Not Implemented
- [ ] Create `internal/pkg/email/content_filter.go` with glob pattern matching
- [ ] Add `--sender` flag (filter by MAIL FROM, glob pattern e.g., `*@example.com`)
- [ ] Add `--recipient` flag (filter by RCPT TO, glob pattern)
- [ ] Add `--address` flag (match either sender OR recipient)
- [ ] Wire existing `--address` flag in hunt command (defined but ignored)
- [ ] Add `--subject` flag (filter by Subject header, glob pattern)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for body/subject)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching
- [ ] Add filter support to sniff, tap, and hunt commands

## Phase 3: TLS/JA3 Fingerprinting (3-4 days)

**Priority:** High - Critical for encrypted traffic analysis

### Protocol Support
- [ ] Create `internal/pkg/tls/` package
- [ ] Add `TLSMetadata` type (SNI, cipher suites, fingerprints)
- [ ] ClientHello parser (no decryption needed)
- [ ] JA3/JA3S/JA4 fingerprint calculation
- [ ] Create `cmd/hunt/tls.go` (hunter node)
- [ ] Create `cmd/tap/tls.go` (standalone capture)
- [ ] Create `cmd/sniff/tls.go` (CLI mode)
- [ ] Add TLS protocol view in TUI (toggle with `v`)
- [ ] Fingerprint database integration hooks

### Content Filtering
- [ ] Add `--sni` flag (filter by SNI hostname, glob pattern e.g., `*.example.com`)
- [ ] Add `--sni-file` flag (bulk SNI patterns from file)
- [ ] Add `--ja3` flag (filter by JA3 fingerprint hash)
- [ ] Add `--ja3-file` flag (known-bad fingerprint list)
- [ ] Add `--ja3s` flag (filter by server JA3S fingerprint)
- [ ] Integrate with Aho-Corasick for multi-SNI matching

## Phase 4: HTTP (4-5 days)

**Priority:** Medium - Complements TLS analysis

### Protocol Support
- [ ] Create `internal/pkg/http/` package
- [ ] Add `HTTPMetadata` type (method, URL, headers, status)
- [ ] HTTP/1.x request/response parser
- [ ] Request/response correlation
- [ ] Create `cmd/hunt/http.go` (hunter node)
- [ ] Create `cmd/tap/http.go` (standalone capture)
- [ ] Create `cmd/sniff/http.go` (CLI mode)
- [ ] Add HTTP protocol view in TUI (toggle with `v`)
- [ ] Content-type classification

### Content Filtering
- [ ] Add `--host` flag (filter by Host header, glob pattern)
- [ ] Add `--url` flag (filter by URL path, glob pattern e.g., `/api/*`)
- [ ] Add `--method` flag (filter by HTTP method: GET, POST, etc.)
- [ ] Add `--status` flag (filter by response status code range e.g., `4xx`, `500-599`)
- [ ] Add `--user-agent` flag (filter by User-Agent header, glob pattern)
- [ ] Add `--content-type` flag (filter by Content-Type header)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for URL/headers/body)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching

## Phase 5: Email - IMAP/POP3 (4-5 days)

**Priority:** Medium - Completes email protocol suite

### Protocol Support
- [ ] Extend `EmailMetadata` for IMAP/POP3 fields
- [ ] IMAP command parser (SELECT, FETCH, SEARCH)
- [ ] POP3 command parser
- [ ] Mailbox operation tracking
- [ ] Update `cmd/hunt/email.go` for IMAP/POP3 support
- [ ] Update `cmd/tap/email.go` for IMAP/POP3 support
- [ ] Update `cmd/sniff/email.go` for IMAP/POP3 support

### Content Filtering
- [ ] Extend Phase 2 email filters to IMAP/POP3 (same `--sender`, `--recipient`, etc.)
- [ ] Add `--mailbox` flag (filter by mailbox name for IMAP)
- [ ] Add `--command` flag (filter by IMAP/POP3 command: FETCH, SEARCH, RETR, etc.)

## Phase 6: Database Protocols (10-14 days) - Optional

**Priority:** Lower - High effort, niche use case

### Protocol Support
- [ ] Create `internal/pkg/database/` package
- [ ] Add `DatabaseMetadata` type (query, username, database, tables)
- [ ] MySQL protocol parser
- [ ] PostgreSQL protocol parser
- [ ] Query extraction and logging
- [ ] Create `cmd/hunt/db.go` (hunter node)
- [ ] Create `cmd/tap/db.go` (standalone capture)
- [ ] Create `cmd/sniff/db.go` (CLI mode)
- [ ] Add Database protocol view in TUI (toggle with `v`)

### Content Filtering
- [ ] Add `--user` flag (filter by database username)
- [ ] Add `--database` flag (filter by database name)
- [ ] Add `--table` flag (filter by table name in query, glob pattern)
- [ ] Add `--query-type` flag (filter by query type: SELECT, INSERT, UPDATE, DELETE)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for query content)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching

## Implementation Notes

1. **Separate packages per protocol:** `internal/pkg/dns/`, `internal/pkg/email/`, etc.
2. **Type-safe metadata:** Add protocol-specific fields to `PacketDisplay` (e.g., `DNSData *DNSMetadata`)
3. **Reuse Aho-Corasick:** Existing `internal/pkg/ahocorasick/` for content filtering in email/HTTP
4. **Filter architecture pattern:**
   - Each protocol package has a `content_filter.go` with `FilterConfig` struct and `Match()` method
   - CLI flags bound to viper (`protocol.filter_field`)
   - Commands read viper config and pass to processor/sniffer
   - Glob patterns use existing `matchGlob()` from DNS (extract to shared package)
   - Bulk patterns use Aho-Corasick matcher
5. **Consistent flag naming:**
   - Single pattern: `--domain`, `--sender`, `--host`
   - Bulk file: `--domains-file`, `--senders-file`, `--hosts-file`
   - Keywords: `--keywords-file` (universal Aho-Corasick patterns)

## Estimated Timeline

| Phase | Protocol | Protocol Support | Content Filtering | Total |
|-------|----------|------------------|-------------------|-------|
| 1 | DNS | ✅ Complete | 1 day | 1 day remaining |
| 2 | SMTP | ✅ Complete | 1-2 days | 1-2 days remaining |
| 3 | TLS/JA3 | 3-4 days | 1 day | 4-5 days |
| 4 | HTTP | 4-5 days | 1-2 days | 5-7 days |
| 5 | IMAP/POP3 | 4-5 days | 0.5 days (reuse Phase 2) | 4-5 days |
| 6 | Database | 10-14 days | 1-2 days | 11-16 days |

**Remaining work (Phases 1-5):** ~16-20 days
- Phase 1-2 filtering backfill: 2-3 days
- Phase 3-5 new work: ~14-17 days

## Current Status (2026-01-04)

### What Works
- DNS and SMTP protocol parsing and display (sniff, hunt, tap, TUI)
- DNS query/response correlation and tunneling detection
- SMTP envelope extraction (MAIL FROM, RCPT TO, Subject)
- BPF port-level filtering for both protocols
- **DNS content filtering complete:**
  - `--domain` flag works in sniff, hunt, and tap commands
  - `--domains-file` flag loads bulk patterns from file
  - Shared `filtering.MatchGlob()` for case-insensitive glob matching
  - `GlobMatcher` type with O(1) exact match optimization

### What's Broken/Incomplete
1. **Email `--address` flag** (`cmd/hunt/email.go`): Flag defined but never passed to any filter logic
2. **Email content filtering**: No filter implementation exists in the email package

### Recommended Next Steps
1. Create `internal/pkg/email/content_filter.go` with sender/recipient/address matching
2. Wire Email `--address`, `--sender`, `--recipient` flags through all commands
3. Add `--keywords-file` for Aho-Corasick pattern matching in email body/subject
