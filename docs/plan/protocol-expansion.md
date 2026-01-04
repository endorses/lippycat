# Protocol Expansion Implementation Plan

**Date:** 2026-01-03
**Status:** Phase 2 In Progress (8/9 tasks complete)
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

## Phase 1: DNS (2-3 days) ✅ COMPLETE

**Priority:** Highest - Low effort, high value, strong LI relevance

- [x] Create `internal/pkg/dns/` package (parser, tracker, plugin)
- [x] Add `DNSMetadata` type in `internal/pkg/types/`
- [x] Create `cmd/hunt/dns.go` (hunter node)
- [x] Create `cmd/tap/dns.go` (standalone capture)
- [x] Create `cmd/sniff/dns.go` (CLI mode)
- [x] Add DNS protocol view in TUI (toggle with `v`)
- [x] Query/response correlation via transaction ID
- [x] DNS tunneling detection (entropy analysis)

## Phase 2: Email - SMTP (3-4 days)

**Priority:** High - Major LI use case

- [x] Create `internal/pkg/email/` package
- [x] Add `EmailMetadata` type (envelope: MAIL FROM, RCPT TO, Subject)
- [x] SMTP parser using TCP reassembly (already working from SIP)
- [x] Create `cmd/hunt/email.go` (hunter node)
- [x] Create `cmd/tap/email.go` (standalone capture)
- [x] Create `cmd/sniff/email.go` (CLI mode)
- [ ] Add Email protocol view in TUI (toggle with `v`)
- [x] STARTTLS detection
- [x] Message-ID correlation

## Phase 3: TLS/JA3 Fingerprinting (3-4 days)

**Priority:** High - Critical for encrypted traffic analysis

- [ ] Create `internal/pkg/tls/` package
- [ ] Add `TLSMetadata` type (SNI, cipher suites, fingerprints)
- [ ] ClientHello parser (no decryption needed)
- [ ] JA3/JA3S/JA4 fingerprint calculation
- [ ] Create `cmd/hunt/tls.go` (hunter node)
- [ ] Create `cmd/tap/tls.go` (standalone capture)
- [ ] Create `cmd/sniff/tls.go` (CLI mode)
- [ ] Add TLS protocol view in TUI (toggle with `v`)
- [ ] Fingerprint database integration hooks

## Phase 4: HTTP (4-5 days)

**Priority:** Medium - Complements TLS analysis

- [ ] Create `internal/pkg/http/` package
- [ ] Add `HTTPMetadata` type (method, URL, headers, status)
- [ ] HTTP/1.x request/response parser
- [ ] Request/response correlation
- [ ] Create `cmd/hunt/http.go` (hunter node)
- [ ] Create `cmd/tap/http.go` (standalone capture)
- [ ] Create `cmd/sniff/http.go` (CLI mode)
- [ ] Add HTTP protocol view in TUI (toggle with `v`)
- [ ] Content-type classification

## Phase 5: Email - IMAP/POP3 (4-5 days)

**Priority:** Medium - Completes email protocol suite

- [ ] Extend `EmailMetadata` for IMAP/POP3 fields
- [ ] IMAP command parser (SELECT, FETCH, SEARCH)
- [ ] POP3 command parser
- [ ] Mailbox operation tracking
- [ ] Update `cmd/hunt/email.go` for IMAP/POP3 support
- [ ] Update `cmd/tap/email.go` for IMAP/POP3 support
- [ ] Update `cmd/sniff/email.go` for IMAP/POP3 support

## Phase 6: Database Protocols (10-14 days) - Optional

**Priority:** Lower - High effort, niche use case

- [ ] Create `internal/pkg/database/` package
- [ ] Add `DatabaseMetadata` type (query, username, database, tables)
- [ ] MySQL protocol parser
- [ ] PostgreSQL protocol parser
- [ ] Query extraction and logging
- [ ] Create `cmd/hunt/db.go` (hunter node)
- [ ] Create `cmd/tap/db.go` (standalone capture)
- [ ] Create `cmd/sniff/db.go` (CLI mode)
- [ ] Add Database protocol view in TUI (toggle with `v`)

## Implementation Notes

1. **Separate packages per protocol:** `internal/pkg/dns/`, `internal/pkg/email/`, etc.
2. **Type-safe metadata:** Add protocol-specific fields to `PacketDisplay` (e.g., `DNSData *DNSMetadata`)
3. **Reuse Aho-Corasick:** Existing `internal/pkg/ahocorasick/` for content filtering in email/HTTP

## Estimated Timeline

| Phase | Protocol | Effort |
|-------|----------|--------|
| 1 | DNS | 2-3 days |
| 2 | SMTP | 3-4 days |
| 3 | TLS/JA3 | 3-4 days |
| 4 | HTTP | 4-5 days |
| 5 | IMAP/POP3 | 4-5 days |
| 6 | Database | 10-14 days |

**Total (Phases 1-5):** ~17-21 days
