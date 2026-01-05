# Protocol Expansion Implementation Plan

**Date:** 2026-01-03
**Updated:** 2026-01-05
**Status:** Phase 0 Complete, Phase 1-2 Protocol Support Complete
**Research:** [docs/research/protocol-expansion-roadmap.md](../research/protocol-expansion-roadmap.md)

## Overview

Expand lippycat beyond VoIP to support additional protocols. Detection signatures already exist for most protocols; the work is creating deep analysis plugins and command variants for the distributed capture architecture.

**Priority:** Hunt/tap (distributed capture) are the primary deployment modes. Sniff is secondary.

## Filter Distribution Architecture

### Current State

The filter distribution infrastructure exists but only supports VoIP filter types:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Processor                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Filter       │───▶│ gRPC         │───▶│ Push to Hunters  │   │
│  │ Registry     │    │ Management   │    │ (FilterUpdate)   │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│         ▲                                                       │
│         │ CRUD                                                  │
│  ┌──────┴──────┐                                                │
│  │ TUI Filter  │  CLI: lc set/rm/list/show filter               │
│  │ Manager     │                                                │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ gRPC SubscribeFilters
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Hunter                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Filter       │◀───│ gRPC         │◀───│ Receive Updates  │   │
│  │ Matcher      │    │ Client       │    │ (FilterUpdate)   │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│         │                                                       │
│         ▼ Match packets                                         │
│  ┌──────────────┐                                               │
│  │ Forward only │                                               │
│  │ matched pkts │                                               │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Existing FilterType Enum (VoIP only)

```protobuf
enum FilterType {
    FILTER_SIP_USER = 0;
    FILTER_PHONE_NUMBER = 1;
    FILTER_IP_ADDRESS = 2;
    FILTER_CALL_ID = 3;
    FILTER_CUSTOM = 4;
    FILTER_BPF = 5;
    FILTER_SIP_URI = 6;
}
```

### Required New Filter Types

| Protocol | Filter Type | Pattern Examples |
|----------|-------------|------------------|
| DNS | `FILTER_DNS_DOMAIN` | `*.example.com`, `malware.com` |
| Email | `FILTER_EMAIL_ADDRESS` | `*@example.com`, `admin@*` |
| Email | `FILTER_EMAIL_SUBJECT` | `*confidential*` |
| TLS | `FILTER_TLS_SNI` | `*.google.com` |
| TLS | `FILTER_TLS_JA3` | `abc123...` (client fingerprint hash) |
| TLS | `FILTER_TLS_JA3S` | `def456...` (server fingerprint hash) |
| TLS | `FILTER_TLS_JA4` | `t13d...` (JA4 format fingerprint) |
| HTTP | `FILTER_HTTP_HOST` | `*.example.com` |
| HTTP | `FILTER_HTTP_URL` | `/api/*`, `*/admin/*` |

### Filter Modes by Command

| Command | Filter Source | Notes |
|---------|---------------|-------|
| `sniff` | Local CLI flags | Standalone, no distribution |
| `tap` | Local CLI flags | Standalone with processor capabilities |
| `hunt` | Processor via gRPC | Receives filters from connected processor |

**Key principle:** Hunt commands do NOT have application-level filter flags. They receive filter configuration from processors via gRPC.

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

## Phase 0: Filter Distribution Infrastructure (2-3 days) ✅

**Priority:** Critical - Required before any protocol content filtering works in distributed mode

**Prerequisite:** This phase must be completed before content filtering in Phases 1-6 can work in hunt mode.

**Status:** Completed 2026-01-05

### Proto Changes ✅
- [x] Add `FILTER_DNS_DOMAIN` to FilterType enum in `api/proto/management.proto`
- [x] Add `FILTER_EMAIL_ADDRESS` to FilterType enum
- [x] Add `FILTER_EMAIL_SUBJECT` to FilterType enum
- [x] Add `FILTER_TLS_SNI` to FilterType enum
- [x] Add `FILTER_TLS_JA3` to FilterType enum (client fingerprint)
- [x] Add `FILTER_TLS_JA3S` to FilterType enum (server fingerprint)
- [x] Add `FILTER_TLS_JA4` to FilterType enum (updated format)
- [x] Add `FILTER_HTTP_HOST` to FilterType enum
- [x] Add `FILTER_HTTP_URL` to FilterType enum
- [x] Regenerate proto: `make proto` (via `cd api/proto && make`)

### Hunter Filter Matching ✅
- [x] Create `internal/pkg/hunter/filter/dns.go` - DNS domain matching
- [x] Create `internal/pkg/hunter/filter/email.go` - Email address/subject matching
- [x] Create `internal/pkg/hunter/filter/tls.go` - SNI/JA3/JA3S/JA4 matching
- [x] Create `internal/pkg/hunter/filter/http.go` - Host/URL matching
- [x] Create `internal/pkg/hunter/filter/matcher.go` - Base matcher interface
- [x] Add filter type capability reporting in hunter registration (SupportedFilterTypes config field)

### Processor Filter Registry ✅
- [x] Processor filter registry already supports new types via proto enum
- [x] Validate filter patterns on creation (glob syntax, JA3 hash format, etc.) - `filtering.ValidatePattern()`
- [x] Push filter updates to hunters via existing gRPC mechanism (already working)

### CLI Updates ✅
- [x] Update `internal/pkg/filtering/types.go` to parse new filter types
- [x] Update `internal/pkg/filtering/conversion.go` with new type conversions
- [x] Update `lc set filter --type` to accept new types (dns_domain, email_address, etc.)
- [x] Add validation for protocol-specific pattern formats (JA3: 32-char hex, JA4: fingerprint format)

### TUI Updates ✅
- [x] Update `filtermanager/list.go` AbbreviateType for new types
- [x] Update `filtermanager/state.go` CycleTypeFilter for new types
- [x] Update `filtermanager/editor.go` CycleFormFilterType for new types
- [x] Add filter type category functions (IsDNSFilterType, IsEmailFilterType, etc.)

## Phase 1: DNS (2-3 days) - Protocol Complete, Filtering Partial ⚠️

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

### Content Filtering - Local (sniff/tap) ✅
- [x] Glob pattern matching implementation (extracted to `internal/pkg/filtering/glob.go`)
- [x] Wire `--domain` flag to sniff mode (`core.go` reads `dns.domain_pattern` from viper)
- [x] Add `--domain` flag to tap command (stores in viper for processor-level filtering)
- [x] Add `--domains-file` flag for bulk domain lists (load patterns from file)
- [x] GlobMatcher type with O(1) exact match lookup and AC integration foundation

### Content Filtering - Distributed (hunt) ⚠️ Infrastructure Complete, Wiring Needed
- [x] `FILTER_DNS_DOMAIN` type in proto (Phase 0 - complete)
- [x] Hunter DNS domain matching logic (`internal/pkg/hunter/filter/dns.go`)
- [ ] Wire DNS filters from TUI/CLI to hunters
- [ ] Test end-to-end domain filter distribution

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

### Content Filtering - Local (sniff/tap) ⚠️ Not Implemented
- [ ] Create `internal/pkg/email/content_filter.go` with glob pattern matching
- [ ] Add `--sender` flag (filter by MAIL FROM, glob pattern e.g., `*@example.com`)
- [ ] Add `--recipient` flag (filter by RCPT TO, glob pattern)
- [ ] Add `--address` flag (match either sender OR recipient)
- [ ] Add `--subject` flag (filter by Subject header, glob pattern)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for body/subject)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching
- [ ] Wire filter flags in sniff and tap commands

### Content Filtering - Distributed (hunt) ⚠️ Infrastructure Complete, Wiring Needed
- [x] `FILTER_EMAIL_ADDRESS` type in proto (Phase 0 - complete)
- [x] `FILTER_EMAIL_SUBJECT` type in proto (Phase 0 - complete)
- [x] Hunter email address/subject matching logic (`internal/pkg/hunter/filter/email.go`)
- [ ] Wire email filters from TUI/CLI to hunters
- [ ] Test end-to-end email filter distribution

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

### Content Filtering - Local (sniff/tap)
- [ ] Add `--sni` flag (filter by SNI hostname, glob pattern e.g., `*.example.com`)
- [ ] Add `--sni-file` flag (bulk SNI patterns from file)
- [ ] Add `--ja3` flag (filter by JA3 client fingerprint hash)
- [ ] Add `--ja3-file` flag (known-bad JA3 fingerprint list)
- [ ] Add `--ja3s` flag (filter by JA3S server fingerprint hash)
- [ ] Add `--ja3s-file` flag (known-bad JA3S fingerprint list)
- [ ] Add `--ja4` flag (filter by JA4 fingerprint)
- [ ] Add `--ja4-file` flag (known-bad JA4 fingerprint list)
- [ ] Integrate with Aho-Corasick for multi-SNI matching
- [ ] Wire filter flags in sniff and tap commands

### Content Filtering - Distributed (hunt) ⚠️ Infrastructure Complete, Wiring Needed
- [x] `FILTER_TLS_SNI` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA3` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA3S` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA4` type in proto (Phase 0 - complete)
- [x] Hunter TLS SNI/JA3/JA3S/JA4 matching logic (`internal/pkg/hunter/filter/tls.go`)
- [ ] Wire TLS filters from TUI/CLI to hunters
- [ ] Test end-to-end TLS filter distribution

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

### Content Filtering - Local (sniff/tap)
- [ ] Add `--host` flag (filter by Host header, glob pattern)
- [ ] Add `--url` flag (filter by URL path, glob pattern e.g., `/api/*`)
- [ ] Add `--method` flag (filter by HTTP method: GET, POST, etc.)
- [ ] Add `--status` flag (filter by response status code range e.g., `4xx`, `500-599`)
- [ ] Add `--user-agent` flag (filter by User-Agent header, glob pattern)
- [ ] Add `--content-type` flag (filter by Content-Type header)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for URL/headers/body)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching
- [ ] Wire filter flags in sniff and tap commands

### Content Filtering - Distributed (hunt) ⚠️ Infrastructure Complete, Wiring Needed
- [x] `FILTER_HTTP_HOST` type in proto (Phase 0 - complete)
- [x] `FILTER_HTTP_URL` type in proto (Phase 0 - complete)
- [x] Hunter HTTP host/URL matching logic (`internal/pkg/hunter/filter/http.go`)
- [ ] Wire HTTP filters from TUI/CLI to hunters
- [ ] Test end-to-end HTTP filter distribution

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

### Content Filtering - Local (sniff/tap)
- [ ] Extend Phase 2 email filters to IMAP/POP3 (same `--sender`, `--recipient`, etc.)
- [ ] Add `--mailbox` flag (filter by mailbox name for IMAP)
- [ ] Add `--command` flag (filter by IMAP/POP3 command: FETCH, SEARCH, RETR, etc.)

### Content Filtering - Distributed (hunt)
- [ ] Reuses Phase 2 `FILTER_EMAIL_ADDRESS` and `FILTER_EMAIL_SUBJECT` (Phase 0)
- [ ] IMAP/POP3-specific filters may need additional filter types if required

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

### Content Filtering - Local (sniff/tap)
- [ ] Add `--user` flag (filter by database username)
- [ ] Add `--database` flag (filter by database name)
- [ ] Add `--table` flag (filter by table name in query, glob pattern)
- [ ] Add `--query-type` flag (filter by query type: SELECT, INSERT, UPDATE, DELETE)
- [ ] Add `--keywords-file` flag (Aho-Corasick patterns for query content)
- [ ] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching

### Content Filtering - Distributed (hunt) ⚠️ Requires Phase 0 Extension
- [ ] Add `FILTER_DB_USER`, `FILTER_DB_TABLE` types to proto if needed
- [ ] Hunter database filter matching logic
- [ ] Processor can push database filters to DB hunters

## Implementation Notes

1. **Separate packages per protocol:** `internal/pkg/dns/`, `internal/pkg/email/`, etc.
2. **Type-safe metadata:** Add protocol-specific fields to `PacketDisplay` (e.g., `DNSData *DNSMetadata`)
3. **Reuse Aho-Corasick:** Existing `internal/pkg/ahocorasick/` for content filtering in email/HTTP
4. **Filter architecture pattern:**
   - **Local (sniff/tap):** Each protocol package has `content_filter.go` with `FilterConfig` and `Match()`
   - **Distributed (hunt):** Filters defined in proto, managed by processor, pushed to hunters via gRPC
   - CLI flags bound to viper for sniff/tap only
   - Glob patterns use `internal/pkg/filtering/glob.go`
   - Bulk patterns use Aho-Corasick matcher
5. **Consistent flag naming (sniff/tap only):**
   - Single pattern: `--domain`, `--sender`, `--host`
   - Bulk file: `--domains-file`, `--senders-file`, `--hosts-file`
   - Keywords: `--keywords-file` (universal Aho-Corasick patterns)
6. **Filter distribution (hunt):**
   - Hunt commands have NO content filtering flags
   - Filters created via TUI (Nodes tab → `f` key) or CLI (`lc set filter`)
   - Processor pushes filters to hunters via gRPC `SubscribeFilters` stream
   - Hunters match filters against parsed protocol metadata before forwarding

## Estimated Timeline

| Phase | Protocol | Protocol Support | Local Filtering | Distributed Filtering | Total |
|-------|----------|------------------|-----------------|----------------------|-------|
| 0 | Infrastructure | N/A | N/A | ✅ Complete | ✅ Complete |
| 1 | DNS | ✅ Complete | ✅ Complete | Ready (Phase 0 done) | 0 days |
| 2 | SMTP | ✅ Complete | 1-2 days | Ready (Phase 0 done) | 1-2 days |
| 3 | TLS/JA3 | 3-4 days | 1 day | Ready (Phase 0 done) | 4-5 days |
| 4 | HTTP | 4-5 days | 1-2 days | Ready (Phase 0 done) | 5-7 days |
| 5 | IMAP/POP3 | 4-5 days | 0.5 days | Reuses Phase 2 | 4-5 days |
| 6 | Database | 10-14 days | 1-2 days | Extension | 11-16 days |

**Critical path:** Phase 0 is now complete - distributed filtering infrastructure is ready.

**Remaining work:**
- Phase 1-2 remaining local filtering: 1-2 days
- Phase 3-5 complete: ~14-17 days

## Current Status (2026-01-05)

### What Works
- DNS and SMTP protocol parsing and display (sniff, hunt, tap, TUI)
- DNS query/response correlation and tunneling detection
- SMTP envelope extraction (MAIL FROM, RCPT TO, Subject)
- BPF port-level filtering for both protocols
- **DNS local content filtering (sniff/tap):**
  - `--domain` flag works in sniff and tap commands
  - `--domains-file` flag loads bulk patterns from file
  - Shared `filtering.MatchGlob()` for case-insensitive glob matching
  - `GlobMatcher` type with O(1) exact match optimization
- **Phase 0 - Filter Distribution Infrastructure:** ✅
  - New filter types in proto: DNS_DOMAIN, EMAIL_ADDRESS, EMAIL_SUBJECT, TLS_SNI, TLS_JA3, TLS_JA3S, TLS_JA4, HTTP_HOST, HTTP_URL
  - Hunter filter matchers for DNS, Email, TLS, HTTP in `internal/pkg/hunter/filter/`
  - TUI filter manager supports all new filter types
  - CLI filtering types.go and conversion.go updated

### What's Incomplete

1. **Email local content filtering (sniff/tap):**
   - No filter implementation exists in the email package
   - Requires `--sender`, `--recipient`, `--subject` flags

2. **Pattern validation:**
   - No validation for JA3 hash format (32-char hex)
   - No validation for glob syntax errors

3. **Hunter capability reporting:**
   - Hunters don't yet report which filter types they support

### Recommended Next Steps

1. **Complete Phase 1 distributed filtering:** Wire DNS filters from TUI/CLI to hunters
2. **Implement Phase 2 email local filtering:** Add sniff/tap filter flags
3. **Add pattern validation:** JA3/JA3S hash format, glob syntax
