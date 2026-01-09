# Protocol Expansion Implementation Plan

**Date:** 2026-01-03
**Updated:** 2026-01-09
**Status:** Phase 0-5 Complete (DNS, Email with IMAP/POP3, TLS, HTTP), Phase 7.1-7.5 Complete (SSLKEYLOGFILE Parser, TLS Record Layer, Cipher Suite Support, Session Tracking & Decryption, Key Forwarding & gRPC Integration)
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

### Content Filtering - Local (sniff/tap) ✅
- [x] Glob pattern matching implementation (extracted to `internal/pkg/filtering/glob.go`)
- [x] Wire `--domain` flag to sniff mode (`core.go` reads `dns.domain_pattern` from viper)
- [x] Add `--domain` flag to tap command (stores in viper for processor-level filtering)
- [x] Add `--domains-file` flag for bulk domain lists (load patterns from file)
- [x] GlobMatcher type with O(1) exact match lookup and AC integration foundation

### Content Filtering - Distributed (hunt) ✅
- [x] `FILTER_DNS_DOMAIN` type in proto (Phase 0 - complete)
- [x] Hunter DNS domain matching logic (`internal/pkg/hunter/filter/dns.go`)
- [x] Wire DNS filters from TUI/CLI to hunters (`ApplicationFilter` integration)
- [x] DNS packet detection and domain matching in `ApplicationFilter.matchDNSPacket()`

## Phase 2: Email - SMTP (3-4 days) - Local Filtering Complete ✅

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

### Content Filtering - Local (sniff/tap) ✅
- [x] Create `internal/pkg/email/content_filter.go` with glob pattern matching
- [x] Add `--sender` flag (filter by MAIL FROM, glob pattern e.g., `*@example.com`)
- [x] Add `--recipient` flag (filter by RCPT TO, glob pattern)
- [x] Add `--address` flag (match either sender OR recipient)
- [x] Add `--subject` flag (filter by Subject header, glob pattern)
- [x] Add `--keywords-file` flag (Aho-Corasick patterns for subject AND body)
- [x] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching
- [x] Wire filter flags in sniff and tap commands

### Body Content Filtering ✅ (Completed 2026-01-05)

**Status:** Implemented with body preview approach (configurable limit, opt-in capture)

**Implementation:**

1. **Extended EmailMetadata type** (`internal/pkg/types/packet.go`)
   - [x] Added `BodyPreview string` field (configurable length limit)
   - [x] Added `BodySize int` field for full message size tracking
   - [x] Added `BodyTruncated bool` flag for truncation indication

2. **Updated SMTP TCP stream handler** (`internal/pkg/email/tcp_stream.go`)
   - [x] Added body capture state machine (tracks header vs body mode)
   - [x] Buffer body content during DATA phase (after blank line separator)
   - [x] Implemented configurable body size limit (default: 64KB)
   - [x] Emit body content to EmailMetadata when message completes (dot terminator)
   - Note: MIME multipart parsing deferred (raw body content captured)

3. **Updated content filter** (`internal/pkg/email/content_filter.go`)
   - [x] Extended `Match()` to search body content with keywords matcher
   - [x] `--keywords-file` searches both subject AND body (subject first, then body)
   - [x] Case-insensitive matching

4. **Added configuration options** (`cmd/sniff/email.go`, `cmd/tap/tap_email.go`)
   - [x] Added `--capture-body` flag (opt-in for body capture, default: false)
   - [x] Added `--max-body-size` flag (limit memory usage, default: 64KB)
   - [x] Viper keys: `email.capture_body`, `email.max_body_size`

5. **Memory management**
   - [x] Body preview approach with bounded memory (default 64KB)
   - [x] Opt-in via `--capture-body` flag (disabled by default)
   - [x] Truncation flag indicates when body exceeded limit

**Usage:**
```bash
# Match keywords in subject only (default, no body capture)
lc sniff email -i eth0 --keywords-file keywords.txt

# Match keywords in both subject AND body
lc sniff email -i eth0 --keywords-file keywords.txt --capture-body

# With custom body size limit (256KB)
lc sniff email -i eth0 --keywords-file keywords.txt --capture-body --max-body-size 262144
```

### Content Filtering - Distributed (hunt) ✅ Complete
- [x] `FILTER_EMAIL_ADDRESS` type in proto (Phase 0 - complete)
- [x] `FILTER_EMAIL_SUBJECT` type in proto (Phase 0 - complete)
- [x] Hunter email address/subject matching logic (`internal/pkg/hunter/filter/email.go`)
- [x] Wire email filters from TUI/CLI to hunters (`ApplicationFilter.emailMatcher` integration)
- [x] Email packet detection and field extraction (`matchEmailPacket()` in ApplicationFilter)
- [x] Test email matcher and SMTP field extraction (unit tests added)
- [x] Hunter-side TCP reassembly for body content filtering (follows VoIP SIP-over-TCP pattern)
- [x] `EmailPacketProcessor` with TCP assembler and packet buffering
- [x] `EmailHunterHandler` implementing `SMTPMessageHandler` for stream callbacks
- [x] Body keyword matching via Aho-Corasick at hunter level
- [x] TCP packet buffering per session for forwarding after filter match

**Implementation details:**
- Hunters perform TCP reassembly locally using `tcpassembly.Assembler` (same as VoIP SIP-over-TCP)
- `EmailHunterHandler` accumulates envelope data across SMTP commands (MAIL FROM, RCPT TO, DATA)
- On DATA_COMPLETE, the handler applies full `ContentFilter` including body keyword matching
- Matched sessions retrieve buffered TCP packets via `GetEmailBufferedPackets()` and forward to processor
- Non-matching sessions discard buffered packets to save bandwidth
- Configurable via `--capture-body`, `--max-body-size`, `--keywords` flags on `hunt email` command

## Phase 3: TLS/JA3 Fingerprinting (3-4 days) ✅ Complete

**Priority:** High - Critical for encrypted traffic analysis

### Protocol Support ✅
- [x] Create `internal/pkg/tls/` package (parser.go, ja3.go, tracker.go, filter.go, core.go, content_filter.go)
- [x] Add `TLSMetadata` type (SNI, cipher suites, fingerprints) in `internal/pkg/types/packet.go`
- [x] ClientHello parser (no decryption needed) - `parser.go:parseClientHello()`
- [x] ServerHello parser - `parser.go:parseServerHello()`
- [x] JA3/JA3S/JA4 fingerprint calculation - `ja3.go`
- [x] Create `cmd/hunt/tls.go` (hunter node)
- [x] Create `cmd/tap/tap_tls.go` (standalone capture)
- [x] Create `cmd/sniff/tls.go` (CLI mode)
- [x] Add TLS protocol view in TUI (toggle with `v`) - `detailspanel.go:renderTLSDetails()`
- [x] Connection correlation via Tracker (correlate ClientHello/ServerHello)

### Content Filtering - Local (sniff/tap) ✅
- [x] Add `--sni` flag (filter by SNI hostname, glob pattern e.g., `*.example.com`)
- [x] Add `--sni-file` flag (bulk SNI patterns from file)
- [x] Add `--ja3` flag (filter by JA3 client fingerprint hash)
- [x] Add `--ja3-file` flag (known-bad JA3 fingerprint list)
- [x] Add `--ja3s` flag (filter by JA3S server fingerprint hash)
- [x] Add `--ja3s-file` flag (known-bad JA3S fingerprint list)
- [x] Add `--ja4` flag (filter by JA4 fingerprint)
- [x] Add `--ja4-file` flag (known-bad JA4 fingerprint list)
- [x] ContentFilter with glob pattern matching for SNI
- [x] Wire filter flags in sniff and tap commands

### Content Filtering - Distributed (hunt) ✅ Complete
- [x] `FILTER_TLS_SNI` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA3` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA3S` type in proto (Phase 0 - complete)
- [x] `FILTER_TLS_JA4` type in proto (Phase 0 - complete)
- [x] Hunter TLS SNI/JA3/JA3S/JA4 matching logic (`internal/pkg/hunter/filter/tls.go`)
- [x] Wire TLS filters from TUI/CLI to hunters (`ApplicationFilter.tlsMatcher` integration)
- [x] TLS packet detection and metadata extraction (`matchTLSPacket()` in ApplicationFilter)
- [x] Initialize `tlsParser` and `tlsMatcher` in `NewApplicationFilter()`
- [x] Update filter build tags to include `tap` variant

## Phase 4: HTTP (4-5 days) ✅ Complete

**Priority:** Medium - Complements TLS analysis

### Protocol Support ✅
- [x] Create `internal/pkg/http/` package (parser.go, tracker.go, aggregator.go, content_filter.go, filter.go, tcp_factory.go, tcp_stream.go, core.go, processor.go)
- [x] Add `HTTPMetadata` type (method, URL, headers, status) in `internal/pkg/types/packet.go`
- [x] HTTP/1.x request/response parser - `parser.go`
- [x] Request/response correlation with RTT measurement - `tracker.go`
- [x] Create `cmd/hunt/http.go` (hunter node)
- [x] Create `cmd/tap/tap_http.go` (standalone capture)
- [x] Create `cmd/sniff/http.go` (CLI mode)
- [x] Add HTTP protocol view in TUI (toggle with `v`) - `internal/pkg/tui/components/httpview.go`
- [x] Content-type classification - In HTTPMetadata

### Content Filtering - Local (sniff/tap) ✅
- [x] Add `--host` flag (filter by Host header, glob pattern)
- [x] Add `--path` flag (filter by URL path, glob pattern e.g., `/api/*`)
- [x] Add `--method` flag (filter by HTTP method: GET, POST, etc.)
- [x] Add `--status` flag (filter by response status code range e.g., `4xx`, `500-599`)
- [x] Add `--user-agent` flag (filter by User-Agent header, glob pattern)
- [x] Add `--content-type` flag (filter by Content-Type header)
- [x] Add `--keywords-file` flag (Aho-Corasick patterns for URL/headers/body)
- [x] Integrate with `internal/pkg/ahocorasick/` for multi-pattern matching
- [x] Wire filter flags in sniff and tap commands
- [x] Add `--hosts-file`, `--paths-file`, `--user-agents-file`, `--content-types-file` for bulk patterns

### Content Filtering - Distributed (hunt) ✅
- [x] `FILTER_HTTP_HOST` type in proto (Phase 0 - complete)
- [x] `FILTER_HTTP_URL` type in proto (Phase 0 - complete)
- [x] Hunter HTTP host/URL matching logic (`internal/pkg/hunter/filter/http.go`)
- [x] Wire HTTP filters from hunter command flags
- [x] HTTP packet processor with content filtering - `processor.go`

## Phase 5: Email - IMAP/POP3 (4-5 days) - Complete ✅

**Priority:** Medium - Completes email protocol suite

**Status:** Complete (2026-01-08) - Protocol support and content filtering

### Protocol Support ✅
- [x] Extend `EmailMetadata` for IMAP/POP3 fields (`internal/pkg/types/packet.go`)
- [x] IMAP command parser (SELECT, FETCH, SEARCH, LOGIN, etc.) (`internal/pkg/email/imap_parser.go`)
- [x] POP3 command parser (USER, PASS, RETR, LIST, etc.) (`internal/pkg/email/pop3_parser.go`)
- [x] Mailbox operation tracking (`internal/pkg/email/imap_tracker.go`, `pop3_tracker.go`)
- [x] IMAP/POP3 TCP stream handlers (`internal/pkg/email/imap_tcp_stream.go`, `pop3_tcp_stream.go`)
- [x] Multi-protocol factory for port-based protocol detection (`internal/pkg/email/multi_protocol_factory.go`)
- [x] Update `cmd/sniff/email.go` for IMAP/POP3 support (`--protocol`, `--imap-port`, `--pop3-port`)
- [x] Update `cmd/tap/email.go` for IMAP/POP3 support
- [x] Update `cmd/hunt/email.go` for IMAP/POP3 support

### Content Filtering - Local (sniff/tap) ✅
- [x] Extend Phase 2 email filters to IMAP/POP3 (same `--sender`, `--recipient`, etc.)
- [x] Add `--mailbox` flag (filter by mailbox name for IMAP)
- [x] Add `--command` flag (filter by IMAP/POP3 command: FETCH, SEARCH, RETR, etc.)

### Content Filtering - Distributed (hunt) ✅
- [x] Reuses Phase 2 `FILTER_EMAIL_ADDRESS` and `FILTER_EMAIL_SUBJECT` (Phase 0)
- [x] `--mailbox` and `--command` flags added for local filtering on hunter

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

## Phase 7: TLS Decryption via SSLKEYLOGFILE (6-8 weeks)

**Priority:** Medium - Enables encrypted traffic content inspection for authorized monitoring

**Approach:** SSLKEYLOGFILE (NSS Key Log Format) - same method used by Wireshark. Works with all cipher suites including forward secrecy and TLS 1.3.

### Overview

SSLKEYLOGFILE contains pre-master secrets or session keys logged by TLS clients/servers. This allows passive decryption without breaking forward secrecy (keys are provided, not derived from private keys).

TLS wraps many protocols: HTTPS, SMTPS, IMAPS, POP3S, database connections, etc. The `--tls-keylog` flag works at the capture level for any TLS-encrypted traffic.

**Key Log Format (NSS):**
```
# Each line: <label> <client_random_hex> <secret_hex>
CLIENT_RANDOM 1234...abcd 5678...efgh
```

**Labels:**
- `CLIENT_RANDOM` - Pre-master secret (TLS 1.2 and earlier)
- `CLIENT_HANDSHAKE_TRAFFIC_SECRET` - TLS 1.3 client handshake
- `SERVER_HANDSHAKE_TRAFFIC_SECRET` - TLS 1.3 server handshake
- `CLIENT_TRAFFIC_SECRET_0` - TLS 1.3 client application data
- `SERVER_TRAFFIC_SECRET_0` - TLS 1.3 server application data

### Architecture

**Key principle:** Preserve original encrypted packets for audit integrity. Forward TLS session keys alongside packets so processor/TUI can decrypt for display while storing original evidence.

```
┌─────────────────────────────────────────────────────────────────┐
│                   Capturing Node (sniff/tap/hunt)               │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ SSLKEYLOG    │───▶│ Key Store    │◀───│ TLS Session      │   │
│  │ File/Pipe    │    │ (by Client   │    │ Tracker          │   │
│  │ Reader       │    │  Random)     │    │ (ClientHello)    │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│                             │                    │              │
│                             ▼                    ▼              │
│                      ┌──────────────────────────────┐           │
│                      │ TLS Record Decryptor         │           │
│                      │ - Derive session keys        │           │
│                      │ - Decrypt records            │           │
│                      │ - Reassemble app data        │           │
│                      └──────────────────────────────┘           │
│                                    │                            │
│                                    ▼                            │
│                      ┌──────────────────────────────┐           │
│                      │ Content Filter               │           │
│                      │ - Parse decrypted payload    │           │
│                      │ - Apply protocol filters     │           │
│                      │ - Match → forward session    │           │
│                      └──────────────────────────────┘           │
│                                    │                            │
│                                    ▼ On match                   │
│                      ┌──────────────────────────────┐           │
│                      │ Forward to Processor/TUI     │           │
│                      │ - Original encrypted packets │           │
│                      │ - TLS session keys           │           │
│                      └──────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    │ gRPC (encrypted pkts + keys)
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Processor / TUI                            │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │ Receive Keys     │───▶│ Local Key Store                  │   │
│  │ (per session)    │    │ (decrypt for display)            │   │
│  └──────────────────┘    └──────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │ PCAP Writer      │    │ Keylog Writer                    │   │
│  │ (encrypted pkts) │    │ (Wireshark-compatible)           │   │
│  └──────────────────┘    └──────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ TUI Display                                              │   │
│  │ - Decrypt using forwarded keys                           │   │
│  │ - Show decrypted content (HTTP, SMTP, etc.)              │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow:**
1. Capturing node reads TLS keys from keylog file/pipe
2. Decrypts traffic locally to apply content filters
3. On filter match, forwards **original encrypted packets + session keys**
4. Processor stores encrypted PCAP + keylog file (audit-ready, Wireshark-compatible)
5. Processor/TUI decrypts using forwarded keys for display

### Phase 7.1: SSLKEYLOGFILE Parser (3-4 days) - Complete ✅

- [x] Create `internal/pkg/tls/keylog/` package
- [x] Implement NSS Key Log format parser (`parser.go`)
- [x] Support all TLS 1.2 and TLS 1.3 labels
- [x] Create key store indexed by client_random (`store.go`)
- [x] File watcher for live key log updates (fsnotify/polling)
- [x] Named pipe support for real-time key injection
- [x] Unit tests with sample key log files

### Phase 7.2: TLS Record Layer (1-2 weeks) - Complete ✅

- [x] Create `internal/pkg/tls/decrypt/` package
- [x] TLS record layer parser (`record.go`)
  - [x] Record header parsing (content type, version, length)
  - [x] Record reassembly across TCP segments
  - [x] Encrypted vs plaintext record detection
- [x] TLS 1.2 key derivation (`kdf_tls12.go`)
  - [x] PRF (Pseudo-Random Function) implementation
  - [x] Master secret → session keys derivation
  - [x] Client/server write keys, IVs, MAC keys
- [x] TLS 1.3 key derivation (`kdf_tls13.go`)
  - [x] HKDF-Extract and HKDF-Expand-Label
  - [x] Handshake traffic secrets → keys
  - [x] Application traffic secrets → keys

### Phase 7.3: Cipher Suite Support (2-3 weeks) - Complete ✅

- [x] Implement decryption for common cipher suites (`ciphers/`)
- [x] **TLS 1.2 cipher suites:**
  - [x] AES-128-GCM, AES-256-GCM (AEAD)
  - [x] AES-128-CBC, AES-256-CBC (with HMAC-SHA1/SHA256)
  - [x] ChaCha20-Poly1305
- [x] **TLS 1.3 cipher suites:**
  - [x] TLS_AES_128_GCM_SHA256
  - [x] TLS_AES_256_GCM_SHA384
  - [x] TLS_CHACHA20_POLY1305_SHA256
- [x] Sequence number tracking (per-direction)
- [x] AEAD nonce construction (explicit + implicit IV)
- [x] Unit tests with known-answer test vectors

### Phase 7.4: Session Tracking & Decryption (1-2 weeks) - Complete ✅

- [x] Extend existing TLS tracker for decryption state
- [x] Match captured sessions to key log entries by client_random
- [x] Handle key log entries arriving before/after handshake
- [x] Decrypt application data records
- [x] Reassemble decrypted data into application stream
- [x] Handle session resumption (session ID, tickets)
- [x] Memory management (bounded session cache)

### Phase 7.5: Key Forwarding & gRPC Integration (1 week) - Complete ✅

- [x] Extend `PacketData` proto with TLS session key field (`TLSSessionKeys` message in `api/proto/data.proto`)
- [x] Forward session keys on first matched packet of a session (`TLSKeyForwarder` in `internal/pkg/hunter/`)
- [x] Processor receives and stores keys in local key store (`TLSKeylogWriter` in `internal/pkg/processor/`)
- [x] Processor writes keylog file alongside PCAP (Wireshark-compatible NSS format)
- [x] Processor `--tls-keylog-dir` flag for keylog file output
- [x] Unit tests for hunter TLSKeyForwarder and processor TLSKeylogWriter
- [ ] TUI decrypts packets using forwarded keys for display (deferred to Phase 7.6)

### Phase 7.6: Command Integration (1 week)

**Live capture:**
- [ ] Add `--tls-keylog` flag to sniff/tap/hunt commands
- [ ] Add `--tls-keylog-pipe` for named pipe input
- [ ] Works for any TLS-wrapped protocol (HTTPS, SMTPS, IMAPS, etc.)
- [ ] Processor `--tls-keylog-dir` for keylog file output

**Offline analysis (PCAP + keylog):**
- [ ] Support `lc sniff -r file.pcap --tls-keylog keys.log` for CLI analysis
- [ ] Support `lc watch file -r file.pcap --tls-keylog keys.log` for TUI analysis
- [ ] Full round-trip: capture → store → re-analyze with same decryption

**Display:**
- [ ] Show decryption status in TUI (encrypted/decrypted indicator)
- [ ] Documentation and usage examples

### CLI Usage

**Live capture:**
```bash
# Standalone CLI capture with key log file
sudo lc sniff http -i eth0 --tls-keylog /tmp/sslkeys.log

# Standalone tap (serves TUI, writes PCAP + keylog)
sudo lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log

# Distributed hunter (decrypts for filtering, forwards encrypted + keys)
sudo lc hunt http -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log

# Real-time key injection via named pipe
mkfifo /tmp/sslkeys.pipe
sudo lc tap http -i eth0 --tls-keylog-pipe /tmp/sslkeys.pipe &
SSLKEYLOGFILE=/tmp/sslkeys.pipe ./myserver

# Combined with content filtering (filter decrypted traffic)
sudo lc hunt http -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log \
  --host "*.example.com" --keywords-file sensitive.txt

# Processor stores encrypted PCAP + keylog for Wireshark analysis
lc process --listen :50051 \
  --per-call-pcap --per-call-pcap-dir /var/capture \
  --tls-keylog-dir /var/capture/keys

# Works for any TLS-wrapped protocol
sudo lc hunt email -i eth0 --processor central:50051 \
  --tls-keylog /tmp/sslkeys.log  # SMTPS, IMAPS, POP3S
```

**Offline analysis (PCAP + keylog):**
```bash
# CLI analysis of stored capture
lc sniff http -r capture.pcap --tls-keylog keys.log

# TUI analysis of stored capture
lc watch file -r capture.pcap --tls-keylog keys.log

# Full round-trip workflow:
# 1. Capture with keylog
sudo lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log \
  -w /var/capture/session.pcap

# 2. Later: re-analyze with same decryption capability
lc watch file -r /var/capture/session.pcap \
  --tls-keylog /var/capture/session.keys
```

### Generating Key Logs

**Server-side (typical deployment):**
Configure your TLS server to log session keys. The capturing node runs on the same machine.

**Browsers:**
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
firefox  # or chromium, chrome
```

**curl:**
```bash
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://example.com
```

**OpenSSL (1.1.1+):**
```bash
openssl s_client -connect example.com:443 -keylogfile /tmp/sslkeys.log
```

**Python (requests):**
```python
import os
os.environ['SSLKEYLOGFILE'] = '/tmp/sslkeys.log'
import requests
requests.get('https://example.com')
```

**Go (crypto/tls):**
```go
config := &tls.Config{
    KeyLogWriter: keylogFile,
}
```

### Limitations

1. **Key log required:** Cannot decrypt without SSLKEYLOGFILE (forward secrecy)
2. **No private key decryption:** RSA key exchange is rare/obsolete
3. **Real-time sync:** Keys must arrive before or shortly after handshake
4. **Memory usage:** Session state stored until connection closes
5. **Same-machine deployment:** Key log file must be accessible to capturing node

### Security Considerations

- Key log files contain session secrets - protect appropriately
- Clear key store on file rotation/truncation
- Warn if key log file has insecure permissions
- Forwarded keys are protected by gRPC TLS (hunter→processor)
- Stored keylog files should have restricted permissions

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
| 1 | DNS | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete |
| 2 | SMTP | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete |
| 3 | TLS/JA3 | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete |
| 4 | HTTP | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete |
| 5 | IMAP/POP3 | ✅ Complete | 0.5 days | Reuses Phase 2 | ~0.5 days |
| 6 | Database | 10-14 days | 1-2 days | Extension | 11-16 days |
| 7 | TLS Decryption | 6-8 weeks | N/A | N/A | 6-8 weeks |

**Critical path:** Phases 0-5 protocol support complete (DNS, Email with IMAP/POP3, TLS, HTTP).

**Remaining work:**
- Phase 5 content filtering: ~0.5 days (tap/hunt command updates, `--mailbox`/`--command` flags)
- Phase 6 (Database): ~11-16 days (optional)
- Phase 7 (TLS Decryption): ~6-8 weeks (SSLKEYLOGFILE-based HTTPS decryption)

## Current Status (2026-01-09)

### What Works
- DNS, SMTP, IMAP, POP3, TLS, and HTTP protocol parsing and display (sniff, hunt, tap)
- DNS query/response correlation and tunneling detection
- SMTP envelope extraction (MAIL FROM, RCPT TO, Subject)
- IMAP command/response parsing (SELECT, FETCH, SEARCH, LOGIN, etc.)
- POP3 command/response parsing (USER, PASS, RETR, LIST, etc.)
- TLS ClientHello/ServerHello parsing with JA3/JA3S/JA4 fingerprinting
- HTTP request/response parsing with RTT measurement
- BPF port-level filtering for all protocols
- **DNS local content filtering (sniff/tap):**
  - `--domain` flag works in sniff and tap commands
  - `--domains-file` flag loads bulk patterns from file
  - Shared `filtering.MatchGlob()` for case-insensitive glob matching
  - `GlobMatcher` type with O(1) exact match optimization
- **Email local content filtering (sniff/tap):** ✅ Complete
  - `--sender`, `--recipient`, `--address`, `--subject` flags in sniff and tap commands
  - `--senders-file`, `--recipients-file`, `--addresses-file`, `--subjects-file` for bulk patterns
  - `--keywords-file` for Aho-Corasick matching (subject AND body with `--capture-body`)
  - `--capture-body` flag enables body content capture (default: false for performance)
  - `--max-body-size` flag limits memory usage (default: 64KB)
  - `ContentFilter` with AND logic between filter groups, OR logic within groups
- **Phase 0 - Filter Distribution Infrastructure:** ✅
  - New filter types in proto: DNS_DOMAIN, EMAIL_ADDRESS, EMAIL_SUBJECT, TLS_SNI, TLS_JA3, TLS_JA3S, TLS_JA4, HTTP_HOST, HTTP_URL
  - Hunter filter matchers for DNS, Email, TLS, HTTP in `internal/pkg/hunter/filter/`
  - TUI filter manager supports all new filter types
  - CLI filtering types.go and conversion.go updated
- **Phase 1 - DNS Distributed Filtering:** ✅
  - DNS hunters advertise `dns_domain` filter capability
  - `ApplicationFilter` integrates `DNSMatcher` for domain pattern matching
  - DNS packet detection via centralized detector
  - Domain extraction from DNS queries/answers (including CNAME targets)
  - Full filter ID tracking for LI correlation
- **Phase 2 - Email Distributed Filtering:** ✅
  - Email hunters advertise `email_address`, `email_subject` filter capabilities
  - `ApplicationFilter` integrates `EmailMatcher` for address/subject pattern matching
  - SMTP packet detection via centralized detector
  - Email field extraction from MAIL FROM, RCPT TO, Subject header packets
  - Full filter ID tracking for LI correlation
  - Unit tests for EmailMatcher and SMTP field extraction
  - **Hunter-side TCP reassembly for body content filtering:**
    - `EmailPacketProcessor` creates TCP assembler and feeds packets
    - `EmailHunterHandler` implements `SMTPMessageHandler` for stream callbacks
    - TCP packet buffering per session via `tcp_buffer.go`
    - Body keyword matching via Aho-Corasick at hunter level
    - Full parity with local sniff/tap body filtering capabilities
- **Phase 3 - TLS/JA3 Fingerprinting:** ✅ Complete
  - ClientHello/ServerHello parsing with JA3/JA3S/JA4 fingerprint calculation
  - SNI, cipher suite, and extension extraction
  - `--sni`, `--ja3`, `--ja3s`, `--ja4` flags for local filtering
  - TLS hunters with SNI/fingerprint matching
- **Phase 4 - HTTP:** ✅ Complete
  - HTTP/1.x request/response parsing with `internal/pkg/http/` package
  - Request/response correlation with RTT measurement
  - TCP stream reassembly for complete message reconstruction
  - `--host`, `--path`, `--method`, `--status`, `--user-agent`, `--content-type` flags
  - `--keywords-file` for body content filtering (with `--capture-body`)
  - HTTP hunters with host/path content filtering
- **Phase 5 - IMAP/POP3 Protocol Support:** ✅ Complete
  - Extended `EmailMetadata` with IMAP/POP3-specific fields
  - IMAP parser with command/response parsing, tag tracking, mailbox state
  - POP3 parser with command/response parsing, message tracking
  - IMAP session tracker with command correlation and mailbox state
  - POP3 session tracker with transaction state
  - Multi-protocol factory for port-based protocol detection
  - `--protocol` flag in sniff (smtp, imap, pop3, all)
  - `--imap-port`, `--pop3-port` flags for custom ports
  - Statistics display for all three protocols
- **Phase 7.1 - SSLKEYLOGFILE Parser:** ✅ Complete
  - `internal/pkg/tls/keylog/` package with NSS Key Log format support
  - TLS 1.2 labels: `CLIENT_RANDOM` (pre-master secret)
  - TLS 1.3 labels: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`, `EARLY_EXPORTER_SECRET`, `CLIENT_EARLY_TRAFFIC_SECRET`
  - `Store` for session key storage indexed by client_random (with LRU eviction, TTL cleanup)
  - `Watcher` for live key log file updates (fsnotify with polling fallback)
  - Named pipe support for real-time key injection
  - Comprehensive unit tests
- **Phase 7.2 - TLS Record Layer:** ✅ Complete
  - `internal/pkg/tls/decrypt/` package with TLS record parsing and key derivation
  - TLS record layer parser (`record.go`):
    - Record header parsing (content type, version, length)
    - Record reassembly across TCP segments via `RecordParser` and `StreamReassembler`
    - Encrypted vs plaintext record detection
    - Helper functions: `ExtractClientRandom`, `ExtractServerRandom`, `ExtractCipherSuite`, `ExtractTLSVersion`
  - TLS 1.2 key derivation (`kdf_tls12.go`):
    - PRF (Pseudo-Random Function) implementation via P_hash
    - `DeriveMasterSecret` and `DeriveKeyMaterial` for session key derivation
    - GCM and ChaCha20-Poly1305 nonce construction
    - Additional authenticated data computation
  - TLS 1.3 key derivation (`kdf_tls13.go`):
    - HKDF-Extract and HKDF-Expand-Label per RFC 8446
    - `TLS13KeySchedule` for full key schedule derivation
    - Traffic key derivation and key update support
    - Verified with RFC 8448 test vectors
  - Cipher suite information for common TLS 1.2 and TLS 1.3 suites
  - Comprehensive unit tests
- **Phase 7.3 - Cipher Suite Support:** ✅ Complete
  - `internal/pkg/tls/decrypt/ciphers/` package with cipher implementations
  - TLS 1.2 cipher suites:
    - AES-128-GCM, AES-256-GCM (AEAD with 4-byte implicit + 8-byte explicit nonce)
    - AES-128-CBC, AES-256-CBC with HMAC-SHA1 and HMAC-SHA256
    - ChaCha20-Poly1305 (12-byte IV XOR sequence number nonce)
  - TLS 1.3 cipher suites:
    - TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  - Sequence number tracking (per-direction in SessionState)
  - AEAD nonce construction for both TLS 1.2 and TLS 1.3
  - TLS record decryption helpers (DecryptTLS12Record, DecryptTLS13Record)
  - TLS 1.3 inner plaintext padding removal and content type extraction
  - PKCS#7 padding for CBC mode with constant-time validation
  - Comprehensive unit tests including NIST and RFC 7539 test vectors
- **Phase 7.4 - Session Tracking & Decryption:** ✅ Complete
  - `internal/pkg/tls/decrypt/session.go` with `SessionManager` integrating all components
  - Session tracking by flow key (srcIP:srcPort-dstIP:dstPort)
  - ClientRandom-based key lookup from keylog store
  - Async key arrival handling (keys before or after handshake)
  - TLS 1.2 decryption with AEAD (GCM, ChaCha20) and CBC cipher support
  - TLS 1.3 decryption with traffic secret-based key derivation
  - Decrypted application data stream buffering
  - Session resumption support (session ID and ticket extraction)
  - Bounded session cache with LRU eviction and TTL cleanup
  - `OnDecryptedData` callback for real-time decryption notifications
  - Comprehensive unit tests for session management and decryption flow
- **Phase 7.5 - Key Forwarding & gRPC Integration:** ✅ Complete
  - Extended `CapturedPacket` proto with `TLSSessionKeys` message (`api/proto/data.proto`)
  - `TLSKeyForwarder` in `internal/pkg/hunter/` attaches session keys to first matched packet
  - `TLSKeylogWriter` in `internal/pkg/processor/` receives and stores keys
  - Processor writes Wireshark-compatible NSS keylog files
  - `--tls-keylog-dir` flag in process command for keylog output directory
  - Comprehensive unit tests for TLSKeyForwarder and TLSKeylogWriter

### What's Incomplete

1. **Pattern validation:**
   - No validation for JA3 hash format (32-char hex)
   - No validation for glob syntax errors

2. **Phase 5 content filtering:**
   - Update `cmd/tap/email.go` for IMAP/POP3 support
   - Update `cmd/hunt/email.go` for IMAP/POP3 support
   - Add `--mailbox` flag for IMAP mailbox filtering
   - Add `--command` flag for IMAP/POP3 command filtering

### Recommended Next Steps

1. **Complete Phase 5 content filtering:** Update tap/hunt commands, add mailbox/command flags
2. **Add pattern validation:** JA3/JA3S hash format, glob syntax
3. **Continue Phase 7.6 Command Integration:** Add `--tls-keylog` flag to sniff/tap/hunt commands, TUI decryption display
