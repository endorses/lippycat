# Protocol Expansion Implementation Plan

**Date:** 2026-01-03
**Status:** Pending
**Research:** [docs/research/protocol-expansion-roadmap.md](../research/protocol-expansion-roadmap.md)

## Overview

Expand lippycat beyond VoIP to support additional protocols. Detection signatures already exist for most protocols; the work is creating deep analysis plugins and CLI subcommands.

## Phase 1: DNS (2-3 days)

**Priority:** Highest - Low effort, high value, strong LI relevance

- [ ] Create `internal/pkg/dns/` package (parser, tracker, plugin)
- [ ] Add `DNSMetadata` type in `internal/pkg/types/`
- [ ] Create `cmd/sniff/dns.go`, `cmd/tap/dns.go`, `cmd/hunt/dns.go`
- [ ] Add DNS display format in TUI
- [ ] Query/response correlation via transaction ID
- [ ] DNS tunneling detection (entropy analysis)

## Phase 2: Email - SMTP (3-4 days)

**Priority:** High - Major LI use case

- [ ] Create `internal/pkg/email/` package
- [ ] Add `EmailMetadata` type (envelope: MAIL FROM, RCPT TO, Subject)
- [ ] SMTP parser using TCP reassembly (already working from SIP)
- [ ] Create `cmd/sniff/email.go`, `cmd/tap/email.go`, `cmd/hunt/email.go`
- [ ] STARTTLS detection
- [ ] Message-ID correlation

## Phase 3: TLS/JA3 Fingerprinting (3-4 days)

**Priority:** High - Critical for encrypted traffic analysis

- [ ] Create `internal/pkg/tls/` package
- [ ] Add `TLSMetadata` type (SNI, cipher suites, fingerprints)
- [ ] ClientHello parser (no decryption needed)
- [ ] JA3/JA3S/JA4 fingerprint calculation
- [ ] Create `cmd/sniff/tls.go`, `cmd/tap/tls.go`, `cmd/hunt/tls.go`
- [ ] Fingerprint database integration hooks

## Phase 4: HTTP (4-5 days)

**Priority:** Medium - Complements TLS analysis

- [ ] Create `internal/pkg/http/` package
- [ ] Add `HTTPMetadata` type (method, URL, headers, status)
- [ ] HTTP/1.x request/response parser
- [ ] Request/response correlation
- [ ] Create `cmd/sniff/http.go`, `cmd/tap/http.go`, `cmd/hunt/http.go`
- [ ] Content-type classification

## Phase 5: Email - IMAP/POP3 (4-5 days)

**Priority:** Medium - Completes email protocol suite

- [ ] Extend `EmailMetadata` for IMAP/POP3 fields
- [ ] IMAP command parser (SELECT, FETCH, SEARCH)
- [ ] POP3 command parser
- [ ] Mailbox operation tracking

## Phase 6: Database Protocols (10-14 days) - Optional

**Priority:** Lower - High effort, niche use case

- [ ] MySQL protocol parser
- [ ] PostgreSQL protocol parser
- [ ] Query extraction and logging
- [ ] Create `cmd/sniff/db.go` commands

## Architecture Decisions

1. **Separate packages per protocol:** `internal/pkg/dns/`, `internal/pkg/email/`, etc.
2. **Type-safe metadata:** Add protocol-specific fields to `PacketDisplay` (e.g., `DNSData *DNSMetadata`)
3. **Reuse Aho-Corasick:** Existing `internal/pkg/ahocorasick/` for content filtering in email/HTTP
4. **LI integration:** Map protocols to ETSI X2 (IRI) and X3 (CC)

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
