# Protocol Expansion Roadmap

**Date:** 2025-12-30
**Status:** Research
**Author:** Claude Code

## Executive Summary

This document analyzes which protocols should be added to lippycat beyond the current VoIP (SIP/RTP) support. It evaluates protocols based on:

1. Implementation complexity
2. Usefulness for lippycat's use cases (network monitoring, lawful interception, security)
3. User demand

**Key Findings:**
1. The protocol detection infrastructure already exists for many protocols. The missing piece is deep analysis plugins and CLI subcommands.
2. The existing Aho-Corasick implementation (`internal/pkg/ahocorasick/`) is immediately reusable for content filtering (DLP, threat intel, compliance) in email and HTTP protocols with no changes needed.

---

## Table of Contents

1. [Current State](#current-state)
2. [Protocol Analysis](#protocol-analysis)
   - [DNS](#1-dns)
   - [Email Protocols](#2-email-protocols-smtp-imap-pop3)
   - [HTTP/HTTPS](#3-httphttps-metadata)
   - [TLS/JA3](#4-tlsja3-fingerprinting)
   - [Database Protocols](#5-database-protocols-mysql-postgresql)
   - [ICMP](#6-icmp)
3. [Protocol Comparison Matrix](#protocol-comparison-matrix)
4. [Recommended Roadmap](#recommended-roadmap)
5. [Implementation Patterns](#implementation-patterns)
6. [Architecture Considerations](#architecture-considerations)
7. [Reusing Aho-Corasick for Content Filtering](#reusing-aho-corasick-for-content-filtering)
8. [Resource Estimates](#resource-estimates)
9. [Open Questions](#open-questions)
10. [Conclusion](#conclusion)

---

## Current State

### Existing Infrastructure

lippycat has a well-designed extensible architecture:

| Component | Location | Status |
|-----------|----------|--------|
| Signature Interface | `internal/pkg/detector/signatures/` | Complete |
| Plugin Interface | `internal/pkg/voip/plugins/` | Complete |
| Metadata Types | `internal/pkg/types/` | Extensible |
| CLI Subcommands | `cmd/[sniff\|tap\|hunt]/` | Pattern established |

### Protocols with Detection Signatures

The detector already has signatures for these protocols:

| Protocol | File | Priority | Layer |
|----------|------|----------|-------|
| SIP | `voip/sip.go` | 150 | Application |
| RTP | `voip/rtp.go` | 140 | Application |
| DNS | `application/dns.go` | 120 | Application |
| gRPC/HTTP2 | `application/grpc.go` | 130 | Application |
| TLS | `application/tls.go` | 85 | Application |
| HTTP | `application/http.go` | 80 | Application |
| SSH | `application/ssh.go` | 100 | Application |
| DHCP | `application/dhcp.go` | 110 | Application |
| MySQL | `application/mysql.go` | 90 | Application |
| PostgreSQL | `application/postgresql.go` | 90 | Application |
| MongoDB | `application/mongodb.go` | 90 | Application |
| Redis | `application/redis.go` | 90 | Application |
| SNMP | `application/snmp.go` | 100 | Application |
| OpenVPN | `vpn/openvpn.go` | 100 | Application |
| WireGuard | `vpn/wireguard.go` | 100 | Application |
| IKEv2 | `vpn/ikev2.go` | 100 | Application |
| L2TP | `vpn/l2tp.go` | 100 | Application |
| PPTP | `vpn/pptp.go` | 100 | Application |
| ICMP | `network/icmp.go` | 90 | Network |
| ARP | `link/arp.go` | 95 | Link |

### What's Missing for Full Protocol Support

For each protocol to be fully supported like VoIP, it needs:

1. **Deep Analysis Plugin** - Stateful processing beyond detection
2. **Metadata Type** - Protocol-specific data structure
3. **CLI Subcommand** - `lc sniff/tap/hunt [protocol]`
4. **TUI Integration** - Protocol-specific display

---

## Protocol Analysis

### Evaluation Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Implementation Effort | High | Developer time required |
| User Demand | High | How many users want this |
| LI Relevance | Medium | Lawful interception use case |
| Security Value | Medium | Threat detection capabilities |
| Existing Infrastructure | High | How much is already built |

### Protocol Candidates

#### 1. DNS

**Overview:** Domain Name System - translates hostnames to IP addresses.

| Aspect | Assessment |
|--------|------------|
| Transport | UDP (primary), TCP (zone transfers, large responses) |
| Complexity | Low - simple request/response |
| State | Minimal - correlate query/response by transaction ID |
| Existing Code | Detection signature complete |

**Implementation Effort:** Low (2-3 days)

- gopacket has built-in DNS layer parsing
- UDP-based, no TCP reassembly needed for most cases
- Simple query/response correlation via transaction ID
- Detection signature already exists

**Use Cases:**

- [ ] DNS query logging for compliance/audit
- [ ] DNS tunneling detection (data exfiltration via DNS)
- [ ] Threat intel correlation (known malicious domains)
- [ ] DNS response manipulation detection (MITM)
- [ ] Lawful interception of DNS queries

**Metadata Structure:**

```go
type DNSMetadata struct {
    TransactionID uint16
    IsResponse    bool
    QueryName     string
    QueryType     string   // A, AAAA, MX, TXT, etc.
    ResponseCode  string   // NOERROR, NXDOMAIN, SERVFAIL
    Answers       []string // Resolved addresses
    TTL           uint32
    Authoritative bool
    Truncated     bool
    RecursionDesired bool
}
```

**Features to Implement:**

1. Query/response correlation
2. DNS tunneling detection (entropy analysis, unusual record types)
3. Query rate anomaly detection
4. Domain reputation integration hooks

**Verdict:** **Highest priority** - Low effort, high value, strong LI relevance.

---

#### 2. Email Protocols (SMTP, IMAP, POP3)

**Overview:** Email transport and access protocols.

| Protocol | Port | Transport | Purpose |
|----------|------|-----------|---------|
| SMTP | 25, 587, 465 | TCP | Mail transfer |
| IMAP | 143, 993 | TCP | Mail access (stateful) |
| POP3 | 110, 995 | TCP | Mail access (download) |

**Implementation Effort:** Medium (5-7 days for all three)

- Text-based protocols (easier parsing than binary)
- TCP-based, requires TCP reassembly (already have this from SIP)
- SMTP is simpler (stateless per message)
- IMAP is more complex (stateful mailbox operations)

**Use Cases:**

- [ ] Email metadata interception (LI primary use case)
- [ ] Sender/recipient tracking
- [ ] Subject line capture
- [ ] Attachment detection
- [ ] Spam/phishing detection
- [ ] Data exfiltration monitoring
- [ ] Compliance monitoring (DLP)

**Metadata Structure:**

```go
type EmailMetadata struct {
    // Common fields
    Protocol    string // SMTP, IMAP, POP3
    SessionID   string
    IsEncrypted bool   // STARTTLS upgraded

    // SMTP fields
    MailFrom    string
    RcptTo      []string
    Subject     string
    MessageID   string
    Size        int64
    HasAttachment bool
    AttachmentNames []string

    // IMAP fields
    Command     string // SELECT, FETCH, SEARCH, etc.
    Mailbox     string
    UID         uint32
    Flags       []string

    // Envelope data
    Date        time.Time
    From        string
    To          []string
    CC          []string
}
```

**Complexity Breakdown:**

| Protocol | Effort | Notes |
|----------|--------|-------|
| SMTP | 2-3 days | Simpler, envelope tracking only |
| POP3 | 1-2 days | Simple command/response |
| IMAP | 3-4 days | Complex state machine |

**LI Relevance:** **Very High**

Email interception is one of the most common lawful interception targets. ETSI standards specifically address email interception:
- X2 (IRI): Envelope data (from, to, subject, timestamps)
- X3 (CC): Full message content

**Verdict:** **High priority** - Major LI use case, medium effort.

---

#### 3. HTTP/HTTPS Metadata

**Overview:** Web traffic analysis without decryption.

| Aspect | Assessment |
|--------|------------|
| Transport | TCP |
| Complexity | Medium - request/response correlation |
| State | Per-connection request tracking |
| Existing Code | Detection signature complete |

**Implementation Effort:** Medium (4-5 days)

- HTTP/1.x is text-based
- TCP reassembly already working
- Need request/response correlation
- HTTP/2 is binary and multiplexed (harder)

**Use Cases:**

- [ ] URL logging and filtering
- [ ] Web traffic analysis
- [ ] Malware C2 detection
- [ ] Data exfiltration detection
- [ ] API monitoring
- [ ] Content-type based filtering

**Metadata Structure:**

```go
type HTTPMetadata struct {
    // Request
    Method      string
    URL         string
    Host        string
    UserAgent   string
    ContentType string
    ContentLength int64
    Headers     map[string]string

    // Response
    StatusCode  int
    StatusText  string
    Server      string

    // Correlation
    RequestID   string
    ResponseTime time.Duration
}
```

**Scope Limitation:**

Focus on HTTP/1.x initially. HTTP/2 adds significant complexity:
- Binary framing
- Multiplexed streams
- Header compression (HPACK)

**Verdict:** **Medium priority** - Useful but TLS makes content invisible for most traffic.

---

#### 4. TLS/JA3 Fingerprinting

**Overview:** Extract metadata from encrypted TLS connections without decryption.

| Aspect | Assessment |
|--------|------------|
| Transport | TCP |
| Complexity | Medium - parse ClientHello only |
| State | Minimal - single packet analysis |
| Existing Code | Detection signature complete |

**Implementation Effort:** Medium (3-4 days)

- Only need to parse TLS ClientHello
- JA3/JA4 algorithms are well-documented
- No decryption required
- SNI extraction is straightforward

**Use Cases:**

- [ ] Encrypted traffic classification (identify applications)
- [ ] Malware detection via fingerprint matching
- [ ] TLS version monitoring
- [ ] Certificate validation
- [ ] Cipher suite analysis
- [ ] SNI-based filtering

**Metadata Structure:**

```go
type TLSMetadata struct {
    // Handshake info
    Version         string   // TLS 1.2, 1.3
    SNI             string   // Server Name Indication
    CipherSuites    []uint16
    Extensions      []uint16
    SupportedGroups []uint16
    ECPointFormats  []uint8

    // Fingerprints
    JA3             string   // Client fingerprint
    JA3S            string   // Server fingerprint
    JA4             string   // Updated fingerprint format

    // Certificate info (if captured)
    CertSubject     string
    CertIssuer      string
    CertExpiry      time.Time
    CertSANs        []string
}
```

**JA3 Algorithm:**

```
JA3 = MD5(TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats)
```

**Verdict:** **High priority** - Critical for analyzing encrypted traffic.

---

#### 5. Database Protocols (MySQL, PostgreSQL)

**Overview:** Database wire protocols for query monitoring.

| Protocol | Port | Transport | Complexity |
|----------|------|-----------|------------|
| MySQL | 3306 | TCP | High (binary, auth states) |
| PostgreSQL | 5432 | TCP | High (message-based) |

**Implementation Effort:** High (5-7 days each)

- Binary protocols with complex state machines
- Authentication handshakes
- Query parsing is non-trivial
- Multiple protocol versions

**Use Cases:**

- [ ] Query logging for audit
- [ ] Data exfiltration detection
- [ ] SQL injection detection
- [ ] Slow query monitoring
- [ ] Access pattern analysis
- [ ] Compliance (who accessed what data)

**Metadata Structure:**

```go
type DatabaseMetadata struct {
    Protocol    string // MySQL, PostgreSQL
    SessionID   string
    Username    string
    Database    string

    // Query info
    QueryType   string // SELECT, INSERT, UPDATE, DELETE
    Query       string // Full or truncated
    Tables      []string
    RowsAffected int64

    // Response
    ErrorCode   int
    ErrorMessage string
    ExecutionTime time.Duration
}
```

**Verdict:** **Lower priority** - High effort, niche use case.

---

#### 6. ICMP

**Overview:** Internet Control Message Protocol - network diagnostics.

| Aspect | Assessment |
|--------|------------|
| Transport | IP (no TCP/UDP) |
| Complexity | Very Low |
| State | None |
| Existing Code | Detection signature complete |

**Implementation Effort:** Very Low (1 day)

- Fixed format, no parsing complexity
- No state tracking needed
- gopacket has ICMP layer

**Use Cases:**

- [ ] Ping monitoring
- [ ] ICMP tunneling detection
- [ ] Network diagnostics
- [ ] Path MTU discovery tracking
- [ ] Unreachable destination logging

**Metadata Structure:**

```go
type ICMPMetadata struct {
    Type     uint8  // Echo, Reply, Unreachable, etc.
    Code     uint8
    Checksum uint16

    // Echo specific
    Identifier uint16
    Sequence   uint16

    // Unreachable specific
    OriginalDstIP   string
    OriginalDstPort uint16
}
```

**Verdict:** **Low priority** - Easy but limited value.

---

### Protocol Comparison Matrix

| Protocol | Effort | User Demand | LI Value | Security Value | Existing Infra |
|----------|--------|-------------|----------|----------------|----------------|
| DNS | Low | Very High | High | Very High | Detection done |
| Email (SMTP) | Medium | High | Very High | High | None |
| Email (IMAP) | Medium-High | Medium | High | Medium | None |
| TLS/JA3 | Medium | High | Medium | Very High | Detection done |
| HTTP | Medium | High | Medium | High | Detection done |
| MySQL | High | Medium | Low | High | Detection done |
| PostgreSQL | High | Low | Low | Medium | Detection done |
| ICMP | Very Low | Low | Low | Low | Detection done |

---

## Recommended Roadmap

### Phase 1: DNS (Foundation)

**Duration:** 2-3 days
**Priority:** Highest

**Rationale:**
- Lowest implementation effort
- Highest user demand (every network monitoring tool supports DNS)
- Strong LI relevance
- Enables valuable security features (tunneling detection)
- Establishes pattern for future protocols

**Deliverables:**
- [ ] `DNSMetadata` type in `internal/pkg/types/`
- [ ] DNS plugin in `internal/pkg/dns/` (or extend detector)
- [ ] `lc sniff dns` command
- [ ] `lc tap dns` command
- [ ] `lc hunt dns` command
- [ ] DNS-specific TUI display
- [ ] Query/response correlation
- [ ] Basic tunneling detection

### Phase 2: Email (SMTP)

**Duration:** 3-4 days
**Priority:** High

**Rationale:**
- Major LI use case
- Text-based protocol (easier parsing)
- Clear envelope data extraction
- High compliance value

**Deliverables:**
- [ ] `EmailMetadata` type
- [ ] SMTP parser and plugin
- [ ] `lc sniff email` / `lc tap email` / `lc hunt email`
- [ ] Envelope tracking (MAIL FROM, RCPT TO)
- [ ] Message-ID correlation
- [ ] STARTTLS detection

### Phase 3: TLS/JA3 Fingerprinting

**Duration:** 3-4 days
**Priority:** High

**Rationale:**
- Critical for encrypted traffic analysis
- No decryption needed
- Well-documented algorithms
- High security value

**Deliverables:**
- [ ] `TLSMetadata` type
- [ ] ClientHello parser
- [ ] JA3/JA3S/JA4 calculation
- [ ] SNI extraction
- [ ] `lc sniff tls` / `lc tap tls` / `lc hunt tls`
- [ ] Fingerprint database integration hooks

### Phase 4: HTTP

**Duration:** 4-5 days
**Priority:** Medium

**Rationale:**
- Most common application protocol
- Complements TLS analysis
- Foundation for web security monitoring

**Deliverables:**
- [ ] `HTTPMetadata` type
- [ ] HTTP/1.x request/response parser
- [ ] `lc sniff http` / `lc tap http` / `lc hunt http`
- [ ] URL logging
- [ ] Header extraction
- [ ] Content-type classification

### Phase 5: Email (IMAP/POP3)

**Duration:** 4-5 days
**Priority:** Medium

**Rationale:**
- Completes email protocol suite
- Additional LI coverage
- IMAP is more complex but valuable

**Deliverables:**
- [ ] Extend `EmailMetadata` for IMAP/POP3
- [ ] IMAP command parser
- [ ] POP3 command parser
- [ ] Mailbox operation tracking

### Phase 6: Database Protocols (Optional)

**Duration:** 10-14 days
**Priority:** Lower

**Rationale:**
- Enterprise security use case
- High effort but valuable for specific deployments
- Consider user demand before implementing

**Deliverables:**
- [ ] MySQL protocol parser
- [ ] PostgreSQL protocol parser
- [ ] Query extraction and logging
- [ ] `lc sniff db` commands

---

## Implementation Patterns

### Adding a New Protocol

Based on the existing VoIP implementation, here's the pattern:

#### Step 1: Create Metadata Type

```go
// internal/pkg/types/dns.go
type DNSMetadata struct {
    TransactionID uint16
    IsResponse    bool
    QueryName     string
    // ...
}
```

#### Step 2: Create Protocol Package

```
internal/pkg/dns/
├── parser.go       # DNS packet parsing
├── tracker.go      # Query/response correlation
├── analyzer.go     # Deep analysis (tunneling detection)
└── plugin.go       # Plugin interface implementation
```

#### Step 3: Register Detection Enhancement

If needed, enhance the existing signature in `internal/pkg/detector/signatures/application/dns.go`.

#### Step 4: Create CLI Subcommands

```go
// cmd/sniff/dns.go
var dnsCmd = &cobra.Command{
    Use:   "dns",
    Short: "Capture DNS traffic",
    RunE:  runDNSSniff,
}

func init() {
    SniffCmd.AddCommand(dnsCmd)
    // Add DNS-specific flags
}
```

#### Step 5: Extend TUI (Optional)

Add protocol-specific display in `internal/pkg/tui/`.

#### Step 6: Update Build Tags

Add protocol to appropriate build variants in `cmd/root_*.go`.

---

## Architecture Considerations

### Shared vs. Separate Plugin Packages

**Option A: Extend VoIP plugins package**
- Rename to generic `internal/pkg/protocols/plugins/`
- Pros: Shared infrastructure
- Cons: VoIP-specific code mixed with others

**Option B: Separate packages per protocol**
- `internal/pkg/dns/`, `internal/pkg/email/`, etc.
- Pros: Clean separation
- Cons: Some code duplication

**Recommendation:** Option B - cleaner architecture, protocols have different needs.

### Metadata Extension Strategy

**Option A: Protocol-specific fields in PacketDisplay**
```go
type PacketDisplay struct {
    VoIPData *VoIPMetadata
    DNSData  *DNSMetadata
    EmailData *EmailMetadata
    // ...
}
```

**Option B: Generic metadata map**
```go
type PacketDisplay struct {
    ProtocolData map[string]interface{}
}
```

**Recommendation:** Option A for type safety, add fields as needed.

### LI Integration

New protocols should integrate with the LI system:

- DNS queries → X2 (IRI) as communication metadata
- Email envelopes → X2 (IRI) as addressing info
- Email content → X3 (CC) as communication content
- HTTP URLs → X2 (IRI) as access metadata

---

## Reusing Aho-Corasick for Content Filtering

### Existing Implementation

lippycat already has a sophisticated Aho-Corasick implementation in `internal/pkg/ahocorasick/` that can be reused for keyword detection across new protocols.

**Current Components:**

| File | Purpose |
|------|---------|
| `ahocorasick.go` | Core AC automaton (trie + failure links) |
| `builder.go` | Automaton builder |
| `matcher.go` | `Matcher` interface and types |
| `buffered.go` | Double-buffered wrapper with lock-free reads |
| `dense.go` | Dense state table (SIMD-optimized) |
| `match_amd64.go` | SIMD-optimized matching for amd64 |
| `match_generic.go` | Portable fallback |

**Key Interface:**

```go
type Matcher interface {
    Build(patterns []Pattern) error
    Match(input []byte) []MatchResult
    MatchBatch(inputs [][]byte) [][]MatchResult
    PatternCount() int
}

type Pattern struct {
    ID   int
    Text string
    Type filtering.PatternType  // Prefix, Suffix, Contains
}
```

### Why Aho-Corasick for Content Filtering?

**Performance Advantage:**

For keyword detection in email/HTTP content, AC provides massive speedup:

| Scenario | Linear Scan | Aho-Corasick |
|----------|-------------|--------------|
| 10KB email, 100 keywords | 1M comparisons | 10K operations |
| 10KB email, 10K keywords | 100M comparisons | 10K operations |
| Throughput at 10K patterns | Baseline | **265x faster** |

AC processes text in a single pass regardless of pattern count, making it ideal for:
- DLP (Data Loss Prevention) with large keyword lists
- Threat intel matching (IoC lists with thousands of indicators)
- Compliance filtering (regulated terms, PII patterns)

### Use Cases by Protocol

#### Email (SMTP/IMAP)

| Use Case | Match Target | Pattern Type | AC Benefit |
|----------|--------------|--------------|------------|
| DLP keywords | Body, subject | Contains | Large keyword lists |
| Sensitive data | Body (SSN, CC#) | Contains | Pattern matching |
| Domain blocklist | From/To addresses | Suffix | Efficient suffix match |
| Compliance terms | Subject, body | Contains | Regulatory term lists |
| Threat indicators | URLs in body | Contains | IoC matching |
| Attachment names | Content-Disposition | Contains | Malware detection |

#### HTTP

| Use Case | Match Target | Pattern Type | AC Benefit |
|----------|--------------|--------------|------------|
| URL filtering | Request URL | Contains/Prefix | Blocklist matching |
| Malware C2 | Host header, URL | Contains | Threat intel |
| Data exfiltration | POST body | Contains | DLP patterns |
| API key detection | Headers, body | Contains | Secret scanning |
| Sensitive paths | URL path | Prefix/Contains | Access control |
| User-Agent fingerprinting | UA header | Contains | Bot detection |

#### DNS

| Use Case | Match Target | Pattern Type | AC Benefit |
|----------|--------------|--------------|------------|
| Domain blocklist | Query name | Suffix | `.malware.com` patterns |
| DGA detection | Query name | Contains | Known DGA patterns |
| Tunneling detection | TXT record data | Contains | Encoded data patterns |
| Category filtering | Query name | Contains | Content categories |

### Implementation Architecture

The existing `BufferedMatcher` can be composed into protocol-specific filters:

```
┌─────────────────────────────────────────────────────────────────┐
│  internal/pkg/ahocorasick/  (EXISTING - no changes needed)      │
│  └─ BufferedMatcher, DenseAhoCorasick, Pattern, MatchResult     │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│ VoIP Filter       │ │ Email Filter      │ │ HTTP Filter       │
│ (existing)        │ │ (new)             │ │ (new)             │
│                   │ │                   │ │                   │
│ - SIP users (AC)  │ │ - Subject (AC)    │ │ - URL (AC)        │
│ - SIP URIs (AC)   │ │ - Body (AC)       │ │ - Headers (AC)    │
│ - Phone (Bloom)   │ │ - Sender (AC)     │ │ - Body (AC)       │
│ - IP (Hash/Radix) │ │ - Domain (AC)     │ │ - Host (AC)       │
└───────────────────┘ └───────────────────┘ └───────────────────┘
```

### Example Implementation

```go
// internal/pkg/email/filter.go
type EmailFilter struct {
    subjectMatcher  *ahocorasick.BufferedMatcher  // DLP keywords in subject
    bodyMatcher     *ahocorasick.BufferedMatcher  // DLP keywords in body
    senderMatcher   *ahocorasick.BufferedMatcher  // Sender patterns
    domainMatcher   *ahocorasick.BufferedMatcher  // Domain blocklist (suffix)
}

func NewEmailFilter() *EmailFilter {
    return &EmailFilter{
        subjectMatcher: ahocorasick.NewBufferedMatcher(ahocorasick.AlgorithmAuto),
        bodyMatcher:    ahocorasick.NewBufferedMatcher(ahocorasick.AlgorithmAuto),
        senderMatcher:  ahocorasick.NewBufferedMatcher(ahocorasick.AlgorithmAuto),
        domainMatcher:  ahocorasick.NewBufferedMatcher(ahocorasick.AlgorithmAuto),
    }
}

func (f *EmailFilter) LoadDLPKeywords(keywords []string) error {
    patterns := make([]ahocorasick.Pattern, len(keywords))
    for i, kw := range keywords {
        patterns[i] = ahocorasick.Pattern{
            ID:   i,
            Text: kw,
            Type: filtering.PatternTypeContains,
        }
    }
    return f.bodyMatcher.Build(patterns)
}

func (f *EmailFilter) CheckEmail(email *EmailMetadata, body []byte) *FilterResult {
    result := &FilterResult{}

    // Check subject for DLP keywords
    if matches := f.subjectMatcher.Match([]byte(email.Subject)); len(matches) > 0 {
        result.SubjectMatches = matches
        result.Matched = true
    }

    // Check body for DLP keywords
    if matches := f.bodyMatcher.Match(body); len(matches) > 0 {
        result.BodyMatches = matches
        result.Matched = true
    }

    // Check sender domain against blocklist
    domain := extractDomain(email.From)
    if matches := f.domainMatcher.Match([]byte(domain)); len(matches) > 0 {
        result.DomainMatches = matches
        result.Matched = true
    }

    return result
}
```

### LI Integration with AC Filtering

The AC-based filtering integrates naturally with the existing LI system:

1. **X1 Task Activation**: ADMF sends keyword patterns via X1 interface
2. **Pattern Distribution**: LI Manager builds AC automaton, pushes to hunters/processors
3. **Content Matching**: AC matcher runs on email body/HTTP content
4. **IRI/CC Generation**: Matched content triggers X2 (IRI) or X3 (CC) delivery

**Filter Mapping:**

| LI Target Type | Existing Matcher | New Protocol Use |
|----------------|------------------|------------------|
| SIP URI | AC (BufferedMatcher) | Email addresses |
| Keywords | AC (BufferedMatcher) | Email/HTTP body content |
| Phone Number | Bloom + Hash | - |
| IP Address | Hash + Radix | HTTP client IPs |
| Domain | AC (suffix mode) | DNS queries, email domains |

### Performance Characteristics

**From existing benchmarks:**

| Metric | Value |
|--------|-------|
| Single match (dense SIMD) | 80-90ns |
| Batch of 100 inputs | 10.5ms |
| Memory per 1K states | ~1MB |
| Build time | 4-5x slower than sparse (acceptable) |
| Crossover point | Auto-switches to AC at 100+ patterns |

**Recommendation:** Use `AlgorithmAuto` for all new protocol filters - automatically selects linear scan for small pattern sets and AC for large ones.

### Additional Pattern Matching Infrastructure

Beyond Aho-Corasick, lippycat has other matchers that may be useful:

| Matcher | Location | Use Case |
|---------|----------|----------|
| **PhoneMatcher** | `internal/pkg/phonematcher/` | Phone number suffix matching with bloom filter |
| **IP Matcher** | Hash maps + radix trees | Exact IP and CIDR matching |

**PhoneMatcher** could potentially be adapted for:
- Domain suffix matching (TLDs, subdomains)
- File extension matching
- Any suffix-based pattern matching with high rejection rate

### Conclusion

The existing Aho-Corasick implementation is **immediately reusable** for content filtering in email and HTTP protocols. No changes to the core AC package are needed—only protocol-specific wrapper filters that compose multiple `BufferedMatcher` instances for different content fields.

This significantly reduces implementation effort for content-aware filtering features:
- DLP keyword detection
- Threat intel matching
- Compliance term scanning
- Domain/URL blocklisting

---

## Resource Estimates

| Phase | Protocol | Effort | Dependencies |
|-------|----------|--------|--------------|
| 1 | DNS | 2-3 days | None |
| 2 | SMTP | 3-4 days | TCP reassembly (done) |
| 3 | TLS/JA3 | 3-4 days | None |
| 4 | HTTP | 4-5 days | TCP reassembly (done) |
| 5 | IMAP/POP3 | 4-5 days | SMTP (pattern) |
| 6 | Database | 10-14 days | TCP reassembly (done) |

**Total for Phases 1-5:** ~17-21 days
**Total including Phase 6:** ~27-35 days

---

## Open Questions

1. **Protocol naming:** Should email be `lc sniff email` or separate `lc sniff smtp`, `lc sniff imap`?
2. **TUI integration:** Unified protocol view or protocol-specific tabs?
3. **LI mapping:** How to map new protocols to ETSI IRI/CC categories?
4. **Filter syntax:** How to express protocol-specific filters (DNS domain patterns, email addresses)?
5. **AC filter configuration:** How should users configure keyword lists for DLP/content filtering?
   - CLI flags (`--dlp-keywords-file`)
   - Configuration file
   - X1 task activation only (LI mode)
6. **Filter package organization:** Should protocol filters live in their respective packages (`internal/pkg/email/filter.go`) or in a unified `internal/pkg/filtering/` package?
7. **Match result handling:** Should keyword matches trigger alerts, logging, or LI delivery (or all three)?

---

## Conclusion

DNS should be the first protocol added due to its low implementation effort, high user demand, and strong relevance to lippycat's use cases. Email (SMTP) should follow as the second priority given its critical importance for lawful interception. TLS fingerprinting provides high value for encrypted traffic analysis with moderate effort.

The existing architecture is well-designed for protocol extensibility. The main work is creating protocol-specific analysis packages and CLI subcommands—the detection infrastructure already exists.

**Key advantage:** The existing Aho-Corasick implementation can be immediately reused for content filtering in email and HTTP, enabling DLP, threat intel matching, and compliance monitoring with minimal additional effort. This is a significant force multiplier for the value delivered by new protocol support.
