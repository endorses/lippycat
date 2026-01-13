# LI Multi-Protocol Expansion Research

## Document Information

| Field | Value |
|-------|-------|
| Created | 2026-01-13 |
| Status | Research |
| Author | Claude Code |
| Related Documents | [etsi-x1-x2-x3-integration.md](etsi-x1-x2-x3-integration.md), [protocol-expansion-roadmap.md](protocol-expansion-roadmap.md) |
| Related Standards | ETSI TS 103 221-1, TS 103 221-2, TS 103 280 |

---

## Executive Summary

This document provides a comprehensive assessment of what is required to extend lippycat's Lawful Interception (LI) support from VoIP-only to include DNS, HTTP, TLS, and Email protocols. The current LI implementation provides a solid foundation that can be extended to these protocols.

**Current State:**
- Protocol detection and metadata extraction: Fully implemented for all protocols
- X1/X2/X3 LI support: VoIP (SIP/RTP) only
- Filter types: VoIP-focused (SIP URI, phone numbers, IP addresses)

**Key Findings:**
1. The X2/X3 binary TLV protocol is protocol-agnostic - only new attribute types and encoders are needed
2. The filter types and hunter matching are **already implemented** for non-LI use - only X1 target type mappings are needed
3. The metadata extraction layer is complete - all protocol data is already available in `PacketDisplay`
4. Each protocol requires a dedicated encoder following the existing VoIP encoder pattern
5. **ETSI standards gap:** Most protocol-specific target types (DNS domain, TLS SNI, HTTP host, etc.) are **not** defined in ETSI TS 103 280. Only `EmailAddress` is a standard type. DNS/HTTP/TLS filtering would require proprietary X1 extensions or IP-based targeting with internal protocol filtering.

**Critical Conclusion:**
> **Do not extend X1/X2/X3 to protocols beyond VoIP.** ETSI standards only define X2/X3 encoding for VoIP. Extending to DNS, HTTP, TLS, or Email would require proprietary extensions that standard ADMF/MDF systems cannot understand. Since lippycat already has a proprietary gRPC infrastructure for multi-protocol administration and delivery, creating proprietary X1/X2/X3 extensions provides no benefit. **Keep X1/X2/X3 for VoIP interoperability; use gRPC for everything else.**

---

## Table of Contents

1. [Current Architecture Analysis](#current-architecture-analysis)
2. [Protocol-by-Protocol Assessment](#protocol-by-protocol-assessment)
   - [DNS](#dns-protocol)
   - [HTTP](#http-protocol)
   - [TLS](#tls-protocol)
   - [Email (SMTP/IMAP/POP3)](#email-protocol)
3. [Common Infrastructure Requirements](#common-infrastructure-requirements)
4. [X1 Interface Extensions](#x1-interface-extensions)
5. [X2/X3 Attribute Definitions](#x2x3-attribute-definitions)
6. [Filter System Extensions](#filter-system-extensions)
7. [Processor Integration](#processor-integration)
8. [ETSI Standards Mapping](#etsi-standards-mapping)
9. [Complexity Assessment](#complexity-assessment)
10. [Dependencies and Prerequisites](#dependencies-and-prerequisites)
11. [Open Questions](#open-questions)
12. [ETSI Standards Sources](#etsi-standards-sources)
13. [Standards Compliance Reality](#standards-compliance-reality)
14. [Conclusion](#conclusion)

---

## Current Architecture Analysis

### What Exists

The current LI implementation in `internal/pkg/li/` provides:

| Component | Location | Status |
|-----------|----------|--------|
| LI Manager | `manager.go` | Complete for VoIP |
| Task Registry | `registry.go` | Protocol-agnostic (reusable) |
| Filter Manager | `filters.go` | VoIP target types only |
| X1 Server | `x1/server.go` | Protocol-agnostic (reusable) |
| X1 Client | `x1/client.go` | Protocol-agnostic (reusable) |
| X1 Schema Types | `x1/schema/` | Standard ETSI types |
| PDU Format | `x2x3/pdu.go` | Protocol-agnostic (reusable) |
| X2 Encoder | `x2x3/x2_encoder.go` | VoIP (SIP) only |
| X3 Encoder | `x2x3/x3_encoder.go` | VoIP (RTP) only |
| Delivery Client | `delivery/client.go` | Protocol-agnostic (reusable) |
| Processor Integration | `processor/processor_li.go` | VoIP checks only |

### Metadata Already Available

Protocol-specific metadata types in `internal/pkg/types/packet.go`:

```go
type PacketDisplay struct {
    // ... common fields ...
    VoIPData  *VoIPMetadata   // SIP/RTP - LI supported
    DNSData   *DNSMetadata    // DNS - detection complete
    EmailData *EmailMetadata  // SMTP/IMAP/POP3 - detection complete
    TLSData   *TLSMetadata    // TLS handshakes - detection complete
    HTTPData  *HTTPMetadata   // HTTP - detection complete
}
```

### Current Processor LI Integration

From `internal/pkg/processor/processor_li.go:119-174`:

```go
// Current: VoIP-only checks
if deliverX2 && pkt.VoIPData != nil && !pkt.VoIPData.IsRTP {
    pdu, err := liX2Encoder.EncodeIRI(pkt, task.XID)
    // ...
}

if deliverX3 && pkt.VoIPData != nil && pkt.VoIPData.IsRTP {
    pdu, err := liX3Encoder.EncodeCC(pkt, task.XID)
    // ...
}
```

**Gap:** Non-VoIP packets are silently ignored - they need routing to protocol-specific encoders.

---

## Protocol-by-Protocol Assessment

### DNS Protocol

#### Overview

| Aspect | Value |
|--------|-------|
| Transport | UDP (primary), TCP (zone transfers) |
| Metadata Type | `DNSMetadata` |
| Detection | `internal/pkg/detector/signatures/application/dns.go` |
| LI Relevance | High - query logging, tunneling detection |

#### Metadata Available (`types.DNSMetadata`)

```go
type DNSMetadata struct {
    TransactionID      uint16   // Query/response correlation
    IsResponse         bool     // Query vs response
    Opcode             string   // QUERY, IQUERY, STATUS, etc.
    ResponseCode       string   // NOERROR, NXDOMAIN, etc.
    QueryName          string   // Queried domain name
    QueryType          string   // A, AAAA, MX, CNAME, TXT, etc.
    QueryClass         string   // Usually IN (Internet)
    Answers            []DNSAnswer
    TunnelingScore     float64  // DNS tunneling probability
    EntropyScore       float64  // Entropy analysis
    // ... additional fields
}
```

#### What X2 IRI Should Contain

| IRI Event | Trigger | Attributes |
|-----------|---------|------------|
| DNSQuery | DNS query packet | QueryName, QueryType, TransactionID, Timestamp, Source/Dest IP |
| DNSResponse | DNS response packet | QueryName, QueryType, ResponseCode, Answers, TransactionID |

#### New TLV Attributes Required

| Attribute | Type Code | Size | Description |
|-----------|-----------|------|-------------|
| `AttrDNSQueryName` | 0x0300 | Variable | Domain name queried |
| `AttrDNSQueryType` | 0x0301 | 2 bytes | Record type (A=1, AAAA=28, MX=15, etc.) |
| `AttrDNSQueryClass` | 0x0302 | 2 bytes | Query class (IN=1) |
| `AttrDNSResponseCode` | 0x0303 | 2 bytes | RCODE (0=NOERROR, 3=NXDOMAIN) |
| `AttrDNSTransactionID` | 0x0304 | 2 bytes | Transaction ID |
| `AttrDNSAnswerCount` | 0x0305 | 2 bytes | Number of answers |
| `AttrDNSAnswerData` | 0x0306 | Variable | Encoded answer records |
| `AttrDNSTunnelingScore` | 0x0307 | 4 bytes | Float32 tunneling probability |

#### New IRI Types Required

| IRIType | Value | Trigger |
|---------|-------|---------|
| `IRIDNSQuery` | 10 | DNS query packet |
| `IRIDNSResponse` | 11 | DNS response packet |

#### Filter Target Types Required

| Target Type | Filter Pattern | Example |
|-------------|----------------|---------|
| `TargetTypeDNSDomain` | Domain name suffix | `*.example.com`, `malware.com` |
| `TargetTypeDNSQueryType` | Record type | `TXT`, `NULL` (for tunneling) |

#### X3 Content Delivery

DNS typically only uses X2 (IRI) for metadata. X3 (CC) is optional but could include:
- Full DNS response payload for deep inspection
- TXT record content (potential data exfiltration)

#### Encoder Requirements

```go
// internal/pkg/li/x2x3/dns_encoder.go
type DNSEncoder struct {
    seqNum      atomic.Uint32
    attrBuilder *AttributeBuilder
}

func (e *DNSEncoder) EncodeDNSQuery(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *DNSEncoder) EncodeDNSResponse(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
```

#### Complexity: Low

- UDP-based, no state required
- Simple query/response correlation via transaction ID
- Small metadata set
- Follows existing encoder pattern closely

---

### HTTP Protocol

#### Overview

| Aspect | Value |
|--------|-------|
| Transport | TCP |
| Metadata Type | `HTTPMetadata` |
| Detection | `internal/pkg/detector/signatures/application/http.go` |
| LI Relevance | Medium - URL logging, web access patterns |

#### Metadata Available (`types.HTTPMetadata`)

```go
type HTTPMetadata struct {
    Type           string            // "request" or "response"
    IsServer       bool              // Response indicator
    Method         string            // GET, POST, PUT, etc.
    Path           string            // URL path
    Version        string            // HTTP/1.0, HTTP/1.1
    StatusCode     int               // 200, 404, 500, etc.
    StatusReason   string            // "OK", "Not Found"
    Host           string            // Host header
    ContentType    string            // Content-Type header
    ContentLength  int64             // Content length
    UserAgent      string            // User-Agent header
    Headers        map[string]string // All headers
    QueryString    string            // URL query parameters
    BodyPreview    string            // Body preview (opt-in)
    // ... additional fields
}
```

#### What X2 IRI Should Contain

| IRI Event | Trigger | Attributes |
|-----------|---------|------------|
| HTTPRequest | HTTP request | Method, URL, Host, Headers, Timestamp, Source/Dest IP |
| HTTPResponse | HTTP response | StatusCode, Headers, ContentType, ResponseTime |

#### New TLV Attributes Required

| Attribute | Type Code | Size | Description |
|-----------|-----------|------|-------------|
| `AttrHTTPMethod` | 0x0400 | Variable | HTTP method (GET, POST, etc.) |
| `AttrHTTPPath` | 0x0401 | Variable | URL path |
| `AttrHTTPVersion` | 0x0402 | Variable | HTTP version |
| `AttrHTTPHost` | 0x0403 | Variable | Host header |
| `AttrHTTPStatusCode` | 0x0404 | 2 bytes | Response status code |
| `AttrHTTPStatusReason` | 0x0405 | Variable | Status reason phrase |
| `AttrHTTPContentType` | 0x0406 | Variable | Content-Type header |
| `AttrHTTPContentLength` | 0x0407 | 4 bytes | Content length |
| `AttrHTTPUserAgent` | 0x0408 | Variable | User-Agent header |
| `AttrHTTPQueryString` | 0x0409 | Variable | Query parameters |
| `AttrHTTPHeader` | 0x040A | Variable | Generic header (name:value) |
| `AttrHTTPSessionID` | 0x040B | Variable | Session correlation ID |

#### New IRI Types Required

| IRIType | Value | Trigger |
|---------|-------|---------|
| `IRIHTTPRequest` | 20 | HTTP request |
| `IRIHTTPResponse` | 21 | HTTP response |

#### Filter Target Types Required

| Target Type | Filter Pattern | Example |
|-------------|----------------|---------|
| `TargetTypeHTTPHost` | Host header pattern | `*.example.com` |
| `TargetTypeHTTPPath` | URL path pattern | `/api/*`, `/admin/*` |
| `TargetTypeHTTPMethod` | HTTP method | `POST`, `PUT` |

#### X3 Content Delivery

HTTP content can be delivered via X3:
- Request body (POST data, file uploads)
- Response body (downloaded content)

**Considerations:**
- Body capture is opt-in due to volume
- Content may be compressed (gzip)
- Binary content (images, files) increases volume significantly

#### Encoder Requirements

```go
// internal/pkg/li/x2x3/http_encoder.go
type HTTPEncoder struct {
    seqNum      atomic.Uint32
    attrBuilder *AttributeBuilder
}

func (e *HTTPEncoder) EncodeHTTPRequest(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *HTTPEncoder) EncodeHTTPResponse(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *HTTPEncoder) EncodeHTTPBody(pkt *types.PacketDisplay, xid uuid.UUID, body []byte) (*PDU, error)
```

#### Complexity: Medium

- Request/response correlation needed (session tracking)
- Header parsing already complete in metadata
- Body capture adds complexity and volume
- HTTP/2 multiplexing not currently supported (HTTP/1.x only)

---

### TLS Protocol

#### Overview

| Aspect | Value |
|--------|-------|
| Transport | TCP |
| Metadata Type | `TLSMetadata` |
| Detection | `internal/pkg/detector/signatures/application/tls.go` |
| LI Relevance | High - encrypted traffic fingerprinting, SNI extraction |

#### Metadata Available (`types.TLSMetadata`)

```go
type TLSMetadata struct {
    Version           string   // "TLS 1.3"
    VersionRaw        uint16   // 0x0304
    HandshakeType     string   // "ClientHello", "ServerHello"
    IsServer          bool     // ServerHello indicator
    SNI               string   // Server Name Indication
    CipherSuites      []uint16 // Advertised cipher suites
    Extensions        []uint16 // Extension types
    SupportedGroups   []uint16 // Named curves
    ALPNProtocols     []string // ALPN protocols
    SelectedCipher    uint16   // Selected cipher (ServerHello)
    JA3Fingerprint    string   // Client fingerprint
    JA3SFingerprint   string   // Server fingerprint
    JA4Fingerprint    string   // Modern fingerprint
    // ... additional fields
}
```

#### What X2 IRI Should Contain

| IRI Event | Trigger | Attributes |
|-----------|---------|------------|
| TLSClientHello | ClientHello | SNI, CipherSuites, JA3, ALPN, Timestamp, Source/Dest IP |
| TLSServerHello | ServerHello | SelectedCipher, Version, JA3S, Certificate info |
| TLSHandshakeComplete | Handshake done | Full negotiated parameters |

#### New TLV Attributes Required

| Attribute | Type Code | Size | Description |
|-----------|-----------|------|-------------|
| `AttrTLSVersion` | 0x0500 | 2 bytes | TLS version (raw) |
| `AttrTLSHandshakeType` | 0x0501 | 1 byte | Handshake message type |
| `AttrTLSSNI` | 0x0502 | Variable | Server Name Indication |
| `AttrTLSCipherSuites` | 0x0503 | Variable | Array of cipher suite IDs |
| `AttrTLSExtensions` | 0x0504 | Variable | Array of extension types |
| `AttrTLSSupportedGroups` | 0x0505 | Variable | Named curves |
| `AttrTLSALPN` | 0x0506 | Variable | ALPN protocols |
| `AttrTLSSelectedCipher` | 0x0507 | 2 bytes | Negotiated cipher |
| `AttrTLSJA3` | 0x0508 | 32 bytes | JA3 fingerprint (MD5) |
| `AttrTLSJA3S` | 0x0509 | 32 bytes | JA3S fingerprint |
| `AttrTLSJA4` | 0x050A | Variable | JA4 fingerprint |
| `AttrTLSCertSubject` | 0x050B | Variable | Certificate subject |
| `AttrTLSCertIssuer` | 0x050C | Variable | Certificate issuer |
| `AttrTLSCertSANs` | 0x050D | Variable | Subject Alt Names |

#### New IRI Types Required

| IRIType | Value | Trigger |
|---------|-------|---------|
| `IRITLSClientHello` | 30 | TLS ClientHello |
| `IRITLSServerHello` | 31 | TLS ServerHello |
| `IRITLSHandshakeComplete` | 32 | Handshake finished |

#### Filter Target Types Required

| Target Type | Filter Pattern | Example |
|-------------|----------------|---------|
| `TargetTypeTLSSNI` | SNI pattern | `*.example.com` |
| `TargetTypeTLSJA3` | JA3 fingerprint | `abc123...` (malware signatures) |
| `TargetTypeTLSCertSubject` | Certificate subject | `CN=*.malware.com` |

#### X3 Content Delivery

TLS typically uses X2 only (metadata) unless key material is available:
- If SSLKEYLOGFILE is configured, decrypted content can be captured
- Without decryption, X3 would contain encrypted payload (limited value)

#### Encoder Requirements

```go
// internal/pkg/li/x2x3/tls_encoder.go
type TLSEncoder struct {
    seqNum      atomic.Uint32
    attrBuilder *AttributeBuilder
}

func (e *TLSEncoder) EncodeClientHello(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *TLSEncoder) EncodeServerHello(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *TLSEncoder) EncodeHandshakeComplete(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
```

#### Complexity: Medium

- Only handshake analysis (no decryption)
- Single-packet analysis (ClientHello/ServerHello)
- JA3/JA4 fingerprinting already computed in metadata
- Session correlation for handshake completion

---

### Email Protocol

#### Overview

| Aspect | Value |
|--------|-------|
| Transport | TCP |
| Protocols | SMTP (25, 587, 465), IMAP (143, 993), POP3 (110, 995) |
| Metadata Type | `EmailMetadata` |
| Detection | `internal/pkg/detector/signatures/application/smtp.go`, `imap.go`, `pop3.go` |
| LI Relevance | Very High - primary LI use case, ETSI has specific email standards |

#### Metadata Available (`types.EmailMetadata`)

```go
type EmailMetadata struct {
    Protocol         string   // "SMTP", "IMAP", "POP3"
    IsServer         bool     // Server response indicator
    MailFrom         string   // MAIL FROM address
    RcptTo           []string // RCPT TO addresses
    Subject          string   // Subject header
    MessageID        string   // Message-ID for correlation
    Command          string   // Current command
    ResponseCode     int      // SMTP response code
    STARTTLSOffered  bool     // STARTTLS advertised
    Encrypted        bool     // After STARTTLS
    AuthMethod       string   // AUTH method
    AuthUser         string   // Authenticated user
    BodyPreview      string   // Body preview (opt-in)

    // IMAP-specific
    IMAPTag          string   // Command tag
    IMAPCommand      string   // IMAP command
    IMAPMailbox      string   // Selected mailbox
    IMAPUID          uint32   // Message UID

    // POP3-specific
    POP3Command      string   // POP3 command
    POP3MsgNum       uint32   // Message number
    // ... additional fields
}
```

#### What X2 IRI Should Contain

| IRI Event | Trigger | Attributes |
|-----------|---------|------------|
| EmailEnvelope | SMTP MAIL FROM/RCPT TO | Sender, Recipients, Timestamp |
| EmailHeaders | SMTP DATA headers | MessageID, Subject, Date, Size |
| EmailDelivered | SMTP 250 after DATA | Delivery confirmation |
| EmailFailed | SMTP 4xx/5xx | Error code, reason |
| IMAPAccess | IMAP SELECT/FETCH | Mailbox, UID, User |
| POP3Access | POP3 RETR | Message number, User |

#### New TLV Attributes Required

| Attribute | Type Code | Size | Description |
|-----------|-----------|------|-------------|
| `AttrEmailProtocol` | 0x0600 | 1 byte | 1=SMTP, 2=IMAP, 3=POP3 |
| `AttrEmailMailFrom` | 0x0601 | Variable | Sender address |
| `AttrEmailRcptTo` | 0x0602 | Variable | Recipient address (repeated) |
| `AttrEmailSubject` | 0x0603 | Variable | Subject header |
| `AttrEmailMessageID` | 0x0604 | Variable | Message-ID |
| `AttrEmailSize` | 0x0605 | 4 bytes | Message size |
| `AttrEmailResponseCode` | 0x0606 | 2 bytes | SMTP response code |
| `AttrEmailAuthUser` | 0x0607 | Variable | Authenticated user |
| `AttrEmailAuthMethod` | 0x0608 | Variable | Auth method (PLAIN, LOGIN) |
| `AttrEmailEncrypted` | 0x0609 | 1 byte | STARTTLS status |
| `AttrIMAPMailbox` | 0x060A | Variable | Mailbox name |
| `AttrIMAPUID` | 0x060B | 4 bytes | Message UID |
| `AttrIMAPCommand` | 0x060C | Variable | IMAP command |
| `AttrPOP3MsgNum` | 0x060D | 4 bytes | POP3 message number |

#### New IRI Types Required

| IRIType | Value | Trigger |
|---------|-------|---------|
| `IRIEmailEnvelope` | 40 | SMTP envelope complete |
| `IRIEmailHeaders` | 41 | Email headers extracted |
| `IRIEmailDelivered` | 42 | Delivery confirmed |
| `IRIEmailFailed` | 43 | Delivery failed |
| `IRIIMAPAccess` | 44 | IMAP mailbox access |
| `IRIIMAPFetch` | 45 | IMAP message fetch |
| `IRIPOP3Retrieve` | 46 | POP3 message retrieval |

#### Filter Target Types Required

| Target Type | Filter Pattern | Example |
|-------------|----------------|---------|
| `TargetTypeEmailAddress` | Email address pattern | `*@example.com`, `user@*` |
| `TargetTypeEmailDomain` | Domain suffix | `@company.com` |
| `TargetTypeEmailSubject` | Subject keywords | Aho-Corasick patterns |
| `TargetTypeIMAPMailbox` | Mailbox name | `INBOX`, `Sent` |

#### X3 Content Delivery

Email content is a primary X3 use case:
- Full message body (after SMTP DATA)
- Attachments
- MIME parts

**ETSI Standards Note:** Email LI is specifically addressed in TS 102 232-2 which defines email-specific handover data. However, this standard uses ASN.1 encoding for the HI2/HI3 interfaces. For X2/X3 binary TLV encoding:
- **Content specification:** Follow TS 102 232-2 (what fields to include)
- **TLV encoding:** Use proprietary attribute codes (0xFF00-0xFFFE range) since TS 103 221-2 does not define email-specific TLV types

#### Encoder Requirements

```go
// internal/pkg/li/x2x3/email_encoder.go
type EmailEncoder struct {
    seqNum      atomic.Uint32
    attrBuilder *AttributeBuilder
}

// SMTP encoding
func (e *EmailEncoder) EncodeEnvelope(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *EmailEncoder) EncodeHeaders(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *EmailEncoder) EncodeDelivered(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *EmailEncoder) EncodeBody(pkt *types.PacketDisplay, xid uuid.UUID, body []byte) (*PDU, error)

// IMAP encoding
func (e *EmailEncoder) EncodeIMAPAccess(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
func (e *EmailEncoder) EncodeIMAPFetch(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)

// POP3 encoding
func (e *EmailEncoder) EncodePOP3Retrieve(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error)
```

#### Complexity: High

- Three protocols (SMTP, IMAP, POP3)
- Transaction state tracking
- MIME parsing for body content
- Authentication tracking
- STARTTLS transition handling
- High LI priority - must be robust

---

## Common Infrastructure Requirements

### 1. Protocol Dispatcher in Processor

The processor's LI integration needs to route packets to the appropriate encoder:

```go
// internal/pkg/processor/processor_li.go

func (p *Processor) processLIPacket(pkt *types.PacketDisplay, task *li.InterceptTask) {
    // X2 (IRI) encoding
    if task.DeliveryType.IncludesX2() {
        var pdu *x2x3.PDU
        var err error

        switch {
        case pkt.VoIPData != nil && !pkt.VoIPData.IsRTP:
            pdu, err = p.liX2Encoder.EncodeIRI(pkt, task.XID)
        case pkt.DNSData != nil:
            pdu, err = p.liDNSEncoder.EncodeDNS(pkt, task.XID)
        case pkt.HTTPData != nil:
            pdu, err = p.liHTTPEncoder.EncodeHTTP(pkt, task.XID)
        case pkt.TLSData != nil:
            pdu, err = p.liTLSEncoder.EncodeTLS(pkt, task.XID)
        case pkt.EmailData != nil:
            pdu, err = p.liEmailEncoder.EncodeEmail(pkt, task.XID)
        }

        if pdu != nil && err == nil {
            p.queueX2Delivery(pdu, task.DestinationIDs)
        }
    }

    // X3 (CC) encoding - similar structure
    // ...
}
```

### 2. Encoder Registry Pattern

```go
// internal/pkg/li/x2x3/encoder_registry.go

type EncoderRegistry struct {
    voip  *X2Encoder
    dns   *DNSEncoder
    http  *HTTPEncoder
    tls   *TLSEncoder
    email *EmailEncoder
}

func NewEncoderRegistry() *EncoderRegistry {
    return &EncoderRegistry{
        voip:  NewX2Encoder(),
        dns:   NewDNSEncoder(),
        http:  NewHTTPEncoder(),
        tls:   NewTLSEncoder(),
        email: NewEmailEncoder(),
    }
}
```

### 3. Shared Attribute Builder

The existing `AttributeBuilder` in `x2x3/attributes.go` should be extended with protocol-specific helpers:

```go
// Add DNS-specific builders
func (b *AttributeBuilder) DNSQueryName(name string) TLVAttribute
func (b *AttributeBuilder) DNSQueryType(qtype uint16) TLVAttribute

// Add HTTP-specific builders
func (b *AttributeBuilder) HTTPMethod(method string) TLVAttribute
func (b *AttributeBuilder) HTTPPath(path string) TLVAttribute

// etc.
```

---

## X1 Interface Extensions

### Target Types: ETSI Standard vs. Proprietary

**Important:** ETSI TS 103 280 defines a specific set of target identifier types. Most protocol-specific filters for DNS, HTTP, and TLS are **not** part of the ETSI standard and would be proprietary extensions.

#### Official ETSI TS 103 280 Target Types

These types are defined in the standard and supported by compliant ADMF systems:

| Target Type | ETSI Standard | Currently Implemented |
|-------------|---------------|----------------------|
| `SIPURI` | ✅ Yes | ✅ Yes |
| `TELURI` | ✅ Yes | ✅ Yes |
| `NAI` | ✅ Yes | ✅ Yes |
| `IPv4Address` | ✅ Yes | ✅ Yes |
| `IPv6Address` | ✅ Yes | ✅ Yes |
| `IPv4CIDR` | ✅ Yes | ✅ Yes |
| `IPv6CIDR` | ✅ Yes | ✅ Yes |
| `EmailAddress` | ✅ Yes | ❌ No |
| `IMSI` | ✅ Yes | ❌ No (mobile) |
| `IMEI` | ✅ Yes | ❌ No (mobile) |
| `MACAddress` | ✅ Yes | ❌ No |
| `SUPI/SUCI/PEI/GPSI` | ✅ Yes | ❌ No (5G) |

**For multi-protocol LI, `EmailAddress` is the only additional ETSI-standard target type that applies.**

#### Proprietary Extensions (Non-Standard)

The following target types would be **lippycat-specific extensions**, not interoperable with standard ADMF systems:

```go
// internal/pkg/li/types.go - PROPRIETARY EXTENSIONS

const (
    // DNS - NOT IN ETSI STANDARD
    TargetTypeDNSDomain      TargetType = "DNSDomain"      // Proprietary
    TargetTypeDNSQueryType   TargetType = "DNSQueryType"   // Proprietary

    // HTTP - NOT IN ETSI STANDARD
    TargetTypeHTTPHost       TargetType = "HTTPHost"       // Proprietary
    TargetTypeHTTPPath       TargetType = "HTTPPath"       // Proprietary
    TargetTypeHTTPMethod     TargetType = "HTTPMethod"     // Proprietary

    // TLS - NOT IN ETSI STANDARD
    TargetTypeTLSSNI         TargetType = "TLSSNI"         // Proprietary
    TargetTypeTLSJA3         TargetType = "TLSJA3"         // Proprietary
    TargetTypeTLSCertSubject TargetType = "TLSCertSubject" // Proprietary

    // Email extensions - NOT IN ETSI STANDARD
    TargetTypeEmailDomain    TargetType = "EmailDomain"    // Proprietary (EmailAddress IS standard)
    TargetTypeEmailSubject   TargetType = "EmailSubject"   // Proprietary
    TargetTypeIMAPMailbox    TargetType = "IMAPMailbox"    // Proprietary
)
```

#### Implications

1. **Standard ADMF Integration:** Only `EmailAddress` can be added while maintaining ETSI compliance. An ADMF sending `DNSDomain` or `TLSSNI` targets would be using proprietary extensions.

2. **National Parameter Space:** ETSI allows proprietary extensions via the national parameter space. These would need to be documented as lippycat-specific.

3. **IP-Based Fallback:** For standard compliance, DNS/HTTP/TLS interception could use IP address targets (which ARE standard) combined with protocol detection at the processor level. The ADMF would target an IP, and lippycat would filter by protocol internally.

4. **Hybrid Approach:** Accept standard ETSI target types via X1, but allow CLI/config-based filtering for protocol-specific patterns that don't come from ADMF.

#### Recommended Approach

For maximum flexibility:

```go
const (
    // ETSI Standard - interoperable with any ADMF
    TargetTypeSIPURI       TargetType = "SIPURI"        // ETSI TS 103 280
    TargetTypeTELURI       TargetType = "TELURI"        // ETSI TS 103 280
    TargetTypeNAI          TargetType = "NAI"           // ETSI TS 103 280
    TargetTypeIPv4Address  TargetType = "IPv4Address"   // ETSI TS 103 280
    TargetTypeIPv6Address  TargetType = "IPv6Address"   // ETSI TS 103 280
    TargetTypeIPv4CIDR     TargetType = "IPv4CIDR"      // ETSI TS 103 280
    TargetTypeIPv6CIDR     TargetType = "IPv6CIDR"      // ETSI TS 103 280
    TargetTypeEmailAddress TargetType = "EmailAddress"  // ETSI TS 103 280
    TargetTypeMACAddress   TargetType = "MACAddress"    // ETSI TS 103 280

    // Proprietary Extensions - lippycat-specific, requires compatible ADMF
    TargetTypeDNSDomain    TargetType = "X-DNSDomain"    // Prefixed to indicate non-standard
    TargetTypeTLSSNI       TargetType = "X-TLSSNI"       // Prefixed to indicate non-standard
    TargetTypeHTTPHost     TargetType = "X-HTTPHost"     // Prefixed to indicate non-standard
    // ... etc
)
```

### Task Delivery Type Extensions

```go
const (
    DeliveryTypeX2Only    DeliveryType = "X2Only"     // IRI only (metadata)
    DeliveryTypeX3Only    DeliveryType = "X3Only"     // CC only (content)
    DeliveryTypeX2andX3   DeliveryType = "X2andX3"    // Both

    // Protocol-specific delivery types (optional)
    DeliveryTypeDNSX2     DeliveryType = "DNSX2"      // DNS metadata only
    DeliveryTypeHTTPX2X3  DeliveryType = "HTTPX2X3"   // HTTP with body
    DeliveryTypeEmailFull DeliveryType = "EmailFull"  // Full email content
)
```

---

## X2/X3 Attribute Definitions

### Understanding ETSI LI Interface Layers

ETSI defines **two LI interface families** that serve different purposes:

| Interface Family | Specification | Encoding | Purpose |
|------------------|---------------|----------|---------|
| **HI1/HI2/HI3** | TS 102 232-x | ASN.1/XML | Handover to LEA (Law Enforcement Agency) |
| **X1/X2/X3** | TS 103 221-x | XML (X1), Binary TLV (X2/X3) | Internal NE ↔ LEMF/MDF |

The TS 102 232-x series defines the **semantic content** (what data to deliver) for each service type:
- TS 102 232-2: Email content (sender, recipient, Message-ID, Subject, body, etc.)
- TS 102 232-5: VoIP/IP Multimedia content (SIP headers, RTP streams, etc.)

The TS 103 221-x series defines the **transport mechanisms**:
- TS 103 221-1: X1 administration interface (XML/HTTPS)
- TS 103 221-2: X2/X3 delivery interfaces (binary TLV)

### The X2/X3 Attribute Question

**Key Question:** Does TS 103 221-2 define TLV attribute codes for email content, or only for VoIP?

Looking at the current implementation (based on ETSI TS 103 221-2):
- **Common attributes (0x0001-0x00FF):** Defined - timestamp, IP addresses, ports, etc.
- **VoIP/SIP attributes (0x0100-0x011F):** Defined - Call-ID, From/To URI, SIP method, etc.
- **VoIP/RTP attributes (0x0200-0x021F):** Defined - SSRC, sequence number, payload type, etc.
- **Email attributes:** NOT explicitly defined in TS 103 221-2

This creates a layered situation for email:
1. **Email target type** (`EmailAddress`) = Standard (TS 103 280) ✅
2. **Email content specification** = Standard (TS 102 232-2) ✅
3. **Email X2/X3 TLV encoding** = NOT defined in TS 103 221-2 ⚠️

### Implications

**For Email:** While ETSI defines WHAT data to deliver (TS 102 232-2: sender, recipients, Message-ID, Subject, transaction details), it does NOT define specific X2/X3 TLV attribute type codes for encoding this data in binary TLV format. The traditional HI2/HI3 interfaces use ASN.1 encoding from TS 102 232-2.

**Options for Email X2/X3:**
1. **Follow content spec, use proprietary TLV codes:** Encode the fields defined in TS 102 232-2, but assign our own TLV attribute type codes in the national/proprietary range (0xFF00-0xFFFE)
2. **Embed ASN.1:** Encapsulate the TS 102 232-2 ASN.1-encoded content as payload within an X2/X3 PDU
3. **Request ETSI registration:** Apply for official TLV attribute codes for email

**For DNS, HTTP, TLS:** No ETSI content specification exists (no TS 102 232-x equivalent), so both the content and encoding would be proprietary.

### Proposed Attribute Ranges

| Range | Protocol | Standard Status |
|-------|----------|-----------------|
| 0x0001-0x00FF | Common | ETSI standard (TS 103 221-2) |
| 0x0100-0x01FF | VoIP/SIP | ETSI standard (TS 103 221-2) |
| 0x0200-0x02FF | VoIP/RTP | ETSI standard (TS 103 221-2) |
| 0x0300-0x03FF | DNS | **No ETSI standard** - Proprietary |
| 0x0400-0x04FF | HTTP | **No ETSI standard** - Proprietary |
| 0x0500-0x05FF | TLS | **No ETSI standard** - Proprietary |
| 0x0600-0x06FF | Email | **Content from TS 102 232-2, TLV codes proprietary** |
| 0x0700-0x07FF | Reserved | Future protocols |
| 0xFF00-0xFFFE | National | ETSI-designated proprietary range |
| 0xFFFF | Reserved | ETSI reserved |

**Recommendation:** Use the ETSI-designated national/proprietary range (0xFF00-0xFFFE) for all non-VoIP attributes to avoid conflicts with future ETSI allocations and to clearly signal proprietary extensions to MDF systems.

### IRI Type Value Ranges

ETSI TS 103 221-2 defines IRI types for VoIP. The following are **proprietary**:

| Range | Protocol | Status |
|-------|----------|--------|
| 1-9 | VoIP | ETSI standard (existing) |
| 10-19 | DNS | **Proprietary** |
| 20-29 | HTTP | **Proprietary** |
| 30-39 | TLS | **Proprietary** |
| 40-49 | Email | **Proprietary** |
| 50-99 | Reserved | Future protocols |

---

## Filter System Extensions

### Filter Types Already Exist

The management protobuf (`api/proto/management.proto`) **already defines** all necessary filter types for multi-protocol LI:

```protobuf
enum FilterType {
    // VoIP (existing LI support)
    FILTER_SIP_USER = 0;
    FILTER_PHONE_NUMBER = 1;
    FILTER_IP_ADDRESS = 2;
    FILTER_CALL_ID = 3;
    FILTER_CODEC = 4;
    FILTER_BPF = 5;
    FILTER_SIP_URI = 6;

    // DNS - ALREADY EXISTS
    FILTER_DNS_DOMAIN = 7;

    // Email - ALREADY EXISTS
    FILTER_EMAIL_ADDRESS = 8;
    FILTER_EMAIL_SUBJECT = 9;

    // TLS - ALREADY EXISTS
    FILTER_TLS_SNI = 10;
    FILTER_TLS_JA3 = 11;
    FILTER_TLS_JA3S = 12;
    FILTER_TLS_JA4 = 13;

    // HTTP - ALREADY EXISTS
    FILTER_HTTP_HOST = 14;
    FILTER_HTTP_URL = 15;
}
```

**No protobuf changes required.** The filter infrastructure was already implemented for non-LI filter management.

### FilterManager Extensions

The `internal/pkg/li/filters.go` `mapTargetToFilterType` function needs cases for new targets:

```go
func (m *FilterManager) mapTargetToFilterType(target TargetIdentity) (management.FilterType, string, error) {
    switch target.Type {
    // Existing VoIP cases...

    // DNS
    case TargetTypeDNSDomain:
        return management.FilterType_FILTER_DNS_DOMAIN, target.Value, nil
    case TargetTypeDNSQueryType:
        return management.FilterType_FILTER_DNS_QUERY_TYPE, target.Value, nil

    // HTTP
    case TargetTypeHTTPHost:
        return management.FilterType_FILTER_HTTP_HOST, target.Value, nil
    case TargetTypeHTTPPath:
        return management.FilterType_FILTER_HTTP_PATH, target.Value, nil

    // TLS
    case TargetTypeTLSSNI:
        return management.FilterType_FILTER_TLS_SNI, target.Value, nil
    case TargetTypeTLSJA3:
        return management.FilterType_FILTER_TLS_JA3, target.Value, nil

    // Email
    case TargetTypeEmailAddress:
        return management.FilterType_FILTER_EMAIL_ADDRESS, target.Value, nil
    case TargetTypeEmailDomain:
        return management.FilterType_FILTER_EMAIL_DOMAIN, target.Value, nil

    default:
        return 0, "", fmt.Errorf("unsupported target type: %s", target.Type)
    }
}
```

### Hunter Filter Implementation

Hunter filter matching for these types is **already implemented** as part of the non-LI filter management system. The LI system only needs to:

1. Map X1 target types to existing filter types
2. Push filters via the existing `FilterPusher` interface

| Filter Type | Matcher | Status |
|-------------|---------|--------|
| `FILTER_DNS_DOMAIN` | Aho-Corasick (suffix) | **Already implemented** |
| `FILTER_HTTP_HOST` | Aho-Corasick (suffix) | **Already implemented** |
| `FILTER_HTTP_URL` | Aho-Corasick (prefix/contains) | **Already implemented** |
| `FILTER_TLS_SNI` | Aho-Corasick (suffix) | **Already implemented** |
| `FILTER_TLS_JA3` | Hash set | **Already implemented** |
| `FILTER_TLS_JA3S` | Hash set | **Already implemented** |
| `FILTER_TLS_JA4` | Hash set | **Already implemented** |
| `FILTER_EMAIL_ADDRESS` | Aho-Corasick | **Already implemented** |
| `FILTER_EMAIL_SUBJECT` | Aho-Corasick | **Already implemented** |

---

## Processor Integration

### Initialization Changes

```go
// internal/pkg/processor/processor_li.go

type Processor struct {
    // Existing
    liManager    *li.Manager
    liX2Encoder  *x2x3.X2Encoder
    liX3Encoder  *x2x3.X3Encoder

    // New protocol encoders
    liDNSEncoder   *x2x3.DNSEncoder
    liHTTPEncoder  *x2x3.HTTPEncoder
    liTLSEncoder   *x2x3.TLSEncoder
    liEmailEncoder *x2x3.EmailEncoder
}

func (p *Processor) initLI(config *Config) error {
    // ... existing init ...

    // Initialize protocol encoders
    p.liDNSEncoder = x2x3.NewDNSEncoder()
    p.liHTTPEncoder = x2x3.NewHTTPEncoder()
    p.liTLSEncoder = x2x3.NewTLSEncoder()
    p.liEmailEncoder = x2x3.NewEmailEncoder()

    return nil
}
```

### Packet Processing Pipeline

The `processBatch()` function already iterates packets. The LI step needs to check all metadata types:

```go
func (p *Processor) processLIPackets(batch []*types.PacketDisplay) {
    for _, pkt := range batch {
        // Check if packet matches any LI filters
        matchedFilterIDs := p.getMatchedFilters(pkt)
        if len(matchedFilterIDs) == 0 {
            continue
        }

        // Get matching tasks
        matches := p.liManager.FilterManager.LookupMatches(matchedFilterIDs)
        for _, match := range matches {
            task, ok := p.liManager.Registry.GetTask(match.XID)
            if !ok || task.State != li.TaskStateActive {
                continue
            }

            p.processLIPacket(pkt, task)
        }
    }
}
```

---

## ETSI Standards Mapping

### Relevant Standards by Protocol

| Protocol | ETSI Standard | Notes |
|----------|---------------|-------|
| VoIP | TS 102 232-5 | IP Multimedia (existing) |
| Email | TS 102 232-2 | Email services |
| HTTP/DNS | TS 103 221-1/2 | Generic X1/X2/X3 |
| TLS | TS 103 221-2 | Metadata only (fingerprinting) |

### Protocol-Specific Considerations

**Email (TS 102 232-2):**
- Defines specific email handover parameters
- Envelope vs. content separation
- Authentication tracking requirements

**DNS:**
- No specific ETSI standard - use generic X2 attributes
- Query/response correlation via transaction ID

**HTTP:**
- No specific ETSI standard - use generic X2 attributes
- Session tracking for request/response correlation

**TLS:**
- Metadata only unless decryption keys available
- Fingerprinting for traffic classification

---

## Complexity Assessment

### Summary Matrix

| Protocol | Encoder | Filters | X1 Target Mapping | Processor | Total | Effort |
|----------|---------|---------|-------------------|-----------|-------|--------|
| DNS | 1-2 days | **0** (exists) | 0.5 day | 0.5 day | **2-3 days** | Low |
| HTTP | 2-3 days | **0** (exists) | 0.5 day | 0.5 day | **3-4 days** | Medium |
| TLS | 2 days | **0** (exists) | 0.5 day | 0.5 day | **3 days** | Medium |
| Email | 4-5 days | **0** (exists) | 0.5 day | 1 day | **6-7 days** | High |
| **Total** | | | | | **~15 days** | |

**Note:** Filter types and hunter matching are already implemented for non-LI use. The only filter-related work is adding X1 target type → filter type mappings in `li/filters.go`.

### Recommended Implementation Order

1. **DNS** (2-3 days) - Lowest complexity, establishes pattern
2. **TLS** (3 days) - Medium complexity, high value
3. **HTTP** (3-4 days) - Medium complexity, builds on TLS
4. **Email** (6-7 days) - Highest complexity, most LI value

---

## Dependencies and Prerequisites

### External Dependencies

None - all required libraries are already in use:
- `encoding/binary` for TLV encoding
- `hash/fnv` for correlation IDs
- `sync/atomic` for sequence numbers
- `github.com/google/uuid` for XIDs

### Internal Prerequisites

1. **Protocol detection must be enabled** - Existing detector signatures are complete
2. **TCP reassembly** - Already working for VoIP, reusable for HTTP/Email
3. **Filter infrastructure** - Needs new filter type support in hunters

### Build Tag Considerations

All new encoders should use the `li` build tag:

```go
//go:build li

package x2x3
```

---

## Open Questions

### ETSI Standards Compliance

1. **Proprietary vs. Standard Target Types:** Should lippycat support proprietary X1 target types (DNS domain, TLS SNI, HTTP host) or only ETSI-standard types?
   - Option A: Proprietary extensions with `X-` prefix - flexible but requires compatible ADMF
   - Option B: Standard types only (IP address, EmailAddress) - interoperable but less granular
   - Option C: Hybrid - accept standard X1, add CLI/config for protocol-specific filters

2. **X2/X3 Attribute Encoding Strategy:** The TLV attribute types for non-VoIP protocols are not defined in TS 103 221-2. Options:
   - Option A: Use national/proprietary range (0xFF00-0xFFFE) for custom TLV codes
   - Option B: For email, embed TS 102 232-2 ASN.1-encoded content as X2/X3 payload (maintain HI2/HI3 compatibility)
   - Option C: Apply for ETSI attribute type registration (long-term)
   - Recommendation: Option A for simplicity, with content following TS 102 232-2 semantics for email

3. **IRI Type Values:** The proposed IRI types (DNS: 10-19, HTTP: 20-29, etc.) are not ETSI-registered. Same options as attribute types.

4. **Email X2/X3 vs. HI2/HI3:** Should email delivery use X2/X3 (binary TLV) or implement HI2/HI3 (ASN.1) for better standards compliance?
   - X2/X3: Consistent with VoIP implementation, simpler code
   - HI2/HI3: More standards-compliant but requires ASN.1 encoding
   - Recommendation: X2/X3 with content semantics from TS 102 232-2

### Protocol Scope

1. **HTTP/2 Support:** Should HTTP encoder support HTTP/2 multiplexing or HTTP/1.x only?
   - Recommendation: HTTP/1.x initially, HTTP/2 as future enhancement

2. **Email Body Capture:** Should email body capture be opt-in or default?
   - Recommendation: Opt-in with configurable size limit

3. **TLS Decryption:** Should X3 CC include encrypted payloads if no keys?
   - Recommendation: X2 only unless SSLKEYLOGFILE is configured

### Filter Matching

4. **DNS Wildcards:** How should DNS domain wildcards work?
   - `*.example.com` - suffix match
   - `mail.*` - prefix match
   - Recommendation: Use existing Aho-Corasick suffix matching

5. **Email Address Patterns:** Support wildcards in email addresses?
   - `*@example.com` - domain only
   - `user@*` - local part only
   - Recommendation: Split into local-part and domain matching

### ETSI Compliance

6. **Non-Standard Attributes:** How to handle protocol attributes not defined in ETSI?
   - Recommendation: Use national extension range (0xFF00-0xFFFE)

7. **IRI Type Numbering:** Are the proposed IRI type values appropriate?
   - Recommendation: Verify against ETSI registries

### Performance

8. **High-Volume Protocols:** DNS and HTTP can be very high volume. Sampling?
   - Recommendation: Configurable rate limiting per task

9. **Email Body Size:** Maximum body size to capture via X3?
   - Recommendation: Configurable limit, default 1MB

---

## ETSI Standards Sources

### Core LI Standards

| Standard | Title | Relevance |
|----------|-------|-----------|
| **TS 103 221-1** | Internal Network Interfaces - X1 | X1 administration interface, task activation |
| **TS 103 221-2** | Internal Network Interfaces - X2/X3 | Binary TLV PDU format, IRI/CC delivery |
| **TS 103 280** | Dictionary for Common Parameters | Target identifier types (SIPURI, EmailAddress, etc.) |

**Official PDFs:**
- [TS 103 221-1 V1.21.1 (2025-08)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.21.01_60/ts_10322101v012101p.pdf) - X1 Interface (Latest)
- [TS 103 221-2 V1.9.1 (2025-08)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.09.01_60/ts_10322102v010901p.pdf) - X2/X3 Interface (Latest)
- [TS 103 280 V2.13.1 (2024-07)](https://www.etsi.org/deliver/etsi_ts/103200_103299/103280/02.13.01_60/ts_103280v021301p.pdf) - Common Parameters

### Protocol-Specific Handover Standards (HI2/HI3)

These define what data should be delivered for specific services:

| Standard | Title | Protocol Coverage |
|----------|-------|-------------------|
| **TS 102 232-1** | Handover Interface Part 1 | Generic handover specification |
| **TS 102 232-2** | Handover Interface Part 2 | **Email** (SMTP, IMAP, POP3) |
| **TS 102 232-3** | Handover Interface Part 3 | Internet access (generic IP) |
| **TS 102 232-4** | Handover Interface Part 4 | Layer 2 services |
| **TS 102 232-5** | Handover Interface Part 5 | **VoIP/IP Multimedia** (SIP, RTP) |
| **TS 102 232-6** | Handover Interface Part 6 | PSTN/ISDN services |
| **TS 102 232-7** | Handover Interface Part 7 | Mobile services |

**Relevant PDFs:**
- [TS 102 232-2 V3.19.1 (2022-03)](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223202/03.19.01_60/ts_10223202v031901p.pdf) - Email Services
- [TS 102 232-3 V3.17.1 (2022-03)](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223203/03.17.01_60/ts_10223203v031701p.pdf) - Internet Access
- [TS 102 232-5 V3.21.1 (2024-07)](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223205/03.21.01_60/ts_10223205v032101p.pdf) - IP Multimedia

### Schema Repository

Official XSD and ASN.1 schemas:
- [ETSI TC LI Schemas (GitLab)](https://forge.etsi.org/rep/li/schemas-definitions)
  - `103221-1/` - X1 XSD schemas
  - `103221-2/` - X2/X3 definitions
  - `103280/` - Common parameters (target types)
  - `102232-2/` - Email handover ASN.1

### Key Observations from Standards

#### TS 103 280 - Target Identifiers

The standard defines these target types (Section 5):
- Communication identifiers: SIPURI, TELURI, NAI, H323URI, IMPU, IMPI
- Network identifiers: IPv4/IPv6 Address/CIDR, MACAddress, Port
- Subscriber identifiers: IMSI, IMEI, SUPI, GPSI, EmailAddress
- Location identifiers: CGI, ECGI, NCGI

**Notable absences:** No DNS domain, HTTP URL, TLS SNI, or JA3 fingerprint types.

#### TS 102 232-2 - Email Handover

Defines email-specific IRI content for **HI2/HI3** interfaces (ASN.1 encoded):
- Sender/recipient addresses
- Message-ID, Subject, Date
- SMTP transaction details
- IMAP/POP3 access events

**Important Distinction:** This standard defines WHAT data to deliver for email interception, but it uses ASN.1 encoding for the traditional HI2/HI3 interfaces. It does NOT define TLV attribute codes for the X2/X3 binary format (TS 103 221-2).

For lippycat's X2/X3 implementation, we can:
1. Use the content specification (fields to include) from TS 102 232-2
2. Assign proprietary TLV attribute codes (0xFF00-0xFFFE range) for encoding

#### TS 102 232-3 - Internet Access

Defines generic IP access IRI:
- IP address allocation events
- Session start/end
- Data volume reporting

Does **not** define application-layer (DNS, HTTP, TLS) interception details.

### Standards Gap Analysis

| Protocol | X1 Target | Content Spec (HI2/HI3) | X2/X3 TLV Codes | Overall Status |
|----------|-----------|------------------------|-----------------|----------------|
| **VoIP** | ✅ SIPURI, TELURI | ✅ TS 102 232-5 | ✅ TS 103 221-2 | Fully standard |
| **Email** | ✅ EmailAddress | ✅ TS 102 232-2 | ❌ Not defined | Content spec exists, X2/X3 encoding proprietary |
| **DNS** | ❌ None | ❌ None | ❌ None | Fully proprietary |
| **HTTP** | ❌ None | ❌ None | ❌ None | Fully proprietary |
| **TLS** | ❌ None | ❌ None | ❌ None | Fully proprietary |

**Key Insight for Email:** While ETSI provides a standard target type (EmailAddress) and defines what content to deliver (TS 102 232-2), the encoding of that content in X2/X3 binary TLV format is NOT standardized. The HI2/HI3 interfaces use ASN.1 encoding, but TS 103 221-2 only defines X2/X3 TLV codes for VoIP (SIP/RTP).

### Explanatory Resources

- [ETSI TS 103 221 - X1/X2/X3 Explained](https://www.lawfulinterception.com/explains/etsi-ts-103-221/)
- [ETSI TS 102 232 - Handover Explained](https://www.lawfulinterception.com/explains/etsi-ts-102-232/)
- [ETSI TC-LI Overview](https://www.lawfulinterception.com/explains/etsi-tc-li/)
- [LI Interfaces Comparison](https://group2000.com/articles/lawful-interception-interfaces/)

---

## Standards Compliance Reality

### The Core Problem

For **strict ETSI standards compliance** (interoperability with any ADMF/MDF), the following table summarizes what is feasible:

| Protocol | X1 Task Activation | X2/X3 Delivery | Standards-Compliant? |
|----------|-------------------|----------------|----------------------|
| **VoIP (SIP/RTP)** | ✅ SIPURI, TELURI | ✅ Defined TLV codes (TS 103 221-2) | **Yes** |
| **Email** | ✅ EmailAddress | ❌ No X2/X3 TLV codes defined | **No** |
| **DNS** | ❌ No target type | ❌ No TLV codes | **No** |
| **HTTP** | ❌ No target type | ❌ No TLV codes | **No** |
| **TLS** | ❌ No target type | ❌ No TLV codes | **No** |

**Conclusion:** If interoperability with any standards-compliant ADMF/MDF is required, lippycat's X1/X2/X3 implementation can only support VoIP.

### Why This Limitation Exists

1. **X2/X3 was designed for VoIP first** - TS 103 221-2 defines TLV attribute codes for SIP and RTP only
2. **Email LI predates X2/X3** - Email interception uses the older HI2/HI3 interfaces (TS 102 232-2) with ASN.1 encoding
3. **DNS/HTTP/TLS have no LI standards** - ETSI has not defined LI specifications for these protocols
4. **Target types ≠ delivery encoding** - EmailAddress exists in TS 103 280 for use across multiple standards, but X2/X3 encoding wasn't implemented

### Available Options

#### Option 1: VoIP Only (Standards-Compliant)

Limit X1/X2/X3 LI to VoIP. Use non-LI mechanisms for other protocols:
- PCAP file output
- Custom API delivery
- Syslog/SIEM integration

**Pros:** Full ETSI compliance, works with any ADMF/MDF
**Cons:** Limited protocol coverage for LI

#### Option 2: Email via HI2/HI3 (Standards-Compliant)

Implement TS 102 232-2 with ASN.1 encoding for email delivery instead of X2/X3:
- Accept EmailAddress via X1 (standard)
- Deliver via HI2/HI3 using ASN.1 (standard)

**Pros:** Standards-compliant email LI
**Cons:** Requires implementing a second delivery interface (ASN.1 instead of binary TLV)

#### Option 3: Proprietary Extensions (Non-Standard)

Implement multi-protocol LI using proprietary extensions:
- Use national parameter range (0xFF00-0xFFFE) for TLV attributes
- Define custom X1 target types with `X-` prefix
- Document extensions clearly

**Pros:** Full protocol coverage, consistent X2/X3 architecture
**Cons:** Requires compatible ADMF/MDF that understands lippycat's extensions

#### Option 4: IP-Based Targeting with Internal Filtering

Use standard IP address targets via X1, filter by protocol internally:
- ADMF sends task with `IPv4Address` target (standard)
- lippycat internally filters for DNS/HTTP/TLS
- X2/X3 delivery still requires proprietary TLV codes

**Pros:** Standard X1 interface
**Cons:** X2/X3 content still proprietary, MDF won't understand protocol-specific attributes

### Recommendation

If standards compliance is paramount: **Stay with VoIP only for X1/X2/X3**, use alternative delivery mechanisms for other protocols.

If operational flexibility matters more: **Implement proprietary extensions** with clear documentation, understanding that deployment requires compatible ADMF/MDF systems.

---

## Conclusion

Extending lippycat's LI support to DNS, HTTP, TLS, and Email is **architecturally straightforward but not ETSI standards-compliant**.

### Standards Reality

- **VoIP is the only protocol with full ETSI X1/X2/X3 coverage**
- Multi-protocol LI via X2/X3 requires proprietary extensions
- Any implementation would only work with compatible ADMF/MDF systems
- Email could alternatively use HI2/HI3 (TS 102 232-2) for standards compliance

### If Proceeding with Proprietary Extensions

The existing infrastructure is more complete than initially expected:

**Already Implemented (reusable):**
- X1 server/client (protocol-agnostic)
- PDU format and TLV encoding (protocol-agnostic)
- Delivery client and connection pool (protocol-agnostic)
- Task registry and filter manager (protocol-agnostic)
- **Filter types for DNS, HTTP, TLS, Email** (already in `management.proto`)
- **Hunter filter matching for all protocol types** (already implemented)

**Work Required:**
1. Creating protocol-specific X2/X3 encoders (~10 days)
2. Defining proprietary TLV attribute types in `pdu.go` (using 0xFF00-0xFFFE range)
3. Adding X1 target type → filter type mappings in `li/filters.go` (~1 day)
4. Updating processor packet routing (~1 day)
5. Documenting proprietary extensions for ADMF/MDF integration

**Implementation Order:** DNS → TLS → HTTP → Email (complexity order)

**Total estimated effort:** ~15 development days for all four protocols

### Final Recommendation

**Do not extend X1/X2/X3 to protocols beyond VoIP.**

The only reason to use ETSI X1/X2/X3 interfaces is for interoperability with standard ADMF/MDF systems. Since standard systems only understand VoIP, creating proprietary X1/X2/X3 extensions for other protocols provides no benefit.

lippycat already has a proprietary infrastructure (gRPC) that:
- Handles administration (filter management, task control)
- Handles delivery (packet streaming)
- Supports all protocols (DNS, HTTP, TLS, Email, VoIP)

**Conclusion:** Keep X1/X2/X3 for VoIP interoperability with standard ADMF/MDF. For other protocols, use lippycat's existing gRPC infrastructure.
