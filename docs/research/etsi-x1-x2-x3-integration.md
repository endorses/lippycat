# ETSI X1/X2/X3 Lawful Interception Integration Research

## Document Information

| Field | Value |
|-------|-------|
| Created | 2025-12-21 |
| Status | Research |
| Author | Claude Code |
| Related Standards | ETSI TS 103 221-1, TS 103 221-2, TS 102 232, TS 103 280 |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [ETSI Standards Overview](#etsi-standards-overview)
3. [Interface Specifications](#interface-specifications)
4. [lippycat Architecture Mapping](#lippycat-architecture-mapping)
5. [Implementation Approaches](#implementation-approaches)
6. [Data Model Mapping](#data-model-mapping)
7. [Go Libraries](#go-libraries)
8. [Implementation Roadmap](#implementation-roadmap)
9. [Security Considerations](#security-considerations)
10. [Sources](#sources)

---

## Executive Summary

This document provides implementation research for integrating ETSI X1/X2/X3 lawful interception interfaces into lippycat's processor nodes. The X1/X2/X3 interfaces are **internal network interfaces** defined in **ETSI TS 103 221** that enable:

- **X1**: Administration and provisioning of interception tasks (XML over HTTPS)
- **X2**: Delivery of Intercept Related Information (IRI) - signaling metadata (binary TLV over TLS)
- **X3**: Delivery of Content of Communication (CC) - actual content (binary TLV over TLS)

lippycat's processor architecture is well-suited for LI integration due to its:
- Modular manager-based design with clear extension points
- Existing EventHandler pattern for decoupled event delivery
- Command execution hooks for external system integration
- VoIP call aggregation and correlation capabilities
- Established build tag architecture for specialized binaries

**Recommended approach:** Build-tagged integration (`-tags li`), consistent with
lippycat's existing pattern for `hunter`, `processor`, `cli`, `tui` variants.

---

## ETSI Standards Overview

### Critical Clarification: X vs. HI Interfaces

The LI architecture defines two distinct interface sets:

| Interface Set | Type | Standard | Purpose | Direction |
|---------------|------|----------|---------|-----------|
| X1, X2, X3 | **Internal** | TS 103 221 | Within CSP network | NE → LI Server |
| HI1, HI2, HI3 | **Handover** | TS 102 232 | External to LEA | CSP → LEA |

**Data Flow:**
```
Network Elements → [X1/X2/X3] → Mediation/Delivery Function → [HI2/HI3] → LEA
                   (Internal)                                 (External)
```

lippycat would implement the **X-interfaces** as a Network Element (NE), receiving provisioning via X1 and delivering IRI/CC via X2/X3 to a Mediation & Delivery Function (MDF).

### Relevant Standards

| Standard | Title | Purpose |
|----------|-------|---------|
| **ETSI TS 103 221-1** | Internal Network Interfaces; Part 1: X1 | X1 administration interface specification |
| **ETSI TS 103 221-2** | Internal Network Interfaces; Part 2: X2/X3 | X2/X3 delivery interface specification |
| **ETSI TS 102 232-1** | Handover Interface for IP delivery; Part 1 | HI2/HI3 handover specification (ASN.1) |
| **ETSI TS 102 232-5** | Handover Interface; Part 5: IP Multimedia | VoIP/IMS-specific handover details |
| **ETSI TS 103 280** | Dictionary for common parameters | Common parameter definitions (XSD, ASN.1, JSON) |

### Standards NOT Applicable

| Standard | Why Not Applicable |
|----------|-------------------|
| ETSI TS 101 671 | Legacy circuit-switched networks (GSM, PSTN, ISDN) - not IP |
| 3GPP TS 33.106/107/108 | Mobile network specific (2G/3G/4G/5G) |

---

## Interface Specifications

### X1 Interface (Administration)

**Standard:** ETSI TS 103 221-1

**Purpose:** Bidirectional administration interface between ADMF and network elements.

**Architecture:** X1 is **bidirectional** - both endpoints act as HTTP client AND server:

```
┌──────────────────────────────────────────────────────────────────┐
│                        X1 Interface                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ADMF                                              NE           │
│   ┌─────────┐                                  ┌─────────┐       │
│   │  HTTP   │ ──── Task Management ──────────→ │  HTTP   │       │
│   │  Client │     (Activate, Deactivate, etc.) │  Server │       │
│   ├─────────┤                                  ├─────────┤       │
│   │  HTTP   │ ←─── Notifications/Errors ────── │  HTTP   │       │
│   │  Server │     (TaskError, KeepAlive, etc.) │  Client │       │
│   └─────────┘                                  └─────────┘       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Protocol Stack:**
```
┌───────────────────────────────────┐
│  X1 Messages (XML)                │
├───────────────────────────────────┤
│  HTTPS (RFC 2818)                 │
├───────────────────────────────────┤
│  TLS 1.2+ (mutual auth required)  │
├───────────────────────────────────┤
│  TCP                              │
└───────────────────────────────────┘
```

**Encoding:** XML with XSD schema validation

**Key Concepts:**
- **XID (X1 Identifier):** UUID v4 uniquely identifying each interception task
- **DID (Destination Identifier):** Identifies where X2/X3 traffic should be delivered
- **Task:** Represents an active interception warrant
- **NEId:** Network Element identifier (lippycat processor ID)

**ADMF → NE Operations (NE acts as HTTP server):**
| Operation | Description |
|-----------|-------------|
| ActivateTask | Start intercepting a target |
| DeactivateTask | Stop intercepting a target |
| ModifyTask | Update task parameters |
| GetTaskDetails | Query task status |
| CreateDestination | Define X2/X3 delivery endpoint |
| ModifyDestination | Update delivery endpoint |
| RemoveDestination | Delete delivery endpoint |
| Ping | Health check |

**NE → ADMF Operations (ADMF acts as HTTP server):**
| Operation | Description |
|-----------|-------------|
| ErrorReport | Report task execution errors |
| TaskProgress | Report task activation progress |
| KeepAlive | Periodic heartbeat with NE status |
| CapabilitiesNotification | Report NE capabilities changes |
| DeliveryNotification | Report X2/X3 delivery issues |

**XSD Namespace:** `http://uri.etsi.org/03221/X1/2017/10`

**Schema Files (from ETSI GitLab):**
- `TS_103_221_01_*.xsd` - Main X1 schemas
- Located in `103221-1/` directory of [forge.etsi.org/rep/li/schemas-definitions](https://forge.etsi.org/rep/li/schemas-definitions)

### X2 Interface (IRI - Intercept Related Information)

**Standard:** ETSI TS 103 221-2

**Purpose:** Delivery of signaling/metadata about intercepted communications.

**Protocol Stack:**
```
┌─────────────────────────────────┐
│  X2 PDU (Binary TLV)            │
├─────────────────────────────────┤
│  TLS 1.2+                       │
├─────────────────────────────────┤
│  TCP                            │
└─────────────────────────────────┘
```

**Encoding:** Fixed-length TLV (Type-Length-Value) binary format

**NOT ASN.1** - The format is optimized for high-volume, low-latency delivery.

**PDU Structure:**
```
┌────────────────────────────────────────────────────────┐
│ Version (2 bytes) │ PDU Type (2 bytes) │ Header Len    │
├────────────────────────────────────────────────────────┤
│ Payload Format (2 bytes) │ Payload Length (4 bytes)    │
├────────────────────────────────────────────────────────┤
│ XID (16 bytes - UUID)                                  │
├────────────────────────────────────────────────────────┤
│ Correlation ID (variable)                              │
├────────────────────────────────────────────────────────┤
│ Conditional Attributes (TLV encoded)                   │
├────────────────────────────────────────────────────────┤
│ Payload (IRI content)                                  │
└────────────────────────────────────────────────────────┘
```

**TLV Attribute Structure:**
| Field | Size | Description |
|-------|------|-------------|
| Attribute Type | 2 bytes | Type identifier |
| Length | 2 bytes | Length of contents in octets |
| Attribute Contents | Variable | As defined by type |

**Common Attributes:**
- Sequence Number (4 bytes, unsigned int, network byte order)
- Timestamp (POSIX.1-2017 timespec format)
- Source/Destination IP addresses
- Target identifiers

**VoIP-specific IRI Events:**
- Session initiation (SIP INVITE)
- Session answer (SIP 200 OK)
- Session modification (re-INVITE)
- Session termination (SIP BYE)
- Registration events

### X3 Interface (CC - Content of Communication)

**Standard:** ETSI TS 103 221-2

**Purpose:** Delivery of actual communication content.

**Protocol Stack:** Same as X2 (TLV over TLS)

**PDU Structure:** Same header format as X2, different payload types.

**VoIP Content Types:**
- RTP media streams (audio/video)
- RTCP control data
- Media codec information

**Key Differences from X2:**
- Higher volume (media vs. signaling)
- Different payload format identifiers
- May use separate TLS connections for load distribution

---

## lippycat Architecture Mapping

### Current Architecture

```
Hunters (edge capture)
    ↓ [gRPC StreamPackets]
Processor (central aggregation)
    ├→ PCAP Writers (unified, per-call, auto-rotate)
    ├→ Protocol Enrichment (detection)
    ├→ VoIP Aggregation (call state tracking)
    ├→ Call Correlator (B2BUA correlation)
    ├→ Command Executor (external hooks)
    ├→ Upstream Manager (hierarchy forwarding)
    ├→ Subscriber Manager (TUI broadcast)
    └→ Virtual Interface (packet injection)
```

### Proposed LI Integration Points

```
Hunters (edge capture)
    ↓ [gRPC StreamPackets]
Processor (central aggregation)
    ├→ [existing pipeline...]
    │
    ├→ LI Manager (NEW)                    ← X1 provisioning
    │   ├→ Task Registry (active warrants)
    │   ├→ Target Matcher (identity matching)
    │   └→ Destination Manager (MDF connections)
    │
    ├→ X2 Encoder (NEW)                    ← IRI generation
    │   └→ SIP event → X2 PDU mapping
    │
    └→ X3 Encoder (NEW)                    ← CC generation
        └→ RTP packet → X3 PDU mapping
```

### Extension Points

| Extension Point | Current Use | LI Integration |
|-----------------|-------------|----------------|
| `EventHandler` interface | TUI, remotecapture | LI event delivery |
| `CommandExecutor` | PCAP/VoIP hooks | External MDF notification |
| `processBatch()` pipeline | 10-step processing | Add LI filtering step |
| VoIP `CallAggregator` | Call state tracking | IRI event generation |
| Plugin system | SIP/RTP plugins | LI protocol plugins |

### Key Types to Extend

**PacketDisplay** (`internal/pkg/types/packet.go`):
```go
type PacketDisplay struct {
    // ... existing fields ...
    VoIPData *VoIPMetadata  // Already contains SIP/RTP metadata
    RawData  []byte         // Raw packet for CC delivery
}
```

**VoIPMetadata** (`internal/pkg/types/packet.go`):
```go
type VoIPMetadata struct {
    // SIP fields - map to IRI
    CallID  string
    Method  string  // INVITE, BYE, etc. → IRI events
    From    string  // Target identity
    To      string  // Target identity
    Headers map[string]string

    // RTP fields - map to CC
    IsRTP       bool
    SSRC        uint32
    PayloadType uint8
}
```

---

## Implementation Approaches

### Approach 1: Build-Tagged Integration (Recommended)

**Description:** Compile LI support conditionally using Go build tags.

This approach aligns with lippycat's existing architecture, which already uses build tags
extensively for specialized binaries (`hunter`, `processor`, `cli`, `tui`, `all`).

**Pros:**
- Consistent with existing codebase patterns
- Single binary deployment (no .so files to manage)
- Full debugging, profiling, and static analysis support
- No runtime loading complexity or version matching issues
- LI code simply not compiled when tag absent (zero overhead)
- Works on all platforms (Linux, macOS, Windows)

**Cons:**
- Requires separate binary builds for LI vs non-LI
- LI code in same repository (but can be in separate package)

**Implementation:**
```go
// internal/pkg/processor/li_manager.go
//go:build li

package processor

type LIManager struct {
    x1Server       *x1.Server
    x1Client       *x1.Client       // For NE→ADMF notifications
    x2Encoders     map[string]*x2.Encoder
    x3Encoders     map[string]*x3.Encoder
    tasks          map[string]*InterceptTask
    destinations   map[string]*Destination
    admfEndpoint   string
}

func NewLIManager(config *LIConfig) (*LIManager, error) {
    // ...
}

func (m *LIManager) ProcessPacket(pkt *types.PacketDisplay) {
    // Check if packet matches any active intercept task
    // If so, encode and send via X2/X3
}
```

```go
// internal/pkg/processor/li_manager_stub.go
//go:build !li

package processor

// LIManager is a no-op stub when LI support is not compiled in
type LIManager struct{}

func NewLIManager(config *LIConfig) (*LIManager, error) {
    return nil, nil  // LI not available
}

func (m *LIManager) ProcessPacket(pkt *types.PacketDisplay) {}
```

**Build commands:**
```bash
make build           # Standard build (no LI)
make build-li        # With LI support
make processor-li    # Processor-only with LI
make tap-li          # Tap (standalone) with LI
```

**Makefile addition:**
```makefile
.PHONY: build-li
build-li:
    go build -tags "all,li" -ldflags "$(LDFLAGS)" -o bin/lc ./main.go

.PHONY: processor-li
processor-li:
    go build -tags "processor,li" -ldflags "$(LDFLAGS)" -o bin/lc-processor-li ./main.go

.PHONY: tap-li
tap-li:
    go build -tags "tap,li" -ldflags "$(LDFLAGS)" -o bin/lc-tap-li ./main.go
```

### Approach 2: Plugin Architecture (Not Recommended)

**Description:** Implement LI as an optional plugin loaded at runtime via Go's `plugin` package.

**Pros:**
- No LI code in core binary
- Theoretically hot-pluggable

**Cons:**
- Go plugin system is awkward and limited:
  - Must compile with exact same Go version as host binary
  - Linux and macOS only (no Windows support)
  - All shared dependencies must have matching versions
  - Cannot unload plugins once loaded
  - Debugging is significantly harder
  - No IDE support for cross-module analysis
- Complex deployment (shipping .so files alongside binary)
- The "licensing isolation" argument is weak - interface definitions still in core
- Runtime loading adds failure modes

**Verdict:** Not recommended given Go's plugin limitations and lippycat's existing
build tag infrastructure.

### Approach 3: External EventHandler Client

**Description:** Implement LI as a separate process that connects to the processor's
existing gRPC `SubscribePackets` stream.

**Pros:**
- Zero changes to processor core
- Complete process isolation
- Can be written in any language
- Independent deployment and scaling

**Cons:**
- Adds network hop latency
- May not have access to all required packet data (raw bytes for X3)
- Requires processor to be running first
- Additional operational complexity (two processes)

**Implementation:**
```go
// Separate binary: cmd/li-forwarder/main.go
func main() {
    client := remotecapture.NewClient(processorAddr, &LIEventHandler{
        x2Client: x2.NewClient(mdfAddr),
        x3Client: x3.NewClient(mdfAddr),
        tasks:    loadTasks(),
    })
    client.Subscribe()
}
```

**When to use:** Consider this approach if:
- LI functionality must be completely isolated (separate process/container)
- LI system needs to connect to multiple processors
- You need language flexibility (e.g., Python for rapid prototyping)

---

## Data Model Mapping

### Target Identity Mapping

| lippycat Field | ETSI Target Identity | Notes |
|----------------|---------------------|-------|
| `VoIPMetadata.From` | SIP URI | `sip:user@domain` |
| `VoIPMetadata.To` | SIP URI | `sip:user@domain` |
| `PacketDisplay.SrcIP` | IP Address | IPv4/IPv6 |
| `PacketDisplay.DstIP` | IP Address | IPv4/IPv6 |
| `VoIPMetadata.User` | Username | Extracted from URI |

### SIP Event → X2 IRI Mapping

| SIP Event | IRI Type | lippycat Source |
|-----------|----------|-----------------|
| INVITE | Session Begin | `VoIPMetadata.Method == "INVITE"` |
| 180 Ringing | Session Progress | `VoIPMetadata.Status == 180` |
| 200 OK | Session Answer | `VoIPMetadata.Status == 200` |
| BYE | Session End | `VoIPMetadata.Method == "BYE"` |
| CANCEL | Session Abort | `VoIPMetadata.Method == "CANCEL"` |
| REGISTER | Registration | `VoIPMetadata.Method == "REGISTER"` |

### RTP Packet → X3 CC Mapping

| lippycat Field | X3 PDU Field |
|----------------|--------------|
| `PacketDisplay.Timestamp` | Timestamp attribute |
| `PacketDisplay.RawData` | Payload (RTP packet) |
| `VoIPMetadata.SSRC` | Correlation (stream ID) |
| `VoIPMetadata.CallID` | XID correlation |
| `PacketDisplay.SrcIP:SrcPort` | Source endpoint |
| `PacketDisplay.DstIP:DstPort` | Destination endpoint |

### Call Correlation

The existing `CallCorrelator` (`internal/pkg/processor/call_correlator.go`) provides:
- Cross-B2BUA call correlation via tag pairs
- Multi-leg call tracking
- Can be leveraged for LI correlation IDs

---

## Go Libraries

### X1 Interface (XML/HTTPS)

**XML Encoding:**
- `encoding/xml` (stdlib) - Marshal/unmarshal XML
- No runtime XSD validation in stdlib

**XSD Validation (optional):**
| Library | Description | Dependency |
|---------|-------------|------------|
| [terminalstatic/go-xsd-validate](https://github.com/terminalstatic/go-xsd-validate) | libxml2-based validation | libxml2 (C) |
| [xuri/xgen](https://github.com/xuri/xgen) | Generate Go structs from XSD | Pure Go |
| [krolaw/xsd](https://github.com/krolaw/xsd) | libxml2 wrapper | libxml2 (C) |

**Recommended:** Use `xuri/xgen` to generate Go structs from ETSI XSD files, then use `encoding/xml` for marshal/unmarshal.

**HTTPS Server:**
- `net/http` (stdlib) with `crypto/tls`
- Mutual TLS required for X1

### X2/X3 Interface (TLV/TLS)

**TLV Encoding:**
| Library | Description |
|---------|-------------|
| [pauloavelar/go-tlv](https://github.com/pauloavelar/go-tlv) | Generic TLV decoder, configurable tag/length sizes |
| [go-ndn/tlv](https://pkg.go.dev/github.com/go-ndn/tlv) | TLV with struct tags |
| Custom implementation | ETSI-specific TLV format |

**Recommendation:** Implement custom TLV encoder/decoder matching ETSI TS 103 221-2 PDU structure. The format is simple enough that a custom implementation is preferable for:
- Exact specification compliance
- Performance optimization
- No unnecessary dependencies

**TLS Client:**
- `crypto/tls` (stdlib)
- Certificate management for MDF connections

### Common Libraries

**UUID Generation (XIDs):**
- `github.com/google/uuid` (already in use)

**Timestamp:**
- `time` (stdlib) - POSIX timespec conversion

---

## Implementation Roadmap

### Phase 1: Core Infrastructure

- [ ] Create `internal/pkg/li/` package structure
- [ ] Define LI types: `InterceptTask`, `Destination`, `TargetIdentity`
- [ ] Implement task registry (in-memory, thread-safe)
- [ ] Implement target identity matching (SIP URI, IP address)
- [ ] Create `LIManager` with build tag (`//go:build li`)
- [ ] Create `LIManager` stub for non-LI builds (`//go:build !li`)
- [ ] Wire `LIManager` into processor's `processBatch()` pipeline
- [ ] Add `make build-li` target to Makefile

### Phase 2: X1 Interface (Bidirectional)

**X1 Server (receives ADMF requests):**
- [ ] Generate Go structs from ETSI XSD using xgen
- [ ] Implement HTTPS server with mutual TLS
- [ ] Implement ADMF → NE operations:
  - [ ] ActivateTask / DeactivateTask
  - [ ] ModifyTask
  - [ ] CreateDestination / ModifyDestination / RemoveDestination
  - [ ] GetTaskDetails
  - [ ] Ping
- [ ] Task persistence (optional: file/database)

**X1 Client (sends notifications to ADMF):**
- [ ] Implement HTTPS client with mutual TLS
- [ ] Implement NE → ADMF operations:
  - [ ] ErrorReport (task execution errors)
  - [ ] TaskProgress (activation progress)
  - [ ] KeepAlive (periodic heartbeat)
  - [ ] DeliveryNotification (X2/X3 delivery issues)
- [ ] Retry logic with exponential backoff
- [ ] ADMF endpoint configuration

### Phase 3: X2 Encoder (IRI)

- [ ] Implement X2 PDU structure per TS 103 221-2
- [ ] Implement TLV attribute encoding
- [ ] Map SIP events to IRI types
- [ ] Implement TLS client for MDF connections
- [ ] Add to processor pipeline after VoIP aggregation

### Phase 4: X3 Encoder (CC)

- [ ] Implement X3 PDU structure (shared with X2)
- [ ] Map RTP packets to CC payloads
- [ ] Handle high-volume streaming
- [ ] Connection pooling for multiple destinations

### Phase 5: Integration & Testing

- [ ] End-to-end testing with mock ADMF/MDF
- [ ] Performance testing (throughput, latency)
- [ ] Compliance testing against TS 103 221
- [ ] Security audit

### Phase 6: Documentation & Deployment

- [ ] Deployment guide
- [ ] Certificate management guide
- [ ] Monitoring and alerting integration
- [ ] Operational procedures

---

## Security Considerations

### Authentication & Authorization

| Interface | Authentication | Authorization |
|-----------|---------------|---------------|
| X1 | Mutual TLS (client cert required) | Certificate CN/SAN validation |
| X2/X3 | Mutual TLS (client cert required) | Certificate validation per RFC 6125 |

### Encryption

- TLS 1.2 minimum (TLS 1.3 recommended)
- Strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- Certificate pinning for MDF connections

### Audit Logging

All LI operations must be logged:
- Task activation/deactivation
- Target identity matches
- X2/X3 delivery events
- Authentication failures

**Retention:** Typically 7+ years for LI audit trails

### Data Minimization

- Only intercept data authorized by warrant
- Filter non-target traffic before delivery
- Automatic task expiration enforcement

---

## Sources

### ETSI Standards (Official PDFs)

- [ETSI TS 103 221-1 V1.14.1 (2023-03)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.14.01_60/ts_10322101v011401p.pdf) - X1 Interface
- [ETSI TS 103 221-1 V1.21.1 (2025-08)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.21.01_60/ts_10322101v012101p.pdf) - X1 Interface (Latest)
- [ETSI TS 103 221-2 V1.5.2 (2021-10)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.05.02_60/ts_10322102v010502p.pdf) - X2/X3 Interface
- [ETSI TS 103 221-2 V1.9.1 (2025-08)](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.09.01_60/ts_10322102v010901p.pdf) - X2/X3 Interface (Latest)
- [ETSI TS 102 232-1 V3.29.1 (2023-03)](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223201/03.29.01_60/ts_10223201v032901p.pdf) - HI2/HI3 Handover
- [ETSI TS 102 232-5 V3.21.1 (2024-07)](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223205/03.21.01_60/ts_10223205v032101p.pdf) - IP Multimedia (VoIP)
- [ETSI TS 103 280 V2.13.1 (2024-07)](https://www.etsi.org/deliver/etsi_ts/103200_103299/103280/02.13.01_60/ts_103280v021301p.pdf) - Common Parameters Dictionary

### ETSI Schema Repository

- [ETSI TC LI Schemas Definitions (GitLab)](https://forge.etsi.org/rep/li/schemas-definitions) - Official XSD/ASN.1 schemas
  - `103221-1/` - X1 XSD schemas
  - `103221-2/` - X2/X3 definitions
  - `103280/` - Common parameters

### Explanatory Resources

- [ETSI TS 103 221 - X1/X2/X3 Explained (EVE)](https://www.lawfulinterception.com/explains/etsi-ts-103-221/)
- [ETSI TS 102 232 - Handover Explained (EVE)](https://www.lawfulinterception.com/explains/etsi-ts-102-232/)
- [ETSI TC-LI Overview (EVE)](https://www.lawfulinterception.com/explains/etsi-tc-li/)
- [LI Interfaces - X1/X2/X3 vs HI1/HI2/HI3 (Group2000)](https://group2000.com/articles/lawful-interception-interfaces/)

### Go Libraries

- [xuri/xgen](https://github.com/xuri/xgen) - XSD to Go struct generator
- [terminalstatic/go-xsd-validate](https://github.com/terminalstatic/go-xsd-validate) - XSD validation
- [pauloavelar/go-tlv](https://github.com/pauloavelar/go-tlv) - TLV encoding
- [go-ndn/tlv](https://pkg.go.dev/github.com/go-ndn/tlv) - TLV with struct tags

---

## Appendix A: X2 PDU Header Format (TS 103 221-2)

```
Offset  Size    Field
──────────────────────────────────────
0       2       Version (current: 5)
2       2       PDU Type (1=X2, 2=X3)
4       2       Header Length
6       2       Payload Format
8       4       Payload Length
12      16      XID (UUID)
28      8       Correlation ID
36      var     Conditional Attributes (TLV)
...     var     Payload
```

**Version Field:**
- Upper 8 bits: Major version (increment on breaking changes)
- Lower 8 bits: Minor version

**Timestamp Attribute (Type 0x0001):**
```
┌─────────────────────────────────────┐
│ Seconds since epoch (8 bytes)       │
├─────────────────────────────────────┤
│ Nanoseconds (4 bytes)               │
└─────────────────────────────────────┘
```

---

## Appendix B: X1 XML Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10">
  <ActivateTask>
    <XID>550e8400-e29b-41d4-a716-446655440000</XID>
    <TargetIdentifiers>
      <TargetIdentifier>
        <SIPURI>sip:target@example.com</SIPURI>
      </TargetIdentifier>
    </TargetIdentifiers>
    <DeliveryType>X2andX3</DeliveryType>
    <ListOfDIDs>
      <DID>660e8400-e29b-41d4-a716-446655440001</DID>
    </ListOfDIDs>
    <TaskStartTime>2025-01-15T09:00:00Z</TaskStartTime>
    <TaskEndTime>2025-02-15T09:00:00Z</TaskEndTime>
  </ActivateTask>
</X1Request>
```

---

## Appendix C: lippycat Integration Diagram

```
                                    ┌──────────────┐
                                    │     ADMF     │
                                    │  (Warrant    │
                                    │  Management) │
                                    └──────┬───────┘
                                           │
                              X1 (HTTPS/XML, bidirectional)
                              ┌────────────┴────────────┐
                              │                         │
                              ↓ Tasks                   ↑ Notifications
┌──────────────┐   gRPC    ┌──────────────────────────────────┐  ↑
│    Hunter    ├──────────→│         lc process               │  │
│    (edge)    │  packets  │                                  │  │
└──────────────┘           │  ┌─────────────────────────┐     │  │
                           │  │     LI Manager          │     │  │
┌──────────────┐           │  │  ┌─────────────────┐    │     │  │
│    Hunter    ├──────────→│  │  │  Task Registry  │    │     │  │
│    (edge)    │           │  │  ├─────────────────┤    │     │  │
└──────────────┘           │  │  │ Target Matcher  │    │     │  │
                           │  │  ├─────────────────┤    │     │  │
                           │  │  │ Dest. Manager   │    │     │  │
                           │  │  ├─────────────────┤    │     │  │
                           │  │  │ X1 Client       │────┼─────┼──┘ (errors, keepalive)
                           │  │  └─────────────────┘    │     │
                           │  └───────────┬─────────────┘     │
                           │              │                   │
                           │  ┌───────────┴─────────────┐     │
                           │  │                         │     │
                           │  ↓                         ↓     │
                           │ X2 Encoder            X3 Encoder │
                           │ (SIP→IRI)             (RTP→CC)   │
                           └──────┬──────────────────┬────────┘
                                  │                  │
                                  │ X2 (TLV/TLS)     │ X3 (TLV/TLS)
                                  ↓                  ↓
                           ┌──────────────────────────────┐
                           │            MDF               │
                           │   (Mediation & Delivery)     │
                           └──────────────┬───────────────┘
                                          │ HI2/HI3 (ASN.1)
                                          ↓
                                    ┌──────────┐
                                    │   LEA    │
                                    └──────────┘
```
