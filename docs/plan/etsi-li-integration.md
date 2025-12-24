# ETSI LI Integration Implementation Plan

**Date:** 2025-12-22
**Status:** Not Started
**Research:** `docs/research/etsi-x1-x2-x3-integration.md`
**Branch:** `feature/etsi-li-integration`

## Overview

Implement ETSI X1/X2/X3 lawful interception interfaces for lippycat processor nodes using build-tagged integration (`-tags li`).

**Interfaces:**
- **X1**: Administration (XML/HTTPS, bidirectional with ADMF)
- **X2**: IRI delivery (SIP metadata → binary TLV/TLS)
- **X3**: CC delivery (RTP content → binary TLV/TLS)

**Build targets:**
- `make build-li` - Full suite with LI
- `make processor-li` - Processor-only with LI
- `make tap-li` - Tap-only with LI

## Phase 0: Filter Infrastructure Enhancements

Prerequisites for LI - extend existing filter system.

### Step 0.1: SIPURI filter (new filter type)

Current SIPUser filter extracts user part and uses suffix/wildcard matching (`*49123456789`).
This doesn't work for full URI matching - suffix pattern wouldn't match `user@domain`.

Need separate matching paths:
- **SIPUser**: extract user → suffix matching (existing, for phone numbers)
- **SIPURI**: extract `user@domain` → exact/Aho-Corasick matching (new)

- [x] Add `FILTER_SIP_URI` to `management.proto` FilterType enum
- [x] Implement separate SIPURI matching in `application_filter.go`:
  - Extract `user@domain` from SIP headers
  - Separate Aho-Corasick automaton for URI patterns
  - Only run each matching pass if filters of that type exist:
    - SIPUser filters present → run suffix match on user part
    - SIPURI filters present → run Aho-Corasick on user@domain
  - Typical case (phone numbers only): single pass, no overhead
- [x] Keep existing SIPUser filter unchanged (phone number suffix matching)
- [x] Unit tests for SIPURI matching vs SIPUser matching

### Step 0.2: IP filter optimization

Current IP matching is O(n) linear scan with SIMD comparison.
LI with many concurrent IP targets needs O(1) lookups.
CIDR only works at BPF level (requires capture restart on changes).

- [ ] Exact IP matching: replace linear scan with hash map lookup O(1)
  - `map[netip.Addr][]*Filter` for IPv4/IPv6
  - Fall back to SIMD comparison only if hash miss (shouldn't happen)
- [ ] CIDR matching: implement radix/prefix tree for app-level matching
  - Avoids BPF restart when CIDR filters change
  - O(prefix length) lookup
  - Consider using existing library (e.g., `github.com/kentik/patricia`)
- [ ] Benchmark: verify O(1) for exact, O(log n) or better for CIDR
- [ ] Unit tests for hash map and radix tree correctness

## Phase 1: Core Infrastructure

Create LI package structure and wire into processor.

### Step 1.1: Package structure

- [ ] Create `internal/pkg/li/` directory
- [ ] Create `internal/pkg/li/types.go`:
  ```go
  type InterceptTask struct {
      XID                        uuid.UUID
      Targets                    []TargetIdentity
      Destinations               []string  // DIDs
      DeliveryType               DeliveryType  // X2Only, X3Only, X2andX3
      StartTime                  time.Time
      EndTime                    time.Time
      ImplicitDeactivationAllowed bool  // If true, NE may end task autonomously
      Status                     TaskStatus
  }

  type TargetIdentity struct {
      Type  TargetType  // SIPURI, IPAddress, Username
      Value string
  }

  type Destination struct {
      DID      uuid.UUID
      Address  string
      Port     int
      TLSCert  *tls.Certificate
  }
  ```

### Step 1.2: Task registry

- [ ] Create `internal/pkg/li/registry.go`
- [ ] Implement thread-safe task storage (sync.RWMutex)
- [ ] Add methods matching ETSI X1 terminology:
  - `ActivateTask` - add new intercept task
  - `ModifyTask` - update task parameters (atomic)
  - `DeactivateTask` - remove task
  - `GetTaskDetails` - query task by XID
  - `ListTasks` - internal iteration (no ETSI equivalent)
- [ ] `ModifyTask` must be atomic: reject entire update if any field cannot be modified
- [ ] Implement task lifecycle per ETSI TS 103 221-1:
  - Default: Task ends only via ADMF `DeactivateTask` or terminating fault
  - If `ImplicitDeactivationAllowed=true`: NE may enforce `EndTime` expiration
  - On implicit deactivation: Send status report to ADMF via X1 client

### Step 1.3: Task-to-filter mapping

Leverage existing filter management system with Phase 0 enhancements.

- [ ] Create `internal/pkg/li/filters.go`
- [ ] Map X1 target identities (per ETSI TS 103 280) to lippycat filters:
  - `SIPURI` (sip:user@domain) → SIPURI filter (Phase 0.1)
  - `TELURI` (tel:+number) → SIPUser filter (existing, phone number)
  - `NAI` (user@realm) → SIPURI filter (same format as SIP URI)
  - `IPv4Address` → IP filter with hash map lookup (Phase 0.2)
  - `IPv4CIDR` → IP filter with radix tree lookup (Phase 0.2)
  - Mobile identifiers (IMSI, IMEI, MSISDN) → out of scope for now
- [ ] Store XID ↔ FilterID mapping for correlation
- [ ] On ActivateTask: create filter, push via existing filter management
- [ ] On DeactivateTask: remove filter
- [ ] On ModifyTask: update filter atomically
- [ ] When packets match filter: lookup XID, deliver via X2/X3

### Step 1.4: LI Manager

- [ ] Create `internal/pkg/li/manager.go` with `//go:build li`
- [ ] Create `internal/pkg/li/manager_stub.go` with `//go:build !li`
- [ ] Manager aggregates: registry, matcher, destination manager, X1 client
- [ ] Add `ProcessPacket(pkt *types.PacketDisplay)` method

### Step 1.5: Processor integration

- [ ] Add `liManager *li.Manager` field to Processor
- [ ] Wire LI processing into `processBatch()` pipeline (after VoIP aggregation)
- [ ] Add LI config flags: `--li-enabled`, `--li-x1-listen`, `--li-admf-endpoint`

### Step 1.6: Build system

- [ ] Add `li` build tag to Makefile
- [ ] Add `build-li`, `processor-li`, `tap-li` targets
- [ ] Verify non-LI builds exclude all LI code

## Phase 2: X2/X3 Protocol (TLV Encoder)

Implement binary TLV encoding per TS 103 221-2.

### Step 2.1: PDU structures

- [ ] Create `internal/pkg/li/x2x3/pdu.go`
- [ ] Implement PDU header (version, type, lengths, XID, correlation)
- [ ] Implement TLV attribute encoding (type, length, value)
- [ ] Use network byte order (big-endian)

### Step 2.2: Common attributes

- [ ] Implement Timestamp attribute (POSIX timespec: 8-byte seconds + 4-byte nanos)
- [ ] Implement Sequence Number attribute (4-byte unsigned)
- [ ] Implement IP address attributes (IPv4/IPv6)
- [ ] Implement Correlation ID attribute

### Step 2.3: X2 Encoder (IRI)

- [ ] Create `internal/pkg/li/x2x3/x2_encoder.go`
- [ ] Map SIP INVITE → Session Begin IRI
- [ ] Map SIP 200 OK → Session Answer IRI
- [ ] Map SIP BYE → Session End IRI
- [ ] Map SIP REGISTER → Registration IRI
- [ ] Include: Call-ID, From, To, timestamps

### Step 2.4: X3 Encoder (CC)

- [ ] Create `internal/pkg/li/x2x3/x3_encoder.go`
- [ ] Wrap RTP packets with X3 PDU header
- [ ] Include: SSRC, sequence, timestamp, raw payload
- [ ] Support high-volume streaming

### Step 2.5: Unit tests

- [ ] Test PDU serialization/deserialization
- [ ] Test TLV encoding edge cases
- [ ] Test SIP→IRI mapping
- [ ] Verify byte-level compliance with spec

## Phase 3: X2/X3 Delivery (TLS Client)

Implement delivery to MDF endpoints.

### Step 3.1: Destination manager

- [ ] Create `internal/pkg/li/delivery/destination.go`
- [ ] Manage TLS connections per destination
- [ ] Implement connection pooling for multiple DIDs
- [ ] Add reconnection with exponential backoff

### Step 3.2: Delivery client

- [ ] Create `internal/pkg/li/delivery/client.go`
- [ ] Implement `SendX2(xid uuid.UUID, iri []byte) error`
- [ ] Implement `SendX3(xid uuid.UUID, cc []byte) error`
- [ ] Add sequence numbering per stream
- [ ] Add delivery queue with backpressure

### Step 3.3: TLS configuration

- [ ] Require mutual TLS (client certificate)
- [ ] Support certificate pinning
- [ ] Minimum TLS 1.2, prefer TLS 1.3
- [ ] Add flags: `--li-x2-dest`, `--li-x3-dest`, `--li-tls-cert`, `--li-tls-key`, `--li-tls-ca`

### Step 3.4: Unit tests

- [ ] Test connection management
- [ ] Test delivery with mock server
- [ ] Test reconnection behavior

## Phase 4: X1 Interface (Administration)

Implement bidirectional X1 with ADMF.

### Step 4.1: Generate Go structs from XSD

- [ ] Download ETSI XSD schemas from forge.etsi.org
- [ ] Use `xuri/xgen` to generate Go structs
- [ ] Place in `internal/pkg/li/x1/schema/`

### Step 4.2: X1 Server (receives ADMF requests)

- [ ] Create `internal/pkg/li/x1/server.go`
- [ ] Implement HTTPS server with mutual TLS
- [ ] Implement handlers:
  - [ ] `POST /ActivateTask`
  - [ ] `POST /DeactivateTask`
  - [ ] `POST /ModifyTask`
  - [ ] `GET /GetTaskDetails`
  - [ ] `POST /CreateDestination`
  - [ ] `POST /ModifyDestination`
  - [ ] `DELETE /RemoveDestination`
  - [ ] `GET /Ping`
- [ ] Validate XML against schema
- [ ] Return proper X1 response codes

### Step 4.3: X1 Client (sends notifications to ADMF)

- [ ] Create `internal/pkg/li/x1/client.go`
- [ ] Implement HTTPS client with mutual TLS
- [ ] Implement notifications:
  - [ ] `ErrorReport` (task execution errors)
  - [ ] `TaskProgress` (activation progress)
  - [ ] `KeepAlive` (periodic heartbeat)
  - [ ] `DeliveryNotification` (X2/X3 delivery issues)
- [ ] Add retry with exponential backoff
- [ ] Add configurable heartbeat interval

### Step 4.4: Unit tests

- [ ] Test task activation/deactivation flow
- [ ] Test XML parsing and validation
- [ ] Test error reporting
- [ ] Test keepalive mechanism

## Phase 5: Integration & Testing

### Step 5.1: End-to-end testing

- [ ] Create mock ADMF server for X1 testing
- [ ] Create mock MDF server for X2/X3 testing
- [ ] Test full flow: task activation → packet match → IRI/CC delivery
- [ ] Test ModifyTask updates targets/destinations atomically
- [ ] Test ModifyTask rejection when partial update impossible
- [ ] Test DeactivateTask stops interception
- [ ] Test ImplicitDeactivationAllowed: NE enforces EndTime, sends status to ADMF
- [ ] Test without ImplicitDeactivationAllowed: NE ignores EndTime, waits for ADMF

### Step 5.2: Performance testing

- [ ] Benchmark X2 encoding throughput
- [ ] Benchmark X3 encoding throughput (high-volume RTP)
- [ ] Test delivery under load
- [ ] Verify no impact on non-LI packet processing

### Step 5.3: Security testing

- [ ] Verify mutual TLS enforcement
- [ ] Test certificate validation
- [ ] Verify audit logging completeness
- [ ] Test with expired/invalid certificates

## Phase 6: Documentation

- [ ] Create `docs/LI_INTEGRATION.md` - deployment guide
- [ ] Create `docs/LI_CERTIFICATES.md` - certificate management
- [ ] Create `internal/pkg/li/CLAUDE.md` - architecture docs
- [ ] Update main `CLAUDE.md` with LI section
- [ ] Add LI examples to command help text

## Validation Criteria

**Phase 0 (Filter Infrastructure):**
1. SIPURI filter matches `user@domain`, not just `user`
2. SIPUser filter unchanged (backward compatible)
3. IP exact match: O(1) hash lookup (benchmark)
4. IP CIDR match: O(prefix) radix tree lookup (benchmark)
5. CIDR filter changes don't require capture restart

**Phase 1-6 (LI Integration):**
6. `make build-li` produces binary with LI support
7. `make build` produces binary without LI code (verified with `go tool nm`)
8. X1 server accepts ActivateTask and creates intercept
9. Matching packets generate X2 IRI events
10. RTP packets generate X3 CC events
11. X2/X3 delivered to MDF over TLS
12. DeactivateTask from ADMF stops interception
13. ImplicitDeactivationAllowed tasks: NE enforces EndTime, reports to ADMF
14. All existing tests pass unchanged
15. Audit log captures all LI operations
