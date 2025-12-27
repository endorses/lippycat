# ETSI LI Integration Implementation Plan

**Date:** 2025-12-22
**Status:** Phase 6 complete (all phases complete)
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

- [x] Exact IP matching: replace linear scan with hash map lookup O(1)
  - `map[netip.Addr]struct{}` for IPv4/IPv6
  - Benchmarks: 15.82 ns/op with 1000 filters (constant time)
- [x] CIDR matching: implement radix/prefix tree for app-level matching
  - Uses `github.com/kentik/patricia/generics_tree`
  - Avoids BPF restart when CIDR filters change
  - O(prefix length) lookup via patricia trie
- [x] Benchmark: verify O(1) for exact, O(prefix) for CIDR
  - See `internal/pkg/hunter/ip_filter_bench_test.go`
- [x] Unit tests for hash map and radix tree correctness
  - See `TestIPFilterOptimization` in `application_filter_test.go`

### Step 0.3: PhoneNumberMatcher (LI-optimized phone number matching)

Current SIPUser/PhoneNumber filter uses Aho-Corasick for pattern matching.
For LI with thousands of phone numbers, a specialized approach is more efficient:
- Phone numbers are structured (digits only after normalization)
- Suffix matching handles varying prefixes (+49, 0049, routing codes)
- 99%+ of traffic doesn't match → bloom filter for fast rejection

**Why not Aho-Corasick for this use case:**
- AC is for substring matching in unstructured text
- SIP provides structured fields; parsing + suffix checking is simpler
- Hash set lookups are faster than AC state machine traversal
- Bloom filter pre-check eliminates 99%+ of non-matches in ~10ns

- [x] Create `internal/pkg/phonematcher/` package
- [x] Implement `PhoneNumberMatcher` struct:
  - Bloom filter for quick rejection (false positive rate ~0.1%)
  - Hash set of normalized watchlist numbers
  - Sorted unique lengths for bounded suffix checks
  - Configurable minimum suffix length (default: 10 digits)
- [x] Implement phone number normalization:
  - Strip `tel:`, `sip:`, domain, params, `+`, separators
  - Result: digits-only string
- [x] Implement `Match(observed string) (matched string, ok bool)`:
  - Normalize to digits
  - Check all candidate suffixes against bloom filter
  - If any bloom hit, confirm with hash set (longest match first)
- [x] Implement `UpdatePatterns(patterns []string)`:
  - Rebuild bloom filter and hash set atomically
  - Lock-free reads during rebuild (similar to AC BufferedMatcher)
- [x] Add benchmarks comparing to AC:
  - Achieved: ~85-94ns constant time regardless of watchlist size (100 to 50K patterns)
- [x] Unit tests for normalization, suffix matching, bloom false positives
- [x] Integrate into `application_filter.go`:
  - Use PhoneNumberMatcher for pure-digit `FILTER_PHONE_NUMBER` patterns (LI use case)
  - Use AC for wildcard patterns and non-digit patterns
  - Keep AC for `FILTER_SIP_USER` (alphanumeric usernames)

## Phase 1: Core Infrastructure

Create LI package structure and wire into processor.

### Step 1.1: Package structure

- [x] Create `internal/pkg/li/` directory
- [x] Create `internal/pkg/li/types.go`:
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

- [x] Create `internal/pkg/li/registry.go`
- [x] Implement thread-safe task storage (sync.RWMutex)
- [x] Add methods matching ETSI X1 terminology:
  - `ActivateTask` - add new intercept task
  - `ModifyTask` - update task parameters (atomic)
  - `DeactivateTask` - remove task
  - `GetTaskDetails` - query task by XID
  - `ListTasks` - internal iteration (no ETSI equivalent)
- [x] `ModifyTask` must be atomic: reject entire update if any field cannot be modified
- [x] Implement task lifecycle per ETSI TS 103 221-1:
  - Default: Task ends only via ADMF `DeactivateTask` or terminating fault
  - If `ImplicitDeactivationAllowed=true`: NE may enforce `EndTime` expiration
  - On implicit deactivation: Send status report to ADMF via X1 client

### Step 1.3: Task-to-filter mapping

Leverage existing filter management system with Phase 0 enhancements.

- [x] Create `internal/pkg/li/filters.go`
- [x] Map X1 target identities (per ETSI TS 103 280) to lippycat filters:
  - `SIPURI` (sip:user@domain) → SIPURI filter (Phase 0.1)
  - `TELURI` (tel:+number) → PhoneNumber filter with PhoneNumberMatcher (Phase 0.3)
  - `NAI` (user@realm) → SIPURI filter (same format as SIP URI)
  - `IPv4Address` → IP filter with hash map lookup (Phase 0.2)
  - `IPv4CIDR` → IP filter with radix tree lookup (Phase 0.2)
  - Mobile identifiers (IMSI, IMEI, MSISDN) → out of scope for now
- [x] Store XID ↔ FilterID mapping for correlation
- [x] On ActivateTask: create filter, push via existing filter management
- [x] On DeactivateTask: remove filter
- [x] On ModifyTask: update filter atomically
- [x] When packets match filter: lookup XID, deliver via X2/X3

### Step 1.4: LI Manager

- [x] Create `internal/pkg/li/manager.go` with `//go:build li`
- [x] Create `internal/pkg/li/manager_stub.go` with `//go:build !li`
- [x] Manager aggregates: registry, matcher, destination manager, X1 client
- [x] Add `ProcessPacket(pkt *types.PacketDisplay)` method

### Step 1.5: Processor integration

- [x] Add `liManager *li.Manager` field to Processor
- [x] Wire LI processing into `processBatch()` pipeline (after VoIP aggregation)
- [x] Add LI config flags: `--li-enabled`, `--li-x1-listen`, `--li-admf-endpoint`

### Step 1.6: Build system

- [x] Add `li` build tag to Makefile
- [x] Add `build-li`, `processor-li`, `tap-li` targets
- [x] Verify non-LI builds exclude all LI code
  - Types are shared, but Registry/FilterManager excluded via dead code elimination
  - `make verify-no-li` confirms LI implementation excluded from non-LI builds

## Phase 2: X2/X3 Protocol (TLV Encoder)

Implement binary TLV encoding per TS 103 221-2.

### Step 2.1: PDU structures

- [x] Create `internal/pkg/li/x2x3/pdu.go`
- [x] Implement PDU header (version, type, lengths, XID, correlation)
- [x] Implement TLV attribute encoding (type, length, value)
- [x] Use network byte order (big-endian)

### Step 2.2: Common attributes

- [x] Implement Timestamp attribute (POSIX timespec: 8-byte seconds + 4-byte nanos)
- [x] Implement Sequence Number attribute (4-byte unsigned)
- [x] Implement IP address attributes (IPv4/IPv6)
- [x] Implement Correlation ID attribute

### Step 2.3: X2 Encoder (IRI)

- [x] Create `internal/pkg/li/x2x3/x2_encoder.go`
- [x] Map SIP INVITE → Session Begin IRI
- [x] Map SIP 200 OK → Session Answer IRI
- [x] Map SIP BYE → Session End IRI
- [x] Map SIP REGISTER → Registration IRI
- [x] Include: Call-ID, From, To, timestamps

### Step 2.4: X3 Encoder (CC)

- [x] Create `internal/pkg/li/x2x3/x3_encoder.go`
- [x] Wrap RTP packets with X3 PDU header
- [x] Include: SSRC, sequence, timestamp, raw payload
- [x] Support high-volume streaming (batch encoding, buffer pooling)

### Step 2.5: Unit tests

- [x] Test PDU serialization/deserialization
- [x] Test TLV encoding edge cases
- [x] Test SIP→IRI mapping (X2 encoder tests)
- [x] Test X3 RTP→CC mapping
- [x] Verify byte-level compliance with spec

## Phase 3: X2/X3 Delivery (TLS Client)

Implement delivery to MDF endpoints. Destinations are configured via X1 per ETSI architecture.

### Step 3.1: X1 Schema generation

Generate Go structs from ETSI XSD schemas (full schema, not just destinations).

- [x] Download ETSI XSD schemas from forge.etsi.org (TS 103 221-1, TS 103 280)
- [x] Use `xuri/xgen` to generate Go structs
- [x] Place in `internal/pkg/li/x1/schema/`
- [x] Add `li` build tag to all generated files
- [x] Generated types include: destinations, tasks, notifications, common types

### Step 3.2: X1 Destination management server

Implement X1 server subset for destination CRUD operations.

- [x] Create `internal/pkg/li/x1/server.go`
- [x] Implement HTTPS server with mutual TLS
- [x] Implement destination handlers:
  - [x] `POST /CreateDestination` - register MDF endpoint with DID
  - [x] `POST /ModifyDestination` - update destination config
  - [x] `DELETE /RemoveDestination` - remove destination
  - [x] `GET /Ping` - health check
- [x] Validate XML against schema
- [x] Return proper X1 response codes
- [x] Add CLI flags: `--li-x1-listen`, `--li-x1-tls-cert`, `--li-x1-tls-key`, `--li-x1-tls-ca`

### Step 3.3: Destination manager

- [x] Create `internal/pkg/li/delivery/destination.go`
- [x] Store destinations by DID (from X1 CreateDestination)
- [x] Manage TLS connections per destination
- [x] Implement connection pooling for multiple DIDs
- [x] Add reconnection with exponential backoff

### Step 3.4: Delivery client

- [x] Create `internal/pkg/li/delivery/client.go`
- [x] Implement `SendX2(xid uuid.UUID, destIDs []uuid.UUID, iri []byte) error`
- [x] Implement `SendX3(xid uuid.UUID, destIDs []uuid.UUID, cc []byte) error`
- [x] Resolve destination IDs to connections via destination manager
- [x] Add sequence numbering per stream
- [x] Add delivery queue with backpressure

### Step 3.5: TLS configuration

- [x] Require mutual TLS for X2/X3 delivery (client certificate)
- [x] Support certificate pinning
- [x] Minimum TLS 1.2, prefer TLS 1.3
- [x] Add flags: `--li-delivery-tls-cert`, `--li-delivery-tls-key`, `--li-delivery-tls-ca`

### Step 3.6: Unit tests

- [x] Test X1 destination CRUD operations
- [x] Test connection management
- [x] Test delivery with mock MDF server
- [x] Test reconnection behavior

## Phase 4: X1 Interface (Task Administration)

Complete X1 interface for task management and ADMF notifications.

### Step 4.1: X1 Task handlers

Extend X1 server with task management (destination handlers done in Phase 3).

- [x] Implement task handlers:
  - [x] `POST /ActivateTask` - create intercept with target identities and destination IDs
  - [x] `POST /DeactivateTask` - stop intercept
  - [x] `POST /ModifyTask` - update task parameters atomically
  - [x] `GET /GetTaskDetails` - query task status
- [x] Validate XML against schema
- [x] Return proper X1 response codes

### Step 4.2: X1 Client (sends notifications to ADMF)

- [x] Create `internal/pkg/li/x1/client.go`
- [x] Implement HTTPS client with mutual TLS
- [x] Implement notifications:
  - [x] `ErrorReport` (task execution errors)
  - [x] `TaskProgress` (activation progress)
  - [x] `KeepAlive` (periodic heartbeat)
  - [x] `DeliveryNotification` (X2/X3 delivery issues)
- [x] Add retry with exponential backoff
- [x] Add configurable heartbeat interval
- [x] Add flags: `--li-admf-endpoint`, `--li-admf-tls-cert`, `--li-admf-tls-key`, `--li-admf-tls-ca`, `--li-admf-keepalive`
- [x] Integrate with LI Manager (startup/shutdown notifications, implicit deactivation reports)
- [x] Unit tests for X1 client

### Step 4.3: Unit tests

- [x] Test task activation/deactivation flow
- [x] Test XML parsing and validation
- [x] Test error reporting
- [x] Test keepalive mechanism

## Phase 5: Integration & Testing

### Step 5.1: End-to-end testing

- [x] Create mock ADMF server for X1 testing
- [x] Create mock MDF server for X2/X3 testing
- [x] Test full flow: task activation → packet match → IRI/CC delivery
- [x] Test ModifyTask updates targets/destinations atomically
- [x] Test ModifyTask rejection when partial update impossible
- [x] Test DeactivateTask stops interception
- [x] Test ImplicitDeactivationAllowed: NE enforces EndTime, sends status to ADMF
- [x] Test without ImplicitDeactivationAllowed: NE ignores EndTime, waits for ADMF

### Step 5.2: Performance testing

- [x] Benchmark X2 encoding throughput
- [x] Benchmark X3 encoding throughput (high-volume RTP)
- [x] Test delivery under load
- [x] Verify no impact on non-LI packet processing

### Step 5.3: Security testing

- [x] Verify mutual TLS enforcement
- [x] Test certificate validation
- [x] Verify audit logging completeness
- [x] Test with expired/invalid certificates

## Phase 6: Documentation

- [x] Create `docs/LI_INTEGRATION.md` - deployment guide
- [x] Create `docs/LI_CERTIFICATES.md` - certificate management
- [x] Create `internal/pkg/li/CLAUDE.md` - architecture docs
- [x] Update main `CLAUDE.md` with LI section
- [x] Add LI examples to command help text

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
