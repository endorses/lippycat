# TLS and Transport Fingerprinting Roadmap

**Date:** 2026-08-21
**Status:** Draft
**Priority:** Medium-high

## Overview

Improve lippycat's encrypted-traffic fingerprinting without depending on restricted
fingerprint suites or exact-match hashes as the only detection model.

The near-term work is to make the current TLS baseline trustworthy, measure how much
of the deployed signal is still visible, and add low-risk similarity metadata. The
larger product direction is cross-layer coherence: detecting when TCP/IP, TLS, QUIC,
HTTP/2, and SSH observations tell inconsistent stories about the same endpoint.

## Goals

- Verify and complete the current JA3, JA3S, and JA4 implementation.
- Measure ECH prevalence in real traffic before prioritizing more ClientHello-derived
  work.
- Add similarity-preserving TLS fingerprints as a sidecar, not a replacement.
- Evaluate permissively usable fingerprint corpora before inventing matching data.
- Add protocol parsers where lippycat currently only has signatures: QUIC, SSH, and
  HTTP/2.
- Build a cross-layer coherence model that can surface spoofing and impersonation.

## Non-Goals

- Do not clone restricted JA4+ algorithms or databases.
- Do not replace JA3/JA3S/JA4 filters; existing exact-match workflows remain.
- Do not make coherence scoring block packet forwarding in the first release.
- Do not ship threat labels without corpus-backed confidence.

## Current State

| Area | Current support | Gap |
|------|-----------------|-----|
| TLS JA3 | Implemented in `internal/pkg/tls/ja3.go` | Needs regression tests against known vectors |
| TLS JA3S | Implemented in `internal/pkg/tls/ja3.go` | Needs regression tests against known vectors |
| TLS JA4 | Function exists in `internal/pkg/tls/ja3.go` | Not currently called from the parser path |
| TLS parsing | ClientHello / ServerHello and selected extensions | Missing richer extension body data |
| ECH visibility | Extension IDs are collected | No explicit ECH counter or reporting |
| Certificate parsing | Handshake type recognized | Certificate body not decoded |
| QUIC | Signature detection only | No Initial parsing, decryption, or transport parameters |
| SSH | Banner signature detection | No KEXINIT parsing or HASSH/HASSHServer |
| HTTP/2 | Protocol may be labeled elsewhere | No SETTINGS/pseudo-header fingerprint parser |
| Distributed metadata | Packet metadata has DNS/SIP/RTP/email fields | No structured TLS/QUIC/SSH fingerprint proto fields |

## Design Principles

1. **Keep exact matching stable.** JA3, JA3S, and JA4 stay available for existing
   filters and operational playbooks.
2. **Add structured metadata before labels.** Store observable features and scores;
   defer "Chrome", "malware", or "spoofed" labels until a corpus supports them.
3. **Compute cheap packet-local features at the edge.** Hunters and tap local sources
   should parse fingerprints when capture context is available.
4. **Match and correlate centrally.** Processor nodes should own corpus lookup,
   cross-hunter aggregation, and coherence scoring.
5. **Make uncertainty visible.** Similarity matches and coherence findings should
   report confidence and reason codes, not just a scalar.

## Data Model

Add structured fingerprint metadata in stages. Avoid putting every new field directly
on `PacketDisplay`; use protocol-specific structs in `internal/pkg/types` and mirror
them in `api/proto/data.proto` when distributed mode needs the data.

### Proposed Type Shape

```go
type TLSFingerprintMetadata struct {
    JA3              string
    JA3String        string
    JA3S             string
    JA3SString       string
    JA4              string
    SimHash64        uint64
    ECHOffered       bool
    PaddingLength    int
    PSKModes         []uint8
    KeyShareGroups   []uint16
    Tier0Hash        string
    Tier1Hash        string
    Tier2Hash        string
}

type TransportFingerprintMetadata struct {
    InitialTTL       uint8
    TCPWindowSize    uint16
    TCPWindowScale   int
    TCPMSS           uint16
    TCPOptionOrder   []uint8
}

type CoherenceFinding struct {
    Code        string
    Severity    string
    Confidence  float64
    Evidence    []string
}
```

Final field names should follow existing `TLSMetadata` style once implementation
starts.

## Phase 0: Baseline Audit and Test Vectors

**Priority:** Critical

Make current TLS fingerprinting correct and testable before extending it.

### Tasks

- [x] Add tests for `CalculateJA3` with known ClientHello vectors.
- [x] Add tests for `CalculateJA3S` with known ServerHello vectors.
- [x] Add tests for `CalculateJA4` with known ClientHello vectors.
- [x] Wire `CalculateJA4` into `parseClientHello()` after JA3 calculation.
- [x] Confirm the JA4 hash primitive matches the intended JA4 specification.
- [x] Fix stale comments in `internal/pkg/tls/ja3.go` if implementation and comments
      disagree.
- [x] Add parser tests that prove `TLSMetadata.JA4Fingerprint` is populated for a
      parsed ClientHello.
- [x] Verify `lc sniff tls --ja4 ...` and hunter TLS matching can actually match
      parsed packets.

### Files

| File | Change |
|------|--------|
| `internal/pkg/tls/ja3.go` | Validate/fix JA4 implementation |
| `internal/pkg/tls/parser.go` | Populate JA4 on ClientHello |
| `internal/pkg/tls/*_test.go` | Add vector tests |
| `internal/pkg/hunter/filter/tls.go` | Confirm JA4 matching path works |

### Acceptance Criteria

- `go test ./internal/pkg/tls/...` passes.
- A parsed ClientHello carries JA3 and JA4.
- Existing JA3/JA3S filter behavior is unchanged.

## Phase 1: ECH Visibility Measurement

**Priority:** Critical

Measure whether ClientHello-derived fingerprints remain a strong signal on the
traffic lippycat users actually monitor.

### Tasks

- [ ] Add `ExtensionEncryptedClientHello = 65037` constant.
- [ ] Add `ECHOffered bool` to TLS metadata.
- [ ] Set `ECHOffered` when the ClientHello contains the ECH extension.
- [ ] Add counters for total ClientHellos and ECH-offered ClientHellos.
- [ ] Expose ECH counts in local TLS summary output.
- [ ] Expose ECH counts in TUI/statistics if TLS protocol views are active.
- [ ] Add tests for ECH extension detection.

### Acceptance Criteria

- lippycat can report `ECH offered / total ClientHello` over a capture.
- ECH detection does not require parsing encrypted inner ClientHello data.
- The metric works in sniff, tap, and hunt/process paths where TLS metadata is
  available.

## Phase 2: Corpus and Prior Art Evaluation

**Priority:** High

Before building attribution or thresholds, evaluate available fingerprint corpora and
their licenses.

### Tasks

- [ ] Evaluate Cisco Mercury / pmercury code license and database terms separately.
- [ ] Measure corpus freshness: last update, number of fingerprints, label quality.
- [ ] Run current lippycat TLS captures through Mercury tooling offline.
- [ ] Compare Mercury attribution against controlled clients:
      Chrome, Firefox, curl, Go `crypto/tls`, Python, OpenSSL, rustls.
- [ ] Decide whether to import a corpus, support an external corpus file format, or
      build a lippycat-native format.
- [ ] Document legal review requirements for any third-party corpus.

### Acceptance Criteria

- A written recommendation exists for corpus source and allowed use.
- No corpus data is committed until license compatibility is confirmed.
- Controlled-client captures identify which features are stable and which are noisy.

## Phase 3: TLS SimHash Sidecar

**Priority:** High

Add a similarity-preserving fingerprint alongside exact hashes.

### Design

Compute a 64-bit SimHash over weighted ClientHello features:

| Feature class | Initial weight |
|---------------|----------------|
| Supported groups | High |
| Signature algorithms | High |
| Cipher suites | Medium |
| Extension IDs | Medium |
| ALPN protocols | Low-medium |
| Extension order | Low |
| GREASE position | Low |

Weights are provisional until Phase 2 corpus data calibrates them.

### Tasks

- [ ] Add a small SimHash implementation under `internal/pkg/tls` or a shared
      fingerprint package.
- [ ] Encode TLS ClientHello features into stable tokens.
- [ ] Add `SimHash64` to TLS metadata.
- [ ] Add Hamming distance helper using `math/bits.OnesCount64`.
- [ ] Add unit tests for deterministic output and distance behavior.
- [ ] Add optional CLI display of SimHash for TLS packets.
- [ ] Do not add filtering by distance until thresholds are calibrated.

### Acceptance Criteria

- Existing exact fingerprints remain byte-for-byte stable.
- SimHash is deterministic for the same parsed ClientHello.
- Similar controlled-client variants produce lower Hamming distance than unrelated
  clients in test fixtures.

## Phase 4: Tiered TLS Fingerprints

**Priority:** Medium

Split TLS ClientHello features by volatility so partial matches are explainable.

### Initial Tiers

| Tier | Features | Expected meaning |
|------|----------|------------------|
| Tier 0 | supported groups, signature algorithms, EC point formats, record version | TLS stack family |
| Tier 1 | cipher list, extension set, supported versions | application build family |
| Tier 2 | ALPN, extension order, padding length, PSK mode, key share groups | session/config behavior |

### Parser Additions

- [ ] Decode `key_share` extension group list.
- [ ] Decode `psk_key_exchange_modes`.
- [ ] Decode `padding` length.
- [ ] Decode `application_settings` / ALPS if present.
- [ ] Preserve extension order separately from sorted/hash-oriented forms.

### Acceptance Criteria

- Tier hashes are shown with enough feature detail to explain partial matches.
- Missing extension bodies degrade gracefully.
- Tests cover TLS 1.2, TLS 1.3, and malformed extension bodies.

## Phase 5: SSH HASSH

**Priority:** Medium

Add SSH KEXINIT fingerprints using the established HASSH/HASSHServer model.

### Tasks

- [ ] Add SSH parser package or extend the SSH detector with a parser boundary.
- [ ] Parse protocol banner and `SSH_MSG_KEXINIT`.
- [ ] Extract kex, encryption, MAC, and compression algorithm lists.
- [ ] Compute client HASSH and server HASSHServer.
- [ ] Add SSH fingerprint metadata to `types` and `api/proto/data.proto`.
- [ ] Add TUI/detail panel display.
- [ ] Add tests with OpenSSH fixture payloads.

### Acceptance Criteria

- SSH banner detection remains unchanged.
- HASSH is emitted only when a complete KEXINIT is observed.
- Distributed mode carries SSH fingerprint metadata from hunter to processor/TUI.

## Phase 6: QUIC Initial Fingerprinting Spike

**Priority:** Medium-high

Prove feasibility before committing to full QUIC parser work.

### Spike Scope

- [ ] Parse QUIC v1 and v2 long headers.
- [ ] Extract version, packet type, DCID length, SCID length, token length, packet
      number length, and Initial size.
- [ ] Remove Initial packet protection for v1 using published initial secrets.
- [ ] Decrypt enough CRYPTO data to recover TLS ClientHello bytes where possible.
- [ ] Parse QUIC transport parameters from the recovered handshake.
- [ ] Record failure reasons: unsupported version, fragmented CRYPTO, decryption
      failure, malformed packet, ECH present.

### Output

Produce a short spike report in `docs/research/` with:

- Implementation complexity.
- Required dependencies.
- Packet coverage on available captures.
- Whether QUIC should become a full package under `internal/pkg/quic`.

### Acceptance Criteria

- Spike code is either production-quality and tested or kept out of main packages.
- The team can decide whether full QUIC parsing is worth the implementation cost.

## Phase 7: HTTP/2 Fingerprinting

**Priority:** Medium

Add HTTP/2 client behavior fingerprints for coherence scoring and attribution.

### Tasks

- [ ] Detect HTTP/2 preface on cleartext h2c where visible.
- [ ] Parse HTTP/2 SETTINGS frames when decrypted TLS or cleartext traffic is
      available.
- [ ] Capture SETTINGS order and values.
- [ ] Capture initial WINDOW_UPDATE and PRIORITY behavior.
- [ ] Capture pseudo-header order when request headers are available.
- [ ] Add metadata fields and TUI display.

### Acceptance Criteria

- Parser handles partial frames without panics.
- HTTP/2 metadata can be correlated with TLS ALPN `h2`.
- No encrypted application data is parsed unless TLS decryption is configured.

## Phase 8: Cross-Layer Coherence Scoring

**Priority:** High, corpus-dependent

Detect inconsistent client stories across layers.

### Inputs

| Layer | Features |
|-------|----------|
| IP/TCP | TTL, MSS, window scale, window size, TCP option order |
| TLS | JA3/JA4, SimHash, tier hashes, ALPN, ECH offered |
| QUIC | version, transport parameters, Initial shape |
| HTTP/2 | SETTINGS order/values, pseudo-header order |
| SSH | banner, HASSH |

### Finding Examples

| Code | Example |
|------|---------|
| `tcp_tls_os_mismatch` | TCP options look Linux-like, TLS looks Schannel-like |
| `tls_http2_stack_mismatch` | TLS resembles Chrome, HTTP/2 SETTINGS resemble Go |
| `alpn_protocol_mismatch` | TLS advertises h2 but observed app behavior is HTTP/1.x only |
| `ech_outer_only` | ECH present, confidence reduced for TLS identity |
| `rare_transport_shape` | QUIC/TCP behavior far from corpus neighbors |

### Tasks

- [ ] Create `internal/pkg/fingerprint` for cross-protocol feature normalization.
- [ ] Add flow-level feature aggregation at processor.
- [ ] Define `CoherenceFinding` and `CoherenceScore` types.
- [ ] Implement rules as explicit, explainable checks.
- [ ] Calibrate thresholds using Phase 2 controlled captures.
- [ ] Add detail panel output with reason codes and evidence.
- [ ] Add optional filter type only after false-positive rates are understood.

### Acceptance Criteria

- Output includes a score and explainable findings.
- Unknown or missing layers reduce confidence instead of creating false positives.
- Coherence scoring is disabled or informational by default until calibrated.

## Distributed Architecture

### Hunter and Tap

Hunters and tap local capture should compute packet-local metadata:

- JA3, JA3S, JA4, SimHash, tier hashes.
- ECH offered flag.
- SSH HASSH when KEXINIT is visible.
- QUIC header shape and transport parameters once parser is production-ready.
- TCP/IP option fingerprints from captured packet headers.

### Processor

Processors should own:

- Corpus lookup.
- Similarity nearest-neighbor search.
- Cross-layer flow aggregation.
- Coherence scoring.
- TUI and management API exposure.

This keeps hunters lightweight and avoids distributing large or legally sensitive
corpora to edge nodes.

## Proto and UI Work

Every metadata feature that must survive hunter-to-processor streaming needs protobuf
support.

### Proto Tasks

- [ ] Add TLS fingerprint metadata message to `api/proto/data.proto`.
- [ ] Add SSH fingerprint metadata message when HASSH ships.
- [ ] Add QUIC metadata message when QUIC parser ships.
- [ ] Regenerate code with the repo's proto generation command.
- [ ] Preserve backward compatibility by using new optional fields only.

### UI Tasks

- [ ] Add TLS fingerprint rows to packet details.
- [ ] Add ECH counters to statistics.
- [ ] Add SSH fingerprint rows.
- [ ] Add coherence findings as compact reason-code rows.
- [ ] Avoid widening packet-list columns unless the field is useful for scanning.

## Verification Strategy

### Unit Tests

- TLS fingerprint vector tests.
- Extension parser malformed-input tests.
- SimHash deterministic and distance tests.
- SSH KEXINIT parser tests.
- QUIC long-header parser tests.

### Integration Tests

- Parse known PCAP fixtures for TLS, SSH, and QUIC.
- Verify distributed metadata survives hunter-to-processor conversion.
- Verify TUI detail conversion from proto to `types.PacketDisplay`.

### Manual Checks

```bash
make test
make build
sudo ./bin/lc sniff tls -i eth0
sudo ./bin/lc tap tls -i eth0 --insecure
./bin/lc watch remote --node localhost:55555 --insecure
```

Live capture commands require appropriate interface permissions.

## Recommended Sequence

1. Phase 0: baseline JA4 audit and tests.
2. Phase 1: ECH measurement.
3. Phase 2: corpus evaluation.
4. Phase 3: TLS SimHash sidecar.
5. Phase 6: QUIC spike.
6. Phase 5: SSH HASSH.
7. Phase 4: tiered TLS fingerprints.
8. Phase 7: HTTP/2 fingerprinting.
9. Phase 8: coherence scoring.

Phases 5 and 6 can run in parallel if parser ownership is clear.

## Open Questions

1. Which captures can be used as a labeled calibration corpus?
2. Should fingerprint metadata be stored in packet records, flow records, or both?
3. What is the minimum useful TUI presentation for similarity matches?
4. Should nearest-neighbor search use an in-memory index, SQLite, or an external file
   loaded at processor startup?
5. Should coherence scoring become a filter type after calibration?
6. Which build tags should include QUIC and HTTP/2 deep parsers?
7. What legal review is required before shipping third-party fingerprint corpora?
