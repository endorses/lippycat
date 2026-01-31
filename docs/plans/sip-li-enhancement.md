# SIP LI Enhancement Implementation Plan

**Date:** 2026-01-31
**Task:** Extend SIP method coverage and header extraction for LI compliance
**Effort:** Medium (4 phases)
**Risk:** Low (additive changes, existing tests cover core paths)
**Reference:**
- [LI Non-Call SIP Coverage Research](../research/li-non-call-sip-coverage.md)
- [VoLTE/VoWiFi Header Extraction Research](../research/volte-vowifi-header-extraction.md)

---

## Executive Summary

Two compliance gaps in lippycat's LI implementation:

1. **SIP Method Coverage:** X2 IRI only generated for INVITE/BYE/CANCEL/REGISTER. Missing MESSAGE (SMS-over-IMS), SUBSCRIBE, NOTIFY, INFO, REFER, and others.

2. **Target Identifiers:** X1 accepts IMSI/IMEI targets but filtering is not implemented (SIP headers not parsed for these identifiers).

Additionally, **3GPP IMS headers** (P-Access-Network-Info, P-Visited-Network-ID) provide location/network context valuable for LI and forensics.

---

## Implementation Steps

### Phase 1: Extend IRI Types and SIP Method Classification

#### Step 1.1: Add new IRI types to `internal/pkg/li/x2x3/pdu.go`

- [x] Add `IRISessionContinue` (7) for INFO, UPDATE, re-INVITE, PRACK, ACK
- [x] Add `IRIMessage` (8) for MESSAGE method
- [x] Add `IRISubscription` (9) for SUBSCRIBE
- [x] Add `IRINotification` (10) for NOTIFY
- [x] Add `IRIPresence` (11) for PUBLISH
- [x] Add `IRITransfer` (12) for REFER
- [x] Add `IRIReport` (13) for OPTIONS and other non-session events

#### Step 1.2: Update `classifyIRIType()` in `internal/pkg/li/x2x3/x2_encoder.go`

- [x] Add MESSAGE → IRIMessage mapping
- [x] Add SUBSCRIBE → IRISubscription mapping
- [x] Add NOTIFY → IRINotification mapping
- [x] Add PUBLISH → IRIPresence mapping
- [x] Add INFO, UPDATE, PRACK → IRISessionContinue mapping
- [x] Add REFER → IRITransfer mapping
- [x] Add OPTIONS → IRIReport mapping
- [x] Add ACK → IRISessionContinue mapping
- [x] Run: `go test -race ./internal/pkg/li/...`

---

### Phase 2: MESSAGE Body Extraction (SMS-over-IMS)

#### Step 2.1: Extend VoIPMetadata in `internal/pkg/types/packet.go`

- [x] Add `Body string` field for SIP message body
- [x] Add `ContentType string` field (already existed)
- [x] Update JSON tags (not needed, existing pattern followed)

#### Step 2.2: Update SIP parser in `internal/pkg/voip/processor/sip_detector.go`

- [x] Extract body for MESSAGE method
- [x] Extract Content-Type header
- [x] Limit body extraction to reasonable size (64KB via MaxMessageBodySize)

#### Step 2.3: Include body in X2 IRI encoding

- [x] Add `AttrMessageContent` and `AttrMessageContentType` attributes to PDU
- [x] Encode body in `addSIPAttributes()` for MESSAGE method
- [x] Run: `go test -race ./internal/pkg/li/...`

---

### Phase 3: IMSI/IMEI Target Filtering

#### Step 3.1: Add filter types to `api/proto/management.proto`

- [x] Add `FILTER_IMSI = 16`
- [x] Add `FILTER_IMEI = 17`
- [x] Regenerate: `make proto`

#### Step 3.2: Add IMSI/IMEI extraction to SIP parser

Location of identifiers in SIP:
- **IMSI:** Authorization header username or P-Asserted-Identity (format: `<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`)
- **IMEI:** Contact header `+sip.instance` parameter (format: `urn:gsma:imei:<TAC>-<SNR>-<CD>`)

- [x] Add `ExtractIMSI()` function parsing IMPI format from Authorization/P-Asserted-Identity
- [x] Add `ExtractIMEI()` function parsing URN format from Contact header
- [x] Add `IMSI` and `IMEI` fields to VoIPMetadata
- [x] Run: `go test -race ./internal/pkg/voip/...`

#### Step 3.3: Update filter mapping in `internal/pkg/li/filters.go`

- [x] Add `TargetTypeIMSI` and `TargetTypeIMEI` to `internal/pkg/li/types.go`
- [x] Add `TargetTypeIMSI` and `TargetTypeIMEI` cases to `mapTargetToFilterType()`
- [x] Add `normalizeIMSI()` and `normalizeIMEI()` helper functions

#### Step 3.4: Add filter matchers in `internal/pkg/hunter/application_filter.go`

- [x] Add `imsiFilters` and `imeiFilters` maps to ApplicationFilter
- [x] Handle `FILTER_IMSI` and `FILTER_IMEI` in `UpdateFilters()`
- [x] Add Authorization and Contact header extraction to `extractSIPHeaders()`
- [x] Add `matchIMSIIMEI()` and `matchIMSIIMEIWithIDs()` methods
- [x] Run: `go test -race ./internal/pkg/hunter/...`

---

### Phase 4: 3GPP IMS Header Extraction

#### Step 4.1: Add AccessNetworkInfo struct to `internal/pkg/types/packet.go`

```go
type AccessNetworkInfo struct {
    AccessType string            `json:"access_type"`           // "IEEE-802.11", "3GPP-E-UTRAN"
    BSSID      string            `json:"bssid,omitempty"`       // WiFi AP MAC
    CellID     string            `json:"cell_id,omitempty"`     // Cellular cell ID
    LocalIP    string            `json:"local_ip,omitempty"`    // UE local IP
    Parameters map[string]string `json:"parameters,omitempty"`
}
```

- [x] Add `AccessNetworkInfo *AccessNetworkInfo` to VoIPMetadata
- [x] Add `VisitedNetworkID string` to VoIPMetadata

#### Step 4.2: Parse P-Access-Network-Info header

- [x] Add `parseAccessNetworkInfo()` to SIP parser
- [x] Handle IEEE-802.11 (extract i-wlan-node-id → BSSID)
- [x] Handle 3GPP-E-UTRAN (extract ecgi → CellID)
- [x] Handle 3GPP-GERAN, 3GPP-UTRAN, 3GPP-NR

#### Step 4.3: Parse P-Visited-Network-ID header

- [x] Extract quoted network name
- [x] Add to VoIPMetadata

#### Step 4.4: Update protobuf (optional, for gRPC transport)

- [x] Add `AccessNetworkInfo` message to `api/proto/data.proto`
- [x] Add fields to `SIPMetadata` message
- [x] Regenerate: `cd api/proto && make all`

#### Step 4.5: Display in TUI

- [x] Add access network info to `internal/pkg/tui/components/detailspanel.go`
- [x] Show access type, BSSID/CellID when available

---

## Priority Assessment

| Priority | Items |
|----------|-------|
| **P0** (Critical) | MESSAGE method, MESSAGE body, IMSI filtering, IMEI filtering |
| **P1** (High) | INFO, REFER, SUBSCRIBE/NOTIFY |
| **P2** (Medium) | UPDATE, PRACK, PUBLISH, ACK, P-Access-Network-Info |
| **P3** (Low) | OPTIONS, P-Visited-Network-ID, P-Charging-Vector |

---

## Testing

```bash
# Unit tests
go test -race ./internal/pkg/li/...
go test -race ./internal/pkg/voip/...
go test -race ./internal/pkg/hunter/filters/...

# Integration test with MESSAGE
# (requires test PCAP with MESSAGE method)

# Build verification
make build-li
make verify-no-li
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `internal/pkg/li/x2x3/pdu.go` | Add IRI types 7-13 |
| `internal/pkg/li/x2x3/x2_encoder.go` | Extend `classifyIRIType()` |
| `internal/pkg/types/voip.go` | Add Body, ContentType, IMSI, IMEI, AccessNetworkInfo |
| `internal/pkg/voip/processor/sip_detector.go` | Parse body, IMSI, IMEI, P-Access-Network-Info |
| `api/proto/management.proto` | Add FILTER_IMSI, FILTER_IMEI |
| `internal/pkg/li/filters.go` | Map IMSI/IMEI targets |
| `internal/pkg/hunter/filters/imsi_filter.go` | New file |
| `internal/pkg/hunter/filters/imei_filter.go` | New file |
| `internal/pkg/tui/views/voip_detail.go` | Display new fields |
