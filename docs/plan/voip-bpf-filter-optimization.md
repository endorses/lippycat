# VoIP BPF Filter Optimization Implementation Plan

**Date:** 2025-12-18
**Task:** Add `--udp-only`, `--sip-port`, and `--rtp-port-range` flags to VoIP commands
**Effort:** 4-6 hours
**Risk:** Low
**Reference:** [Research Report](../research/voip-bpf-filter-optimization.md)

---

## Executive Summary

Implement three new flags for `lc sniff voip` and `lc hunt voip` that allow users to optimize BPF filters for high-traffic networks. A shared `VoIPFilterBuilder` abstraction in `internal/pkg/voip/filter.go` will handle filter construction for both commands.

**Problem:** On networks with high TCP traffic but UDP-only SIP, TCP reassembly overhead overwhelms the SIP handler.

**Solution:**
- `--udp-only` — Capture UDP only, bypass TCP entirely
- `--sip-port` — Restrict SIP to specific port(s) while capturing RTP on port ranges
- `--rtp-port-range` — Custom RTP port range(s) for non-standard environments

---

## Implementation Steps

### Phase 1: Core Filter Builder (1.5 hours) ✅

#### Step 1.1: Create `internal/pkg/voip/filter.go`
- [x] Create `PortRange` struct and `VoIPFilterConfig` struct
- [x] Implement `VoIPFilterBuilder.Build()` method
- [x] Add `ParsePortRanges()` and `ParsePorts()` helper functions
- [x] Export `DefaultRTPPortRange()` (10000-32768)
- [x] Run tests: `go test -race ./internal/pkg/voip/...`
- [x] Format: `gofmt -w internal/pkg/voip/filter.go`

#### Step 1.2: Create `internal/pkg/voip/filter_test.go`
- [x] Test filter construction for all flag combinations (from research §4)
- [x] Test edge cases: empty inputs, multiple ranges, combined filters
- [x] Test `ParsePortRanges()` and `ParsePorts()` error handling
- [x] Run tests: `go test -race ./internal/pkg/voip/...`

---

### Phase 2: Command Integration (2 hours)

#### Step 2.1: Update `cmd/sniff/voip.go`
- [ ] Add `--udp-only` flag (bool, default: false)
- [ ] Add `--sip-port` flag (string, comma-separated ports)
- [ ] Add `--rtp-port-range` flag (string, comma-separated ranges)
- [ ] Bind flags to Viper: `voip.udp_only`, `voip.sip_ports`, `voip.rtp_port_ranges`
- [ ] Build effective filter using `VoIPFilterBuilder` before capture
- [ ] Run tests: `go test -race ./cmd/sniff/...`
- [ ] Format: `gofmt -w cmd/sniff/voip.go`

#### Step 2.2: Update `cmd/hunt/voip.go`
- [ ] Add same three flags with Viper bindings under `hunter.voip.*`
- [ ] Integrate `VoIPFilterBuilder` with existing `buildCombinedBPFFilter()` in hunter
- [ ] Run tests: `go test -race ./cmd/hunt/...`
- [ ] Format: `gofmt -w cmd/hunt/voip.go`

---

### Phase 3: Validation & Documentation (1 hour)

#### Step 3.1: Manual Testing
- [ ] Test `--udp-only` generates `udp` filter
- [ ] Test `--sip-port 5060` generates `(port 5060) or (udp portrange 10000-32768)`
- [ ] Test `--sip-port 5060 --udp-only` generates `udp and ((port 5060) or (portrange 10000-32768))`
- [ ] Test `--rtp-port-range 8000-9000` overrides default RTP range
- [ ] Test combination with `--filter "host 10.0.0.1"` produces correct AND combination
- [ ] Test YAML config file values are read correctly

#### Step 3.2: Documentation Updates
- [ ] Update `cmd/sniff/README.md` — Add new flags with examples
- [ ] Update `cmd/hunt/README.md` — Add new flags with examples
- [ ] Update `cmd/sniff/CLAUDE.md` — Document filter builder pattern
- [ ] Update root `CLAUDE.md` — Add flags to CLI usage section
- [ ] Add YAML config examples to relevant READMEs

#### Step 3.3: Final Validation
- [ ] Run full test suite: `make test`
- [ ] Run linter: `golangci-lint run ./...`
- [ ] Build all variants: `make binaries`
- [ ] Commit changes

---

## File Changes Summary

| File | Change |
|------|--------|
| `internal/pkg/voip/filter.go` | **New** — VoIPFilterBuilder and parsing functions |
| `internal/pkg/voip/filter_test.go` | **New** — Unit tests for filter construction |
| `cmd/sniff/voip.go` | **Modify** — Add 3 flags, integrate filter builder |
| `cmd/hunt/voip.go` | **Modify** — Add 3 flags, integrate filter builder |
| `cmd/sniff/README.md` | **Modify** — Document new flags |
| `cmd/hunt/README.md` | **Modify** — Document new flags |
| `cmd/sniff/CLAUDE.md` | **Modify** — Document filter builder pattern |
| `CLAUDE.md` | **Modify** — Add flags to usage section |

---

## Filter Construction Reference

```go
// internal/pkg/voip/filter.go

type PortRange struct {
    Start int
    End   int
}

type VoIPFilterConfig struct {
    SIPPorts      []int       // empty = no SIP port filter
    RTPPortRanges []PortRange // empty = use default 10000-32768
    UDPOnly       bool
    BaseFilter    string      // user's --filter value
}

func (b *VoIPFilterBuilder) Build(config VoIPFilterConfig) string
func ParsePortRanges(s string) ([]PortRange, error)  // "8000-9000,40000-50000"
func ParsePorts(s string) ([]int, error)             // "5060,5061,5080"
```

**Algorithm:** See [Research Report §4](../research/voip-bpf-filter-optimization.md#4-filter-construction-logic)

---

## Success Criteria

- [ ] `VoIPFilterBuilder` correctly generates all filter combinations from research §3
- [ ] Both commands accept new flags and produce correct BPF filters
- [ ] YAML config file support works for all three options
- [ ] All tests pass with race detector
- [ ] Documentation covers all new flags with examples
- [ ] No breaking changes to existing behavior (empty flags = original behavior)

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Breaking existing `--filter` behavior | BaseFilter combined with AND, tested explicitly |
| Hunter dynamic filter conflicts | Test integration with `buildCombinedBPFFilter()` |
| Invalid BPF syntax | Unit tests cover all combinations; gopacket validates at runtime |
| Viper binding issues | Follow existing pattern from other voip flags |

---

## Quick Reference: Expected Outputs

| Input | Expected BPF Filter |
|-------|---------------------|
| `--udp-only` | `udp` |
| `--sip-port 5060` | `(port 5060) or (udp portrange 10000-32768)` |
| `--sip-port 5060 --udp-only` | `udp and ((port 5060) or (portrange 10000-32768))` |
| `--sip-port 5060,5080` | `(port 5060 or port 5080) or (udp portrange 10000-32768)` |
| `--rtp-port-range 8000-9000` | `(udp portrange 8000-9000)` |
| `--sip-port 5060 --rtp-port-range 8000-9000` | `(port 5060) or (udp portrange 8000-9000)` |
| `--filter "host 10.0.0.1" --sip-port 5060` | `(host 10.0.0.1) and ((port 5060) or (udp portrange 10000-32768))` |
