# ESP-NULL Explicit Mode

## Goal

Add `--esp-null` and `--esp-icv-size` flags so operators can tell lippycat that ESP traffic is NULL-encrypted, bypassing heuristic detection. This improves correctness for non-VoIP inner protocols and eliminates cold-start detection overhead.

## Background

Currently, ESP-NULL decapsulation uses a three-tier heuristic:

1. **Content heuristics** — scan inner payload for SIP/RTP signatures
2. **SPI cache** — reuse previously detected protocol for known SPIs
3. **Trailer validation** — parse ESP trailer padding to infer inner protocol

This works well for VoIP but fails for non-SIP/RTP inner protocols (e.g., plain HTTP, DNS, or proprietary protocols inside ESP-NULL). The SPI cache makes subsequent packets fast, but the first packet per SPI must pass content or trailer validation.

With explicit mode, all ESP packets are assumed NULL-encrypted and decapsulated using trailer parsing alone (no content validation needed).

## Design

### New Flags

| Flag | Type | Default | Viper Key | Description |
|------|------|---------|-----------|-------------|
| `--esp-null` | bool | `false` | `esp_null` | Assume all ESP traffic is NULL-encrypted |
| `--esp-icv-size` | int | `-1` (auto) | `esp_icv_size` | ICV size in bytes (0, 8, 12, 16). -1 = auto-detect |

### Behavior Matrix

| `--esp-null` | `--esp-icv-size` | Behavior |
|:---:|:---:|---|
| off | any | Current heuristic detection (ignore `--esp-icv-size`) |
| on | -1 (auto) | Skip content heuristics, use trailer validation with all ICV candidates |
| on | N | Skip content heuristics, use trailer validation with fixed ICV size only |

### Flag Placement

Register on all commands that perform capture with ESP decapsulation:

- [x] `cmd/sniff/sniff.go` — PersistentFlags, inherited by voip subcommand
- [x] `cmd/tap/tap.go` — PersistentFlags, inherited by voip subcommand
- [x] `cmd/hunt/hunt.go` — PersistentFlags, inherited by voip subcommand

Note: Flags are registered as PersistentFlags on parent commands, so voip subcommands inherit them automatically.

### Config File Support

```yaml
esp_null: true
esp_icv_size: 12
```

## Implementation

### Task 1: Add Flags

- [x] Register `--esp-null` (bool) and `--esp-icv-size` (int) in each command listed above
- [x] Bind to Viper keys `esp_null` and `esp_icv_size`
- [x] Validate: `--esp-icv-size` must be one of -1, 0, 8, 12, 16 — error on invalid values
- [x] Validate: `--esp-icv-size` without `--esp-null` emits a warning (ignored without explicit mode)

### Task 2: Modify `decapsulateESPNull()`

File: `internal/pkg/capture/capture.go`

Current flow (lines ~1082-1309):

```
1. Extract ESP payload
2. Try content heuristics (SIP/RTP detection) → set innerProto
3. If failed, try SPI cache → set innerProto
4. If failed, try trailer validation → set innerProto
5. Rebuild packet with innerProto
```

New flow when `--esp-null` is enabled:

```
1. Extract ESP payload
2. Try trailer validation (with fixed or auto ICV size) → set innerProto
3. If failed AND SPI cache has entry, use cached proto
4. Rebuild packet with innerProto
```

Changes:

- [x] Read `viper.GetBool("esp_null")` and `viper.GetInt("esp_icv_size")` at the top of the function (or cache in a package-level variable on first call for performance)
- [x] When `esp_null` is true, skip the content heuristic block (Tier 1) entirely
- [x] When `esp_icv_size` >= 0, modify `tryESPTrailerValidation()` to use only the specified ICV size instead of iterating all candidates
- [x] Keep SPI cache as a secondary fallback even in explicit mode (handles continuation segments where trailer may be ambiguous)

### Task 3: Modify `tryESPTrailerValidation()`

File: `internal/pkg/capture/capture.go` (lines ~999-1080)

- [x] Add an `icvSize` parameter: `tryESPTrailerValidation(espPayload []byte, icvSize int) (layers.IPProtocol, int, bool)`
- [x] When `icvSize >= 0`, use only that size (skip the loop over `[]int{12, 16, 8, 0}`)
- [x] When `icvSize < 0` (auto), keep current behavior (try all candidates)
- [x] Update all call sites

### Task 4: Modify `decapsulateIPv6FragmentESP()`

File: `internal/pkg/capture/capture.go` (lines ~1311-1510)

- [x] Apply the same explicit-mode logic as Task 2
- [x] Skip content heuristics when `esp_null` is true
- [x] Pass ICV size through to trailer validation

### Task 5: Cache Viper Reads

Reading Viper on every packet is wasteful. Cache the values:

- [x] Add package-level variables:
  ```go
  var (
      espNullConfigOnce sync.Once
      espNullEnabled    bool
      espFixedICVSize   int  // -1 = auto
  )
  ```
- [x] Initialize once on first call via `sync.Once` in `getESPNullConfig()`

Preferred approach: `sync.Once` with Viper reads, consistent with existing patterns (`getPacketBufferSize()`, `GetPcapTimeout()`).

### Task 6: Tests

- [x] Unit test: `--esp-null` mode decapsulates ESP packets without SIP/RTP content
- [x] Unit test: `--esp-icv-size 12` uses only HMAC-SHA1-96 trailer parsing
- [x] Unit test: `--esp-icv-size 0` handles NULL authentication correctly
- [x] Unit test: invalid `--esp-icv-size` value (e.g., 7) rejected at flag validation
- [x] Regression: existing heuristic detection still works when `--esp-null` is off

### Task 7: Documentation

- [x] Update `cmd/sniff/README.md` with new flags
- [x] Update `cmd/tap/README.md` with new flags
- [x] Update `cmd/hunt/README.md` with new flags
- [ ] Update `CLAUDE.md` CLI examples section
- [ ] Add config file example to relevant README

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| False decapsulation of actually-encrypted ESP | Trailer padding validation still runs — sequential padding check discriminates NULL from encrypted |
| Performance regression from Viper reads | Cache via `sync.Once` (Task 5) |
| Breaking existing behavior | `--esp-null` defaults to `false`, no change unless explicitly enabled |
| ICV size mismatch | Auto-detect remains the default; fixed size is opt-in for operators who know their network |
