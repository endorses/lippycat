# Plan: Code Review Fixes (2026-03-14)

Based on [docs/reviews/CODE_REVIEW_2026-03-14.md](../reviews/CODE_REVIEW_2026-03-14.md).

---

## Phase 1: Critical & High — Security and Data Integrity

### C-1: Fix API key timing side-channel attack
- [x] In `internal/pkg/auth/validator.go`, replace map lookup with constant-time comparison
- [x] Iterate all keys with `crypto/subtle.ConstantTimeCompare` (no early return), removed `keyMap` field and `rebuildKeyMap` method
- [x] Existing tests pass (valid key, invalid key, wrong role)

### H-1: Add eviction to unbounded `sync.Map` caches
- [x] `internal/pkg/capture/capture.go` — replaced `espNullSPICache` with `ttlCache[uint32, layers.IPProtocol]` (5min TTL)
- [x] `internal/pkg/capture/capture.go` — replaced `ipv6FragIDCache` with `ttlCache[uint32, ipv6FragInfo]` (30s TTL)
- [x] `internal/pkg/detector/signatures/voip/sip.go` — added TTL-based eviction to `knownSIPIPPairs` (30min TTL) with `SweepSIPIPPairs()` method
- [x] Sweep calls added to existing cleanup goroutine in capture.go

### H-2: Consolidate double shutdown logic
- [x] In `internal/pkg/processor/processor_lifecycle.go`, consolidated shutdown into `Shutdown()` only — `Start()` now calls `Shutdown()` after ctx done
- [x] Added `shutdownOnce sync.Once` to Processor struct, wrapping all cleanup in `Shutdown()`
- [x] Removed duplicate defers from `Start()` (pcapWriter.Stop, upstreamManager.Disconnect, vifManager.Shutdown)
- [x] Added missing cleanup to `Shutdown()` (pcapWriter.Stop, upstreamManager.Disconnect, hunterMonitor.Stop)

### H-3: Fix unified PCAP writer hardcoded LinkType
- [x] In `internal/pkg/processor/pcap/writer.go`, deferred file header writing until first packet batch, using actual `LinkType` from packet
- [x] Falls back to `LinkTypeEthernet` for legacy packets without LinkType field
- [ ] Add test with non-Ethernet link type (e.g., Linux cooked mode SLL)

---

## Phase 2: Medium — Functional Gaps and Modernization

### M-5: Implement hunter flow control
- [ ] In `internal/pkg/hunter/connection/manager.go` (line 548), implement handling for PAUSE, SLOW, RESUME signals from processor
- [ ] Wire `handleStreamControl` to call `handleFlowControl` in `hunter.go`
- [ ] Add tests for flow control state transitions

### M-6: Add tests for `tlsutil` package
- [ ] Add unit tests for `internal/pkg/tlsutil/` covering certificate loading, TLS configuration, and the `InsecureSkipVerify` production-mode guard

### M-1: Replace custom `replaceAll`/`indexSubstring` with stdlib
- [ ] In `internal/pkg/processor/pcap_writer.go` (lines 614-635), replace `replaceAll()` with `strings.ReplaceAll()` and remove `indexSubstring()`

### M-2: Replace custom `bytesEqual` with `bytes.Equal`
- [ ] In `internal/pkg/capture/capture.go` (lines 429-439), replace `bytesEqual()` with `bytes.Equal()`
- [ ] Consider replacing SIP method prefix checks (lines 402-424) with `bytes.HasPrefix()`

### M-3: Remove custom `min()` functions shadowing builtin
- [ ] Remove custom `min()` from:
  - [ ] `internal/pkg/hunter/connection/manager.go` (line 783)
  - [ ] `internal/pkg/tui/components/packetlist.go` (line 848)
  - [ ] `internal/pkg/detector/signatures/application/utils.go` (line 4)
  - [ ] `internal/pkg/voip/plugins/plugin_test.go` (line 389)
  - [ ] `internal/pkg/voip/calltracker_security_test.go` (line 387)

### M-4: Migrate `grpc.Dial` to `grpc.NewClient`
- [ ] In `internal/pkg/hunter/connection/manager.go` (lines 375, 383), replace `grpc.Dial()` with `grpc.NewClient()`
- [ ] Adjust options as needed for the new API

---

## Phase 3: Low — Hardening and Cleanup

### L-1: Use `atomic.Int64` for diagnostic counters
- [ ] In `internal/pkg/voip/call_aggregator.go` (lines 17-31), change `int64` counters to `atomic.Int64` and update all access sites

### L-3: Generic auth error to clients
- [ ] In `internal/pkg/auth/validator.go` (lines 79-98), return a single generic "authentication failed" error to clients
- [ ] Log the specific failure reason (missing key, invalid key, insufficient permissions) server-side only

### L-5: Fix `createCallSafely` returning internal pointer
- [ ] In `internal/pkg/voip/lockfree_calltracker.go` (line 118), return a snapshot copy via `getSnapshot()` instead of the internal `CallInfo` pointer on the `LoadOrStore` existing-entry path

---

## Notes

- Each phase should be committed separately after tests pass
- Run `make test` after each fix to verify no regressions
- Phase 1 is the priority — security and data integrity fixes
- M-7 (subscriber broadcast clone) is omitted — the current architecture is safe since subscribers only serialize for gRPC; adding per-subscriber cloning would hurt performance for no practical benefit
- L-2 (espNullConfigOnce) is omitted — acceptable for current usage, no dynamic config reload exists
- L-4 (TODOs) is informational only, not actionable as a single fix
