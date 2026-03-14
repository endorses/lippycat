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
- [x] In `internal/pkg/hunter/connection/manager.go`, call `flowControlHandler` in `handleStreamControl` instead of TODO comment
- [x] Wiring already existed: `handleStreamControl` → `flowControlHandler` → `hunter.handleFlowControl` → `forwarding.Manager.HandleFlowControl`
- [x] Add tests for flow control state transitions in `internal/pkg/hunter/forwarding/manager_test.go`

### M-6: Add tests for `tlsutil` package
- [x] Add unit tests for `internal/pkg/tlsutil/` covering certificate loading, TLS configuration, and the `InsecureSkipVerify` production-mode guard

### M-1: Replace custom `replaceAll`/`indexSubstring` with stdlib
- [x] Replaced `replaceAll()` with `strings.ReplaceAll()` in `pcap_writer.go`, `auto_rotate_pcap.go`, `tls_keylog_writer.go`
- [x] Removed `replaceAll()` and `indexSubstring()` from `pcap_writer.go`
- [x] Removed corresponding tests (`TestReplaceAll`, `TestIndexSubstring`) from `pcap_writer_test.go`

### M-2: Replace custom `bytesEqual` with `bytes.Equal`
- [x] In `internal/pkg/capture/capture.go`, replaced `bytesEqual()` calls with `bytes.HasPrefix()` (simpler, no manual length check needed)
- [x] Removed `bytesEqual()` function

### M-3: Remove custom `min()` functions shadowing builtin
- [x] Remove custom `min()` from:
  - [x] `internal/pkg/hunter/connection/manager.go`
  - [x] `internal/pkg/tui/components/packetlist.go`
  - [x] `internal/pkg/detector/signatures/application/utils.go` (file deleted, was only content)
  - [x] `internal/pkg/voip/plugins/plugin_test.go`
  - [x] `internal/pkg/voip/calltracker_security_test.go`

### M-4: Migrate `grpc.Dial` to `grpc.NewClient`
- [x] In `internal/pkg/hunter/connection/manager.go`, replaced both `grpc.Dial()` calls with `grpc.NewClient()`

---

## Phase 3: Low — Hardening and Cleanup

### L-1: Use `atomic.Int64` for diagnostic counters
- [x] In `internal/pkg/voip/call_aggregator.go`, changed 9 `int64` counters to `atomic.Int64` and replaced `atomic.AddInt64`/`atomic.LoadInt64` with `.Add()`/`.Load()` methods

### L-3: Generic auth error to clients
- [x] Replaced `ErrMissingAPIKey`, `ErrInvalidAPIKey`, `ErrInsufficientPermissions` with single `ErrAuthenticationFailed` in `internal/pkg/auth/types.go`
- [x] All failure paths in `validator.go` now return generic error; specific reasons logged server-side via `logger.Warn`

### L-5: Fix `createCallSafely` returning internal pointer
- [x] In `internal/pkg/voip/lockfree_calltracker.go`, changed `LoadOrStore` existing-entry path to return `getSnapshot()` instead of internal `CallInfo` pointer

---

## Notes

- Each phase should be committed separately after tests pass
- Run `make test` after each fix to verify no regressions
- Phase 1 is the priority — security and data integrity fixes
- M-7 (subscriber broadcast clone) is omitted — the current architecture is safe since subscribers only serialize for gRPC; adding per-subscriber cloning would hurt performance for no practical benefit
- L-2 (espNullConfigOnce) is omitted — acceptable for current usage, no dynamic config reload exists
- L-4 (TODOs) is informational only, not actionable as a single fix
