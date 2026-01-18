# Code Review Fixes Implementation Plan

**Reference:** [docs/review/CODE_REVIEW_2026-01-09.md](../review/CODE_REVIEW_2026-01-09.md)
**Created:** 2026-01-09
**Status:** Completed ✅

## Summary

This plan addresses issues identified in the 2026-01-09 code review. Skipped issues marked as acceptable/mitigated: #5 (Registry callback pattern), #6 (MustRegister panic), #10 (auth bypass - already mitigated).

---

## Immediate Priority (Before Next Release)

### Issue #1: Command Injection in CommandExecutor [CRITICAL] ✅ FIXED

**File:** `internal/pkg/processor/command_executor.go`

The `ExecutePcapCommand` (line 82) and `ExecuteVoipCommand` (lines 97-101) substitute attacker-controllable values from SIP packets directly into shell commands.

- [x] Add shell escaping for substituted values
  - Implemented `shellEscape()` function using single-quote wrapping with embedded quote escaping
  - `ExecutePcapCommand`: Escapes `filePath` before substitution
  - `ExecuteVoipCommand`: Escapes all metadata fields (`CallID`, `DirName`, `Caller`, `Called`, `CallDate`)

- [x] Add input validation to reject shell metacharacters
  - Created `containsShellMetachars(s string) bool` helper function
  - Logs warning when metacharacters are detected (still executes safely with escaping)
  - Characters checked: `;|&$`\"'<>(){}[]!#~*?\n\r`

- [x] Add unit tests for command injection prevention
  - `TestShellEscape`: Tests escaping of various metacharacters and edge cases
  - `TestContainsShellMetachars`: Tests detection of shell metacharacters
  - `TestExecutePcapCommand_CommandInjectionPrevention`: Tests quote-based injection
  - `TestExecuteVoipCommand_CommandInjectionPrevention_CallID`: Tests Call-ID injection
  - `TestExecuteVoipCommand_CommandInjectionPrevention_Caller`: Tests backtick execution
  - `TestExecuteVoipCommand_CommandInjectionPrevention_SubshellExpansion`: Tests $() execution
  - `TestExecuteVoipCommand_PathWithSpaces`: Tests proper handling of spaces

### Issue #2: Build Constraint Test Failures [HIGH] ✅ FIXED

**Files:** `internal/pkg/processor/`, `internal/pkg/tls/keylog/`

Tests failed without `-tags all` because `internal/pkg/processor` imported `internal/pkg/tls/keylog` which had build constraints, but processor itself had no constraints.

**Root Cause:** The `processor` package had no build tags but imported packages with build tags (`tls/keylog`). When running `go test ./...` without tags, keylog was excluded but processor tried to import it.

**Solution:** Add proper build constraints to the processor package (since it's only used by processor/tap/all builds):

- [x] Add `//go:build processor || tap || all` to all processor package files (28 files)
  - All `.go` files in `internal/pkg/processor/`
  - All `*_test.go` files in `internal/pkg/processor/`
  - LI files updated to combined constraints: `(processor || tap || all) && li` / `(processor || tap || all) && !li`

- [x] Add `processor` to `tls/keylog` package build tags
  - Updated all files in `internal/pkg/tls/keylog/` to include `processor` tag
  - Changed from `cli || hunter || tap || all` to `cli || hunter || processor || tap || all`

- [x] Verify Makefile test target (already correct)
  - `make test` already uses `go test -tags all ./...` (line 166)
  - No changes needed

- [x] Verify CONTRIBUTING.md documentation (already correct)
  - Already documents `-tags all` requirement (lines 576-595)
  - No changes needed

---

## Short-Term Priority (Next Sprint)

### Issue #4: X1 Rate Limiting [MEDIUM] ✅ FIXED

**File:** `internal/pkg/li/x1/server.go`

The X1 HTTPS server lacks per-IP rate limiting. XML parsing can be expensive.

- [x] Add rate limiting middleware
  - Use `golang.org/x/time/rate` for per-IP rate limiting
  - Store rate limiters in `sync.Map` keyed by IP
  - Configure via `RateLimitPerIP` (default: 10 req/s) and `RateLimitBurst` (default: 20)
  - Added `getRateLimiter()` helper and `extractClientIP()` for X-Forwarded-For support

- [x] Add request timeout for XML parsing
  - XML parsing wrapped in goroutine with configurable `XMLParseTimeout` (default: 5s)
  - Returns 503 if parsing times out

- [x] Add unit tests for rate limiting
  - `TestServer_RateLimiting`: Tests burst limit enforcement
  - `TestServer_RateLimiting_PerIP`: Tests separate rate limiters per IP
  - `TestServer_RateLimiting_XForwardedFor`: Tests proxy IP extraction
  - `TestServer_RateLimiting_XForwardedFor_Chain`: Tests X-FF chain parsing
  - `TestExtractClientIP`: Tests IP extraction from various formats
  - `TestServer_GetRateLimiter`: Tests limiter creation and reuse
  - `TestServer_DefaultConfig`: Tests default config values
  - `TestServer_CustomConfig`: Tests custom config values

### Issue #11: Subscriber Channel Leak [MEDIUM] ✅ FIXED

**File:** `internal/pkg/processor/subscriber/manager.go`

The `Remove()` method (lines 43-46) deletes from sync.Map but does not close the channel, leaving readers blocked forever.

- [x] Close channel on Remove
  - Created `safeChannel` wrapper type with synchronized `Close()` and `TrySend()` methods
  - Uses RWMutex to prevent races between closing and sending
  - `Remove()` now calls `safeChannel.Close()` which properly closes the underlying channel
  - Callers receiving from the channel will see the channel as closed

- [x] Update `Broadcast()` to handle closed channel gracefully
  - Uses `safeChannel.TrySend()` which checks the closed flag under RLock before attempting send
  - No panic possible from sending to closed channel
  - Added comprehensive unit tests including race detector verification

### Issue #8: writtenKeys Memory Growth [MEDIUM] ✅ FIXED

**File:** `internal/pkg/processor/tls_keylog_writer.go`

The `writtenKeys` map (line 68) grows unboundedly while `keyStore` has cleanup.

- [x] Add periodic cleanup for writtenKeys
  - Changed `writtenKeys` from `map[string]bool` to `map[string]time.Time` to track insertion time
  - Added cleanup goroutine that runs every 5 minutes (matching keyStore)
  - Added LRU eviction when MaxEntries is reached (`evictOldestLocked()`)

- [x] Add cleanup goroutine
  - Added `cleanupLoop()` goroutine started in `NewTLSKeylogWriter()`
  - Added `stopChan` and `WaitGroup` for clean shutdown
  - `cleanupWrittenKeys()` removes entries older than SessionTTL
  - `Close()` now stops cleanup goroutine before releasing resources
  - Added unit tests for eviction and TTL cleanup

### Issue #9: X1 Error Response Missing Details [LOW-MEDIUM] ✅ FIXED

**File:** `internal/pkg/li/x1/server.go`

The `buildErrorResponse()` function (lines 1105-1132) logs error details but returns empty response without error code/description.

- [x] Include error details in X1 response per ETSI spec
  - Created `flexibleResponseContainer` type with custom `MarshalXML` method
  - Changed `buildErrorResponse` to return `*schema.ErrorResponse` with proper error info
  - Changed all handler functions from `*schema.X1ResponseMessage` to `any` return type
  - Response XML now includes `<errorResponse>`, `<errorInformation>`, `<errorCode>`, `<errorDescription>`
  - Added `TestServer_ErrorResponse_IncludesDetails` and `TestServer_ErrorResponse_XMLStructure` tests

---

## Medium-Term Priority (Next Quarter)

### Issue #3: CallIDDetector Race Condition [MEDIUM] ✅ FIXED

**File:** `internal/pkg/voip/tcp_stream.go`

Small TOCTOU window in `SetCallID()` (lines 53-78) between atomic load and channel close.

- [x] Move channel operations fully under mutex
  - Changed `closed` from atomic `int32` to mutex-protected `bool`
  - Changed `mu` from `RWMutex` to `Mutex` (simpler, no need for read-only path)
  - `SetCallID()` now checks both `closed` and `set` under the same lock
  - `Close()` now uses mutex instead of atomic CAS, only closes channel if `set` is false

- [x] Add race detector test
  - Added "Concurrent SetCallID and Close stress test" subtest in `TestCallIDDetector_RaceConditions`
  - Runs 100 iterations with 10 goroutines each for SetCallID, Close, and Wait
  - All goroutines start simultaneously for maximum contention
  - Passes with `-race` flag

### Issue #7: Context Propagation in Delivery Client [MEDIUM] ✅ FIXED

**File:** `internal/pkg/li/delivery/client.go`

The `sendSync()` method (line 529) accepts context but doesn't pass it to `GetConnection()` (line 542).

- [x] Add context parameter to GetConnection
  - Updated `Manager.GetConnection(ctx context.Context, did uuid.UUID)` signature
  - Added `dialDestinationWithContext()` that uses the provided context for TCP dial and TLS handshake
  - Context deadline is respected for connection timeout
  - Early cancellation check added before handshake

- [x] Update all call sites to pass context
  - `sendSync()`: Passes caller's context to GetConnection
  - `deliverToDestination()`: Creates timeout context from SendTimeout config
  - Test updated to use `context.Background()`

### Test Coverage Improvements [MEDIUM] ✅ DONE

**Packages:** remotecapture (28.2%), downstream (32.6%), source (36.4%)

- [x] Add tests for `internal/pkg/remotecapture`
  - Added tests for call state tracking (`updateCallState`)
  - Added tests for RTP quality tracking (`updateRTPQuality`, packet loss, sequence wrap)
  - Added tests for call update throttling (`maybeNotifyCallUpdates`)
  - Added edge case tests (empty call ID, nil SIP metadata)

- [x] Add tests for `internal/pkg/processor/downstream`
  - Added tests for Get/GetAll operations
  - Added tests for Unregister operations
  - Added tests for health check with topology publisher
  - Added tests for chain error wrapping
  - Added tests for concurrent access
  - Added tests for TLS configuration

- [x] Add integration tests for hunter-processor communication
  - Existing tests in `test/remotecapture_integration_test.go` already cover:
    - Connect and stream (`TestIntegration_RemoteCapture_ConnectAndStream`)
    - Filtered stream (`TestIntegration_RemoteCapture_FilteredStream`)
    - Hot-swap subscription (`TestIntegration_RemoteCapture_HotSwapSubscription`)
    - Multiple subscribers (`TestIntegration_RemoteCapture_MultipleSubscribers`)
    - Topology queries (`TestIntegration_RemoteCapture_GetTopology`)
  - Additional tests in `test/integration_test.go` cover:
    - Basic hunter-processor flow
    - Hunter crash recovery
    - Processor restart with connected hunters

---

## Checklist Summary

**Immediate (2 tasks):**
- [x] Fix command injection (#1) ✅
- [x] Fix build constraints (#2) ✅

**Short-Term (4 tasks):**
- [x] Add X1 rate limiting (#4) ✅
- [x] Fix subscriber channel leak (#11) ✅
- [x] Add writtenKeys cleanup (#8) ✅
- [x] Include X1 error details (#9) ✅

**Medium-Term (4 tasks):**
- [x] Fix CallIDDetector race (#3) ✅
- [x] Propagate context in delivery (#7) ✅
- [x] Improve test coverage ✅
- [x] Add integration tests ✅
