# Code Review Fixes Implementation Plan

**Reference:** [docs/review/CODE_REVIEW_2026-01-09.md](../review/CODE_REVIEW_2026-01-09.md)
**Created:** 2026-01-09
**Status:** Pending

## Summary

This plan addresses issues identified in the 2026-01-09 code review. Skipped issues marked as acceptable/mitigated: #5 (Registry callback pattern), #6 (MustRegister panic), #10 (auth bypass - already mitigated).

---

## Immediate Priority (Before Next Release)

### Issue #1: Command Injection in CommandExecutor [CRITICAL]

**File:** `internal/pkg/processor/command_executor.go`

The `ExecutePcapCommand` (line 82) and `ExecuteVoipCommand` (lines 97-101) substitute attacker-controllable values from SIP packets directly into shell commands.

- [ ] Add shell escaping for substituted values
  - Import `github.com/alessio/shellescape` (or equivalent)
  - In `ExecutePcapCommand` (line 82): Escape `filePath` before substitution
  - In `ExecuteVoipCommand` (lines 97-101): Escape `meta.CallID`, `meta.DirName`, `meta.Caller`, `meta.Called` before substitution
  - Alternative: Refactor to use `exec.Command` with separate arguments instead of shell evaluation

- [ ] Add input validation to reject shell metacharacters
  - Create helper function `containsShellMetachars(s string) bool`
  - Log warning and skip execution if metacharacters detected
  - Characters to check: `;`, `|`, `&`, `$`, `` ` ``, `\`, `"`, `'`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`

- [ ] Add unit tests for command injection prevention
  - Test with Call-ID containing `; rm -rf /`
  - Test with caller/called containing backticks and $()

### Issue #2: Build Constraint Test Failures [HIGH]

**Files:** Multiple test files in `internal/pkg/processor/`

Tests fail without `-tags all` due to `TLSKeylogWriter` being build-tagged but referenced unconditionally.

- [ ] Add test file build constraints
  - Ensure `processor_test.go` and related test files have `//go:build all` or appropriate tags
  - Add `processor_tls_keylog_writer_test.go` with `//go:build processor || tap || all`

- [ ] Update Makefile test target
  - Modify `make test` to use `go test -tags all ./...`
  - Document this requirement in CONTRIBUTING.md

- [ ] Verify CI/CD pipeline uses correct test invocation

---

## Short-Term Priority (Next Sprint)

### Issue #4: X1 Rate Limiting [MEDIUM]

**File:** `internal/pkg/li/x1/server.go`

The X1 HTTPS server lacks per-IP rate limiting. XML parsing can be expensive.

- [ ] Add rate limiting middleware
  - Use `golang.org/x/time/rate` for per-IP rate limiting
  - Store rate limiters in `sync.Map` keyed by IP
  - Configure via `X1RateLimitPerIP` (default: 10 req/s) and `X1RateLimitBurst` (default: 20)

- [ ] Add request timeout for XML parsing
  - Wrap XML parsing in context with timeout (e.g., 5s)
  - Return 503 if parsing times out

### Issue #11: Subscriber Channel Leak [MEDIUM]

**File:** `internal/pkg/processor/subscriber/manager.go`

The `Remove()` method (lines 43-46) deletes from sync.Map but does not close the channel, leaving readers blocked forever.

- [ ] Close channel on Remove
  - Modify `Remove()` to retrieve channel before deletion
  - Close the channel after deletion
  - Document that subscribers must handle closed channels

```go
func (m *Manager) Remove(clientID string) {
    if val, ok := m.subscribers.LoadAndDelete(clientID); ok {
        close(val.(chan *data.PacketBatch))
    }
    m.filters.Delete(clientID)
}
```

- [ ] Update `Broadcast()` to handle closed channel gracefully
  - The existing `select` with `default` already handles this

### Issue #8: writtenKeys Memory Growth [MEDIUM]

**File:** `internal/pkg/processor/tls_keylog_writer.go`

The `writtenKeys` map (line 68) grows unboundedly while `keyStore` has cleanup.

- [ ] Add periodic cleanup for writtenKeys
  - Option A: Use same TTL-based cleanup as keyStore
  - Option B: Convert to bounded LRU cache (e.g., `github.com/hashicorp/golang-lru`)
  - Keep at most `MaxEntries` keys (default 10000)

- [ ] Add cleanup goroutine or piggyback on keyStore cleanup
  - Track insertion time per key
  - Remove keys older than SessionTTL during periodic cleanup

### Issue #9: X1 Error Response Missing Details [LOW-MEDIUM]

**File:** `internal/pkg/li/x1/server.go`

The `buildErrorResponse()` function (lines 1105-1132) logs error details but returns empty response without error code/description.

- [ ] Include error details in X1 response per ETSI spec
  - Modify return type to use `schema.ErrorResponse` instead of base `X1ResponseMessage`
  - Populate `ErrorCode` and `ErrorDescription` fields
  - Update response marshaling to include error elements

---

## Medium-Term Priority (Next Quarter)

### Issue #3: CallIDDetector Race Condition [MEDIUM]

**File:** `internal/pkg/voip/tcp_stream.go`

Small TOCTOU window in `SetCallID()` (lines 53-78) between atomic load and channel close.

- [ ] Move channel operations fully under mutex
  - Remove redundant atomic check inside mutex (line 68)
  - Set `closed` flag within the same mutex-protected block
  - Or use single atomic CAS for the entire close operation

```go
func (c *CallIDDetector) SetCallID(id string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.closed == 1 || c.set {
        return
    }

    c.callID = id
    c.set = true

    select {
    case c.detected <- id:
        close(c.detected)
    default:
    }
}
```

- [ ] Add race detector test
  - Create test that spawns multiple goroutines calling SetCallID and Close concurrently
  - Run with `-race` flag

### Issue #7: Context Propagation in Delivery Client [MEDIUM]

**File:** `internal/pkg/li/delivery/client.go`

The `sendSync()` method (line 529) accepts context but doesn't pass it to `GetConnection()` (line 542).

- [ ] Add context parameter to GetConnection
  - Update `Manager.GetConnection(ctx, did)` signature
  - Use context for connection establishment timeout
  - Propagate cancellation

- [ ] Update all call sites to pass context

### Test Coverage Improvements [MEDIUM]

**Packages:** remotecapture (28.2%), downstream (32.6%), source (36.4%)

- [ ] Add tests for `internal/pkg/remotecapture`
  - Test EventHandler callbacks
  - Test reconnection logic
  - Test error handling

- [ ] Add tests for `internal/pkg/processor/downstream`
  - Test processor hierarchy communication
  - Test flow control

- [ ] Add integration tests for hunter-processor communication
  - Use in-memory gRPC server
  - Test packet forwarding and acknowledgment

---

## Checklist Summary

**Immediate (2 tasks):**
- [ ] Fix command injection (#1)
- [ ] Fix build constraints (#2)

**Short-Term (4 tasks):**
- [ ] Add X1 rate limiting (#4)
- [ ] Fix subscriber channel leak (#11)
- [ ] Add writtenKeys cleanup (#8)
- [ ] Include X1 error details (#9)

**Medium-Term (4 tasks):**
- [ ] Fix CallIDDetector race (#3)
- [ ] Propagate context in delivery (#7)
- [ ] Improve test coverage
- [ ] Add integration tests
