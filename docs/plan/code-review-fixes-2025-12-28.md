# Code Review Fixes Plan

**Source:** [CODE_REVIEW_2025-12-28.md](../review/CODE_REVIEW_2025-12-28.md)
**Created:** 2025-12-28

---

## Phase 1: High Priority (Security & Concurrency)

### 1. Fix GetSecurityConfig race condition
- [x] Replace double-checked locking with `sync.Once` in `internal/pkg/voip/security.go:55-66`
```go
var securityConfigOnce sync.Once

func GetSecurityConfig() *SecurityConfig {
    securityConfigOnce.Do(initSecurityConfig)
    return securityConfig
}
```

### 2. Fix methodRoles mapping in auth interceptor
- [x] Audit `internal/pkg/auth/interceptor.go:12-28`
- [x] Compare method names against `api/proto/*.proto` service definitions
- [x] Align method names with actual gRPC service paths

### 3. Implement or remove GenerateAPIKey
- [x] Implement in `internal/pkg/auth/validator.go:151-160`:
```go
func GenerateAPIKey() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("generate random bytes: %w", err)
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

### 4. Fix LockFreeCallInfo snapshot writer sharing
- [x] Modify `internal/pkg/voip/lockfree_calltracker.go:337-355`
- [x] Nil out SIPWriter and RTPWriter in snapshots (read-only semantics)
```go
snapshot := &CallInfo{
    // ... other fields
    SIPWriter: nil,  // Snapshots are read-only
    RTPWriter: nil,
}
```

### 5. Add rate limiting to authentication
- [x] Add rate limiter to `internal/pkg/auth/interceptor.go`
- [x] Track failed attempts per client IP with TTL
- [x] Block after 5 failures in 60 seconds
- [x] Consider using `golang.org/x/time/rate` or simple map with cleanup

### 6. Migrate RSA PKCS1v15 to PSS
- [x] Update `internal/pkg/processor/proxy/auth.go:148`
- [x] Change `rsa.SignPKCS1v15` to `rsa.SignPSS`
- [x] Update verification to use `rsa.VerifyPSS`
- [x] Document breaking change in CHANGELOG

### 7. Fix SIPStream goroutine leak
- [x] Modify `internal/pkg/voip/tcp_stream.go`
- [x] Implement `safeReader` wrapper using `io.Pipe` to decouple tcpreader from consumer
- [x] Ensure context cancellation interrupts blocked readers (pipe close unblocks consumer reads)

### 8. Fix CallAggregator ring buffer race
- [ ] Review `internal/pkg/voip/call_aggregator.go:217-220`
- [ ] Option A: Implement reference counting for CallInfo
- [ ] Option B: Return copies instead of pointers from GetCall()
- [ ] Add test for concurrent access during eviction

### 9. Extract shared packet converter
- [ ] Create `internal/pkg/capture/converter_shared.go`
- [ ] Extract common logic from:
  - `internal/pkg/tui/bridge.go`
  - `internal/pkg/remotecapture/client_conversion.go`
  - `internal/pkg/capture/converter.go`
- [ ] Refactor all three to use shared implementation
- [ ] Estimated reduction: ~1,200 lines

---

## Phase 2: Medium Priority (Error Handling & Observability)

### 10. Address incomplete TODOs
- [ ] Review each TODO and either implement or create GitHub issue:
  - `processor_grpc_handlers.go:1008` - BPF filtering
  - `processor_li.go:97` - X2/X3 encoding
  - `downstream/manager.go:133` - TLS credentials
  - `hunter/connection/manager.go:439` - Hardcoded version
  - `voip/simd.go:151` - SIMD assembly

### 11. Fix PCAP sync error handling
- [ ] Update `internal/pkg/processor/pcap_writer.go:357-360`
- [ ] Log sync errors instead of ignoring:
```go
if err := writer.sipFile.Sync(); err != nil {
    logger.Warn("Failed to sync SIP PCAP", "error", err, "call_id", writer.callID)
    writer.statsCollector.IncrementSyncErrors()
}
```

### 12. Fix virtual interface injection log level
- [ ] Update `internal/pkg/processor/processor_packet_pipeline.go:208-209`
- [ ] Change `logger.Debug` to `logger.Warn`
- [ ] Add injection failure counter to stats

### 13. Refactor global capture state
- [ ] Review `internal/pkg/tui/model.go:29-32`
- [ ] Move globals into struct with proper synchronization
- [ ] Pass state through function parameters or use context

### 14. Fix TCP stream cleanup silent drops
- [ ] Update `internal/pkg/voip/tcp_factory.go:206-239`
- [ ] Log when valid streams are dropped during cleanup
- [ ] Consider using temporary buffer during cleanup

### 15. Add explicit TLS cipher configuration
- [ ] Update TLS configs in `internal/pkg/tlsutil/`
- [ ] Set `MinVersion: tls.VersionTLS12` (or TLS13)
- [ ] Explicitly configure strong cipher suites

### 16. Statistics counter bounds (Low risk, skip if needed)
- [ ] Review `internal/pkg/tui/model.go:187-193`
- [ ] Consider if uint64 overflow is a real concern (probably not)

---

## Phase 3: Low Priority (Code Quality)

### 17. Improve error handling in Close operations
- [ ] Audit `defer Close()` patterns in critical paths
- [ ] Add error logging for PCAP writers, gRPC connections

### 18. Extract magic numbers to constants
- [ ] Create constants file or add to existing configs
- [ ] Document purpose of each constant

### 19. Improve test coverage
- [ ] Add `-tags all` note to CI documentation
- [ ] Focus on `hunter/connection` package (0.3% coverage)
- [ ] Add fuzz tests for SIP parsing

### 20. Optimize sync.Pool usage
- [ ] Review `internal/pkg/tui/bridge.go` and `internal/pkg/voip/pools.go`
- [ ] Ensure objects are reset before returning to pool

---

## Testing Strategy

For each fix:
1. Write failing test demonstrating the issue (if applicable)
2. Implement fix
3. Verify test passes
4. Run `go test -race -tags all ./...` for concurrency issues
5. Run benchmarks for performance-sensitive changes

---

## Commit Strategy

- Group related fixes into logical commits
- Use conventional commit format: `fix(pkg): description`
- Reference this plan in commit messages
