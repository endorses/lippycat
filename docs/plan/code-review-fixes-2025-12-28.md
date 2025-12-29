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
- [x] Review `internal/pkg/voip/call_aggregator.go:217-220`
- [ ] ~~Option A: Implement reference counting for CallInfo~~ (not needed, Option B already implemented)
- [x] Option B: Return copies instead of pointers from GetCall() (already implemented via `deepCopyCall()`)
- [x] Add test for concurrent access during eviction (`TestCallAggregator_RingBufferEvictionRace`)

### 9. Extract shared packet converter
- [x] Create `internal/pkg/capture/converter_shared.go`
- [x] Extract common logic from:
  - `internal/pkg/tui/bridge.go`
  - `internal/pkg/remotecapture/client_conversion.go`
  - `internal/pkg/capture/converter.go`
- [x] Refactor all three to use shared implementation
- [x] Actual reduction: ~550 lines (converter.go: 137→13, client_conversion.go: 697→476, bridge.go: 996→745)

---

## Phase 2: Medium Priority (Error Handling & Observability)

### 10. Address incomplete TODOs
- [x] Review each TODO and either implement or create GitHub issue:
  - [x] `processor_grpc_handlers.go:1008` - BPF filtering (implemented in `bpf_filter.go`)
  - [x] `processor_li.go:97` - X2/X3 encoding (implemented using x2x3 encoders)
  - [x] `downstream/manager.go:133` - TLS credentials (uses `tlsutil.BuildClientCredentials`)
  - [x] `hunter/connection/manager.go:439` - Hardcoded version (uses `version.GetVersion()`)
  - [x] `voip/simd.go:151` - SIMD assembly (implemented in `simd_amd64.s`)

### 11. Fix PCAP sync error handling
- [x] Update `internal/pkg/processor/pcap_writer.go:357-360`
- [x] Log sync errors instead of ignoring
- [x] Added `syncErrors` counter to `CallPcapWriter` struct
- [x] Include sync error count in close log message

### 12. Fix virtual interface injection log level
- [x] Update `internal/pkg/processor/processor_packet_pipeline.go:208-209`
- [x] Change `logger.Debug` to `logger.Warn`
- [x] Add `vifInjectionErrors` atomic counter to Processor struct

### 13. Refactor global capture state
- [x] Review `internal/pkg/tui/model.go:29-32`
- [x] Move globals into struct with proper synchronization
- [x] Pass state through function parameters or use context
- Created `capture_state.go` with `CaptureState` struct using `sync.RWMutex`
- Provides thread-safe access via `globalCaptureState` singleton
- Updated `capture_lifecycle.go`, `capture_events.go`, `exports.go` to use CaptureState
- Removed raw global variables from `model.go`

### 14. Fix TCP stream cleanup silent drops
- [x] Update `internal/pkg/voip/tcp_factory.go:206-239`
- [x] Log when valid streams are dropped during cleanup
- [x] Consider using temporary buffer during cleanup
- Implemented temporary buffer to hold valid streams during cleanup
- Separate tracking of stale vs valid dropped streams
- Warning log when valid streams are dropped due to queue capacity
- Debug log for normal stale stream cleanup

### 15. Add explicit TLS cipher configuration
- [x] Update TLS configs in `internal/pkg/tlsutil/`
- [x] Set `MinVersion: tls.VersionTLS12` (or TLS13)
- [x] Explicitly configure strong cipher suites
- `tlsutil.go`: TLS 1.3 minimum (cipher suites fixed automatically, added documentation)
- `li/x1/server.go`: TLS 1.2 minimum + explicit AEAD cipher suites
- `li/x1/client.go`: TLS 1.2 minimum + explicit AEAD cipher suites
- `li/delivery/destination.go`: Already configured with explicit cipher suites

### 16. Statistics counter bounds (Low risk, skip if needed)
- [x] Review `internal/pkg/tui/model.go:187-193`
- [x] Consider if uint64 overflow is a real concern (probably not)
- Changed `TotalPackets` from `int` to `int64` in Statistics struct
- Changed `TotalPackets` and `MatchedPackets` from `int` to `int64` in PacketStore
- Changed `BoundedCounter.counts` from `map[string]int` to `map[string]int64`
- Ensures consistent behavior across 32-bit and 64-bit platforms

---

## Phase 3: Low Priority (Code Quality)

### 17. Improve error handling in Close operations
- [x] Audit `defer Close()` patterns in critical paths
- [x] Add error logging for PCAP writers, gRPC connections
- Added logger import and error logging to `internal/pkg/remotecapture/client.go:Close()`
- Added error logging for file Close() operations in `internal/pkg/voip/encryption.go:DecryptPCAPFile()`
- Existing good patterns found: `internal/pkg/processor/pcap_writer.go`, `internal/pkg/hunter/connection/manager.go`

### 18. Extract magic numbers to constants
- [x] Create constants file or add to existing configs
- [x] Document purpose of each constant
- Added pool size class constants to `voip/constants.go` (128B-64KB with documentation)
- Added pool config constants (PoolDefaultInitialSize, PoolDefaultMaxSize, etc.)
- Added security validation constants (MaxCallIDLength, MaxContentLengthDigits)
- Added PCAP writer constants to `constants/constants.go` (DefaultPCAPMaxFileSize, etc.)
- Added forwarding constants (MaxConsecutiveSendFailures, DefaultSendTimeout)
- Updated pools.go to use PoolSizeClass* and PoolDefault* constants
- Updated security.go to use MaxCallIDLength and MaxContentLengthDigits constants
- Updated pcap_writer.go and auto_rotate_pcap.go to use DefaultPCAP* constants
- Updated forwarding/manager.go to use constants.MaxConsecutiveSendFailures

### 19. Improve test coverage
- [x] Add `-tags all` note to CI documentation
- [x] Focus on `hunter/connection` package (0.3% coverage)
- [x] Add fuzz tests for SIP parsing

### 20. Optimize sync.Pool usage
- [x] Review `internal/pkg/tui/bridge.go` and `internal/pkg/voip/pools.go`
- [x] Ensure objects are reset before returning to pool
- Fixed `CallInfoPool.Put()` to reset `EndTime` field before returning to pool
- Removed unused `packetDisplayPool` and `byteBufferPool` from `bridge.go` (memory leak - buffers never returned)
- Simplified `convertPacket()` to use direct allocation instead of leaking pool

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
