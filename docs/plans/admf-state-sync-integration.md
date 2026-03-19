# ADMF State Synchronization Integration

## Goal

Enable lippycat to query the ADMF for current task/destination state on startup (and optionally periodically) so that in-memory state is restored after restarts without waiting for the ADMF to re-push via `ActivateTask`.

**Research:** [docs/research/admf-state-sync-integration.md](../research/admf-state-sync-integration.md)

## Phase 1: X1 Client Response Parsing

**File:** `internal/pkg/li/x1/client.go`

The current `sendRequest()` (line 648) discards the response body after checking HTTP status. Query operations need to parse XML responses.

- [x] Add `sendQueryRequest(ctx context.Context, rootElement string, req any, resp any) error` method
  - Reuse marshaling/HTTP logic from `sendRequest()`
  - Read and unmarshal response body into `resp` (pointer to expected response type)
  - Handle `X1ResponseMessage` error responses (check `ErrorInformation` field) — return typed error
  - Handle HTTP error status codes with response body for diagnostics
  - Use `sendRequestWithRetry()` for retry logic
- [x] Add `sendQueryRequestWithRetry()` wrapper following existing retry pattern

## Phase 2: Query Methods

**File:** `internal/pkg/li/x1/client.go`

- [ ] Add `GetAllDetails(ctx context.Context) (*schema.GetAllDetailsResponse, error)`
  - Build `GetAllDetailsRequest` using `buildRequestMessage()`
  - Call `sendQueryRequest()` with root element `"GetAllDetailsRequest"`
  - Return parsed `GetAllDetailsResponse`
- [ ] Add `GetAllTaskDetails(ctx context.Context) (*schema.GetAllTaskDetailsResponse, error)`
  - Same pattern, root element `"GetAllTaskDetailsRequest"`

## Phase 3: Response Type Conversion

**New file:** `internal/pkg/li/x1/convert.go`

Convert ETSI X1 response types to internal lippycat types.

- [ ] `TaskResponseDetailsToInterceptTask(details *schema.TaskResponseDetails) (*li.InterceptTask, error)`
  - Map `TaskDetails.XId` → `InterceptTask.XID`
  - Map `TaskDetails.TargetIdentifiers` → `[]TargetIdentity` (iterate CHOICE fields: SipUri, TelUri, E164Number, Ipv4Address, etc.)
  - Map `TaskDetails.ListOfDIDs` → `[]uuid.UUID`
  - Map `TaskDetails.DeliveryType` → `li.DeliveryType`
  - Map `TaskDetails.ImplicitDeactivationAllowed` → bool
  - Handle optional fields (StartTime, EndTime, ProductID)
- [ ] `DestinationResponseDetailsToDestination(details *schema.DestinationResponseDetails) (*li.Destination, error)`
  - Map DID, address, port, TLS config, X2/X3 enabled flags

**New file:** `internal/pkg/li/x1/convert_test.go`

- [ ] Test conversion of fully populated task response
- [ ] Test conversion with minimal/missing optional fields
- [ ] Test each target identifier type maps correctly
- [ ] Test destination conversion

## Phase 4: Configuration

### ManagerConfig

**File:** `internal/pkg/li/manager.go` (ManagerConfig, line 37)

- [ ] Add `SyncOnStartup bool` (default: true) — query ADMF for state on startup
- [ ] Add `SyncTimeout time.Duration` (default: 30s) — timeout for startup sync
- [ ] Add `ReconcileInterval time.Duration` (default: 0) — periodic reconciliation (0 = disabled)

**File:** `internal/pkg/li/manager_stub.go` (stub ManagerConfig, line 23)

- [ ] Add matching fields to stub config (values ignored but needed for compilation)

### CLI Flags

**File:** `cmd/process/flags_li.go`

- [ ] Add `--li-admf-sync-on-startup` flag (bool, default: true)
- [ ] Add `--li-admf-sync-timeout` flag (duration, default: 30s)
- [ ] Add `--li-admf-reconcile-interval` flag (duration, default: 0)
- [ ] Bind flags to viper and wire into `GetLIConfig()` → `ManagerConfig`

## Phase 5: Startup State Sync

**File:** `internal/pkg/li/manager.go`

- [ ] Add `syncStateFromADMF(ctx context.Context) error` method on Manager
  1. Call `x1Client.GetAllDetails(ctx)` to fetch tasks and destinations
  2. For each destination in response: call `registry.CreateDestination()` to register MDF endpoints
  3. For each task in response: convert via `TaskResponseDetailsToInterceptTask()`, call `ActivateTask()` to register and create filters
  4. Log summary: "State sync complete: N tasks, M destinations restored"
  5. Handle `UnsupportedOperation` error — log warning and continue (ADMF may not support this operation)
- [ ] Update `Start()` method (line 213): after startup notification goroutine, call `syncStateFromADMF()` if `config.SyncOnStartup` is true and `x1Client` is configured
  - Run with `SyncTimeout` context
  - On failure: log error and continue (lippycat must still start even if ADMF is unreachable)

## Phase 6: Periodic Reconciliation (Optional)

**File:** `internal/pkg/li/manager.go`

- [ ] Add `startReconciliation()` method — background goroutine on `ReconcileInterval` ticker
  - Call `GetAllDetails()` and compare with registry state
  - Log discrepancies: missing tasks, extra tasks, mismatched parameters
  - Optionally auto-correct: activate missing tasks, deactivate extras
- [ ] Start in `Start()` if `ReconcileInterval > 0`
- [ ] Stop in `Stop()` via context cancellation

## Phase 7: Tests

**File:** `internal/pkg/li/x1/client_test.go`

- [ ] Test `GetAllDetails()` with httptest mock server returning valid XML response
- [ ] Test `GetAllTaskDetails()` with httptest mock server
- [ ] Test response parsing with `ErrorResponse` (error code + message)
- [ ] Test response parsing with `UnsupportedOperation` error
- [ ] Test with empty response (no tasks/destinations)
- [ ] Test with HTTP error status codes

**File:** `internal/pkg/li/manager_test.go`

- [ ] Test `syncStateFromADMF()` — full flow: GetAllDetails → destinations created → tasks activated
- [ ] Test startup sync with ADMF unreachable — should timeout and continue
- [ ] Test startup sync with ADMF returning error — should log and continue
- [ ] Test startup sync disabled (`SyncOnStartup: false`) — should skip entirely
- [ ] Test reconciliation detecting drift (if Phase 6 implemented)

## Files Summary

| File | Change |
|------|--------|
| `internal/pkg/li/x1/client.go` | `sendQueryRequest()`, `GetAllDetails()`, `GetAllTaskDetails()` |
| `internal/pkg/li/x1/convert.go` | **New** — response type → internal type conversion |
| `internal/pkg/li/x1/convert_test.go` | **New** — conversion tests |
| `internal/pkg/li/x1/client_test.go` | Query method tests |
| `internal/pkg/li/manager.go` | `syncStateFromADMF()`, `startReconciliation()`, ManagerConfig fields, Start() update |
| `internal/pkg/li/manager_stub.go` | Stub ManagerConfig field additions |
| `internal/pkg/li/manager_test.go` | Startup sync tests |
| `cmd/process/flags_li.go` | New CLI flags |

## Implementation Notes

- **XML namespaces:** ADMF responses may include ETSI namespace (`http://uri.etsi.org/03221/X1/2017/10`). The Go `encoding/xml` decoder may need namespace annotations on schema struct tags. Test against real ADMF to confirm.
- **Graceful degradation:** All sync failures must be non-fatal. The ADMF can always push state later via `ActivateTask`.
- **No schema changes needed:** `GetAllDetailsRequest`, `GetAllDetailsResponse`, `GetAllTaskDetailsRequest`, `GetAllTaskDetailsResponse` already exist in `internal/pkg/li/x1/schema/x1.go` (lines 497-548).
- **Estimated scope:** ~300 lines new Go code, ~400 lines tests, ~50 lines config/flags.
