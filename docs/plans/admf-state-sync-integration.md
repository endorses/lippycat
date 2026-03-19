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

- [x] Add `GetAllDetails(ctx context.Context) (*schema.GetAllDetailsResponse, error)`
  - Build `GetAllDetailsRequest` using `buildRequestMessage()`
  - Call `sendQueryRequest()` with root element `"GetAllDetailsRequest"`
  - Return parsed `GetAllDetailsResponse`
- [x] Add `GetAllTaskDetails(ctx context.Context) (*schema.GetAllTaskDetailsResponse, error)`
  - Same pattern, root element `"GetAllTaskDetailsRequest"`

## Phase 3: Response Type Conversion

**New file:** `internal/pkg/li/convert.go` (in `li` package to avoid circular dependency)

Convert ETSI X1 response types to internal lippycat types.

- [x] `TaskResponseDetailsToInterceptTask(details *schema.TaskResponseDetails) (*InterceptTask, error)`
  - Map `TaskDetails.XId` → `InterceptTask.XID`
  - Map `TaskDetails.TargetIdentifiers` → `[]TargetIdentity` (iterate CHOICE fields: SipUri, TelUri, E164Number, Ipv4Address, etc.)
  - Map `TaskDetails.ListOfDIDs` → `[]uuid.UUID`
  - Map `TaskDetails.DeliveryType` → `DeliveryType`
  - Map `TaskDetails.ImplicitDeactivationAllowed` → bool
  - Handle optional fields (StartTime, EndTime, ProductID)
- [x] `DestinationResponseDetailsToDestination(details *schema.DestinationResponseDetails) (*Destination, error)`
  - Map DID, address, port, TLS config, X2/X3 enabled flags

**New file:** `internal/pkg/li/convert_test.go`

- [x] Test conversion of fully populated task response
- [x] Test conversion with minimal/missing optional fields
- [x] Test each target identifier type maps correctly
- [x] Test destination conversion

## Phase 4: Configuration

### ManagerConfig

**File:** `internal/pkg/li/manager.go` (ManagerConfig, line 37)

- [x] Add `SyncOnStartup bool` (default: true) — query ADMF for state on startup
- [x] Add `SyncTimeout time.Duration` (default: 30s) — timeout for startup sync
- [x] Add `ReconcileInterval time.Duration` (default: 0) — periodic reconciliation (0 = disabled)

**File:** `internal/pkg/li/manager_stub.go` (stub ManagerConfig, line 23)

- [x] Add matching fields to stub config (values ignored but needed for compilation)

### CLI Flags

**File:** `cmd/process/flags_li.go` and `cmd/tap/flags_li.go`

- [x] Add `--li-admf-sync-on-startup` flag (bool, default: true)
- [x] Add `--li-admf-sync-timeout` flag (duration, default: 30s)
- [x] Add `--li-admf-reconcile-interval` flag (duration, default: 0)
- [x] Bind flags to viper and wire into `GetLIConfig()` → `ManagerConfig`

## Phase 5: Startup State Sync

**File:** `internal/pkg/li/manager.go`

- [x] Add `syncStateFromADMF(ctx context.Context) error` method on Manager
  1. Call `x1Client.GetAllDetails(ctx)` to fetch tasks and destinations
  2. For each destination in response: call `registry.CreateDestination()` to register MDF endpoints
  3. For each task in response: convert via `TaskResponseDetailsToInterceptTask()`, call `ActivateTask()` to register and create filters
  4. Log summary: "State sync complete: N tasks, M destinations restored"
  5. Handle `UnsupportedOperation` error — log warning and continue (ADMF may not support this operation)
- [x] Update `Start()` method: after startup notification goroutine, call `syncStateFromADMF()` if `config.SyncOnStartup` is true and `x1Client` is configured
  - Run with `SyncTimeout` context
  - On failure: log error and continue (lippycat must still start even if ADMF is unreachable)

## Phase 6: Periodic Reconciliation (Optional)

**File:** `internal/pkg/li/manager.go`

- [x] Add `startReconciliation()` method — background goroutine on `ReconcileInterval` ticker
  - Call `GetAllDetails()` and compare with registry state
  - Log discrepancies: missing tasks, extra tasks, mismatched parameters
  - Auto-activate missing tasks; log-only for tasks present locally but not in ADMF
- [x] Start in `Start()` if `ReconcileInterval > 0`
- [x] Stop in `Stop()` via `stopChan` close

## Phase 7: Tests

All tests implemented inline with their respective phases.

**File:** `internal/pkg/li/x1/client_test.go` (Phases 1-2)

- [x] Test `GetAllDetails()` with httptest mock server returning valid XML response
- [x] Test `GetAllTaskDetails()` with httptest mock server
- [x] Test response parsing with `ErrorResponse` (error code + message)
- [x] Test response parsing with `UnsupportedOperation` error
- [x] Test with empty response (no tasks/destinations)
- [x] Test with HTTP error status codes

**File:** `internal/pkg/li/manager_test.go` (Phase 5-6)

- [x] Test `syncStateFromADMF()` — full flow: GetAllDetails → destinations created → tasks activated
- [x] Test startup sync with ADMF unreachable — should timeout and continue
- [x] Test startup sync with ADMF returning error — should log and continue
- [x] Test startup sync disabled (`SyncOnStartup: false`) — should skip entirely
- [x] Test partial failure — some tasks fail, others succeed

## Files Summary

| File | Change |
|------|--------|
| `internal/pkg/li/x1/client.go` | `sendQueryRequest()`, `GetAllDetails()`, `GetAllTaskDetails()` |
| `internal/pkg/li/convert.go` | **New** — response type → internal type conversion |
| `internal/pkg/li/convert_test.go` | **New** — conversion tests |
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
