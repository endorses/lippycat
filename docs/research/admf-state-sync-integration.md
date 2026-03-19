# ADMF State Synchronization Integration for lippycat

## Date: 2026-03-18

## Problem

When lippycat restarts, all in-memory task and destination state is lost. Therefore, lippycat should actively query the ADMF for current state on startup using the standard `GetAllDetails` operation, which is defined in the specification for exactly this purpose.

Additionally, periodic reconciliation would guard against configuration drift between lippycat and the ADMF over long uptimes.

## Current State

### What lippycat implements today

**X1 Client (NE → ADMF)** — notification-only:
- `KeepaliveRequest` — periodic heartbeat
- `ReportTaskIssueRequest` — task errors, progress, implicit deactivation
- `ReportDestinationIssueRequest` — delivery errors, recovery, connection status
- `ReportNEIssueRequest` — startup, shutdown, warnings, errors

**X1 Server (ADMF → NE)** — full admin interface:
- `ActivateTask`, `ModifyTask`, `DeactivateTask`, `DeactivateAllTasks`
- `CreateDestination`, `ModifyDestination`, `RemoveDestination`
- `GetTaskDetails`, `GetDestinationDetails`, `GetNEStatus`
- `GetAllDetails` (returns tasks + destinations + NE status)
- `Ping`

**Missing from X1 Client:**
- `GetAllDetailsRequest` — query all tasks, destinations, NE status from ADMF
- `GetAllTaskDetailsRequest` — query all tasks from ADMF
- Any response parsing (current client is fire-and-forget for notifications)

### ETSI TS 103 221-1 operations involved

Both operations are defined in the ETSI TS 103 221-1 XSD schema:
- `GetAllDetailsRequest` → returns NE status + all tasks + all destinations + generic objects
- `GetAllTaskDetailsRequest` → returns all tasks only

Per the specification, the ADMF should return the subset of tasks assigned to the requesting NE (identified by `neIdentifier`).

### Schema types already defined

lippycat already has Go types for the query operations in `internal/pkg/li/x1/schema/x1.go`:

```go
// Line 497-500
type GetAllDetailsRequest struct {
    *X1RequestMessage
}

// Line 502-509
type GetAllDetailsResponse struct {
    NeStatusDetails                    *NeStatusDetails
    ListOfTaskResponseDetails          *ListOfTaskResponseDetails
    ListOfDestinationResponseDetails   *ListOfDestinationResponseDetails
    ListOfGenericObjectResponseDetails *ListOfGenericObjectResponseDetails
    *X1ResponseMessage
}

// Line 539-542
type GetAllTaskDetailsRequest struct {
    *X1RequestMessage
}

// Line 544-548
type GetAllTaskDetailsResponse struct {
    ListOfTaskResponseDetails *ListOfTaskResponseDetails
    *X1ResponseMessage
}
```

The response types reference `TaskResponseDetails` (line 424-428) and `TaskDetails` (line 102-115), which include XID, targets, delivery type, destination IDs, and all other task parameters needed to reconstruct state.

## What Needs to Be Implemented

### 1. X1 Client Response Parsing

**File:** `internal/pkg/li/x1/client.go`

The current `sendRequest()` method (line 648-694) sends XML via HTTP POST and only checks the HTTP status code — it discards the response body entirely. For query operations, we need to parse the XML response.

**Changes needed:**

- [ ] Add a `sendQueryRequest()` method that marshals the request, sends it, reads the response body, and unmarshals the XML response into the appropriate Go type
- [ ] Parse `ResponseContainer` with embedded `X1ResponseMessage` array
- [ ] Handle `ErrorResponse` — check if the response message is an error (has `errorInformation` set) and return a typed error
- [ ] Handle HTTP error status codes with response body for diagnostics

**Design consideration:** The existing `sendRequestWithRetry()` can be reused for retry logic. The new method needs a generic approach since different queries return different response types.

Suggested signature:
```go
func (c *Client) sendQueryRequest(ctx context.Context, rootElement string, req any, resp any) error
```

Where `resp` is a pointer to the expected response type, populated by XML unmarshaling.

### 2. GetAllDetails Client Method

**File:** `internal/pkg/li/x1/client.go`

- [ ] Add `GetAllDetails(ctx) (*schema.GetAllDetailsResponse, error)` method
- [ ] Builds `GetAllDetailsRequest` with `buildRequestMessage()`
- [ ] Calls `sendQueryRequest()` with the request
- [ ] Returns parsed `GetAllDetailsResponse` containing tasks, destinations, NE status

### 3. GetAllTaskDetails Client Method

**File:** `internal/pkg/li/x1/client.go`

- [ ] Add `GetAllTaskDetails(ctx) (*schema.GetAllTaskDetailsResponse, error)` method
- [ ] Same pattern as above but returns only task details

### 4. Startup State Synchronization in Manager

**File:** `internal/pkg/li/manager.go`

The current `Start()` method (approximately line 280-330):
1. Starts X1 server
2. Starts X1 client keepalive
3. Starts registry expiration checker
4. Sends startup notification to ADMF
5. Sets packet processor callback

**Changes needed:**

- [ ] After startup notification, call `syncStateFromADMF()`
- [ ] `syncStateFromADMF()` should:
  1. Call `x1Client.GetAllDetails(ctx)` to fetch all tasks and destinations
  2. For each destination in response: call `registry.CreateDestination()` to register MDF endpoints
  3. For each task in response: convert `TaskResponseDetails` → `InterceptTask`, call `ActivateTask()` to register and create filters
  4. Log summary: "State sync complete: N tasks, M destinations restored"
- [ ] Handle failure gracefully — log error and continue (lippycat should still start even if ADMF is unreachable; the ADMF can push state later via `ActivateTask`)
- [ ] Add a configurable flag `--li-admf-sync-on-startup` (default: true) to enable/disable

### 5. Response Type Conversion

**New file:** `internal/pkg/li/x1/convert.go` (suggested)

Convert X1 response types to internal lippycat types:

- [ ] `TaskResponseDetailsToInterceptTask(*schema.TaskResponseDetails) (*li.InterceptTask, error)`
  - Map `TaskDetails.XId` → `InterceptTask.XID`
  - Map `TaskDetails.TargetIdentifiers` → `[]TargetIdentity` (iterate `TargetIdentifier` CHOICE fields)
  - Map `TaskDetails.ListOfDIDs` → `[]uuid.UUID`
  - Map `TaskDetails.DeliveryType` → `li.DeliveryType`
  - Map `TaskDetails.ImplicitDeactivationAllowed` → bool
  - Handle optional fields (StartTime, EndTime, ProductID)

- [ ] `DestinationResponseDetailsToDestination(*schema.DestinationResponseDetails) (*li.Destination, error)`
  - Map DID, address, port, TLS config, X2/X3 enabled flags

### 6. X1 Client XML Response Handling

**Important implementation detail:** The current client sends requests with a `rootElement` parameter that becomes the XML root tag name (e.g., `"keepaliveRequest"`, `"reportTaskIssueRequest"`). For query requests, the root element should be `"GetAllDetailsRequest"` or `"GetAllTaskDetailsRequest"`.

For receiving responses, the client needs to handle the standard ETSI TS 103 221-1 response format. Per the specification, responses are wrapped in `<X1Response>` (a `ResponseContainer`), so unmarshaling should target `ResponseContainer` first, then extract the specific response message from the `X1ResponseMessage` array.

**Expected response format per ETSI TS 103 221-1:**
```xml
<X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">
  <x1ResponseMessage xsi:type="GetAllDetailsResponse">
    <neStatusDetails>...</neStatusDetails>
    <listOfTaskResponseDetails>
      <taskResponseDetails>
        <taskDetails>
          <xId>...</xId>
          <targetIdentifiers>...</targetIdentifiers>
          <deliveryType>X2andX3</deliveryType>
          <listOfDIDs><dId>...</dId></listOfDIDs>
        </taskDetails>
        <taskStatus>
          <provisioningStatus>complete</provisioningStatus>
        </taskStatus>
      </taskResponseDetails>
    </listOfTaskResponseDetails>
    <listOfDestinationResponseDetails>...</listOfDestinationResponseDetails>
  </x1ResponseMessage>
</X1Response>
```

**Namespace consideration:** ADMF implementations using XML libraries that produce namespace-qualified output (e.g., Python xsdata, Java JAXB) will include the ETSI namespace (`http://uri.etsi.org/03221/X1/2017/10`) on elements. The Go `encoding/xml` decoder needs to handle this. The existing schema types may need XML namespace annotations added to their struct tags (e.g., `xml:"http://uri.etsi.org/03221/X1/2017/10 neStatusDetails"`). Testing against a real ADMF will confirm what adjustments are needed.

### 7. Periodic Reconciliation (Optional Enhancement)

- [ ] Add a configurable reconciliation interval (`--li-admf-reconcile-interval`, default: 0 = disabled)
- [ ] Background goroutine that periodically calls `GetAllDetails` and compares with registry state
- [ ] Log discrepancies (missing tasks, extra tasks, mismatched parameters)
- [ ] Optionally auto-correct by activating missing tasks and deactivating extras

### 8. Configuration Changes

**File:** `cmd/process/flags_li.go`

New flags needed:
- [ ] `--li-admf-sync-on-startup` (bool, default: true) — Enable state sync on startup
- [ ] `--li-admf-sync-timeout` (duration, default: 30s) — Timeout for initial state sync
- [ ] `--li-admf-reconcile-interval` (duration, default: 0) — Periodic reconciliation interval (0 = disabled)

**File:** `internal/pkg/li/manager.go` — ManagerConfig additions:
```go
type ManagerConfig struct {
    // ... existing fields ...
    SyncOnStartup      bool          // Query ADMF for state on startup
    SyncTimeout        time.Duration // Timeout for startup sync
    ReconcileInterval  time.Duration // Periodic reconciliation (0 = disabled)
}
```

## ADMF-Side Considerations

### NE Task Assignment

Per ETSI TS 103 221-1, when lippycat sends a `GetAllDetailsRequest`, the ADMF returns the tasks assigned to the requesting `neIdentifier`. This means tasks must be associated with lippycat's NE identifier in the ADMF for them to be included in the response. ADMF implementations typically establish this association when tasks are activated via the ADMF management API.

### Error Handling

If the ADMF returns an `ErrorResponse` (e.g., NE not recognized, unsupported operation), the startup sync should handle this gracefully:
- Log the error with full details
- Continue startup without pre-loaded state
- The ADMF can push tasks later via `ActivateTask`

### Compatibility

Not all ADMF implementations support `GetAllDetailsRequest` or `GetAllTaskDetailsRequest`. The startup sync should treat an `UnsupportedOperation` error response the same as an unreachable ADMF — log a warning and continue. This ensures lippycat remains compatible with minimal ADMF implementations that only push state via `ActivateTask`.

## Testing Strategy

- [ ] Unit tests for `GetAllDetails()` and `GetAllTaskDetails()` client methods with httptest mock server
- [ ] Unit tests for response parsing including error responses and `UnsupportedOperation`
- [ ] Unit tests for `TaskResponseDetailsToInterceptTask` conversion
- [ ] Integration test for full startup sync flow: Manager.Start() → GetAllDetails → tasks activated
- [ ] Integration test for reconciliation detecting drift
- [ ] Test with empty response (no tasks) — should succeed without errors
- [ ] Test with ADMF unreachable — should timeout and continue startup
- [ ] Test with ADMF returning `ErrorResponse` — should log and continue

## Implementation Order

1. **Phase 1: Response parsing** — Add `sendQueryRequest()` to X1 client
2. **Phase 2: Query methods** — Add `GetAllDetails()` and `GetAllTaskDetails()`
3. **Phase 3: Type conversion** — `TaskResponseDetails` → `InterceptTask` mapping
4. **Phase 4: Startup sync** — Wire into `Manager.Start()`
5. **Phase 5: Configuration** — Add CLI flags and config file support
6. **Phase 6: Tests** — Full test coverage
7. **Phase 7: Reconciliation** — Optional periodic sync (if needed)

## Files to Modify

| File | Change |
|------|--------|
| `internal/pkg/li/x1/client.go` | Add `sendQueryRequest()`, `GetAllDetails()`, `GetAllTaskDetails()` |
| `internal/pkg/li/x1/convert.go` | New file: response type → internal type conversion |
| `internal/pkg/li/x1/client_test.go` | Tests for new query methods |
| `internal/pkg/li/x1/convert_test.go` | Tests for type conversion |
| `internal/pkg/li/manager.go` | Add `syncStateFromADMF()`, update `Start()` |
| `internal/pkg/li/manager_test.go` | Tests for startup sync |
| `internal/pkg/li/types.go` | Add `SyncOnStartup`, `SyncTimeout`, `ReconcileInterval` to ManagerConfig |
| `cmd/process/flags_li.go` | Add new CLI flags |
| `internal/pkg/li/CLAUDE.md` | Update documentation |

## Estimated Scope

- ~300 lines new Go code (client methods, conversion, manager changes)
- ~400 lines new test code
- ~50 lines config/flag changes
- No changes to existing schema types (already defined)
- No changes to X1 server (only client-side additions)
