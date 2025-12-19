# CLI Filter Management Implementation Plan

**Date:** 2025-12-19
**Status:** In Progress (Phase 2 complete)
**Research:** `docs/research/cli-filter-management.md`

## Overview

Implement CLI commands for remote filter management via gRPC, enabling automation and scripting of filter operations on processor nodes.

**Commands:**
- `lc list filters` - List all filters
- `lc show filter --id <id>` - Show single filter
- `lc set filter` - Create/update filter (upsert)
- `lc rm filter --id <id>` - Delete filter

## Phase 1: Shared Filter Package

Extract filter types and parsing from processor to shared package.

### Step 1.1: Create `internal/pkg/filtering/` package

- [x] Create `types.go` - FilterConfig, FilterYAML structs
- [x] Create `parser.go` - ParseFile(), WriteFile()
- [x] Create `validation.go` - ValidateFilter(), ValidateFilterType()
- [x] Create `conversion.go` - YAMLToProto(), ProtoToYAML(), ProtoToJSON()
- [x] Add unit tests for all functions

### Step 1.2: Migrate processor filtering

- [x] Update `internal/pkg/processor/filtering/persistence.go` to import shared package
- [x] Remove duplicated types
- [x] Verify processor still works with existing tests

## Phase 2: Filter Client Package

Create gRPC client for CLI filter operations.

### Step 2.1: Create `internal/pkg/filterclient/` package

- [x] Create `client.go`:
  ```go
  type ClientConfig struct {
      Address     string
      TLSEnabled  bool
      TLSCAFile   string
      TLSCertFile string
      TLSKeyFile  string
      TLSSkipVerify bool
  }

  type FilterClient struct { ... }
  func NewFilterClient(config ClientConfig) (*FilterClient, error)
  func (c *FilterClient) Close() error
  ```

- [x] Create `operations.go`:
  ```go
  func (c *FilterClient) List(opts ListOptions) ([]*management.Filter, error)
  func (c *FilterClient) Get(id string) (*management.Filter, error)
  func (c *FilterClient) Set(filter *management.Filter) (*management.FilterUpdateResult, error)
  func (c *FilterClient) Delete(id string) (*management.FilterUpdateResult, error)
  ```

- [x] Create `batch.go`:
  ```go
  func (c *FilterClient) SetBatch(filters []*management.Filter) (*BatchResult, error)
  func (c *FilterClient) DeleteBatch(ids []string) (*BatchResult, error)
  ```

- [x] Add unit tests with mock gRPC server

## Phase 3: CLI Commands

Implement filter management commands with build tags `cli || all`.

### Step 3.1: Create verb parent commands

- [ ] Create `cmd/set/set.go` - `lc set` parent command
- [ ] Create `cmd/rm/rm.go` - `lc rm` parent command
- [ ] Update `cmd/list/list.go` - add filters subcommand hook
- [ ] Update `cmd/show/show.go` - add filter subcommand hook

### Step 3.2: Create filter subcommands

- [ ] Create `cmd/filter/filter.go` - shared flags (--processor, --tls-*)
- [ ] Create `cmd/filter/list.go` - `lc list filters`
- [ ] Create `cmd/filter/show.go` - `lc show filter`
- [ ] Create `cmd/filter/set.go` - `lc set filter`
- [ ] Create `cmd/filter/rm.go` - `lc rm filter`

### Step 3.3: Wire up commands

- [ ] Update `cmd/root_all.go` - register set, rm commands
- [ ] Update `cmd/root_cli.go` - register set, rm commands
- [ ] Add config file support for `remote.processor` and `remote.tls.*`

## Phase 4: Integration Tests

### Step 4.1: Add integration tests

- [ ] Create `test/filter_cli_integration_test.go`
- [ ] Test list, show, set, rm operations
- [ ] Test batch operations with --file
- [ ] Test TLS connections
- [ ] Test error handling and JSON error output

## File Structure

```
internal/pkg/filtering/           # NEW - shared filter types
├── types.go
├── parser.go
├── parser_test.go
├── validation.go
├── validation_test.go
├── conversion.go
└── conversion_test.go

internal/pkg/filterclient/        # NEW - gRPC client
├── client.go
├── client_test.go
├── operations.go
├── operations_test.go
├── batch.go
└── batch_test.go

cmd/filter/                       # NEW - filter subcommands
├── filter.go                     # //go:build cli || all
├── list.go
├── show.go
├── set.go
└── rm.go

cmd/set/                          # NEW - set verb
└── set.go                        # //go:build cli || all

cmd/rm/                           # NEW - rm verb
└── rm.go                         # //go:build cli || all
```

## Output Format

All commands output JSON to stdout:
```json
{"id": "abc123", "success": true, "hunters_updated": ["hunter-1"]}
```

Errors output JSON to stderr:
```json
{"error": "connection refused", "code": "UNAVAILABLE"}
```

Exit codes: 0=success, 1=general error, 2=connection error, 3=validation error

## Dependencies

- Phase 2 depends on Phase 1 (needs shared types)
- Phase 3 depends on Phase 2 (needs client package)
- Phase 4 can run after Phase 3

## Notes

- JSON output only (no --output table) - use TUI for human interaction
- Batch operations are best-effort, not atomic
- Single-level processor support initially (multi-level via --processor-chain future)
- ID auto-generated (UUID) if not provided on `lc set filter`
