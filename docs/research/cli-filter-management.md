# CLI Filter Management Research

**Date:** 2025-12-19
**Status:** Research Complete
**Related:** `docs/plan/cli-verb-object-restructure.md`

## Overview

This document captures research for implementing CLI-based filter management commands that connect to processor nodes via gRPC to perform CRUD operations on filters.

## Goals

1. **Automation-first**: JSON output by default for easy parsing in scripts
2. **Verb-object pattern**: Align with planned CLI restructure (`lc <verb> <object>`)
3. **Batch operations**: Support file-based bulk filter management
4. **Reusable components**: Abstract filter file parsing for use by both processor and CLI

## Proposed Command Structure

### Commands

| Command | Description |
|---------|-------------|
| `lc list filters` | List all filters on processor |
| `lc show filter --id <id>` | Show single filter details |
| `lc set filter` | Create or update a filter (upsert) |
| `lc rm filter --id <id>` | Delete a filter |

### Connection Flags (all commands)

```
--processor, -p    Processor address (host:port) [required unless configured]
--tls              Enable TLS encryption
--tls-ca           CA certificate file
--tls-cert         Client certificate (mTLS)
--tls-key          Client key (mTLS)
--tls-skip-verify  Skip certificate verification
```

### `lc list filters`

```bash
lc list filters -p processor:50051 \
  [--type <type>] \           # Filter by type
  [--hunter <hunter_id>] \    # Filter by target hunter
  [--enabled] \               # Only enabled filters
  [--disabled]                # Only disabled filters
```

**Output (JSON array):**
```json
[
  {
    "id": "abc123",
    "type": "sip_user",
    "pattern": "alice",
    "target_hunters": [],
    "enabled": true,
    "description": "VIP user"
  }
]
```

### `lc show filter`

```bash
lc show filter -p processor:50051 --id abc123
```

**Output (JSON object):**
```json
{
  "id": "abc123",
  "type": "sip_user",
  "pattern": "alice",
  "target_hunters": [],
  "enabled": true,
  "description": "VIP user"
}
```

### `lc set filter`

```bash
# Create new filter
lc set filter -p processor:50051 \
  --type sip_user \
  --pattern "alice" \
  [--hunters h1,h2] \         # Empty = all hunters
  [--description "VIP user"] \
  [--enabled=true]            # Default: true

# Update existing filter
lc set filter -p processor:50051 \
  --id abc123 \
  --pattern "alice*" \
  [--enabled=false]

# Batch set from file
lc set filter -p processor:50051 --file filters.yaml
```

**Output (JSON):**
```json
{
  "id": "abc123",
  "success": true,
  "hunters_updated": ["hunter-1", "hunter-2"]
}
```

**Batch output:**
```json
{
  "results": [
    {"id": "abc123", "success": true, "hunters_updated": ["hunter-1"]},
    {"id": "def456", "success": false, "error": "invalid pattern"}
  ],
  "summary": {
    "total": 2,
    "succeeded": 1,
    "failed": 1
  }
}
```

### `lc rm filter`

```bash
# Delete single filter
lc rm filter -p processor:50051 --id abc123

# Batch delete from file (by ID)
lc rm filter -p processor:50051 --file filters.yaml
```

**Output (JSON):**
```json
{
  "id": "abc123",
  "success": true,
  "hunters_updated": ["hunter-1", "hunter-2"]
}
```

### Filter Types

| Type | CLI value | Description |
|------|-----------|-------------|
| `FILTER_SIP_USER` | `sip_user` | SIP user matching (From/To headers) |
| `FILTER_PHONE_NUMBER` | `phone_number` | Phone number patterns |
| `FILTER_IP_ADDRESS` | `ip_address` | IP/CIDR matching |
| `FILTER_CALL_ID` | `call_id` | SIP Call-ID matching |
| `FILTER_CODEC` | `codec` | Codec filtering |
| `FILTER_BPF` | `bpf` | Custom BPF expressions |

## Current Architecture Analysis

### Existing gRPC API

**File:** `api/proto/management.proto`

The gRPC API already supports all required operations:

```protobuf
service ManagementService {
  // Filter operations
  rpc GetFilters(FilterRequest) returns (FilterResponse);
  rpc UpdateFilter(Filter) returns (FilterUpdateResult);
  rpc DeleteFilter(FilterDeleteRequest) returns (FilterUpdateResult);
  rpc SubscribeFilters(FilterRequest) returns (stream FilterUpdate);

  // Multi-level processor operations
  rpc GetFiltersFromProcessor(ProcessorFilterQuery) returns (FilterResponse);
  rpc UpdateFilterOnProcessor(ProcessorFilterRequest) returns (FilterUpdateResult);
  rpc DeleteFilterOnProcessor(ProcessorFilterDeleteRequest) returns (FilterUpdateResult);
}
```

**Messages:**
```protobuf
message Filter {
  string id = 1;
  FilterType type = 2;
  string pattern = 3;
  repeated string target_hunters = 4;  // Empty = all hunters
  bool enabled = 5;
  string description = 6;
}

message FilterUpdateResult {
  bool success = 1;
  string error = 2;
  repeated string hunters_updated = 3;
}
```

### Existing Filter File Format

**File:** `internal/pkg/processor/filtering/persistence.go`

```go
type FilterConfig struct {
    Filters []*FilterYAML `yaml:"filters"`
}

type FilterYAML struct {
    ID            string   `yaml:"id"`
    Type          string   `yaml:"type"`
    Pattern       string   `yaml:"pattern"`
    TargetHunters []string `yaml:"target_hunters,omitempty"`
    Enabled       bool     `yaml:"enabled"`
    Description   string   `yaml:"description,omitempty"`
}
```

**Example YAML:**
```yaml
filters:
  - id: "abc123"
    type: "sip_user"
    pattern: "alice"
    target_hunters: []
    enabled: true
    description: "VIP user"
  - id: "def456"
    type: "bpf"
    pattern: "udp port 5060"
    enabled: true
```

### Existing Config Structure

**File:** `cmd/root_all.go`, `cmd/tui/tui.go`

Config file locations (priority order):
1. `~/.config/lippycat/config.yaml`
2. `~/.config/lippycat.yaml`
3. `~/.lippycat.yaml`

Current Viper keys used:
- `tui.tls.enabled`
- `tui.tls.ca_file`
- `tui.tls.cert_file`
- `tui.tls.key_file`

### Remote Capture Client

**File:** `internal/pkg/remotecapture/client.go`

The TUI uses `remotecapture.Client` for gRPC connections with:
- TLS configuration support
- TCP keepalive tuning
- gRPC keepalive settings
- Auto-reconnection logic

This client is designed for long-lived streaming connections. For the CLI filter commands, we need a simpler connection pattern (connect, execute, disconnect).

## Build Tag Strategy

The new CLI filter commands use build tag `cli || all`:

| Build | Includes filter CLI? | Reason |
|-------|---------------------|--------|
| `all` | ✅ Yes | Complete suite |
| `cli` | ✅ Yes | Primary target for automation |
| `tui` | ❌ No | Has built-in FilterManager UI |
| `hunter` | ❌ No | Filter consumer, not manager |
| `processor` | ❌ No | Manages filters locally |

**Packages affected:**
- `cmd/filter/` - Build tagged `cli || all`
- `cmd/list/`, `cmd/show/`, `cmd/set/`, `cmd/rm/` - Build tagged `cli || all`
- `internal/pkg/filterclient/` - No build tags (compiled only when imported)
- `internal/pkg/filtering/` - No build tags (shared by processor and CLI)

## Required Changes

### 1. New Shared Package: `internal/pkg/filtering`

Extract filter file parsing from `internal/pkg/processor/filtering/persistence.go` to a shared package.

**Files to create:**
```
internal/pkg/filtering/
├── types.go          # FilterConfig, FilterYAML structs
├── parser.go         # ParseFile(), WriteFile(), ParseFilters()
├── validation.go     # ValidateFilter(), ValidateFilterType()
└── conversion.go     # YAMLToProto(), ProtoToYAML(), ProtoToJSON()
```

**Migration:**
- Move `FilterConfig`, `FilterYAML` to `internal/pkg/filtering/types.go`
- Move `yamlToProtoFilter`, `protoToYAMLFilter` to `internal/pkg/filtering/conversion.go`
- Move `parseFilterType`, `filterTypeToString` to `internal/pkg/filtering/conversion.go`
- `internal/pkg/processor/filtering/persistence.go` imports shared package

### 2. New CLI Package: `internal/pkg/filterclient`

Simple gRPC client for filter operations (connect, execute, disconnect pattern).

**Files to create:**
```
internal/pkg/filterclient/
├── client.go         # FilterClient struct, Connect(), Close()
├── operations.go     # List(), Get(), Set(), Delete()
└── batch.go          # SetBatch(), DeleteBatch()
```

**Client interface:**
```go
type FilterClient struct {
    conn   *grpc.ClientConn
    client management.ManagementServiceClient
}

func NewFilterClient(config ClientConfig) (*FilterClient, error)
func (c *FilterClient) Close() error

func (c *FilterClient) List(opts ListOptions) ([]*management.Filter, error)
func (c *FilterClient) Get(id string) (*management.Filter, error)
func (c *FilterClient) Set(filter *management.Filter) (*management.FilterUpdateResult, error)
func (c *FilterClient) Delete(id string) (*management.FilterUpdateResult, error)
func (c *FilterClient) SetBatch(filters []*management.Filter) (*BatchResult, error)
func (c *FilterClient) DeleteBatch(ids []string) (*BatchResult, error)
```

### 3. New CLI Commands: `cmd/filter/`

**Files to create:**
```
cmd/filter/
├── filter.go         # Parent command setup, shared flags
├── list.go           # lc list filters
├── show.go           # lc show filter
├── set.go            # lc set filter
└── rm.go             # lc rm filter
```

**Build tags:** `cli` and `all` only.

```go
//go:build cli || all
```

**Rationale:**
- `cli` - Primary target for automation/scripting use cases
- `all` - Complete suite includes everything
- `tui` excluded - TUI has built-in FilterManager component for interactive use
- `hunter` excluded - Hunters are filter consumers, not managers
- `processor` excluded - Processors manage filters locally; operators use separate `cli` binary for remote management

### 4. Config File Extension

Add remote processor configuration to config file.

**New Viper keys:**
```yaml
remote:
  processor: "processor.example.com:50051"
  tls:
    enabled: true
    ca_file: "/path/to/ca.crt"
    cert_file: "/path/to/client.crt"  # Optional, for mTLS
    key_file: "/path/to/client.key"   # Optional, for mTLS
```

The CLI commands will:
1. Check for `--processor` flag
2. Fall back to `viper.GetString("remote.processor")`
3. Error if neither is set

### 5. Root Command Updates

**Files to modify:**
```
cmd/root_all.go       # Add filter commands
cmd/root_cli.go       # Add filter commands
```

The verb-object pattern requires:
- `lc list` parent command with `filters` subcommand
- `lc show` parent command with `filter` subcommand
- `lc set` parent command with `filter` subcommand
- `lc rm` parent command with `filter` subcommand

**Note:** This aligns with `docs/plan/cli-verb-object-restructure.md` which plans:
- `lc list interfaces` (replaces `lc interfaces`)
- `lc show health/metrics/...` (replaces `lc debug ...`)

## Implementation Notes

### JSON Output

All commands output JSON by default. Use Go's `encoding/json` with:
```go
encoder := json.NewEncoder(os.Stdout)
encoder.SetIndent("", "  ")
encoder.Encode(result)
```

For errors, output JSON to stderr:
```json
{"error": "connection refused", "code": "UNAVAILABLE"}
```

Exit codes:
- `0`: Success
- `1`: General error
- `2`: Connection error
- `3`: Validation error

### Connection Pattern

Unlike the TUI's long-lived streaming connection, CLI commands use:
```go
client, err := filterclient.NewFilterClient(config)
if err != nil {
    return err
}
defer client.Close()

result, err := client.Set(filter)
```

No keepalive, no reconnection - just connect, execute, disconnect.

### Batch Operations

For `--file` flag:
1. Parse YAML file using `internal/pkg/filtering`
2. Iterate filters, call gRPC for each
3. Collect results
4. Output summary JSON

Alternative: Add batch gRPC endpoints (future optimization).

### ID Generation

For `lc set filter` without `--id`:
- Generate UUID client-side
- Include in JSON output so user can reference it

### Upsert Semantics

`lc set filter`:
- If `--id` matches existing filter: update
- If `--id` not found or not provided: create new

This matches the existing `UpdateFilter` gRPC behavior.

## File Summary

### New Files

| Path | Purpose |
|------|---------|
| `internal/pkg/filtering/types.go` | Shared filter types |
| `internal/pkg/filtering/parser.go` | YAML parsing |
| `internal/pkg/filtering/validation.go` | Filter validation |
| `internal/pkg/filtering/conversion.go` | Proto/YAML/JSON conversion |
| `internal/pkg/filterclient/client.go` | gRPC client |
| `internal/pkg/filterclient/operations.go` | CRUD operations |
| `internal/pkg/filterclient/batch.go` | Batch operations |
| `cmd/filter/filter.go` | Parent command |
| `cmd/filter/list.go` | List command |
| `cmd/filter/show.go` | Show command |
| `cmd/filter/set.go` | Set command |
| `cmd/filter/rm.go` | Remove command |
| `cmd/list/list.go` | `lc list` verb command |
| `cmd/show/show.go` | `lc show` verb command |
| `cmd/set/set.go` | `lc set` verb command |
| `cmd/rm/rm.go` | `lc rm` verb command |

### Modified Files

| Path | Changes |
|------|---------|
| `internal/pkg/processor/filtering/persistence.go` | Import shared package, remove duplicated types |
| `cmd/root_all.go` | Add verb commands |
| `cmd/root_cli.go` | Add verb commands |

## Open Questions

1. **Should we support `--output table` for human-readable output?**
   - Decision: No, JSON only for automation. Use TUI for human interaction.

2. **Should batch operations be atomic (all-or-nothing)?**
   - Decision: No, best-effort with detailed per-filter results in output.

3. **Should we add batch gRPC endpoints for efficiency?**
   - Decision: Future optimization. Start with client-side iteration.

4. **How to handle multi-level processor hierarchies in CLI?**
   - Decision: Initially support single-level only. Multi-level via `--processor-chain` flag (future).

## References

- `api/proto/management.proto` - gRPC API definitions
- `internal/pkg/processor/filtering/persistence.go` - Current filter persistence
- `internal/pkg/remotecapture/client.go` - TUI remote connection
- `docs/plan/cli-verb-object-restructure.md` - Planned CLI restructure
- `cmd/tui/components/filtermanager/` - TUI filter management (reference)
