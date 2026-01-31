# Plan: Display Tap Nodes in TUI Nodes Tab

## Overview

Add visual distinction between tap nodes (local capture) and pure processors (aggregation only) in the TUI nodes tab, with badge/label and interface display for taps.

## Current State

- Tap nodes appear as regular processors in the nodes tab
- No way to distinguish tap (captures locally) from processor (receives from hunters)
- `ProcessorNode` proto has no `node_type` or `capture_interfaces` fields
- Table/graph views render all processors identically

## Implementation

### 1. Proto Changes

**File:** `api/proto/management.proto`

Add new fields to `ProcessorNode` message (lines 573-600):

```protobuf
message ProcessorNode {
    // ... existing fields ...

    // Node type: TAP captures locally, PROCESSOR receives from hunters
    NodeType node_type = 10;

    // Interfaces being captured (only populated for TAP nodes)
    repeated string capture_interfaces = 11;
}

enum NodeType {
    NODE_TYPE_PROCESSOR = 0;  // Default: pure processor (receives from hunters)
    NODE_TYPE_TAP = 1;        // Tap: captures locally
}
```

### 2. Regenerate Proto

```bash
make proto
```

### 3. Processor Changes

**File:** `internal/pkg/processor/downstream/manager.go` (GetTopology)

Update node building (line 237-243) to include:
- `NodeType` from processor config
- `CaptureInterfaces` from local source config

**File:** `internal/pkg/processor/processor.go`

Add method to check if processor has local capture:
```go
func (p *Processor) HasLocalCapture() bool {
    return p.localSource != nil
}

func (p *Processor) GetCaptureInterfaces() []string {
    if p.localSource == nil {
        return nil
    }
    return p.localSource.Interfaces()
}
```

**File:** `internal/pkg/processor/source/local.go`

Add `Interfaces()` method to expose configured interfaces.

### 4. TUI ProcessorInfo Changes

**File:** `internal/pkg/tui/components/nodesview/table_view.go`

Add to `ProcessorInfo` struct (line 19-33):
```go
type ProcessorInfo struct {
    // ... existing fields ...
    NodeType          management.NodeType   // TAP or PROCESSOR
    CaptureInterfaces []string              // Interfaces being captured (TAP only)
}
```

**File:** `internal/pkg/tui/components/nodesview.go`

Same addition to main `ProcessorInfo` struct (line 39-53).

### 5. TUI Rendering Changes

**File:** `internal/pkg/tui/components/nodesview/table_view.go`

In `RenderTreeView` (around line 250-323), modify processor line rendering:

```go
// Add node type badge
var nodeTypeBadge string
if proc.NodeType == management.NodeType_NODE_TYPE_TAP {
    nodeTypeBadge = "[TAP]"
    if len(proc.CaptureInterfaces) > 0 {
        nodeTypeBadge += " " + strings.Join(proc.CaptureInterfaces, ",")
    }
} else {
    nodeTypeBadge = "[PROC]"
}

// Update procLine format:
// Before: "📡 Processor: %s [%s] (%d hunters)"
// After:  "📡 %s %s [%s] (%d hunters)"
```

**File:** `internal/pkg/tui/components/nodesview/graph_view.go`

Similar changes to graph view processor box rendering.

### 6. Remote Capture Client Changes

**File:** `internal/pkg/remotecapture/client.go`

Update topology parsing to extract new fields when building ProcessorInfo.

## Files Modified

- [x] `api/proto/management.proto` - Add NodeType enum and fields
- [x] `internal/pkg/processor/processor.go` - Add GetCaptureInterfaces method
- [x] `internal/pkg/processor/source/local.go` - Add Interfaces() method
- [x] `internal/pkg/processor/downstream/manager.go` - Set fields in GetTopology
- [x] `internal/pkg/processor/processor_grpc_handlers.go` - Pass NodeType/CaptureInterfaces to GetTopology
- [x] `internal/pkg/tui/components/nodesview.go` - Add fields to ProcessorInfo, update converter
- [x] `internal/pkg/tui/components/nodesview/table_view.go` - Add fields, render badge
- [x] `internal/pkg/tui/components/nodesview/graph_view.go` - Render badge in graph boxes
- [x] `internal/pkg/tui/store/connection_manager.go` - Add fields to ProcessorConnection
- [x] `internal/pkg/tui/capture_events.go` - Copy new fields in topology processing, **call GetTopology on connect**
- [x] `internal/pkg/tui/node_operations.go` - Copy new fields in getProcessorInfoList
- [x] `internal/pkg/tui/model.go` - Add NodeType/CaptureInterfaces fields to ProcessorConnectedMsg

### Bug Fix: TUI not receiving initial topology state

**Issue**: TUI was only subscribing to topology updates, not getting the initial processor state via `GetTopology`. This meant the processor's `NodeType` was never populated.

**Fix**: In `capture_events.go`, call `client.GetTopology()` after connecting to get the processor's initial state, and store `NodeType` and `CaptureInterfaces` in the `ProcessorConnection`.

## Verification

1. Run `make proto` to regenerate protobuf code
2. Run `make test` to ensure no regressions
3. Run `make build` to verify compilation
4. Manual testing:
   - Start a tap: `lc tap -i eth0 --insecure`
   - Start a processor: `lc process --listen :55555 --insecure`
   - Connect TUI: `lc watch remote --nodes processor:55555 --insecure`
   - Verify tap shows `[TAP] eth0` and processor shows `[PROC]`
