# Research: Multi-File PCAP Support for `lc watch file`

## Objective

Simplify the CLI by removing the redundant `-r` flag and support multiple PCAP files with timestamp-based merging.

**Current:**
```bash
lc watch file -r capture.pcap
```

**Proposed:**
```bash
lc watch file capture.pcap
lc watch file sip.pcap rtp.pcap  # Multiple files, merged by timestamp
```

**Additional requirement:** Display filenames without path (basename only) in TUI.

---

## Current Architecture Analysis

### 1. CLI Layer (`cmd/watch/file.go`)

**Current implementation:**
```go
var fileReadFile string  // Single file path

func init() {
    fileCmd.Flags().StringVarP(&fileReadFile, "read-file", "r", "", "PCAP file to analyze (required)")
    _ = fileCmd.MarkFlagRequired("read-file")
}

func runFile(cmd *cobra.Command, args []string) {
    if fileReadFile == "" {
        fmt.Fprintln(os.Stderr, "Error: --read-file/-r is required for file mode")
        os.Exit(1)
    }
    // ... uses single fileReadFile
}
```

**Changes needed:**
- [ ] Remove `-r` flag
- [ ] Accept positional arguments via Cobra's `Args` field
- [ ] Validate at least one file is provided
- [ ] Pass `[]string` of files to downstream functions

---

### 2. Capture Starter (`internal/pkg/capture/snifferstarter.go`)

**Current signature (line 38):**
```go
func StartOfflineSniffer(readFile string, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string))
```

Opens a single file and creates a single-element `devices` slice.

**Changes needed:**
- [ ] Change signature to `StartOfflineSniffer(readFiles []string, filter string, ...)`
- [ ] Loop through files, open each, create `offlineInterface` for each
- [ ] Collect into `[]pcaptypes.PcapInterface` and pass to `startSniffer`

**Good news:** The downstream architecture already supports multiple devices:
```go
// RunOffline (line 185-266) already handles multiple devices
for _, iface := range devices {
    captureWg.Add(1)
    go func(pif pcaptypes.PcapInterface) {
        captureFromInterface(ctx, pif, filter, packetBuffer)
    }(iface)
}
```

---

### 3. Packet Source Identification (`internal/pkg/capture/capture.go:369`)

**Current implementation:**
```go
pktInfo := PacketInfo{
    LinkType:  handle.LinkType(),
    Packet:    packet,
    Interface: filepath.Base(iface.Name()),  // Already uses basename!
}
```

**Status:** Already uses `filepath.Base()` - displays filename without path.

**No changes needed here.**

---

### 4. TUI Model (`internal/pkg/tui/model.go`)

**Current signature (line 127):**
```go
func NewModel(bufferSize int, interfaceName string, bpfFilter string, pcapFile string, ...) Model
```

Stores single `pcapFile` and sets `interfaceName = pcapFile` for display (line 150).

**Changes needed:**
- [ ] Change `pcapFile string` to `pcapFiles []string`
- [ ] Store slice of files for header display
- [ ] When single file: behave as now
- [ ] When multiple files: show merged indicator in header

---

### 5. Header Display (`internal/pkg/tui/components/header.go`)

**Current (line 270):**
```go
middleText = fmt.Sprintf("Interface: %s", h.iface)
```

For offline mode, `h.iface` is set to the PCAP filename.

**Changes needed:**
- [ ] Support displaying multiple files
- [ ] Options:
  - "Files: file1.pcap, file2.pcap" (if fits)
  - "Files: file1.pcap +2 more" (if too long)
  - Just basenames, no paths

---

### 6. Packet List Display (`internal/pkg/tui/components/packetlist.go:914-921`)

**Current:**
```go
var source string
if pkt.NodeID == "" || pkt.NodeID == "Local" {
    source = pkt.Interface  // Shows filename
} else {
    source = fmt.Sprintf("%s (%s)", pkt.NodeID, pkt.Interface)
}
```

**Status:** Already displays `Interface` field which contains the basename.

**No changes needed** - each packet already shows its source file.

---

### 7. Details Panel (`internal/pkg/tui/components/detailspanel.go:185`)

**Current:**
```go
captureSource := fmt.Sprintf("%s / %s", d.packet.NodeID, d.packet.Interface)
```

**Status:** Already displays `Interface` field.

**No changes needed.**

---

### 8. Settings View (`internal/pkg/tui/components/settings/offline.go`)

**Current:**
```go
type OfflineSettings struct {
    pcapFileInput textinput.Model  // Single file input
    // ...
}

pcapFileInput.Placeholder = "/path/to/file.pcap"
pcapFileInput.CharLimit = 512
```

**Changes needed:**
- [ ] Support multiple file paths (comma-separated or space-separated)
- [ ] Update placeholder text: `"file1.pcap file2.pcap ..."`
- [ ] Update validation to check all files exist
- [ ] Consider: file dialog for multiple file selection (more complex)

---

### 9. Settings Message (`internal/pkg/tui/components/settings/mode.go:75`)

**Current:**
```go
type RestartCaptureMsg struct {
    // ...
    PCAPFile    string // Path to PCAP file (offline mode)
}
```

**Changes needed:**
- [ ] Change to `PCAPFiles []string`
- [ ] Update all consumers of this message

---

### 10. Capture Lifecycle (`internal/pkg/tui/capture_lifecycle.go`)

**Current (line 161):**
```go
go startOfflineCapture(ctx, msg.PCAPFile, m.bpfFilter, program, done)
```

**Current (line 204):**
```go
func startOfflineCapture(ctx context.Context, pcapFile string, filter string, ...) {
    capture.StartOfflineSniffer(pcapFile, filter, ...)
}
```

**Changes needed:**
- [ ] Change `pcapFile string` to `pcapFiles []string`
- [ ] Pass slice to `StartOfflineSniffer`

---

## Timestamp-Based Merging Analysis

### Current Behavior

Packets from multiple files are processed in **parallel goroutines** and fed into a single `PacketBuffer` channel. Order depends on goroutine scheduling - **NOT timestamp order**.

### Options for True Chronological Merge

**Option A: Simple Sequential Read (No Timestamp Sorting)**
- Read files sequentially: file1 completely, then file2
- Pro: Simple, no buffering needed
- Con: Packets not in timestamp order across files

**Option B: Parallel Read with Heap-Based Merge (True Timestamp Sort)**
- Each file read in separate goroutine
- Use min-heap (priority queue) keyed by timestamp
- Pop smallest timestamp, send to consumer, refill from that file
- Pro: True chronological order
- Con: More complex, requires buffering

**Option C: Read All, Sort, Stream**
- Read all packets into memory
- Sort by timestamp
- Stream to TUI
- Pro: Simple sorting
- Con: Memory-intensive for large files

### Recommendation

**Start with Option A** (simple sequential) with clear documentation that files are processed in order, not merged by timestamp.

**Future enhancement:** Implement Option B if users need true timestamp merging. This would require:
- [ ] New `MergingPacketSource` that wraps multiple packet sources
- [ ] Min-heap for timestamp-ordered merging
- [ ] Per-file buffering (configurable depth)

---

## File Locations Summary

| File | Change Required | Priority |
|------|-----------------|----------|
| `cmd/watch/file.go` | Accept positional args, remove `-r` | HIGH |
| `internal/pkg/capture/snifferstarter.go` | `StartOfflineSniffer([]string, ...)` | HIGH |
| `internal/pkg/tui/model.go` | Store `[]string` for files | HIGH |
| `internal/pkg/tui/capture_lifecycle.go` | Pass `[]string` to capture | HIGH |
| `internal/pkg/tui/components/header.go` | Display multiple files | MEDIUM |
| `internal/pkg/tui/components/settings/offline.go` | Multi-file input | MEDIUM |
| `internal/pkg/tui/components/settings/mode.go` | `PCAPFiles []string` in msg | MEDIUM |
| `internal/pkg/capture/capture.go` | No changes (already uses basename) | NONE |
| `internal/pkg/tui/components/packetlist.go` | No changes (already shows Interface) | NONE |
| `internal/pkg/tui/components/detailspanel.go` | No changes (already shows Interface) | NONE |

---

## Interface Field Verification

**Question:** Is `Interface` field currently showing full path or basename for offline mode?

**Answer:** Basename only. See `capture.go:369`:
```go
Interface: filepath.Base(iface.Name())
```

**Status:** Already correct.

---

## Test Files Affected

Files that may need updates:
- [ ] `internal/pkg/tui/components/settings/offline_test.go`
- [ ] `internal/pkg/tui/components/settings/factory_test.go`
- [ ] Any integration tests for offline capture

---

## Breaking Changes

1. **CLI:** `-r` flag removed
   - Impact: Scripts using `lc watch file -r file.pcap` will break
   - Mitigation: Document in changelog, simple find/replace for users

2. **API:** `StartOfflineSniffer` signature change
   - Impact: Internal only, no external API

3. **Messages:** `RestartCaptureMsg.PCAPFile` → `PCAPFiles`
   - Impact: Internal only

---

## Open Questions

1. **File validation:** Should we validate all files exist before starting capture, or fail gracefully per-file?
   - Recommendation: Validate upfront, error if any file missing

2. **Link type mismatch:** What if files have different link types (Ethernet vs. Loopback)?
   - Current: Each packet carries its own `LinkType`
   - Recommendation: Allow mixing, warn user if detected

3. **Settings UI:** How to input multiple files in TUI settings?
   - Option A: Comma/space-separated text input
   - Option B: Multi-select file dialog (more complex)
   - Recommendation: Start with Option A

4. **Header display when many files:**
   - Truncate with "+N more"?
   - Show count only: "Merging 5 files"?
   - Recommendation: "file1.pcap +N more" pattern

---

## Dependencies

No new external dependencies required.

Internal:
- Uses existing `pcaptypes.PcapInterface` abstraction
- Uses existing `PacketBuffer` for multi-source collection
- Uses existing `filepath.Base()` for display
