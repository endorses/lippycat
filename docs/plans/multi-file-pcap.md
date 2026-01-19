# Implementation Plan: Multi-File PCAP Support

**Goal:** `lc watch file file1.pcap file2.pcap` with merged display, basenames only.

**Research:** [docs/research/multi-file-pcap-support.md](../research/multi-file-pcap-support.md)

---

## Phase 1: CLI and Capture Layer

### 1.1 Update CLI (`cmd/watch/file.go`)
- [x] Remove `-r`/`--read-file` flag and `fileReadFile` variable
- [x] Change `Use` to `"file [files...]"` with `Args: cobra.MinimumNArgs(1)`
- [x] Pass `args []string` to downstream functions (uses `args[0]` until phase 1.2)
- [x] Update command help text and examples
- [x] Add upfront file existence validation

### 1.2 Update StartOfflineSniffer (`internal/pkg/capture/snifferstarter.go`)
- [ ] Change signature: `StartOfflineSniffer(readFiles []string, filter string, ...)`
- [ ] Loop through files, validate each exists
- [ ] Create `offlineInterface` for each file
- [ ] Collect into `[]pcaptypes.PcapInterface`

### 1.3 Update file.go capture call
- [ ] Update `runFile()` to pass `args` slice to capture functions
- [ ] Update `startFileSniffer` if needed

---

## Phase 2: TUI Model and Lifecycle

### 2.1 Update TUI Model (`internal/pkg/tui/model.go`)
- [ ] Change `NewModel()` parameter from `pcapFile string` to `pcapFiles []string`
- [ ] Store files for header display
- [ ] Set `interfaceName` to joined basenames or summary

### 2.2 Update Settings Message (`internal/pkg/tui/components/settings/mode.go`)
- [ ] Change `PCAPFile string` to `PCAPFiles []string` in `RestartCaptureMsg`

### 2.3 Update Capture Lifecycle (`internal/pkg/tui/capture_lifecycle.go`)
- [ ] Update `startOfflineCapture()` to accept `[]string`
- [ ] Pass slice to `StartOfflineSniffer`
- [ ] Update all `RestartCaptureMsg` handlers

---

## Phase 3: TUI Display

### 3.1 Update Header (`internal/pkg/tui/components/header.go`)
- [ ] For single file: `"File: capture.pcap"`
- [ ] For multiple: `"Files: sip.pcap +2 more"` or `"Files: sip.pcap, rtp.pcap"` (if fits)
- [ ] Use basenames only

### 3.2 Update Offline Settings (`internal/pkg/tui/components/settings/offline.go`)
- [ ] Change input to accept space-separated paths
- [ ] Update placeholder: `"file1.pcap file2.pcap ..."`
- [ ] Update validation to check all files
- [ ] Update `ToRestartMsg()` to return `PCAPFiles []string`

### 3.3 Update Settings View (`internal/pkg/tui/components/settings.go`)
- [ ] Update `GetPCAPFile()` → `GetPCAPFiles()` returning `[]string`
- [ ] Update any callers

---

## Phase 4: Tests and Documentation

### 4.1 Update Tests
- [ ] `internal/pkg/tui/components/settings/offline_test.go`
- [ ] `internal/pkg/tui/components/settings/factory_test.go`
- [ ] Add test for multiple files in capture layer

### 4.2 Update Documentation
- [ ] `cmd/watch/README.md` - update examples
- [ ] `CLAUDE.md` - update CLI examples
- [ ] `CHANGELOG.md` - document breaking change (removal of `-r`)

---

## Implementation Notes

**File validation:** Validate all files exist upfront before starting capture. Fail with clear error listing missing files.

**Link type:** Allow mixed link types - each packet carries its own `LinkType`. Log warning if mismatch detected.

**Timestamp order:** Files processed in parallel, packets interleaved by scheduler (not timestamp-sorted). Document this behavior. True timestamp merge is future enhancement.

**Header truncation:** Use pattern `"file1.pcap +N more"` when multiple files exceed display width.

---

## Files Changed

```
cmd/watch/file.go                                    # CLI args
internal/pkg/capture/snifferstarter.go               # []string signature
internal/pkg/tui/model.go                            # []string storage
internal/pkg/tui/capture_lifecycle.go                # Pass []string
internal/pkg/tui/components/header.go                # Multi-file display
internal/pkg/tui/components/settings/mode.go         # PCAPFiles field
internal/pkg/tui/components/settings/offline.go      # Multi-file input
internal/pkg/tui/components/settings.go              # GetPCAPFiles()
```

---

## Breaking Change

**Removed:** `-r`/`--read-file` flag

**Migration:** `lc watch file -r capture.pcap` → `lc watch file capture.pcap`
