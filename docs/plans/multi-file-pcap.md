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
- [x] Change signature: `StartOfflineSniffer(readFiles []string, filter string, ...)`
- [x] Loop through files, open each, create `offlineInterface` for each
- [x] Collect into `[]pcaptypes.PcapInterface`
- [x] Handle cleanup: close all files on error or completion
- [x] Scale timeout with number of files
- [x] Log multi-file capture info
- [x] Update all callers (sniff, tui, voip, dns, tls, http, email)
- [x] Update tests

### 1.3 Update file.go capture call
- [x] Update `runFile()` to pass `args` slice to `StartOfflineSniffer`
- [x] `startFileSniffer` unchanged (receives devices from capture layer)

---

## Phase 2: TUI Model and Lifecycle

### 2.1 Update TUI Model (`internal/pkg/tui/model.go`)
- [x] Change `NewModel()` parameter from `pcapFile string` to `pcapFiles []string`
- [x] Store files for header display
- [x] Set `interfaceName` to joined basenames or summary

### 2.2 Update Settings Message (`internal/pkg/tui/components/settings/mode.go`)
- [x] Change `PCAPFile string` to `PCAPFiles []string` in `RestartCaptureMsg`

### 2.3 Update Capture Lifecycle (`internal/pkg/tui/capture_lifecycle.go`)
- [x] Update `startOfflineCapture()` to accept `[]string`
- [x] Pass slice to `StartOfflineSniffer`
- [x] Update all `RestartCaptureMsg` handlers

---

## Phase 3: TUI Display

### 3.1 Update Header (`internal/pkg/tui/components/header.go`)
- [x] For single file: `"File: capture.pcap"`
- [x] For multiple: `"Files: sip.pcap +2 more"` or `"Files: sip.pcap, rtp.pcap"` (if fits)
- [x] Use basenames only

### 3.2 Update Offline Settings (`internal/pkg/tui/components/settings/offline.go`)
- [x] Change input to accept space-separated paths
- [x] Update placeholder: `"file1.pcap file2.pcap ..."`
- [x] Update validation to check all files
- [x] Update `ToRestartMsg()` to return `PCAPFiles []string`

### 3.3 Update Settings View (`internal/pkg/tui/components/settings.go`)
- [x] Update `GetPCAPFile()` → `GetPCAPFiles()` returning `[]string`
- [x] Update any callers

---

## Phase 4: Tests and Documentation

### 4.1 Update Tests
- [x] `internal/pkg/tui/components/settings/offline_test.go`
- [x] `internal/pkg/tui/components/settings/factory_test.go`
- [x] Add test for multiple files in capture layer

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
