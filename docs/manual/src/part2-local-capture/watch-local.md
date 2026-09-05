# Interactive Capture with `lc watch`

`lc watch` provides an interactive Terminal User Interface (TUI) for real-time packet monitoring. If `lc sniff` is like tcpdump, then `lc watch` is like Wireshark — but in your terminal.

## Live Capture Mode

### Starting Live Capture

```bash
# Start live capture (default mode)
sudo lc watch

# Explicitly specify live mode
sudo lc watch live

# Capture on a specific interface with a BPF filter
sudo lc watch live -i eth0 -f "port 5060"

# Enable promiscuous mode
sudo lc watch live -i eth0 -p
```

**Key flags:**

| Flag               | Short | Default | Description                                       |
| ------------------ | ----- | ------- | ------------------------------------------------- |
| `--interface`      | `-i`  | `any`   | Network interface(s), comma-separated             |
| `--filter`         | `-f`  | —       | BPF filter expression                             |
| `--promiscuous`    | `-p`  | `false` | Promiscuous mode                                  |
| `--buffer-size`    | —     | `10000` | Maximum packets in memory                         |
| `--max-calls`      | —     | `5000`  | Maximum VoIP calls in memory                      |
| `--enable-gpu`     | —     | `false` | Enable GPU-accelerated VoIP parsing               |
| `--gpu-backend`    | `-g`  | `auto`  | GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd` |
| `--gpu-batch-size` | —     | `100`   | Batch size for GPU processing                     |
| `--debug-log`      | —     | —       | Write debug logs to file                          |

### TUI Layout

The interface is organized into five tabs:

| Tab        | Shortcut       | Purpose                                          |
| ---------- | -------------- | ------------------------------------------------ |
| Capture    | `Alt+1`        | Packets, calls, DNS queries, email, HTTP traffic |
| Nodes      | `Alt+2`        | Hunter/processor node management                 |
| Statistics | `Alt+3`        | Protocol breakdown, traffic analytics            |
| Settings   | `Alt+4`        | Capture configuration                            |
| Help       | `Alt+5` or `?` | Searchable keybindings and workflows             |

### Global Keybindings

These work on any tab:

| Key                     | Action                 |
| ----------------------- | ---------------------- |
| `Space`                 | Pause/resume capture   |
| `p`                     | Open protocol selector |
| `Tab` / `Shift+Tab`     | Next / previous tab    |
| `Alt+1` through `Alt+5` | Jump to tab            |
| `?`                     | Jump to Help tab       |
| `q` / `Ctrl+C`          | Quit                   |

### Capture Tab Navigation

The Capture tab is the main view. Navigate with vim-style keys:

| Key             | Action                                         |
| --------------- | ---------------------------------------------- |
| `j` / `↓`       | Scroll down                                    |
| `k` / `↑`       | Scroll up                                      |
| `g` / `Home`    | Jump to first packet                           |
| `G` / `End`     | Jump to last packet                            |
| `PgUp` / `PgDn` | Page up / down                                 |
| `h` / `←`       | Focus left pane (packet list)                  |
| `l` / `→`       | Focus right pane (details/hex)                 |
| `d`             | Toggle details panel                           |
| `t`             | Toggle time display (clock / relative)         |
| `v`             | Toggle view mode (packets / protocol-specific) |
| `x`             | Flush/clear all packets                        |
| `w`             | Save packets to PCAP                           |

### Filtering in the TUI

Press `/` on the Capture tab to enter filter mode. Type a filter expression and press `Enter` to apply.

**Filter types:**

| Filter       | Example             | Description              |
| ------------ | ------------------- | ------------------------ |
| Protocol     | `protocol:voip`     | Show only VoIP traffic   |
| Text (all)   | `text:all alicent`  | Search all fields        |
| Text (src)   | `text:src 10.0.0.1` | Search source            |
| Text (dst)   | `text:dst 10.0.0.1` | Search destination       |
| Text (info)  | `text:info INVITE`  | Search info field        |
| BPF port     | `port 5060`         | Specific port            |
| BPF host     | `host 10.0.0.1`     | Source or destination IP |
| VoIP Call-ID | `callid abc123`     | Specific call            |
| SIP method   | `method:INVITE`     | SIP method type          |

**Filter management:**

| Key         | Action             |
| ----------- | ------------------ |
| `/`         | Enter filter mode  |
| `Enter`     | Apply filter       |
| `Escape`    | Cancel             |
| `c`         | Remove last filter |
| `C` (Shift) | Clear all filters  |

### View Modes

Press `v` to toggle between protocol-specific views:

| Protocol | Views                  |
| -------- | ---------------------- |
| VoIP     | Packets ↔ Calls        |
| DNS      | Packets ↔ Queries      |
| HTTP     | Packets ↔ HTTP Traffic |
| Email    | Packets ↔ Emails       |

## PCAP File Analysis

### Opening PCAP Files

Analyze previously captured traffic — no elevated privileges needed:

```bash
# Open a single PCAP file
lc watch file capture.pcap

# Open multiple PCAP files (merged display)
lc watch file sip.pcap rtp.pcap signaling.pcap
```

When opening multiple files, packets are merged and displayed in timestamp order.

Opening indexes all accepted logical packets into private temporary storage.
The progress modal shows reading, sorting and indexing phases, source count,
logical packets/bytes, elapsed time, and temporary disk usage. Escape cancels and waits for cleanup; failed or cancelled
replacement keeps the previous ready dataset. Browsing begins only after analysis
finalizes successfully. Input BPF (`-f`) applies before indexing; reassembly and
decapsulation can change logical packets relative to source records.

Every indexed packet remains navigable, filterable, and exportable after cache
eviction. `watch.buffer_size` / `--buffer-size` limits live/remote packet rings and
retained event history, not offline packet completeness. The header shows total
packets; Statistics separates total and matching packets from cached rows/bytes
and index bytes. The bottom area remains reserved for notifications. Global and
matching statistics cover their complete dataset/query; bounded endpoint estimates
are labelled separately. Events and Calls still have bounded retained histories;
their filters do not provide complete-file event or call history.

Interactive packet filters scan the whole dataset asynchronously. Escape cancels
the scan. Failed/cancelled scans preserve the last completed query, filter labels,
and statistics. Removing/clearing filters also queries the complete dataset.

Backward timestamps are supported: normalized logical packets are ordered on disk
before stateful analysis, preserving timestamps and using argument order, then
original source sequence to break ties. Sorting uses bounded memory and shares
the configured disk budget with datasets and queries. Malformed input, disk
exhaustion and invalid BPF fail the open without publishing partial results.
Up to 64 regular-file
sources are supported; PCAP and single-section, single-interface PCAPNG files may
be mixed. Split multi-section/interface PCAPNG captures before opening them.

**File mode flags:**

| Flag                         | Short | Default                | Description                                                       |
| ---------------------------- | ----- | ---------------------- | ----------------------------------------------------------------- |
| `--filter`                   | `-f`  | none                   | Source-level BPF filter                                           |
| `--tls-keylog`               | —     | none                   | SSLKEYLOGFILE for TLS decryption                                  |
| `--offline-session-dir`      | —     | OS temporary directory | Existing writable parent of private session directories           |
| `--offline-max-disk-bytes`   | —     | `4294967296` (4 GiB)   | Combined sorting/dataset/query disk budget                                |
| `--offline-cache-bytes`      | —     | `67108864` (64 MiB)    | Display cache, pinned details, prefetch and in-flight read budget |
| `--offline-max-record-bytes` | —     | `8388608` (8 MiB)      | Maximum encoded packet record; must fit cache/disk budgets        |
| `--offline-max-sources`      | —     | `64`                   | Simultaneous sources, from 1 to 64                                |

These flags override `watch.offline.*` [configuration keys](../appendices/config-reference.md#watch--watch-tui-settings).
They also apply when switching into offline mode using Settings or a file dialog.
Leave offline mode before changing resource budgets. Settings' buffer field is for
live/remote packet rings and retained event history; configure offline storage
through the flags or YAML keys above.

Disk accounting includes summaries, details, offsets, manifests, and query files;
the ready and replacement datasets share the budget. Allow space for both during
replacement and for all-match query vectors. Normalized storage can exceed source
size. Physical disk exhaustion, configured budget limits, and permission errors
fail explicitly, preserving the last completed dataset/query. Free space or
change the directory/budget and retry. Owned temporary files are removed on
cancellation/shutdown; cleanup failures remain visible for retry. The cache budget
is not a process RSS limit: reader/reassembly, analyzer, retained event/call, and
Go runtime memory are additional. Offline TLS plaintext has a separate 16 MiB cap;
exceeding it fails indexing.

Press `w` to export the last completed matching query (or all packets with no
packet filter). Export streams a fixed snapshot to nanosecond PCAP, preserving
normalized raw bytes, effective link type, timestamps, and captured/original
lengths. Mixed effective link types are rejected; export those inputs separately.
Missing timestamps or timestamps outside unsigned 32-bit Unix seconds also fail
explicitly. Empty queries report no packets to save. Escape cancels the export.
The destination is replaced atomically only on success; cancellation or errors
preserve an existing destination and remove temporary output. Export requires
additional free space beside the destination, outside the session disk budget.

### TLS Decryption

If you have a TLS key log file (e.g., from `SSLKEYLOGFILE` environment variable), you can decrypt HTTPS traffic in file analysis:

```bash
lc watch file capture.pcap --tls-keylog keys.log
```

## TUI Features

### Statistics Tab

Press `Alt+3` to view real-time traffic statistics:

- Protocol breakdown and packet counts
- Traffic rates
- Distributed node statistics (when connected to processors)

The packet-detail view is deliberately bounded during live capture. Exact
ingress counters continue to account for every valid packet, while the detail
feed may sample packets, drop a queued detail batch, or evict the oldest packet
from its pending ring to keep the newest diagnostics visible. The Statistics
tab reports these stages separately as **Sampled Out**, **Batch Queue Drops**,
and **Pending Evictions**. **Packets Delivered** and its retained percentage
measure end-to-end detail retention from valid TUI ingress; they do not measure
capture integrity or packets written to PCAP.

Recognized SIP packets bypass adaptive detail sampling, but they can still be
lost at the later batch-queue or pending-ring stages. Offline PCAP replay uses a
separate preserve-all pending path and does not inherit live-ring eviction.

All of these TUI counters are cumulative for the current session. Do not add
successive snapshots. A low retained percentage means packet rows are an
incomplete diagnostic sample. Use the exact ingress/protocol counters for
traffic rates and a PCAP sink when complete packet evidence is required.

Toggle between Overview and Distributed sub-views with `v` or the `1`/`2` keys. Export statistics to JSON with `e`.

### Settings Tab

Press `Alt+4` to view and modify capture settings:

- Interface selection
- BPF filter configuration
- Toggle theme with `t`

### Help Tab

Press `?` to open the searchable help system:

- Keybindings reference
- Filter syntax
- Commands
- Workflows

Search with `/`, navigate results with `n`/`N`. Jump to sections with `1`-`4`.

### Toast Notifications

Status messages appear as toast notifications at the bottom of the screen, auto-dismissing after 2-5 seconds. Types include success (green), error (red), info (blue), and warning (yellow). Related toasts supersede each other — for example, "Paused" is replaced by "Resumed".

### Saving Packets

Press `w` on the Capture tab to save displayed packets to a PCAP file. A file dialog opens to choose the output path. Press `w` again to stop streaming to the file.

---

Now that you're comfortable with local capture (CLI and TUI), you're ready to learn about distributed capture in [Part III](../part3-distributed/architecture.md) — where hunters capture at the edge and processors aggregate centrally.
