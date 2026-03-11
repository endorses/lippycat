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

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | `any` | Network interface(s), comma-separated |
| `--filter` | `-f` | — | BPF filter expression |
| `--promiscuous` | `-p` | `false` | Promiscuous mode |
| `--buffer-size` | — | `10000` | Maximum packets in memory |
| `--max-calls` | — | `5000` | Maximum VoIP calls in memory |
| `--enable-gpu` | — | `false` | Enable GPU-accelerated VoIP parsing |
| `--gpu-backend` | `-g` | `auto` | GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd` |
| `--gpu-batch-size` | — | `100` | Batch size for GPU processing |
| `--debug-log` | — | — | Write debug logs to file |

### TUI Layout

The interface is organized into five tabs:

| Tab | Shortcut | Purpose |
|-----|----------|---------|
| Capture | `Alt+1` | Packets, calls, DNS queries, email, HTTP traffic |
| Nodes | `Alt+2` | Hunter/processor node management |
| Statistics | `Alt+3` | Protocol breakdown, traffic analytics |
| Settings | `Alt+4` | Capture configuration |
| Help | `Alt+5` or `?` | Searchable keybindings and workflows |

### Global Keybindings

These work on any tab:

| Key | Action |
|-----|--------|
| `Space` | Pause/resume capture |
| `p` | Open protocol selector |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `Alt+1` through `Alt+5` | Jump to tab |
| `?` | Jump to Help tab |
| `q` / `Ctrl+C` | Quit |

### Capture Tab Navigation

The Capture tab is the main view. Navigate with vim-style keys:

| Key | Action |
|-----|--------|
| `j` / `↓` | Scroll down |
| `k` / `↑` | Scroll up |
| `g` / `Home` | Jump to first packet |
| `G` / `End` | Jump to last packet |
| `PgUp` / `PgDn` | Page up / down |
| `h` / `←` | Focus left pane (packet list) |
| `l` / `→` | Focus right pane (details/hex) |
| `d` | Toggle details panel |
| `t` | Toggle time display (clock / relative) |
| `v` | Toggle view mode (packets / protocol-specific) |
| `x` | Flush/clear all packets |
| `w` | Save packets to PCAP |

### Filtering in the TUI

Press `/` on the Capture tab to enter filter mode. Type a filter expression and press `Enter` to apply.

**Filter types:**

| Filter | Example | Description |
|--------|---------|-------------|
| Protocol | `protocol:voip` | Show only VoIP traffic |
| Text (all) | `text:all alice` | Search all fields |
| Text (src) | `text:src 10.0.0.1` | Search source |
| Text (dst) | `text:dst 10.0.0.1` | Search destination |
| Text (info) | `text:info INVITE` | Search info field |
| BPF port | `port 5060` | Specific port |
| BPF host | `host 10.0.0.1` | Source or destination IP |
| VoIP Call-ID | `callid abc123` | Specific call |
| SIP method | `method:INVITE` | SIP method type |

**Filter management:**

| Key | Action |
|-----|--------|
| `/` | Enter filter mode |
| `Enter` | Apply filter |
| `Escape` | Cancel |
| `c` | Remove last filter |
| `C` (Shift) | Clear all filters |

### View Modes

Press `v` to toggle between protocol-specific views:

| Protocol | Views |
|----------|-------|
| VoIP | Packets ↔ Calls |
| DNS | Packets ↔ Queries |
| HTTP | Packets ↔ HTTP Traffic |
| Email | Packets ↔ Emails |

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

**File mode flags:**

| Flag | Short | Description |
|------|-------|-------------|
| `--filter` | `-f` | BPF filter expression |
| `--tls-keylog` | — | SSLKEYLOGFILE for TLS decryption |

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

Status messages appear as toast notifications at the top of the screen, auto-dismissing after 2-5 seconds. Types include success (green), error (red), info (blue), and warning (yellow). Related toasts supersede each other — for example, "Paused" is replaced by "Resumed".

### Saving Packets

Press `w` on the Capture tab to save displayed packets to a PCAP file. A file dialog opens to choose the output path. Press `w` again to stop streaming to the file.

---

Now that you're comfortable with local capture (CLI and TUI), you're ready to learn about distributed capture in [Part III](../part3-distributed/architecture.md) — where hunters capture at the edge and processors aggregate centrally.
