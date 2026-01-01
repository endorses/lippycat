# Keybindings

## Global Keybindings

These keys work on all tabs.

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `Ctrl+Z` | Suspend (return to shell) |
| `Tab` | Next tab |
| `Shift+Tab` | Previous tab |
| `Alt+1` | Go to Capture tab |
| `Alt+2` | Go to Nodes tab |
| `Alt+3` | Go to Statistics tab |
| `Alt+4` | Go to Settings tab |
| `Space` | Pause/Resume capture |
| `p` | Open protocol selector |
| `t` | Toggle theme |
| `?` | Open Help tab |

## Navigation

Vim-style navigation works in list views.

| Key | Action |
|-----|--------|
| `j` / `Down` | Move down |
| `k` / `Up` | Move up |
| `h` / `Left` | Focus left pane |
| `l` / `Right` | Focus right pane |
| `g` / `Home` | Jump to top |
| `G` / `End` | Jump to bottom |
| `PgUp` | Page up |
| `PgDown` | Page down |

## Capture Tab

| Key | Action |
|-----|--------|
| `/` | Enter filter mode |
| `c` | Remove last filter |
| `C` | Clear all filters |
| `d` | Toggle details panel |
| `v` | Toggle view (packets/calls) |
| `w` | Save packets to PCAP |
| `x` | Flush/clear packets |

### Filter Mode

| Key | Action |
|-----|--------|
| `Enter` | Apply filter |
| `Esc` | Cancel |
| `Up/Down` | Browse filter history |

### Filter Syntax

- `ip:192.168.1.1` - Filter by IP address
- `port:5060` - Filter by port
- `proto:sip` - Filter by protocol
- `method:INVITE` - Filter by SIP method
- `callid:abc123` - Filter by Call-ID
- `from:alice` - Filter by From header
- `to:bob` - Filter by To header

Combine filters: Each filter stacks (AND logic).

## Nodes Tab

| Key | Action |
|-----|--------|
| `a` | Add new node |
| `d` | Delete selected node |
| `s` | Select hunters (subscribe) |
| `f` | Open filter manager |
| `v` | Toggle view (table/graph) |

### Graph Mode

Arrow keys navigate spatially in the graph view.

## Statistics Tab

| Key | Action |
|-----|--------|
| `v` | Toggle view mode |

## Settings Tab

| Key | Action |
|-----|--------|
| `Enter` | Edit/toggle selected setting |
| `Esc` | Cancel editing |
| `Left/Right` | Switch between modes |
| `j/k` | Navigate settings |
