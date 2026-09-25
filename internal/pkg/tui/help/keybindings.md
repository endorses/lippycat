# Keybindings

## Global Keybindings

These keys work on all tabs.

| Key            | Action                    |
| -------------- | ------------------------- |
| `q` / `Ctrl+C` | Quit                      |
| `Ctrl+Z`       | Suspend (return to shell) |
| `Tab`          | Next tab                  |
| `Shift+Tab`    | Previous tab              |
| `Alt+1`        | Go to Capture tab         |
| `Alt+2`        | Go to Nodes tab           |
| `Alt+3`        | Go to Statistics tab      |
| `Alt+4`        | Go to Settings tab        |
| `Space`        | Pause/Resume capture      |
| `p`            | Open protocol selector    |
| `t`            | Toggle theme              |
| `?`            | Open Help tab             |

## Navigation

Click a footer keybinding hint (its key or description) to perform the same action
as pressing that key. This works on every tab and for filter input controls.

Drag with the left mouse button to select text; releasing copies it automatically.
Selections stay in the pane where the drag started. In packet dumps, hex and
ASCII are separate selection areas. The displayed text stays still during the
drag while capture continues; releasing restores the live view. A click without
dragging still selects a row, and scrollbars still scroll. Press `Esc` to cancel
a selection without copying.

This works in packet, event, and call lists and details, Nodes, Statistics, and
Help. Over SSH, copying uses OSC 52 to reach your local clipboard; enable terminal
clipboard access if your terminal or multiplexer requires it.
The tmux passthrough path requires `set -g allow-passthrough on` in tmux.

Vim-style navigation works in list views.

| Key           | Action           |
| ------------- | ---------------- |
| `j` / `Down`  | Move down        |
| `k` / `Up`    | Move up          |
| `h` / `Left`  | Focus left pane  |
| `l` / `Right` | Focus right pane |
| `g` / `Home`  | Jump to top      |
| `G` / `End`   | Jump to bottom   |
| `PgUp`        | Page up          |
| `PgDown`      | Page down        |

## Capture Tab

| Key | Action                      |
| --- | --------------------------- |
| `/` | Enter filter mode           |
| `c` | Remove last filter          |
| `C` | Clear all filters           |
| `d` | Toggle details panel        |
| `v` | Toggle view (packets/calls) |
| `w` | Save packets to PCAP        |
| `x` | Flush/clear packets         |

### Filter Mode

| Key       | Action                |
| --------- | --------------------- |
| `Enter`   | Apply filter          |
| `Esc`     | Cancel                |
| `Up/Down` | Browse filter history |

See the **Filters** section (press `2`) for complete filter syntax.

## Nodes Tab

| Key | Action                     |
| --- | -------------------------- |
| `a` | Add new node               |
| `d` | Delete selected node       |
| `s` | Select hunters (subscribe) |
| `f` | Open filter manager        |
| `v` | Toggle view (table/graph)  |

### Graph Mode

Arrow keys navigate spatially in the graph view.

## Statistics Tab

| Key | Action           |
| --- | ---------------- |
| `v` | Toggle view mode |

## Settings Tab

| Key          | Action                       |
| ------------ | ---------------------------- |
| `Enter`      | Edit/toggle selected setting |
| `Esc`        | Cancel editing               |
| `Left/Right` | Switch between modes         |
| `j/k`        | Navigate settings            |
