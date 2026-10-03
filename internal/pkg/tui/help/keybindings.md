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

| Key           | Action             |
| ------------- | ------------------ |
| `j` / `Down`  | Move down          |
| `k` / `Up`    | Move up            |
| `h` / `Left`  | Focus list pane    |
| `l` / `Right` | Focus details pane |
| `g` / `Home`  | Jump to top        |
| `G` / `End`   | Jump to bottom     |
| `PgUp`        | Page up            |
| `PgDown`      | Page down          |

## Capture Tab

| Key   | Action                                                   |
| ----- | -------------------------------------------------------- |
| `/`   | Enter filter mode                                        |
| `c`   | Remove last filter                                       |
| `C`   | Clear all filters                                        |
| `d`   | Toggle details                                           |
| `Esc` | Return from details to list                              |
| `v`   | Cycle packet/event/call views                            |
| `m`   | Toggle current packet mark                               |
| `M`   | Add packet range to marks                                |
| `w`   | Save marked packets, or normal save when none are marked |
| `x`   | Flush/clear packets                                      |

Packet, event, and call details adapt to the available space: beside the list,
below it when the terminal is tall enough, or in the full content area. Press
`d` to open or close details at any size. Split layouts keep the list focused
and following incoming traffic; full-area details take focus. `Esc` returns focus
to the list. Use
`h`/`Left` and `l`/`Right` to switch panes. Resizing preserves the focused pane,
selection, and scroll position (clamped to the available content).

Only full-area details, with the list hidden, pin the inspected item. Focusing
details in either split layout does not pause following. Packet
and event snapshots remain readable if their list row leaves the capture buffer;
call details continue updating for the same call. Returning to the list or a split
layout restores the previous following setting. Use `End` in the list to resume
following after browsing history. Long values wrap and packet hex rows adapt
to the pane width. Very short terminals reduce padding and header/tab chrome.

When packet, event, or call details have focus, `Home`/`g` scrolls to the top and
`End`/`G` scrolls to the bottom of the details without changing the selected item.

### Mark packets for export

In the packet list, `m` toggles a mark and `M` adds the range from the last clicked
or individually marked packet to the current row. Marked rows have an asterisk in
the left margin. Plain clicks move the row and range anchor without clearing marks.
Ctrl+click toggles a mark, Shift+click replaces marks with a range, and
Ctrl+Shift+click adds a range. Ranges use the current filtered list order. If the
anchor was filtered out or evicted, click or mark another packet first. Some
terminals intercept modified clicks; `m` and `M` remain available from the keyboard.

Marks survive filtering and buffer eviction. With marks present, `w` saves only
marked packets, including ones no longer shown in the list, as a one-shot PCAP in
capture order. Press `Esc` to cancel an export in progress. The footer shows the
count and the save dialog identifies the
marked export. Saving keeps marks; use **Clear marks** in the save dialog to remove
all of them. Flushing packets or replacing the capture clears marks. An active
recording still uses `w` to stop first; press it again to export the marked set.

Live and remote marks retain independent copies of packet bytes; offline marks
reference the indexed capture. The defaults allow 10,000 marked packets and
64 MiB of retained payload, configurable with `watch.marked_packet_limit` and
`watch.marked_bytes_limit` in YAML configuration. Additions exceeding a limit are
rejected without changing existing marks; save and clear marks to release space.
Packets without available capture bytes cannot be marked. PCAP export rejects
mixed link types and invalid timestamps without replacing an existing file.

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

## Help Tab

| Key          | Action                          |
| ------------ | ------------------------------- |
| `Home` / `g` | Go to the top of the section    |
| `End` / `G`  | Go to the bottom of the section |

While entering a search, `g` and `G` are typed into the search query.
