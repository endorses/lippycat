# TUI mouse text selection

Mouse dragging selects displayed text and copies it on release. Selection stays
inside its starting pane; packet dump hex and ASCII columns are separate regions.
Existing clicks, scrolling, and scrollbar dragging continue to work.

- [x] Add cell-aware selection and highlighting over a stable display snapshot.
- [x] Define selection regions for capture lists/details, nodes, statistics, and help, including separate packet dump columns.
- [x] Integrate mouse gestures and automatic clipboard copy with visible feedback, preferring OSC 52 over SSH.
- [x] Document the interaction and verify pane boundaries, live updates, Unicode, and existing mouse controls.
- [x] Format and run the relevant checks.

Validation: the full TUI package test suite and vet pass with `-tags all`;
the standalone binary builds with `-tags tui`. Clipboard tests exercise native
fallback and SSH/tmux/screen OSC 52 sequences without changing a real clipboard.
Terminal clipboard permission remains controlled by the user's terminal;
tmux passthrough requires `allow-passthrough on`.

Commit the verified implementation and this plan together.
