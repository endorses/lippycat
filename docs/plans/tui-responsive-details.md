# Responsive capture details

Packet, event, and call details must remain accessible as terminal dimensions
change. Use side-by-side panes when useful widths fit, stacked panes when enough
height remains, and a single list or detail pane otherwise. Layout decisions use
available content space, including chrome and padding.

- [x] Share layout geometry across rendering, sizing, keyboard navigation, mouse
      input, scrollbars, and text selection; preserve focus and selection on resize.
- [x] Make `d` toggle visible details at every size and `Esc` return from details
      to the list. Preserve filters and scroll state; expose details in compact hints.
- [x] Adapt detail content with wrapping, responsive hex rows, and reduced spacing;
      keep the inspected item stable while capture continues.
- [x] Add focused regression tests for layout transitions, input, retained state,
      and narrow/short rendering; update TUI help and architecture notes.
- [x] Format changes, run relevant TUI checks, verify these tasks, and commit code
      and this completed plan.

Validation: `go test -tags tui ./internal/pkg/tui/...` passed, along with focused
race checks for responsive details, inspection, mouse input, and offline browsing.
The bounded closure review is complete; both discovered state-transition defects
were fixed and covered by regressions.

- [x] Correct the event list's outer width so its scrollbar stays inside the
      border in full-width, stacked, and side-by-side layouts.
