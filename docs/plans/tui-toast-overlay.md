# Capture toast overlay experiment

Try transient notifications above the footer without resizing packet, event, or
call panes. Keep the experiment on `experiment/tui-toast-overlay` for comparison.

- [x] Remove toast height from capture layout calculations and render a centered,
      bounded overlay; keep filter input and modal precedence intact.
- [x] Use the rendered bounds for dismissal and consume mouse input over the toast.
- [x] Verify stable geometry, rendering bounds, and dismissal; format and commit.

Validation: `go test -tags tui ./internal/pkg/tui/components ./internal/pkg/tui`
passed. Coverage includes all three capture views, layout thresholds, tiny
terminals, expiry, and queued dismissal without selecting underlying packets.
