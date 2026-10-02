# Clickable TUI modals and shared action buttons

Status: implemented and verified on `feature/tui-clickable-modals` (2026-10-02).

## Objective

Make modal dialogs usable with both mouse and keyboard. Introduce one reusable
button component using the existing Lip Gloss styles and layout-based click
detection, then use it throughout the shared modal layer. Add direct interaction
to the protocol selector, file dialog, and filter manager.

Use the existing Bubble Tea v1 and Bubbles dependencies. No new widget library,
BubbleZone integration, or framework upgrade is required. Keep existing command
results, validation, asynchronous operations, and cancellation cleanup intact.

## Interaction contract

| Element         | Mouse behavior                                                 | Keyboard behavior                                                                                                                  |
| --------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Action button   | Left click invokes the enabled action once                     | Tab/Shift+Tab focus; Enter/Space activate a focused button; existing action shortcuts remain available in their applicable context |
| Selection list  | Single click selects a row                                     | Existing arrows and list shortcuts remain                                                                                          |
| Checkbox        | Click checkbox or its associated label toggles it once         | Existing toggle shortcut remains; Space toggles when focused                                                                       |
| Text field      | Click focuses the field                                        | Existing text editing remains; action shortcuts must not consume typed characters                                                  |
| Scrollable list | Wheel scrolls the list under the pointer                       | Existing page and navigation keys remain                                                                                           |
| Modal backdrop  | Dismisses only the visible modal layer through the shared host | Existing Esc cancellation semantics remain                                                                                         |

Buttons show a clear action label and, when useful, its shortcut, for example
`[ Cancel · Esc ] [ Apply · Enter ]`. Use theme colors and visible boundaries;
focus, disabled state, and destructive actions must remain distinguishable
without relying only on color. Hover feedback is optional when mouse motion is
available; it must not be required to discover or activate controls.

Single-click selects, and an explicit button confirms. Add double-click shortcuts
for protocol application, directory navigation, and opening files in open mode,
but never require them. In save mode, choosing an existing file supplies its name
for editing; double-click focuses that filename without accepting a save.
Track the same stable target within the same modal layer and list context; reset
double-click state on scrolling, navigation, resizing, dismissal, or replacement
of the list. A click following navigation must not activate a new row by accident.

Retain navigation hints as text. Turn concrete actions into buttons rather than
making every instruction a button. Keep actions reachable in narrow or short
terminals by wrapping the action bar and scrolling the content area. If even the
minimal chrome cannot fit, show a compact resize message and keep Esc available.

## Existing integration points

| Area                        | Files and behavior                                                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared modal rendering      | `internal/pkg/tui/components/modal.go`: `RenderModal`, `ModalRenderOptions`, `Modal`, and shared backdrop hit testing                             |
| Modal ownership and routing | `internal/pkg/tui/modal.go` and `model.go`: `activeModal`, adapters, input routing, and dismissal gesture suppression                             |
| Existing clickable hints    | `internal/pkg/tui/components/footer.go` and `mouse_handler.go`: shared rendering/hit geometry and action routing pattern                          |
| Protocol selection          | `internal/pkg/tui/components/protocolselector.go`: single selection, Enter applies, selected description currently shifts rows                    |
| File browsing               | `internal/pkg/tui/components/filedialog.go`: open/save dialogs, navigation, search, filename editing, and folder creation                         |
| Filter management           | `internal/pkg/tui/components/filtermanager.go` and `filtermanager/{list,editor,state}.go`: list, editor, target selector, and nested confirmation |
| Other hosted dialogs        | `hunterselector.go`, `confirmdialog.go`, `nodesview.go`, `offline_lifecycle.go`, and `offline_filter.go`                                          |
| Existing regression tests   | `modal_mouse_test.go`, `modal_offline_test.go`, `components/modal_mouse_test.go`, `components/modal_dismiss_test.go`, and `footer_mouse_test.go`  |

The file dialog is currently a single-file picker in its implemented selection
paths. Do not expand unused multiple-selection configuration into a new feature.
File deletion, renaming, drag-and-drop, and protocol multi-selection are outside
this scope.

## Implementation tasks

### Shared buttons and modal layout

- [x] Add a reusable button/action-bar component, using purpose-based filenames such as `components/button.go`. Define stable action IDs, labels, shortcut hints, enabled state, and normal/primary/destructive presentation.
- [x] Make rendering and hit testing consume the same layout calculation. Include the button's visible padding in its hit region; keep gaps, borders, and unrelated text inert. Measure terminal cells correctly for ANSI styles, Unicode, and wide glyphs.
- [x] Keep rendering read-only. Prepare or calculate geometry without storing state from `View`; hit testing must work before the next render after an update or resize.
- [x] Extend the shared modal contract/options with structured actions and layout information. Keep informational footer text separate from action buttons; do not parse action semantics from human-readable footer strings.
- [x] Share the modal origin and content/action rectangles between drawing and hit testing, accounting for borders, padding, centering, wrapping, scrolling, and clipping. Dialogs may declare content targets, but must not duplicate backdrop or terminal-offset logic.
- [x] Add focus traversal through content controls and enabled buttons. Preserve contextual Enter behavior in existing fields/lists; when a button is focused, Enter/Space invokes that button. Hidden or disabled controls are skipped, and focus moves predictably if an action becomes unavailable.
- [x] Add themed normal, focused, disabled, and destructive button styles. Keep primary-action emphasis distinct from keyboard focus and selected list rows.
- [x] Reserve height for the title and wrapped action bar; let modal content use the remaining viewport. Remove the current minimum-width behavior that can force modal chrome beyond a tiny terminal, and provide a compact fallback when usable layout is impossible.

### Shared action dispatch and modal ownership

- [x] Give each dialog explicit action handlers used by both keys and buttons. Keep Save/Apply/Cancel independent of synthetic keystrokes so clicking Save while a text field is active cannot type a shortcut or trigger another mode's Enter action.
- [x] Extend `activeModal` and its adapters to expose the visible layer's actions and targets, including nested filter confirmations and hunter selection. Route input to that layer before the underlying dialog, main footer, text selection, or tabs.
- [x] Activate buttons once on a left press, consistent with the existing clickable footer. Consume the remaining gesture when activation closes or replaces a modal so release/motion cannot reach newly exposed controls. Ignore right/middle clicks and wheel events for button activation.
- [x] Preserve existing outside-click dismissal in the host and its cleanup/result semantics. A modal-level Cancel action calls `Dismiss`; inline edit cancellation remains a separately named action where needed.
- [x] Scope action IDs, focus, and pending gestures to the current modal layer. Revalidate enabled state at activation and suppress duplicate submissions while operations are pending.
- [x] Continue routing asynchronous results, errors, progress, and directory-read messages to their owners while a modal is visible. Mouse support must not interfere with the existing recurring tick chain or capture event processing.

### Protocol selector

- [x] Make the entire visible protocol row selectable by click; retain single-selection semantics and keyboard navigation.
- [x] Move the selected protocol description into a reserved area below the list so changing selection does not move other rows. Bound or wrap the description within the prepared layout.
- [x] Add Apply and Cancel buttons; Apply invokes the same selection-result path as Enter. Add optional double-click application using the shared gesture policy.
- [x] Support wheel scrolling when the available terminal height requires a list viewport; preserve selection and keep the focused row visible during keyboard navigation.

### File dialog

- [x] Make rows selectable by click, support wheel scrolling, and add double-click activation according to the open/save contract above. Keep directory navigation separate from accepting a file; Open on a selected directory navigates into it. In save mode, clicking an existing file fills the filename and double-click focuses it; Save or the existing filename-confirmation key path is required to accept.
- [x] Add Up and clickable path breadcrumbs. Use real path components as targets, make the root boundary explicit, and retain access to navigation when long paths are shortened for display.
- [x] Make search/filter and filename fields focusable by click. Integrate them into the focus order while preserving the familiar list-to-filename Tab path in save mode.
- [x] Add Open or Save, Cancel, New folder, and Details controls. Show useful enabled states: Open needs an actionable selection, Save needs a valid filename, and Up is unavailable at the filesystem root.
- [x] Provide contextual Apply filter/Clear filter and Create folder/Cancel edit actions as applicable. Distinguish Cancel edit from closing the entire dialog; preserve existing Esc behavior within each editing mode.
- [x] Factor file acceptance into shared mouse/keyboard handlers that preserve filename validation, extension rules, configured filters, result messages, and error reporting. Preserve directory selection and the existing filename when focusing unrelated controls.
- [x] Verify existing-file save behavior before wiring the Save button. The current filename handler sets an overwrite warning but immediately returns `FileSelectedMsg`; provide a real confirmation through the shared confirmation dialog before returning a save result for an existing destination. Cancel returns to the file dialog without losing the entered filename.
- [x] Apply the behavior to every FileDialog host: capture export, settings PCAP selection, and settings nodes-file selection. Keep folder creation failures visible and recoverable.

### Filter manager and nested selectors

- [x] Make filter rows selectable and the existing enabled checkbox independently clickable. Clicking the row selects; clicking its checkbox toggles exactly once without also opening the editor. Support wheel scrolling with correct row mapping after search and filtering.
- [x] Add New, Edit, Delete, and Close buttons. Edit/Delete require a valid selected filter; preserve existing delete confirmation, processor operations, pending-state behavior, and error feedback.
- [x] Make Search directly focusable and add a clear-search control. Turn Type and Status into clickable selectors with equivalent keyboard behavior; preserve selection by filter identity across list updates where possible.
- [x] Make editor text fields focusable, type choices selectable, enabled state toggleable, and hunter targets clickable. Add persistent Save and Cancel buttons that use the existing validation and submission paths.
- [x] Give the nested hunter selector clickable rows/checkboxes and All, None, Confirm, and Cancel buttons. Keep unconfirmed choices local and return to the parent editor on cancellation.
- [x] Use one capability-filtered hunter projection for rendering, keyboard navigation, mouse targets, and bulk selection. Key targets by hunter identity and reconcile selection on refresh; do not index an unfiltered backing list with a displayed row index. Define All/None over eligible hunters and preserve the intended target semantics when filter type changes.
- [x] Ensure the action bar follows the visible list, editor, search, hunter selector, or confirmation state. Preserve draft edits when moving between editor and target selection; never dispatch a parent action through an overlaid confirmation.

### Complete the migration across hosted modals

- [x] Migrate the standalone hunter subscription selector to clickable checkboxes and All, None, Confirm, and Cancel buttons, sharing behavior with the filter target selector where practical. Preserve the distinction between all hunters and an explicitly empty subscription.
- [x] Give generic confirmation dialogs explicit, context-specific confirm/cancel buttons. Preserve existing result payloads and destructive-action semantics, including confirmations nested inside other components.
- [x] Add Confirm and Cancel buttons to the add-node modal, and make its existing input fields focusable by click. Preserve validation and the current node-add result path.
- [x] Give offline opening and filtering progress dialogs a Cancel button. During cancellation, show a disabled Cancelling state and retain the modal until worker cleanup finishes; never turn cancellation into immediate dismissal.
- [x] Preserve and expose existing actionable progress/error states, including Retry cleanup and Quit where currently offered, through the same owner handlers. Informational text such as Waiting for cleanup remains text.
- [x] Audit every `RenderModal` call and every `activeModal` branch. Replace actionable footer hints with structured actions, and verify every adapter and nested layer participates in shared routing. Update TUI architecture guidance to explain shared geometry and action ownership.

### Validation, documentation, and completion

- [x] Test shared behavior rather than duplicating presentation assertions: disabled actions, focused Enter/Space, context shortcuts while typing, one activation per gesture, button padding versus gaps, and focus changes when controls disappear.
- [x] Extend host tests for nested layers, click-through prevention after Apply/Cancel/confirmation, modal replacement, resize before render, wrapped action bars, scrolling, Unicode widths, and tiny-terminal fallback. Keep existing outside-dismiss tests passing.
- [x] Test protocol row stability and selection-result parity between keys and clicks. Test double-click identity/reset behavior with explicit timestamps rather than sleeps.
- [x] Test file navigation, breadcrumb targets, open/save modes, inline edit cancellation, filename validation, existing-file confirmation, folder-creation errors, and each settings/export host using temporary fixture directories.
- [x] Test filter row/checkbox separation, search/type/status controls, editor focus and validation, async list refresh, pending submission, deletion confirmation, hunter selection cancellation, mixed-capability hunter lists and bulk actions, and parent draft preservation.
- [x] Test offline progress cancellation and cleanup retry through buttons, including repeated clicks and cleanup failures, without bypassing existing lifecycle checks.
- [x] Run `go test -tags all ./internal/pkg/tui/...`, `go test -tags tui ./internal/pkg/tui/...`, and `go vet -tags all ./internal/pkg/tui/...`. Run targeted race tests when shared asynchronous handling changes; ask before running tests outside the sandbox if necessary.
- [x] Build the TUI variant with `go build -tags tui -o /tmp/lippycat-clickable-modals-check .` and remove the temporary binary afterward. Clean any task-owned temporary caches.
- [x] Manually exercise the dialogs in a terminal with mouse support and with keyboard only, in light/dark themes and narrow/short sizes. Verify scroll targeting, focus visibility, nested cancellation, and action reachability; record the cases exercised.
- [x] Update affected user documentation in `internal/pkg/tui/README.md`, `cmd/watch/README.md`, and the manual. For changed manual content, update every language in `docs/manual/languages.json`, review affected fuzzy translations, and run `make manual-check` and `make manual`.
- [x] Format changed files, review the scoped diff, record validation evidence below, and check off only verified tasks. Commit the implementation and updated plan together, excluding unrelated workspace changes.

## Completion criteria

All hosted modals expose their applicable actions through the shared button
component. The protocol selector, file dialog, and filter manager can be operated
with the mouse, with typing required only for text entry. Existing keyboard
workflows, cancellation results, asynchronous cleanup, and validation remain
correct. Clicking a modal action never activates the layer underneath it.

Rendering and hit testing use consistent geometry at supported terminal sizes;
essential actions remain available when content scrolls. No external widget
dependency or unrelated capture, protocol, or backend behavior changes are needed.

## Validation evidence

Closure: **CLOSED**. All scoped implementation tasks are complete. One bounded
closure review found two issues, both fixed and covered by regressions: contextual
Enter hints in the open-file dialog, and arrow-key focus visibility in a short
filter editor. The integrated post-fix review found no remaining material issue.

| Check                                                                                                                                                     | Result                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `go test -tags all ./internal/pkg/tui/...`                                                                                                                | Passed                                                                                              |
| `go test -tags tui ./internal/pkg/tui/...`                                                                                                                | Passed                                                                                              |
| `go vet -tags all ./internal/pkg/tui/...`                                                                                                                 | Passed                                                                                              |
| `go test -race -tags all ./internal/pkg/tui ./internal/pkg/tui/components -run 'TestModalActions\|TestButtons\|TestFilterModal\|TestFileDialog' -count=1` | Passed                                                                                              |
| `go build -tags tui -o /tmp/lippycat-clickable-modals-check .`                                                                                            | Passed                                                                                              |
| `make manual-check manual`                                                                                                                                | Passed in a writable temporary mirror of the final manual sources and catalogs; both editions built |
| Formatting and `git diff --check`                                                                                                                         | Passed                                                                                              |

Go commands used the task-owned cache
`GOCACHE=/tmp/lippycat-clickable-modals-cache`. Tests ran without requiring
outside-sandbox execution. Temporary previews, binaries, caches, and runtime
configuration were removed after validation.

Production-boundary coverage includes all file-dialog hosts through `Model.Update`,
one overwrite confirmation with draft-preserving cancellation, consumption of the
remaining mouse gesture after Apply, and cancellation/retry/quit through real
offline worker and cleanup fixtures. Component tests cover button geometry,
Unicode wrapping, disabled controls, focus, shortcuts, protocol row stability,
double-click identity/reset, file navigation/errors/validation, filter pending
operations, stable selection, and capability-filtered hunter drafts.

Manual checks used the actual TUI with the bundled DNS PCAP at 100x30: protocol
row click and Apply, Tab focus and Esc, export dialog and Cancel, and Quit
confirmation. A temporary real Bubble Tea preview with controlled data exercised
filter row selection/editing, typed descriptions, nested hunter All/Cancel with
parent draft preservation, standalone hunter toggles/confirmation, add-node field
focus/editing, and generic confirmation cancellation. At 44x18 and 70x13, wheel
scrolling and Tab traversal kept actions and focused controls reachable; at
18x6, the compact resize fallback retained Esc cancellation. No live remote node
or backend modification was used for these checks.

A temporary 64-case rendering matrix covered eight dialog states at 100x30,
44x18, 70x13, and 18x6 with dark/light terminal-background hints. The application
currently has one Solarized palette, so this verifies the supported palette under
both hints rather than claiming two separate application themes. Non-fallback
canvases exposed every action hit region without terminal-width overflow.

All ten new or changed modal manual messages have reviewed, non-fuzzy German
translations. Existing unrelated untranslated manual messages remain unchanged;
all affected modal content was verified in the rendered German edition.

The implementation and this completed plan are committed together. No changes
to dependency versions or backend filtering/subscription contracts were needed.
