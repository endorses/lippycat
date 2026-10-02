# Remote Nodes tab change highlighting

Status: implemented and verified on `feature/tui-node-change-highlighting`.

## Objective

Make changes in the remote-mode Nodes tab easy to spot using brief cell
highlights, directional indicators, and clear connection/health markers. Preserve
the existing table and graph layouts, navigation, and status meanings. The user
does not want split-flap animation; values update immediately, with a temporary
highlight that expires.

## Agreed direction and scope

| Change                                            | Presentation                                                                         |
| ------------------------------------------------- | ------------------------------------------------------------------------------------ |
| CPU or RAM displayed value changes                | Brief neutral cell highlight and an up/down arrow                                    |
| Captured or forwarded counters advance            | One subtle activity marker per node, without flashing both counters                  |
| Active filter count changes                       | Highlight the count with a temporary signed delta                                    |
| Hunter or processor joins an established topology | Temporary `NEW` marker and a subtle node accent                                      |
| Connection or reported health deteriorates        | Highlight the status area; retain the existing health/connection indicator afterward |
| Connection or reported health recovers            | Temporary `RECOVERED` marker; restore the current status styling                     |
| Node disappears through a confirmed disconnect    | Record the removal in a stationary recent-event line                                 |

Direction is distinct from severity. Rising CPU, RAM, or traffic does not itself
create a warning. Existing reported health and connection states remain the
authority for red/amber/green status styling. Use arrows and labels so color is
not the only signal.

Use a single temporary highlight followed by normal styling. Start with a
one-second metric highlight and a five-second lifecycle marker. These are
adjustable interaction defaults, not performance acceptance gates. Repeated
identical reports must not extend a highlight. A newer actual change replaces the
previous direction/delta and starts a new expiry.

Include a quiet preference that suppresses temporary backgrounds and border
accents while retaining textual change markers, current status, and the event
line. Do not add scrolling tickers, character rolling, blinking loops, automatic
row sorting by activity, or new packet-rate columns in this implementation.

Freshness alarms are a separate follow-up: unchanged counters cannot establish
stale telemetry, and locally generated direct-hunter status callbacks do not
prove a successful remote poll. This work must not invent a stale/offline state
from inactivity. Keep missing values distinct from zero and preserve existing
connection-state behavior.

## Existing integration points

| Area                 | Files and current behavior                                                                                                                          |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Remote status input  | `internal/pkg/remotecapture/client_subscriptions.go` polls processor hunter status every two seconds; topology changes also arrive through a stream |
| TUI messages         | `internal/pkg/tui/eventhandler.go` forwards status, topology, and disconnect messages into the Bubble Tea loop                                      |
| State reconciliation | `internal/pkg/tui/capture_events.go` merges status into topology and calls `NodesView.SetProcessors` from several paths                             |
| Node component       | `internal/pkg/tui/components/nodesview.go` owns selection, viewport content, table/graph mode, and the current node snapshots                       |
| Rendering            | `internal/pkg/tui/components/nodesview/{table_view,graph_view,rendering}.go` formats values and applies status/selection styling                    |
| Refresh              | `internal/pkg/tui/update_handlers.go` and `model.go` already provide one recurring tick chain, including slower ticks while paused/inactive         |
| Preferences          | `internal/pkg/tui/preferences.go` and the settings components provide configuration integration                                                     |

Presentation is subscription-filtered, so a row disappearing from a displayed
snapshot is not sufficient evidence of a disconnect. Initial topology discovery,
explicit subscription changes, and reconnect snapshots must be distinguishable
from new lifecycle events.

## Implementation tasks

### Change tracking and event semantics

- [x] Introduce a small node-change tracker owned by the TUI component, with explicit timestamps and immutable previous-value snapshots. Keep it independent of network operations and output styling.
- [x] Key processors by their established address identity and hunters by owning processor identity plus hunter ID, resolving hierarchical address/ID aliases at the reconciliation boundary. Never key changes or selection by row index alone.
- [x] Establish a baseline on initial discovery and first metrics receipt for each node. Unknown-to-known CPU/RAM values initialize their baseline without directional highlights. Opening the tab, resizing, changing theme, or changing view must not generate changes.
- [x] Compare formatted CPU/RAM values using the existing formatting contract before highlighting. Derive direction from the underlying values only after a visible change is established. Ignore ordinary uptime and heartbeat progression.
- [x] Compare packet totals for a single node activity cue. A counter decrease resets the baseline rather than producing underflow, negative traffic, or an inferred restart. Clear activity when telemetry is unavailable or the connection is lost.
- [x] Compute filter deltas against the preceding observed count. Retain normal values after transient deltas expire.
- [x] Feed explicit connection/topology transitions into the tracker before removed nodes disappear. Deduplicate transitions also observed through status polling; unchanged reports and repeated snapshot setters are not events.
- [x] Suppress `NEW` events for initial/reconnect snapshots and user subscription changes. Emit recovery only after an observed disconnected/unhealthy state; a first healthy observation is a baseline.
- [x] Treat loss of a processor connection as loss of visibility through that processor, without fabricating independent disconnect events for every child. Preserve downstream state as required by the existing connection model.
- [x] Remove tracker entries when their node is removed or the remote session is reset; clear expired transient metadata. Do not retain an unbounded history of node identities.

### Table, graph, and recent-event presentation

- [x] Pass prepared per-node change state into table and graph renderer parameters. Render functions consume state without starting timers or mutating change history.
- [x] Add metric-cell accents, fixed-width direction/activity indicators, and filter deltas to tree and flat table views. Reserve indicator space so highlights appearing or expiring do not shift columns.
- [x] Add a brief border accent and changed-value emphasis to graph nodes, sharing the same change state as the table. Do not rearrange graph layout on metric updates.
- [x] Define style precedence: selection remains identifiable, health symbols remain legible, and transient highlights use remaining cell/border styling. Verify both light and dark themes and reduced-color terminals.
- [x] Preserve selection by stable node identity across insertions, removals, and sorted snapshots. When the selected node actually disappears, choose a deterministic nearby valid selection and preserve reasonable scroll position.
- [x] Add one stationary recent-event line for lifecycle and health transitions, including removals. Keep a bounded ring of 20 entries, show the latest event with its age, and expose a count of additional events in the preceding 30 seconds. These are presentation defaults; no history browser or persistence is required.
- [x] Keep the event line in a fixed layout slot when space permits, clear its display after 30 seconds, and omit it on very short terminals. Account for its space in viewport sizing, mouse hit regions, scrollbars, and text selection.
- [x] Fit long node names and badges through existing width-aware truncation. Prefer retaining node identity, current status, and metric values over optional deltas or labels on narrow terminals.

### Refresh and preferences

- [x] Advance expiry using the existing `TickMsg.Time` path, including paused/inactive remote mode. Do not create a second recurring tick chain, per-cell goroutines, or network polling.
- [x] Refresh Nodes viewport content when a visible value, highlight state, or displayed event age changes. Clean ticks do not need to rebuild the node tree; low-frequency ticks may expire cues on their next delivery.
- [x] Track updates while another tab is active, but do not replay expired highlights when returning. Switching table/graph views preserves the original expiry and does not create events.
- [x] Add a remote Nodes highlighting preference with `normal` and `quiet` modes, defaulting to `normal`, using the existing settings/configuration patterns. Handle preference load/save errors through the project's logging conventions.

### Verification, documentation, and completion

- [x] Add deterministic tracker tests with an injected clock for baseline behavior, displayed-value comparison, direction, expiry, repeated reports, filter deltas, counter resets, and recovery semantics. Avoid sleep-based animation tests.
- [x] Test reconciliation with polling plus duplicate topology events, initial/reconnect snapshots, subscription changes, duplicate hunter IDs on different processors, and processor loss with downstream nodes.
- [x] Test selection preservation when sorted nodes are inserted or removed, and ensure removed-node tracker state is cleaned up while bounded recent-event text remains available.
- [x] Extend table/graph rendering tests for selected changed nodes, fixed column widths, narrow/short terminals, missing metrics, quiet mode, and theme variants. Verify mouse hit regions, scrolling, and text selection with the event line present.
- [x] Test expiry through the existing tick path during pause and tab changes, including event-line aging without fresh network messages. Verify no duplicate recurring tick chain is introduced.
- [x] Run `go test -tags all ./internal/pkg/tui/...`, `go vet -tags all ./internal/pkg/tui/...`, and `go build -tags tui -o /tmp/lippycat-node-highlighting-check .`; remove the temporary binary afterward. Ask before running tests outside the sandbox if needed.
- [x] Manually inspect remote table and graph views with controlled metric, connection, and topology updates. Verify highlights remain readable over SSH and in both themes; do not use production node disruptions for validation.
- [x] Document the cues, quiet preference, and distinction between activity and health in `internal/pkg/tui/README.md` and `cmd/watch/README.md`, updating the manual where those settings are described.
- [x] Format changed files, review the scoped diff, record validation results here, and check off only verified tasks. Commit the implementation and updated plan together, excluding unrelated workspace changes.

## Completion criteria

The implementation is complete when meaningful observed changes receive the
specified cues in remote table and graph views, duplicate/initial/subscription
updates remain quiet, selection stays attached to its node, and transient state
expires without additional network activity. Existing local and offline capture
behavior remains intact. Validation covers the correctness and presentation
requirements above; this plan introduces no latency, throughput, CPU, or memory
performance acceptance target.

## Validation and closure

Implemented in the dedicated `lippycat-node-highlighting` worktree. The single
closure review found four concrete issues, all repaired with focused regression
coverage: polling before a join event, selected-row ANSI styling, reconnect metric
baselines, and self-origin processor reconnect events. The final establishment
baseline correction covers initial status/stream messages even when the optional
full topology request is unavailable.

Validation passed:

- `go test -tags all ./internal/pkg/tui/... ./internal/pkg/remotecapture`
- `go vet -tags all ./internal/pkg/tui/... ./internal/pkg/remotecapture`
- `go build -tags tui -o /tmp/lippycat-node-highlighting-check .`
- `make manual-check` and `make manual` for English and German; every added manual
  entry is translated and non-fuzzy.
- Controlled actual-component terminal inspection of table/graph views, selected
  and unselected nodes, both theme palettes, normal/quiet modes, narrow/short
  terminals, join/recovery events, metric deltas, and expiry.
- Isolated local OpenSSH transport of the same controlled component output. The
  received frames matched local output byte-for-byte after newline normalization,
  including ANSI colors and Unicode cues. Local PTY inspection and SSH stream
  transport were checked separately; no production node or remote host was used.

The isolated SSH test required disabling strict authorized-key path checks only
in its temporary server configuration because its keys were under `/tmp`. No
user/system SSH configuration was changed. Temporary fixtures, binaries, and keys
were removed. Existing unrelated untranslated manual entries were not changed.

Closure: all scoped implementation and verification obligations are satisfied.
The implementation and this completed checklist are committed together.
