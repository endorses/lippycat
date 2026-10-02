# Remote node resource utilization colors

Status: implemented and verified in `feature/tui-node-change-highlighting`.

## Behavior and compatibility

Replace CPU/RAM change flashes and arrows with persistent foreground colors:
normal/default below 70%, Solarized orange at 70%, and Solarized red at 90%.
These are configurable presentation defaults, not performance acceptance gates
or changes to node health. Require three distinct telemetry observations before
escalating; clear orange below 65% and red below 85% to avoid boundary flicker.
For custom thresholds the hysteresis margin is the smaller of five percentage
points, half the elevated threshold, and half the gap between thresholds.

CPU utilization is the existing process CPU percentage divided by effective CPU
capacity in cores. Keep the existing displayed percentage and wire field meaning
(100% is one core); capacity may be fractional. Memory utilization is process RSS
divided by the reported cgroup memory limit, an approximate process-to-limit
ratio rather than a complete measurement of cgroup memory pressure.

Add optional-by-default protobuf scalars for capacity and the actual metrics
sample timestamp using new field numbers. Zero or invalid capacity means unknown.
The sample timestamp prevents cached status responses or packet-only heartbeat
updates from advancing escalation. New clients keep resources neutral for older
nodes or intermediaries that omit the sample timestamp; old clients continue
consuming the original fields unchanged. Missing CPU capacity or memory limits
likewise leave the corresponding metric neutral. Normal and
quiet modes both retain resource foregrounds. Existing counter/filter/lifecycle
highlights and their base3 foregrounds remain in place.

Linux capacity collection must account for CPU affinity and visible cgroup v1/v2
quota constraints, including fractional quotas and more restrictive ancestors.
Do not substitute GOMAXPROCS for capacity. Unsupported or indeterminate capacity
remains unknown. Keep collection bounded and avoid new polling/timer chains.

## Tasks

- [x] Add Linux effective-capacity collection and deterministic coverage for affinity, quota parsing, ancestors, unlimited quotas, malformed/unavailable data, and non-Linux fallback.
- [x] Add the protobuf capacity and sample timestamp fields without renumbering or changing existing fields; regenerate Go bindings and verify old/new wire compatibility.
- [x] Propagate capacity through hunter statistics, tap/local source, processor management/status forwarding, remote conversion, and TUI topology reconciliation.
- [x] Replace CPU/RAM transient changes with persistent utilization state and foreground styling in tree, flat, and graph views; preserve selection, quiet mode, and unknown telemetry behavior.
- [x] Add configurable utilization thresholds, hysteresis, and escalation based on distinct reports; duplicate snapshots and redraws must not advance escalation.
- [x] Add focused collector, telemetry propagation, compatibility, classification, and rendered-color regression tests; retain counter rounding/expiry coverage.
- [x] Update user documentation and every configured manual translation, documenting units, thresholds, unknown/old peers, and memory limitations.
- [x] Run relevant tests/vet, specialized build checks, `make manual-check`, and `make manual`; format, inspect the scoped diff, and commit implementation and completed plan together.

## Validation

Passed package tests for `sysmetrics`, generated management protobufs, hunter
stats, processor hunter management, processor/local source, remote conversion,
CLI status JSON, and all TUI packages. Regression coverage includes a legacy
protobuf reader, unknown-field forwarding and omission, distinct sample identity,
fractional CPU allocation, concurrent metric snapshots, topology conversion,
threshold hysteresis, and actual terminal colors. Race checks passed for
`sysmetrics` and the new hunter/source snapshot tests. Vet passed across the
changed backend and TUI packages.

The full processor suite passed outside the sandbox after its normal filesystem
ownership checks rejected the sandbox's `nobody` ownership of `/` and `/tmp`.
No secure-storage checks were changed. A new TUI view-switch test initially
lacked a selected hunter; its fixture was corrected and both the focused test
and full TUI suite passed.

Hunter, processor, tap, and TUI specialized builds passed. The sysmetrics test
binary also cross-compiled for Darwin to verify the unsupported-platform path.
`make manual-check` and `make manual` passed for English and German, with all new
and changed manual paragraphs translated. Temporary cache and binaries were
removed after validation.

Capacity uses process-leader affinity and visible ancestor quotas; hidden
ancestors and competition from other processes cannot establish a guaranteed
reservation. RAM classification uses the existing reported memory limit and
RSS, not total cgroup consumption. Older peers without the new sample identity
remain neutral while their numeric values are still displayed.
