# Offline dataset phase 6 acceptance

Date: 2026-09-05. This closes the release acceptance work in the
[offline dataset plan](../plans/watch-file-scalable-offline-dataset.md).
The [dataset measurement report](watch-file-offline-phase6-benchmarks.md)
records fixed-budget storage/indexing, complete queries, memory profiles,
multi-source behavior, cancellation and browsing latency.

## Independent correctness and failure checks

| Requirement                             | Evidence                                                                                                                                                                                                                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Complete global and matching statistics | `offline.TestReleaseStatisticsAndDetailsFullScanReference` independently accumulates all statistics fields over a generated 12,017-record, four-protocol reference; it never uses the production accumulator or summary adapter for expected values.                           |
| Actual input/indexer agreement          | `tui.TestOfflineReleaseIndexerFullScanReference` reads source PCAPs independently with pcapgo, stable-sorts the small test-only reference, and compares complete global/matching statistics, raw bytes, timestamps, link types, source/sequence and captured/original lengths. |
| Reload after eviction                   | Both reference tests reread beginning/middle/end details after hundreds of distinct reads under a 128 KiB cache; the storage test asserts that each selected detail really left the LRU before reload. Global and matching statistics remain unchanged.                        |
| OS and configured disk exhaustion       | `TestReleaseStorageOSDiskFullNeverPublishes` injects actual `/dev/full` ENOSPC after a valid record; `TestStorageSharedDiskLimitsAndFailureCleanup` covers configured/shared limits while preserving an existing dataset.                                                      |
| Permission errors                       | `TestReleaseStoragePermissionDenied` removes directory write permission and checks EACCES, no builder and no disk charge. It skips when run as root; the acceptance run uses an unprivileged user.                                                                             |
| Truncated/incompatible storage          | `TestStorageCorruptionRejected` covers record truncation and unsupported schema versions.                                                                                                                                                                                      |
| Late source failure                     | `TestOfflineReleaseLateSourceTruncationNeverPublishes` corrupts a source's final record after valid input, then checks no successful session/Ready state and zero remaining disk charge.                                                                                       |
| Analyzer finalization failure           | `TestOfflineReleaseAnalyzerFinalizationFailureNeverPublishes` independently proves the SIP fixture's per-packet Assemble calls succeed but EOF Close fails, then checks that the complete indexer rejects publication and cleans storage.                                      |
| Replacement and cleanup failures        | `TestOfflineLifecycleAtomicReplacementAndFailure`, `TestOfflineFailedOpenCleanupRetainsRetryModal`, and `TestStorageCleanupCanRetryAfterRemovalFailure` verify prior-session preservation and explicit cleanup retry.                                                          |
| Complete exports and query ownership    | Existing 4,097-packet roundtrips, timestamp/link/error rejection, cancellation, save-key dispatch, snapshot pins and abandoned worker tests remain in the full suite.                                                                                                          |

The reference slice exists only in a small test. Production offsets, match IDs,
and records remain disk-backed; no acceptance code is added to production paths.

## Mixed-mode event correctness

`TestEventPhase6MixedModeAcceptance` runs the same controlled interaction sequence
through local delivery, remote delivery, and retained history in a published
offline session. It verifies exact arrival/retention/eviction counters, one
incremental projection per due interval, intersecting protocol/source/user
filters, keyboard and mouse selection, resizing, detail scrolling, read-only
rendering, pause/resume, explicit loss accounting, and clearing event history
without clearing offline packets. Offline indexing and EOF delivery are verified
separately by the full-indexer tests; this interaction test does not simulate a
still-running stream after offline publication.

Existing randomized rendering-equivalence/purity, incremental cursor, duplicate
event-ID, remote backlog/pause, related-packet identity/eviction and offline
distant-packet navigation tests also remain acceptance requirements. Their
coverage preserves live/remote rings and does not reinterpret cache eviction as
capture loss or promise complete event/call history.

## Repeated event performance

Same host and workload as the [phase 0 baseline](watch-file-offline-baseline.md):
Linux amd64, Core i9-13900HX, Go 1.26.3, GOMAXPROCS 32, `all`, no race
instrumentation, 160×40 viewport. Five one-second samples per benchmark; reported
values are medians. These timings exclude a physical terminal driver and network
transport. DNS replay includes decoding, the production analyzer and bounded
delivery, 50 packets per iteration. Component benchmarks isolate their named
operation.

| Workload                                                  |           Median | Allocations/op | Acceptance                                      |
| --------------------------------------------------------- | ---------------: | -------------: | ----------------------------------------------- |
| DNS analysis/delivery, tick and Events render, 50 packets |         1.618 ms |          6,319 | Pass: ≤1.79 ms and ≤6,952 allocations           |
| Prepared timeline, 1,000 retained                         |         0.225 ms |            648 | Comparable to 10,000-row viewport cost          |
| Prepared timeline, 10,000 retained                        |         0.223 ms |            648 | Pass: ≤0.280 ms and ≤713 allocations            |
| Unprepared timeline, 10,000 retained                      |         0.466 ms |          1,726 | Control; prepared rendering is about 52% faster |
| Incremental append, 1,000 / 10,000 retained               |   137 / 169.5 ns |          0 / 0 | No full retained-history rebuild                |
| Unfiltered store delta, 1,000 / 10,000 capacity           | 140.4 / 144.0 ns |          1 / 1 | Approximately constant per delta                |
| Filtered store delta, 1,000 / 10,000 capacity             | 124.2 / 124.4 ns |          0 / 0 | Approximately constant per delta                |
| Cached related-packet miss, 1,000 / 10,000 retained       |   207 / 206.1 ns |          1 / 1 | Independent of retained packet count            |

Run the repeated comparison with:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/tui ./internal/pkg/tui/components ./internal/pkg/tui/store \
  -run '^$' -bench 'BenchmarkModelEventDNSReplay$|BenchmarkEventsViewRenderTimeline$|BenchmarkEventStoreIncrementalProjection$|BenchmarkEventsViewAppendIncremental$|BenchmarkHasRelatedPacketMiss$|BenchmarkEventPhase6' \
  -benchtime=1s -count=5 -benchmem
```

A separate five-second DNS replay CPU profile measured 1.466 ms/op and 6,319
allocations. `RenderTimeline` accounted for 6.09% cumulative CPU and update-side
`buildTimelineCache` for 9.88%; reporting both includes formatting work moved out
of rendering. The prior event-plan profile reported 5.57% and 9.89%, respectively.
This is consistent with preserving the optimized path, not a claim of another
Phase 6 rendering speedup. Reproduce with the same replay selector,
`-benchtime=5s -cpuprofile=/tmp/lippycat-phase6-events.cpu`, then
`/tmp/lippycat-phase6-pprof -top -cum /tmp/lippycat-phase6-events.cpu` (tool build
instructions are in the dataset report).

## Per-view CPU and allocations

`BenchmarkEventPhase6ModeViews` feeds the same 50-packet/50-event batch into
10,000-entry live/remote stores, ticks and renders each active view. Live mode
also receives its separate exact ingress-telemetry snapshot. Assertions verify
packet/event arrivals, retained counts, and that only the Events view projects
the stream. This measures delivery/model/presentation work, not NIC or gRPC
throughput. Fixed-flow fixtures intentionally isolate presentation costs.

| Mode   | Active view | Median per 50-packet cycle | Allocated bytes/op | Allocations/op |
| ------ | ----------- | -------------------------: | -----------------: | -------------: |
| Live   | Events      |                   0.787 ms |            499,459 |          2,051 |
| Live   | Packets     |                   0.464 ms |            306,839 |          1,391 |
| Live   | Statistics  |                   0.284 ms |            209,793 |            692 |
| Remote | Events      |                   0.732 ms |            505,786 |          2,031 |
| Remote | Packets     |                   0.462 ms |            312,468 |          1,431 |
| Remote | Statistics  |                   0.295 ms |            209,458 |            672 |

Both modes keep exactly 10,000 events/packets and account for every supplied
batch. Statistics and Packets do not spend CPU projecting hidden event history.
The benchmark passes synthetic packets without raw bytes to the existing
background processor; full background protocol analysis and transport throughput
are outside this measurement. Every model is shut down after its sample.
Initial development samples with the remote model still on its default Nodes tab
or missing the remote packet identity were discarded. Final assertions prevent
either setup error from silently producing reassuring timings.

`BenchmarkEventPhase6OfflineReadyViews` indexes 20,000 DNS/ordinary-UDP packets,
publishes the actual session and loads the selected page/detail/relationship
before timing idle ticks and rendering. It asserts that idle ticks never
reproject event history. Each ready-mode iteration costs 0.751 ms / 0.436 ms /
0.243 ms for Events / Packets / Statistics, respectively, with 1,600 / 1,410 /
657 allocations. Median allocated bytes are 322,711 / 146,688 / 48,126 per
iteration, not retained memory. At the idle one-second tick interval the Events
measurement represents about 0.075% of one CPU core for this work alone; terminal,
runtime and input activity are additional. Storage/analyzer retained and sampled
peak memory are reported separately in the dataset measurements.

## Terminal acceptance

Scripted standard-library PTYs ran the built `all` and `tui` binaries with
explicit temporary configuration and isolated working/config directories. Each
offline run opened a generated 257-record PCAP with buffer size 8, exercised
End/Home/details, applied `src:192.0.2.2`, and used the real `w` filename dialog.
Independent readback verified all 86 matching exported records, including exact
bytes, timestamps and captured/original lengths. Events/Statistics switching,
160×40 to 100×28 resizing and quit passed with exit 0 and no panic.

A remote PTY connected to a temporary localhost processor, exercised Nodes,
Events, Statistics, pause/resume and resizing, then quit cleanly. Processor logs
confirmed subscription/unsubscription and the processor exited cleanly after
SIGTERM. This checks connection and terminal lifecycle; controlled remote event
traffic and pressure accounting are covered by the model tests and benchmarks.

Raw loopback capture was attempted but libpcap reported `Permission Denied`;
the environment has no noninteractive sudo grant. No system capabilities or
privileges were changed. `TestPhase6LiveTerminalSmoke` instead runs the actual
Tea program in a PTY with controlled 10 Hz live packet/event delivery, exercising
Events/Packets, details, selection, pause/resume, resize and Statistics. It checks
bounded retention, eviction and zero unexplained transport loss. This closes
live terminal presentation acceptance at the delivery boundary, not privileged
NIC capture or network throughput. Those unchanged paths are not inferred from
these measurements.

Reproduce the opt-in live terminal test with a compiled TUI test executable in
an interactive terminal:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -c -tags tui \
  -o /tmp/lippycat-phase6-terminal.test ./internal/pkg/tui
LIPPYCAT_PHASE6_TERMINAL_SMOKE=1 /tmp/lippycat-phase6-terminal.test \
  -test.run '^TestPhase6LiveTerminalSmoke$' -test.v
```

Use `v`, arrows, `d`, Space twice, resize, switch tabs and `q`. Normal suites skip
this opt-in interactive test. The run's scripts, terminal transcripts, exports
and independent checks were recorded under `/tmp/lippycat-phase6-smoke/`; the
checked-in tests and descriptions above provide lasting reproduction instructions.

## Verification commands

All commands below passed: uncached full focused suites under both build tags,
uncached full offline/TUI race suites, and both binary builds. The opt-in live
terminal test also passed separately with 51 arrivals, 8 retained, 33 evicted,
10 paused and zero transport loss; root independently reran its PTY harness.

```sh
GOCACHE=/tmp/lippycat-go-cache go test -count=1 -tags all \
  ./internal/pkg/capture ./internal/pkg/offline ./internal/pkg/tui/... ./cmd/watch
GOCACHE=/tmp/lippycat-go-cache go test -count=1 -tags tui \
  ./internal/pkg/capture ./internal/pkg/offline ./internal/pkg/tui/... ./cmd/watch
GOCACHE=/tmp/lippycat-go-cache go test -count=1 -race -tags all \
  ./internal/pkg/offline ./internal/pkg/tui/...
GOCACHE=/tmp/lippycat-go-cache go build -tags all -o /tmp/lippycat-phase6-all .
GOCACHE=/tmp/lippycat-go-cache go build -tags tui -o /tmp/lippycat-phase6-tui .
```

No capture or shared packet-type implementation changed in Phase 6, so hunter,
processor, tap and CLI specialized-build changes are not required. New production
changes are presentation/help wording and removal of an unreachable transitional
warning. Operator documentation now describes complete packet scope, bounded
event/call scope, ordering rejection, resource settings, disk exhaustion,
replacement/cancellation and exact export semantics.
