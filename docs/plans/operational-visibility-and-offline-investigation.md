# Operational visibility and offline investigation implementation plan

**Date:** 2026-10-25
**Status:** Complete; all six selected workstreams implemented, verified and committed
**Assessment baseline:** `8ba8ed27`
**Scope:** Six ordered workstreams selected from the existing plans and research

## Objective

Strengthen failover integration coverage, expose encrypted-traffic visibility,
make existing detection decisions available as structured notices, and improve
offline investigation completeness and readiness. Then extend protocol analysis
with SSH fingerprints and a bounded QUIC feasibility study.

This document owns the implementation sequence and the scope selected from the
original documents. It does not reopen their completed milestones or adopt every
unchecked item. All implementation tasks below remain unchecked until verified.
Implementation was authorized after plan creation. Preserve the selected scope
and verify each increment before marking it complete.

## Sequence and release boundaries

| Order | Workstream                          | Deliverable                                                                                     | Dependency and release boundary                                                                                     |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1     | Failover integration follow-up      | Actual hunter switching between independent processors, with protocol and custody assertions    | Builds on the completed failover implementation; an independent, bounded follow-up                                  |
| 2     | TLS ECH visibility                  | Explicit ECH-offer metadata and trustworthy ClientHello counts across supported capture paths   | Builds on completed JA3/JA3S/JA4 work; independently releasable                                                     |
| 3     | Notice foundation and DNS migration | Typed DNS tunneling notices, `notice.log`, command compatibility, and local/remote TUI delivery | Reuses the implemented event platform; ship foundation, durable output, and interactive output as scoped increments |
| 4     | Complete offline Events history     | Disk-backed complete event browsing and asynchronous filtering for `watch file`                 | Extends the existing offline session; includes new ECH and notice metadata where applicable                         |
| 5     | Compact-index Milestone B           | Complete-base browsing while ordered analysis continues, with immutable analysis revisions      | Integrates workstream 4's complete event history into completed analysis publication                                |
| 6     | SSH/HASSH, then QUIC feasibility    | Production SSH metadata and fingerprints, followed by a report and reproducible QUIC spike      | Reuses the extended event, query, log, and offline paths; full production QUIC analysis is a separate decision      |

The order expresses priority, not a technical dependency between every adjacent
row. Workstreams 1 and 2 do not require notice or offline changes. Keep each
workstream independently reviewable; do not combine all six into one release or
pull request. Coordinate changes to shared schemas and offline ownership rather
than developing conflicting contracts in parallel.

## Original plans and research

| Source                                                                                                                                     | Selected scope and disposition                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Hunter processor failover](hunter-processor-failover.md#implementation-and-validation-checkpoint--2026-10-17)                             | The final remaining-work list: actual hunter deployment coverage, selected crash boundaries, and TCP/VoIP handover. The core release stays complete. |
| [Hunter failover research](../research/hunter-processor-failover.md)                                                                       | Endpoint, custody, replay, and independent-processor versus common-upstream semantics.                                                               |
| [TLS fingerprinting roadmap](tls-fingerprinting-roadmap.md)                                                                                | Phase 1 ECH visibility, Phase 5 SSH/HASSH, and Phase 6 QUIC spike. Phase 0 is already implemented.                                                   |
| [Alerting and notice pipeline](../research/alerting-and-notice-pipeline.md#suggested-delivery-phases)                                      | Delivery phases 1–3: notice foundation, DNS migration, and durable/interactive outputs.                                                              |
| [Structured event transport and TUI](structured-protocol-event-transport-and-tui.md)                                                       | Existing event identity, authority, negotiation, sensitive-field projection, subscriptions, and loss contracts.                                      |
| [Structured protocol logs](structured-protocol-logs.md)                                                                                    | Existing schema/rotation/sink contracts; add genuine transport-to-log coverage alongside these changes.                                              |
| [Scalable offline dataset](watch-file-scalable-offline-dataset.md#deferred-optimizations-and-extensions)                                   | The explicitly deferred complete disk-backed event history and asynchronous event-filter extension.                                                  |
| [Compact source-backed index](watch-file-compact-source-index.md#phase-5--publish-a-complete-base-before-analysis-finishes)                | Milestone B, original Phases 5–6, excluding optional persistent index reuse. Milestone A stays complete.                                             |
| [Offline contracts](../design/watch-file-offline-contracts.md) and [field inventory](../design/watch-file-packet-field-inventory.md)       | Field readiness, source lifetime, budgets, query/export semantics, and ownership.                                                                    |
| [Zeek log expansion assessment](../research/zeek-log-expansion-assessment.md) and [completed first wave](zeek-log-expansion-first-wave.md) | Reuse the typed producer-to-consumer integration pattern for notice and SSH events. DHCP, NTP, and inventories are already delivered.                |

Where historical text conflicts with current code, establish the current contract
with a focused source check before editing. In particular, TLS packet metadata
and versioned typed event transport already exist; extend their current messages
instead of recreating the older roadmap's proposed infrastructure.

## Shared implementation requirements

- [x] Record the starting commit and any existing working-tree changes for each
      workstream. Preserve unrelated work and read the applicable directory
      `AGENTS.md` files before implementation.
- [x] Extend the shared analysis runtime and typed event contracts. Preserve
      processor authority in packet mode and edge authority in event mode; avoid
      producing the same canonical observation at both ends.
- [x] Preserve stable event identity, origin provenance, flow identity, configured
      bounds, authorization, expiry, and existing durability semantics. Keep
      subscriber loss separate from producer loss and local retention eviction.
- [x] Make protobuf changes additive, regenerate checked-in code through the
      repository's generator, and test capability negotiation and mixed versions.
      Keep sensitive fields subject to existing projection policy.
- [x] Keep live packet processing independent of slow log/TUI sinks. Offline
      complete-history construction may apply bounded backpressure to its own
      analysis pipeline; storage failure must produce an explicit failure rather
      than a falsely complete result.
- [x] Use the latest stable dependencies if a new dependency is necessary, verify
      compatibility and licensing, and prefer existing project facilities where
      they already satisfy the requirement.
- [x] Update affected user documentation with each delivered feature. For manual
      edits, update every language in `docs/manual/languages.json`, review affected
      fuzzy translations, and run `make manual-check` and `make manual`.
- [x] Format changed files before staging, record relevant verification evidence,
      update only the original checklist items actually fulfilled, and commit the
      implementation together with this plan's corresponding progress updates.

Acceptance concerns correctness, explicit completeness, lifecycle behavior, and
configured resource limits. Record performance observations where useful without
inventing throughput, latency, restart, soak, CPU, or RSS acceptance targets. An
agent-written target in an older plan supplies no independent acceptance
authority. Preserve established correctness and safety requirements.

## Workstream 1 — Failover integration follow-up

**Original scope:** The final remaining-work list in
[the failover plan](hunter-processor-failover.md). The completed core and its
documented limitations remain the baseline.

**Touchpoints:** `internal/pkg/hunter`, `internal/pkg/hunter/connection`,
`internal/pkg/processor`, `internal/pkg/processor/upstream`, existing reliable
packet and relay integration tests, and `test/` integration harnesses.

### Implementation

- [x] Build a reusable harness with an actual hunter runtime and two independent
      processor runtimes. Use deterministic generated packet/event input and
      ephemeral loopback listeners; exercise production registration, transport,
      failover selection, and shutdown rather than substituting fake services for
      both processors. Keep privileged capture optional and separately identified.
- [x] Exercise raw-packet and normalized-event forwarding in separate producer
      sessions. Disconnect the active processor, observe backup selection, recover
      the first processor, and assert the existing sticky-destination behavior.
- [x] Assert filter readiness, selected destination/status, producer identity,
      source/epoch isolation, and actual output at the receiving processor. State
      expected losses separately for best-effort delivery and configured reliable
      delivery profiles.
- [x] Add selected composed reliable-delivery scenarios for receiver commit before
      a lost receipt, sender restart with retained work, and restart after a
      downstream effect but before its completion checkpoint. Reuse existing fault
      hooks and assert the documented custody/deduplication boundaries and
      at-least-once output behavior.
- [x] Add generated TCP and SIP/RTP handover scenarios, including replay after a
      configured protocol idle-expiry boundary and overlapping private addresses
      in different observation domains. Assert that expired/finalized state is not
      revived and independent processors do not inherit each other's analysis
      state. A common-upstream scenario must assert only the continuity supported
      by that topology.
- [x] Make readiness and completion assertions synchronize with explicit signals.
      Derive expiry cases from controlled clocks or configured timeouts, and keep
      test cleanup cancellable with all runtimes and owned storage joined/closed.
- [x] Correct only defects exposed within these supported scenarios, add focused
      regressions, and document scenario coverage and remaining limitations.

**Completion:** Real hunter-to-processor paths demonstrate the documented
failover, attribution, expiry, and custody behavior. This follow-up does not
require the whole historical optional matrix, automatic state replication,
matched-session TLS-key delivery, or new LI deployment validation.

## Workstream 2 — TLS ECH visibility

**Original scope:** [TLS roadmap Phase 1](tls-fingerprinting-roadmap.md#phase-1-ech-visibility-measurement).
JA3/JA3S/JA4 baseline work is already complete.

**Touchpoints:** `internal/pkg/tls`, `internal/pkg/types`, TLS metadata in
`api/proto/data.proto`, `internal/pkg/events`, `api/proto/events/v1`,
`internal/pkg/eventanalysis`, query/TUI projections, and TLS command summaries.

### Implementation

- [x] Define and document the counting unit as accepted, completely framed
      ClientHello observations at the canonical analysis authority. Distinguish
      observation counts from unique connections; define retransmission and
      midstream-capture behavior explicitly. Transport retry, serialization, and
      subscriber fan-out must not increment capture observations again.
- [x] Add explicit ECH-offer detection for the extension identified in the
      original plan and carry observation availability with the result. Preserve
      unknown/not-observed versus an observed ClientHello without that extension,
      including data received from older peers.
- [x] Extend existing TLS domain and wire metadata, runtime mappings, and typed
      event projections as needed. Ensure handshake coalescing does not erase the
      evidence needed by the documented numerator and denominator; do not assume
      every TLS summary represents exactly one ClientHello.
- [x] Expose ECH-offered and total-ClientHello counts in TLS summaries and the
      applicable TUI statistics/detail views. Carry sufficient typed evidence for
      equivalent reporting from sniff, tap, processor packet mode, hunter event
      mode, and offline analysis without a second counter authority.
- [x] Test complete and segmented ClientHellos, extension absence/presence,
      malformed/truncated extension bodies, ServerHello-only input, transport
      retries, and older metadata without the new fields. Retain byte-for-byte
      JA3/JA3S/JA4 regression expectations.
- [x] Document ECH offer visibility as an observation, without claiming acceptance
      by the server, visibility into the inner ClientHello, or application identity.

**Completion:** The reported fraction has a defined counting unit and preserves
unknown observations across modes. Existing fingerprints and filters continue to
work. Corpus evaluation, similarity fingerprints, and coherence scores remain
outside this workstream.

## Workstream 3 — Notice foundation and DNS migration

**Original scope:** Delivery phases 1–3 of
[notice pipeline research](../research/alerting-and-notice-pipeline.md#suggested-delivery-phases).
Reuse the current event/runtime/log/subscription platform.

**Touchpoints:** `internal/pkg/dns/tunneling.go`, DNS callback wiring in
`internal/pkg/processor`, `internal/pkg/events`, `internal/pkg/eventanalysis`,
`internal/pkg/logschema`, `internal/pkg/logstream`, `internal/pkg/eventquery`,
`api/proto/events/v1`, and local/remote TUI event adapters.

### A. Typed notices and DNS production

- [x] Define a versioned typed security-notice event with detector/version,
      category, severity, observation time, threshold/score evidence, and bounded
      references to contributing observations. Specify notice identity,
      debounce/suppression accounting, and the initial lifecycle semantics.
- [x] Anchor DNS notices in real observation provenance. A domain finding may
      aggregate several flows; retain bounded evidence references rather than
      inventing one synthetic flow or requiring an unrelated non-flow envelope
      redesign.
- [x] Publish notices through existing bounded dispatch and negotiated event
      delivery. Define the detector authority in packet/event modes and hierarchy
      emission behavior so retransmission or relay does not create a new finding.
- [x] Wire DNS notice production independently of `--tunneling-command` while
      preserving detector enablement, threshold, and debounce behavior. Use the
      offline observation clock for deterministic replay where applicable.
- [x] Keep the current command option through an opt-in notice sink using the
      existing safe command-execution facilities. Preserve substitutions, failure
      reporting, and bounded execution; do not execute the same action again merely
      because a notice is relayed or replayed through another consumer.

### B. Durable output and interactive delivery

- [x] Add canonical `notice.log` TSV and JSONL schemas/records and integrate
      existing rotation, queue-pressure, drain, and sensitive-field controls.
      Document file-sink durability boundaries separately from best-effort TUI
      delivery and external command success.
- [x] Add event adapters, capability negotiation, canonical query projection,
      summaries, filtering, details, and local/remote TUI scope support.
- [x] Expose notice emission, suppression, drop, and sink-failure observations
      without making slow subscriber queues affect hunter flow control.
- [x] Test DNS findings with command execution disabled and enabled, threshold and
      debounce boundaries, deterministic offline production, duplicate transport
      delivery, slow subscribers, sink failure, and graceful shutdown.
- [x] Add actual hunter-transport-to-log and tap-runtime-to-log coverage using
      generated DNS traffic. Include compatible behavior when a peer lacks notice
      support; direct calls to an event-mapping helper alone do not cover these
      paths.
- [x] Document notice evidence, scope, retention, loss, and command compatibility
      without promising exactly-once external actions across crashes.

**Completion:** An enabled DNS detector can produce a structured notice without
a command hook, and the same typed finding reaches logs and authorized TUI
subscribers. General rules, scripting, webhook delivery, operational-alert
migration, additional detectors, and automatic PCAP retention remain deferred.

## Workstream 4 — Complete offline Events history

**Original scope:** The event-specific extension under
[scalable offline dataset deferred work](watch-file-scalable-offline-dataset.md#deferred-optimizations-and-extensions).
Packet completeness is already implemented; Calls remain a separate bounded view.

**Touchpoints:** `internal/pkg/offline`, `internal/pkg/tui/offline_indexer.go`,
offline session ownership, `internal/pkg/tui/store/event_store.go`,
`internal/pkg/tui/components/eventsview.go`, and `internal/pkg/eventquery`.

### Implementation

- [x] Define an offline event dataset/projection with stable row identity,
      ordering, typed schema/version, paging, asynchronous queries, and detail
      lookup. Specify update/amendment and duplicate-ID behavior explicitly;
      event identity is not automatically a unique row position.
- [x] Persist every event admitted by the configured offline analysis and
      projection policy using bounded queues/buffers and storage accounting.
      Preserve event identities and sensitive-field rules; generic event history
      must not acquire file bodies or other excluded content.
- [x] Publish complete event storage atomically with the completed offline
      session. Define explicit behavior for disk exhaustion, malformed records,
      cancellation, and failed cleanup. A truncated event stream must never be
      labeled complete.
- [x] Adapt EventsView to page from the offline event dataset while preserving
      viewport formatting, navigation, details, and selection. Keep the existing
      bounded store behavior for live/remote sessions.
- [x] Evaluate event filters across the complete event dataset asynchronously,
      with cancellable work, stale-result rejection, and preservation of the last
      successful query after cancellation or error. Report total and matching
      events separately from cached/visible rows.
- [x] Keep event and packet flow-navigation semantics consistent. Use bounded
      lookups/queries rather than loading all records to find a related flow.
- [x] Join event readers and queries before session storage closes. Cover rapid
      reopen, file replacement, stale completion, mode switches, quit, and cleanup
      retries without blocking the Bubble Tea update loop.
- [x] Test inputs producing more events than the current retained ring capacity,
      matches outside the old retained window, repeated/amended IDs, all supported
      event kinds, corruption, quota failure, and cancellation. Compare event
      content/identity and packet behavior with the completed-analysis baseline.
- [x] Update completeness labels and manual text for Events only after these
      guarantees are delivered. Continue to describe Calls history accurately.

**Completion:** All events admitted by a successful offline analysis are browsable
and filterable after cache eviction within configured resource limits. This
milestone retains completed-analysis publication; background analysis arrives in
workstream 5. Persistent reuse and complete call-history storage are excluded.

## Workstream 5 — Compact-index Milestone B

**Original scope:** [Compact-index Phases 5–6](watch-file-compact-source-index.md#phase-5--publish-a-complete-base-before-analysis-finishes),
the [offline contracts](../design/watch-file-offline-contracts.md), and the
[field inventory](../design/watch-file-packet-field-inventory.md).

**Touchpoints:** `internal/pkg/offline/contracts.go`, builders/manifests,
query/detail/export pins and cache keys, offline lifecycle/controller messages,
and `internal/pkg/tui/offline_{indexer,lifecycle,export,event}.go`.

### Implementation

- [x] Refactor construction into complete normalization/order/base finalization
      followed by bounded ordered analysis. Publish an immutable complete base;
      retain stable logical packet IDs and never expose scan-time provisional IDs.
- [x] Add analysis revision to asynchronous request/result tokens, including
      errors, query/detail/export pins, cache keys, and stale-result checks.
      Specify base-only and completed-analysis revisions explicitly.
- [x] Apply the existing field dependency inventory to navigation, details,
      filters, statistics, and export. Permit complete base-field operations while
      analysis runs; show analysis-dependent fields and operations as pending.
      Treat Protocol and Info as dependent unless equivalence is demonstrated.
- [x] Keep complete raw unfiltered export available from the base. Pin
      analysis-dependent queries/exports to one completed immutable revision;
      refresh active queries explicitly on publication while preserving valid
      selection IDs.
- [x] Atomically publish finalized metadata, protocol statistics, and workstream
      4's complete event dataset as one completed analysis revision. Calls retain
      their documented bounded history. This extends the original plan's bounded
      Events-view clause only for offline sessions; live/remote retention stays
      bounded.
- [x] Retain a valid base after analysis failure or cancellation with an explicit
      status. Release failed overlay resources while keeping revisions already
      pinned by readers alive until those readers close.
- [x] Extend cancellation and ownership across base construction, background
      analysis, event storage, queries, and export. Close source/backing handles
      only after workers/readers join; preserve source-integrity checks, budgets,
      cleanup error reporting, and retryable cleanup ownership.
- [x] Test pending-field filters, stale revision successes/errors, pinned exports
      across publication, analyzer EOF failures, cancellation after base success,
      replacement during analysis, source mutation, and concurrent close. Include
      workstream 4's complete-history and query invariants in these tests.
- [x] Run the relevant original correctness/format/ownership acceptance cases.
      Measure complete-base readiness, first useful page, and completed-analysis
      time separately with reproducible generated captures; record any unavailable
      private fixtures without inventing substitutes or performance gates.
- [x] Update progress/readiness UI, operator documentation, and original milestone
      status to match the delivered behavior. Leave optional cache/reuse work
      explicitly deferred.

**Completion:** Users can browse a complete ordered base before analysis finishes,
pending metadata is distinguishable from absence, and each operation sees one
immutable generation/revision. Full-analysis semantics match the completed path.
Persistent index reuse, query caches, and further parallelization are outside this
milestone; the original Phase 6 reuse branch is not an implicit requirement.

## Workstream 6 — SSH/HASSH and QUIC feasibility

**Original scope:** [TLS roadmap Phase 5](tls-fingerprinting-roadmap.md#phase-5-ssh-hassh)
and [Phase 6](tls-fingerprinting-roadmap.md#phase-6-quic-initial-fingerprinting-spike),
using the producer-to-consumer pattern in the
[log expansion assessment](../research/zeek-log-expansion-assessment.md#acceptance-criteria-for-any-new-stream).

**Touchpoints:** Existing SSH/QUIC signatures in
`internal/pkg/detector/signatures/application`, shared TCP reassembly,
`internal/pkg/eventanalysis`, typed domain/event/wire metadata, canonical log and
query schemas, and local/offline/remote TUI projections.

### A. Production SSH metadata and fingerprints

- [x] Specify the supported initial cleartext SSH handshake, bounded framing,
      endpoint roles, missing/partial observation behavior, and event completion
      semantics. Use the current authoritative HASSH/HASSHServer definitions and
      verify any new dependency's stable release and license before adoption.
- [x] Implement banner and complete initial KEXINIT parsing using shared bounded
      TCP reassembly. Preserve algorithm ordering for fingerprint calculation,
      support segmentation/coalescing, and reject invalid lengths without
      unbounded allocation. Do not treat encrypted rekey traffic as cleartext.
- [x] Compute client HASSH and server HASSHServer only from complete eligible
      messages, retaining the evidence needed to explain them. Preserve existing
      signature detection for banner-only and unsupported observations.
- [x] Add typed SSH production, additive negotiated transport, canonical query
      projection, and a documented `ssh.log` schema with TSV/JSONL output.
      Distinguish partial/banner observations from complete fingerprint evidence.
- [x] Add local/remote TUI event details and offline complete-history support.
      Extend packet metadata only where packet-mode consumers require it; avoid
      speculative unused messages or a separate analysis pipeline.
- [x] Validate independent client/server reference fingerprints with generated
      or redistributable controlled-client fixtures. Cover partial handshakes,
      malformed lists, tuple reuse, retransmission, expiry, mixed-version peers,
      producer parity, and actual transport/log/TUI integration.
- [x] Document supported fields and intentional limits, update applicable manual
      translations, and release SSH independently of the QUIC decision.

**SSH completion:** Supported initial handshakes produce reproducible fingerprints
and typed metadata across the applicable capture/output modes; incomplete input
does not produce a fabricated fingerprint.

### B. Bounded QUIC Initial feasibility study

- [x] Recheck the existing QUIC detector and authoritative v1/v2 packet-format
      references; define a reusable result type and bounds for the spike without
      committing to a new production protocol package or public schema.
- [x] Parse v1/v2 long-header shapes and packet types, versions, connection-ID
      lengths, tokens, and packet lengths. Handle supported coalesced input and
      report version-negotiation/Retry/unsupported cases explicitly.
- [x] Implement v1 Initial header-protection removal and decryption for controlled
      fixtures, with bounded CRYPTO reassembly sufficient to recover a visible TLS
      ClientHello and transport parameters. v2 decryption is outside this spike's
      required scope; do not imply it follows from v2 header recognition.
- [x] Record structured reasons for incomplete/fragmented CRYPTO data, unsupported
      versions, malformed input, decryption failure, and ECH-limited visibility.
      Reuse TLS parsing where appropriate without claiming access to an encrypted
      inner ClientHello or application traffic.
- [x] Test valid reference packets and malformed/truncated/bounded-state cases.
      Keep experimental code outside production analysis paths unless it meets the
      project's normal correctness and integration requirements.
- [x] Write a reproducible report in `docs/research/` recording supported cases,
      coverage on available captures, implementation/dependency costs, resource
      observations, and a proceed/defer recommendation for production QUIC work.
      Identify unavailable real-world evidence explicitly.

**QUIC completion:** The bounded spike and decision report are complete, whether
the recommendation is to proceed or defer. A full QUIC analyzer, HTTP/3, v2 Initial
decryption, application attribution, and coherence scoring require separate scope.

## Verification and progress recording

- [x] For each workstream, identify changed packages/build partitions, run focused
      unit and meaningful integration tests, and use race tests for changed
      concurrency/lifecycle paths. Reuse generated fixtures and existing harnesses.
- [x] Run protobuf generation checks for wire changes and `make build-matrix` when
      shared APIs or build-tagged integrations change. Use the configured CUDA
      builder only if changed code affects that partition; CUDA infrastructure
      provisioning is not an additional workstream here.
- [x] Run broader repository checks appropriate to the final change after focused
      checks pass. Do not rerun unrelated benchmark/soak campaigns as a substitute
      for the named correctness scenarios.
- [x] If tests need to run outside the sandbox, request permission as required by
      project instructions. Remove task-owned temporary/cache artifacts afterward.
- [x] Record commit IDs, commands/results, delivered limitations, and original-plan
      checklist mappings below as each release increment completes. Mark tasks
      complete only after the corresponding behavior and checks are verified.

| Workstream                   | Implementation commits | Verification evidence                                                                          | Disposition |
| ---------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------- | ----------- |
| 1. Failover integration      | `9bd9b347`, `0e1c05d4` | Runtime, custody, topology, expiry, race and build checks below                                | Complete    |
| 2. ECH visibility            | `07945e59`             | Parser/runtime/wire/log/CLI/TUI race checks; manual and build matrix                           | Complete    |
| 3. DNS notices               | `2767d2bf`             | Canonical runtime/transport/log/action/UI race suites, manual and build matrix                 | Complete    |
| 4. Offline event history     | `e966aefb`             | Complete storage/UI lifecycle race suites, build matrix and translated manual                  | Complete    |
| 5. Compact-index Milestone B | `0856f6b6`             | Revision/pipeline/UI race checks, generated readiness report, build and manual                 | Complete    |
| 6A. SSH/HASSH                | `f8139502`             | Parser/runtime, negotiated transport/log, local/remote/offline Events, manual and build checks | Complete    |
| 6B. QUIC study               | `0f6f5fe6`             | Independent reference/controlled packets, malformed/bounds/race/vet tests, reproducible report | Complete    |

## Deferred scope

Hierarchy authorization expansion, reliable matched-session TLS-key delivery,
production X1 schema enforcement, RADIUS/MDF deployment acceptance, raw-IP/email LI,
Rust hunter, full IDS/rule/plugin infrastructure, remaining Zeek log families,
fingerprint corpora/SimHash/coherence, and persistent offline caches remain outside
this plan. They may be reprioritized for a concrete deployment need through their
own scoped plans; they do not block these six workstreams.

## Implementation evidence

### Workstream 1 checkpoint — 2026-10-25

Starting revision: `8ba8ed27`. The only initial working-tree change was this
untracked plan, created in the preceding planning task. No unrelated changes
were present. New integration tests are isolated from concurrent ECH work.

`TestHunterFailoverIndependentProcessorDeployment` runs real hunter and processor
lifecycles in packet and normalized-event modes. It verifies filter readiness,
destination/failover status, original observation provenance, independent raw
analysis versus retained edge analysis, recovery without automatic failback, and
actual PCAP bytes. Input is generated and injected into the capture queue; no
capture device or privileged interface is required. The test sends traffic after
route readiness and makes no claim that best-effort outage traffic is retained.

`TestRawCustodyCommitBeforeLostReceiptRecoversAndDeduplicates` drops the signed
receipt after real durable admission, reopens receiver custody, and verifies the
retry's identity, signed receipt, deduplication, and single recovered output.
`TestRawCustodyRestartAfterOutputBeforeCompletionCheckpoint` verifies the distinct
at-least-once boundary: output before an uncommitted processing checkpoint is
repeated after restart, while checkpointed ingress retries remain deduplicated.
The existing actual-hunter restart test also verifies retained sender identity and
spooled work through real receiver receipt and PCAP output.

Verified commands use `GOCACHE=/tmp/lippycat-visibility-go.ZiSWhY` for this ongoing
task. The user authorized Go integration/race tests outside the sandbox after the
sandbox rejected localhost listeners.

```sh
go test -tags all ./internal/pkg/hunter -run '^TestHunterFailoverIndependentProcessorDeployment$' -count=1
go test -race -tags all ./internal/pkg/hunter -run '^(TestHunterFailoverIndependentProcessorDeployment|TestReliableRawOfflineProductionRestartAndReceiverReceipt)$' -count=1
go test -tags all ./internal/pkg/processor -run '^TestRawCustody(RestartAfterOutputBeforeCompletionCheckpoint|CommitBeforeLostReceiptRecoversAndDeduplicates)$' -count=1
go test -race -tags all ./internal/pkg/processor -run '^TestRawCustody(RestartAfterOutputBeforeCompletionCheckpoint|CommitBeforeLostReceiptRecoversAndDeduplicates)$' -count=1
```

All listed checks passed. The initial checkpoint was committed as `9bd9b347`.

### Workstream 1 completion — 2026-10-25

The real mTLS protocol-handover scenarios now verify segmented TCP and SIP/RTP
continuity only at a common analysis owner, absence of inherited state at
independent processors, and isolation of identical private tuples across origin
nodes and capture epochs. Controlled clocks exercise TCP idle expiry and late
SIP/RTP replay after call finalization; packet subscribers and dispatcher flush
barriers observe completed effects, including unchanged finalized PCAP contents.

The cross-epoch test exposed a concrete production defect: the reassembly cache
key included capture epoch, but the namespace digest omitted it. The digest now
includes epoch, with both topology and hash-identity regressions.

```sh
go test -race -tags all ./internal/pkg/processor -run '^TestFailover(TCP|SIPRTP)' -count=10
go test -race -tags all ./internal/pkg/eventanalysis -run 'Test.*(Reassembl|AssociationScope|CachedScope|NamespacedEndpoint|TypedReassembly|NetworkAssociationScope)' -count=1
make build-matrix
```

These checks passed. The bounded W1 closure review found no material remaining
findings: **CLOSED** for this workstream. The broader historical optional crash
matrix, auxiliary TLS-key path, and LI deployment checks remain outside its
selected scope. The remaining four workstreams and W2's separate release record
are not completed by this W1 decision.

### Workstream 2 completion — 2026-10-25

Starting revision: `8ba8ed27`; initial worktree contained only this untracked
plan. W1 work proceeded in separate owned files and commits. Complete outer
ClientHello framing now qualifies ECH-offer evidence; malformed, legacy and
server-only observations remain unknown. Canonical runtime counters count after
reassembly, before asynchronous delivery, and survive additive packet/event wire
mappings and log coalescing. The SSL schema adds fields at its end without
changing existing field meanings or exact JA3/JA3S/JA4 fingerprints.

The CLI reports per-pass counts from the shared runtime, including capture with
no log sink. Its two-pass segmented-PCAP test also retries the same TCP bytes.
TUI packet/event details and a retained-event statistics card distinguish unknown
evidence and explicitly label retention scope. The actual edge-runtime/spool to
gRPC ingress integration test retries each batch and verifies equivalent log and
subscriber counts without creating a second processor capture authority.

One review finding was fixed: the first CLI provider used cumulative session
counters alongside a per-pass summary. Per-summary deltas and the actual two-pass
regression now keep those scopes consistent. Focused independent review and
integrated verification found no remaining material issue: **CLOSED** for W2.

Verification includes full focused package race suites, the edge transport test,
protobuf adapter/golden-schema tests, `make build-matrix`, `make manual-check`,
and `make manual`. English, Catalan and German editions built successfully, with
5921/5921 current translations in each catalog. The existing mdBook helper/runtime
minor-version warning did not prevent builds or structural parity checks.
Protobuf generation used cached `protoc-gen-go` 1.36.12 and
`protoc-gen-go-grpc` 1.6.2; the locally available compiler is `protoc` 7.36.1 rather
than the previous headers' 7.36.2, accurately reflected in regenerated payload
headers. Reproduction matched the delivered generated payloads; unrelated service
outputs were preserved. Task-owned generator tools were removed.

The [original TLS roadmap](tls-fingerprinting-roadmap.md) marks its Phase 1 and
duplicate ECH-statistics task complete. Later fingerprinting/corpus phases stay
separate. The shared task cache remains owned by the ongoing umbrella
implementation and must be removed when that task finishes.

### Offline ECH codec correction — 2026-10-25

While validating W4's event storage against the full offline package, the tests
exposed an integration omission from W2: the compact TLS field list still omitted
`ClientHelloObserved` and `ECHOffered`, and the declaration-order packet codec's
version still described the previous layout. The compact format now appends both
fields and advances to 2.6; the declaration-order format advances to version 7.
Older temporary formats are rejected instead of silently reinterpreted. Repeated
known, absent and unknown ECH observations round-trip through both codecs. This
is a focused repair of the affected offline boundary, with no new W2 audit.

Verification passed: focused codec round-trip/schema tests and
`go test -race -tags all ./internal/pkg/offline -count=1`. Current/unsupported
version tests were updated with the format decisions; unchanged packet and
storage tests passed.

### Workstream 3 completion — 2026-10-25

Starting revision: `07945e59`; W3 started from the committed W1/W2 tree. The
separate offline ECH correction is `7bdee794`. W4's new event-storage files and
indexer integration are separate working-tree changes and are excluded from this
W3 release increment.

Schema-1 `dns.tunneling` notices now carry warning/triggered decisions, explicit
detector authority/generation, real triggering-flow provenance, bounded evidence,
score/threshold/entropy/counts and independent redaction/truncation flags. Complete
UDP messages and bounded, ordered DNS-over-TCP frames feed one canonical detector.
Per-scope state uses one globally bounded domain table; capture timestamps govern
expiry and debounce. Independent enablement and existing DNS/command options are
part of the shared analysis-policy fingerprint.

The optional `notice` log stream, typed negotiated transport, canonical query
projection, and local/remote DNS and All TUI views consume the same finding.
Commands use an opt-in local emission route with a joined, bounded worker;
received/recovered notice payloads cannot authorize effects, even with forged
matching authority fields. Command completion, event/file output, subscriber loss
and crash durability remain separate contracts. Fixed action bounds and the
at-least-once crash/reanalysis limitation are documented.

The independent review found one hierarchy defect: a raw-forwarding processor
accepted an event-only child and could acknowledge notices without a route to
the terminal. Shared registration now rejects that combination or selects the
child's explicit packet fallback, using the effective upstream mode after initial
negotiation. Authenticated hunter and processor registrations cover both choices;
the integrated post-fix review resolved the finding. **CLOSED** for W3, with no
additional discovery or remaining material finding.

Verification passed with the shared task cache and authorized host test execution:

```sh
go test -race -tags all ./internal/pkg/dns ./internal/pkg/eventanalysis -count=1
go test -race -tags all ./internal/pkg/eventconfig ./internal/pkg/events/... ./internal/pkg/hunter/connection ./internal/pkg/processor/upstream ./internal/pkg/statusclient -count=1
go test -race -tags all ./internal/pkg/processor -count=1
go test -race -tags all ./internal/pkg/processor -run '^(TestDNSNotice|TestNetwork|TestInventoryPromise|TestEffectivePacketMode)' -count=1
go test -race -tags all ./internal/pkg/hunter -run '^TestDNSNoticeActualHunter' -count=1
go test -race -tags all ./cmd/tap -count=1
go test -race -tags all ./cmd/sniff -count=1
go test -tags all ./cmd/sniff ./cmd/tap ./cmd/hunt ./cmd/process ./cmd/watch -count=1
make build-matrix
make manual-check
make manual
```

Additional focused race suites passed for log schemas/records, event queries,
coalescing, TUI components/store/model, remote capture, and authorized/redacted
subscriptions. Tests exercise actual hunter runtime/spool/mTLS-to-log and tap
libpcap/local-runtime-to-log paths, old-peer refusal, deterministic framing and
scope isolation, retries, WAL recovery, slow subscribers, forced file-write
failure, command pressure/cancellation and graceful drain. Management/status JSON
reports local decision and command outcomes plus clearly labeled shared sink
counters. Generated payloads were reproducible using the same current Go
codegenerators and available `protoc` recorded for W2.

English, Catalan and German manual editions built with structural parity; all 47
manual helper tests passed and both translation catalogs contained 5933/5933
current translations. Task-owned private generator/review artifacts were removed;
the umbrella task's shared cache remains owned until final task cleanup.

### Workstream 4 checkpoint — 2026-10-25

Event-storage work began in separately owned files during W3's final verification;
UI/session integration uses the committed `2767d2bf` baseline. At that boundary,
all remaining working-tree changes belong to W4. The packet-codec ECH correction
is separately committed as `7bdee794`.

A dedicated metadata dataset now preserves one-based event arrival ordinals,
including repeated/amended delivery IDs, with versioned checksummed frames,
disk-backed offsets and filtered row vectors, bounded page/detail leases, shared
storage accounting and retryable cleanup. Its focused race tests cover 4097 rows,
all current metadata kinds, far-history queries, identity/snapshot ownership,
corruption, quota/write failure, cancellation, query pins and cleanup retry.
Session persistence and virtual Events browsing/filtering subsequently completed.
The implementation is frozen for the single bounded closure campaign described
below; no W4 completion checklist is checked before its terminal decision.

### Workstream 4 completion — 2026-10-25

The session persists metadata through the existing bounded lossless dispatcher,
before the compatibility ring. An event write failure cancels indexing and remains
observable through sink flush/close; packet and event datasets publish together
only after both finalize. File-content events remain excluded. Reader/query owners
are registered with the session and joined before backing cleanup; failed cleanup
remains owned for retry.

Offline Events now borrows bounded pages and selected details from complete event
storage. Arrival ordinals identify rows independently of delivery IDs. Filters scan
the full dataset asynchronously, reject stale successes/errors, and preserve the
last successful query and description on cancellation or failure. Counts distinguish
total, matching, and cached rows. Virtual navigation, mouse selection, scrolling and
details do not retain a full-history map or slice. Canonical timestamps remain UTC
on disk; virtual event formatting preserves the prior local-clock presentation.
Live/remote Events and all Calls views retain their existing bounded behavior.
Related-packet queries and packet export keep their separate packet semantics.

Verification passed with the shared task cache and authorized host execution:

```sh
go test -race -tags all ./internal/pkg/offline
go test -race -tags all ./internal/pkg/tui -run 'TestOffline(EventSink|Indexer(PublishesCompleteEventHistory|PersistsCanonicalECH|EventQuota|EventCancellation)|Session)' -count=1
go test -race -tags all ./internal/pkg/tui -run 'TestOffline(Indexer|CompactIndexer|CompactOracle|ReleaseAnalyzerFinalizationFailure|ReleaseLateSourceTruncation)' -count=1
go test -race -tags all ./internal/pkg/tui ./internal/pkg/tui/components ./internal/pkg/tui/store -count=1
go test -race -tags all ./internal/pkg/tui -run '^TestCompleteOfflineEvent' -count=1
make build-matrix
make manual-check
make manual
```

Persistence parity uses 2,049 events beyond a retained ring; UI tests use 4,099
rows over an eight-row ring and select/filter matches outside its old window.
Coverage includes typed ECH/notices and every current metadata kind, repeated and
amended IDs, corruption/write/quota failure, cancelled scans, borrowed ownership,
abandoned results, reopen, quit, cleanup retries, related-packet navigation,
keyboard/resize/mouse behavior, and uint64 arithmetic. Unchanged indexer oracle,
source-truncation and analyzer-EOF failure regressions pass. The build matrix
compiled supported non-CUDA and LI partitions and vetted them. All 47 manual
helper tests passed, both catalogs have 5933/5933 current translations, and all
three editions built with structural parity.

The one primary review found one UI regression: hiding and returning to Events
lost the selected row's detail-scroll position. The hidden branch now saves its
arrival identity and scroll before releasing the lease; the permanent reproducer
and related browser/event/publication/detail-scroll race suite passed. The backend
finding list was empty. One integrated check confirmed the fix and the existing
cross-boundary persistence/ownership evidence. **CLOSED**, discovery 1/1, primary
1/1, integrated 1/1, supplemental 0, with no remaining material finding.

The event-history extension in the original scalable-offline plan is fulfilled
and checked. Call-history persistence remains separate and deferred, as selected
by this umbrella plan. No packet completeness or retention milestone is reopened.

### Workstream 5 checkpoint — 2026-10-25

Starting revision: `e966aefb`; the W4 tree was clean before W5 began. The single
W4 closure campaign is complete and is not reopened by this work. Separately
owned backend, pipeline/session, and UI changes implement immutable base and
completed-analysis revisions over shared validated backings. All W5 checklist
items remain unchecked until their implementation and named correctness cases
are verified. No new performance acceptance target is adopted.

### Workstream 6 parser preparation — 2026-10-25

Isolated `internal/pkg/ssh` parser work began from `e966aefb` while the separately
owned W5 backend/pipeline/UI changes were in progress. These files are excluded
from the W5 release increment; SSH runtime/schema/log/TUI integration follows it.
The current maintained Corelight HASSH implementation and RFC 4251/4253/8308
were checked directly. The new parser preserves exact list order and requires
independent endpoint role evidence, with bounded per-direction framing and no
encrypted rekey parsing. It introduces no dependency.

`go test -race ./internal/pkg/ssh -count=1` passed, including published client
reference, independently calculated server reference, asymmetric-direction,
segmentation/ownership, invalid-list/length, partial, NEWKEYS and fuzz-seed cases.
A focused fuzz-seed rerun passed after tightening the error-state assertion.
These are parser tests only; no W6 production integration/completion task is
checked by this preparation checkpoint.

### Workstream 5 completion — 2026-10-25

Complete ordered base revision 0 now publishes before application analysis.
Completed revision 1 owns independent immutable metadata, statistics and complete
Events history over the same validated backing leases. Exact revision tokens bind
queries, caches, manifests, pages, details and pins. Pending fields are explicit;
base-field filters and raw exports remain usable. Completed query refresh preserves
PacketID selection, and failures preserve the installed query and its revision.
Analysis cancellation/failure retains the base; session replacement cancels all
owners before joining them and preserves failed cleanup for retry. Optional
persistent reuse remains deferred.

Verification passed using the shared task cache and authorized host execution:

```sh
go test -race ./internal/pkg/offline
go test -race -tags all ./internal/pkg/tui -run 'TestOffline(Indexer|Compact|Locator|Session|Progressive)' -count=1 -timeout=3m
go test -race -tags all ./internal/pkg/tui ./internal/pkg/tui/components ./internal/pkg/tui/store -count=1
go test -race -tags all ./internal/pkg/tui/components -count=1
go test -race -tags all ./internal/pkg/tui -run '^(TestOfflineProgressive|TestOfflineLifecycle|TestOfflineBrowser|TestOfflineFilter|TestOfflineEvent|TestOfflineMark|TestOfflineExport)' -count=1
go test -race -tags all ./internal/pkg/tui -run '^TestOfflineSessionDiscardCandidate' -count=1 -timeout=90s
go test -tags tui ./internal/pkg/tui ./internal/pkg/tui/components -run '^(TestOfflineProgressive|TestOfflineReadiness)' -count=1
make build-matrix
make manual-check
make manual
```

The first combined UI run exposed two component assertions about count-label
prefixes; the labels retain those prefixes with readiness qualifiers, and the
complete component race suite subsequently passed. Final focused UI races passed
after the closure fixes, and the full offline race suite passed again (11.672 s).
Correctness coverage includes 1086 mixed-source/protocol rows with completed-path
packet/metadata/event parity, exact revision rejection, immutable pinned exports,
source mutation and frozen-handle ownership, query selection, quota/EOF failure,
accepted cancellation, replacement, concurrent close and retryable cleanup.
All 47 manual helper tests passed; CA/DE catalogs have 5935/5935 current
translations and all three editions built with structural parity.

The single bounded closure campaign found two P2 defects: failed constructor
cleanup discarded its retry owner, and accepted cancellation could lose to an
already queued successful analysis result. Constructors now return a cleanup-only
Builder with the error when removal fails, and all session sites retain it before
checking that error. Cancellation wins before publication and disposes of the
candidate asynchronously without touching base exports. Real permission-denied
constructor regressions and candidate-discard retry/concurrent-close regressions
passed. One integrated check confirmed both fixes and their ownership boundaries.
**CLOSED**, discovery 1/1, primary 1/1, integrated 1/1, supplemental 0, with no
remaining material finding.

[Generated readiness observations](../research/watch-file-progressive-readiness.md)
separate base readiness, first useful page and completed analysis. They are one
reproducible observation, not acceptance thresholds. The private capture was
unavailable. Original compact-plan Phase 5 is fulfilled; the selected Phase 6
correctness/readiness work is recorded there without claiming the historical
private/performance matrix or optional reuse was completed.

### Workstream 6 implementation checkpoint — 2026-10-25

Production integration starts from `0856f6b6`; only the separately owned SSH
parser preparation was untracked at the W5 boundary. The shared runtime,
additive SSH event/wire/query/log contracts, and local/remote/offline Events
integration are being verified with real controlled client/server traffic.
The isolated `experiments/quicinitial` code and decision report remain outside
the SSH release and production capture paths. W6 tasks stay unchecked until
each selected deliverable is verified and committed independently.

### Workstream 6A completion — 2026-10-25

Production SSH starts from `0856f6b6` and includes the isolated parser preparation
recorded above. No dependency was added. Shared bounded TCP reassembly now emits
owned per-direction banner and terminal observations on any port. Complete first
KEXINITs preserve all ten ordered lists; independent SYN/SYNACK role evidence
qualifies client HASSH or server HASSHServer. Missing/conflicting role evidence
retains complete lists without a fabricated hash. Gaps, malformed frames, partial
input, expiry, tuple replacement, NEWKEYS and admission rejection remain explicit.

Additive typed SSH events, canonical queries and opt-in `ssh.log` TSV/JSONL share
the existing runtime, transport and sink ownership. Required SSH production is
negotiated across each relay/child boundary; optional unsupported kinds report
compatibility loss. Packet fallback requires local SSH analysis. Transport retries
retain identity without analysis. Local/remote Events and completed offline
revision 1 carry the same evidence; live retention and pending base revision 0
retain their existing meanings. No unused packet metadata pipeline was added.

The single bounded closure campaign found one primary P2: SSH probing could take
ownership of SSH-looking HTTP body bytes before HTTP analysis. Validated HTTP
framing now retains body ownership. Its one integrated review found that this
ownership outlived the completed message and suppressed a later CONNECT-to-TLS
handshake. The single supplemental repair releases the HTTP boundary when its
message emits. Permanent raw/transported coalesced/split body, custom-port/prelude,
and CONNECT-to-TLS regressions pass, along with the complete runtime race suite.
**CLOSED**, discovery 1/1, primary 1/1, integrated 1/1, supplemental 1/1, with no
remaining material finding. The cookie documentation also now states accurately
that cookies are neither hashed nor retained.

Verification uses the shared task cache and previously authorized host execution:

```sh
go test -race ./internal/pkg/ssh -count=1
go test -race -tags all ./internal/pkg/eventanalysis -count=1
go test -race -tags all ./internal/pkg/eventconfig ./internal/pkg/events/... ./internal/pkg/eventquery ./internal/pkg/logschema ./internal/pkg/logstream/... ./internal/testutil/eventfixture -count=1
go test -race -tags all ./internal/pkg/hunter ./internal/pkg/hunter/connection ./internal/pkg/processor ./internal/pkg/processor/upstream ./internal/pkg/remotecapture -count=1
go test -race -tags all ./internal/pkg/tui ./internal/pkg/tui/components ./internal/pkg/tui/store -count=1
go test -race -tags all ./cmd/sniff ./cmd/tap ./internal/pkg/hunter ./internal/pkg/processor ./internal/pkg/tui -run 'SSH|Ssh' -count=1
make build-matrix
make manual-check
make manual
```

The prior full suites, byte-identical repository protobuf regeneration, dedicated
`tui` partition, and final affected race checks passed. Evidence includes a real
controlled `x/crypto/ssh` client/server exchange on a custom port through actual
hunter transport/subscription/log, tap capture/log and sniff/log paths; published
client and independently calculated OpenSSH-server reference hashes; malformed,
partial, retry, expiry, isolation, mixed-version and globally bounded-state cases;
and complete offline history beyond live retention. Supported non-CUDA and LI
partitions compile and vet. CUDA-specific code is unchanged. All 47 manual helper
tests passed, CA/DE catalogs have 5940/5940 current translations, and English,
Catalan and German editions built with structural parity. The previously recorded
mdBook helper/runtime warning remains nonblocking.

The original TLS roadmap's Phase 5 and duplicate SSH wire/UI tasks are mapped to
these delivered typed contracts. Its historical packet-message proposal is
replaced by the current event wire path, as required by this umbrella's scope;
full QUIC production, later corpus/coherence work and unrelated historical tasks
remain separate. Experimental QUIC files and its report are excluded from this
SSH release increment and will be committed afterward.

### Workstream 6B completion — 2026-10-25

The isolated experiment started from `0856f6b6` alongside SSH integration and is
released after the independent production SSH commit `f8139502`. The existing
heuristic QUIC detector and RFC 9000/9001/9369 were checked before implementing a
bounded result contract in `experiments/quicinitial`. No dependency was added and
no production package imports the experiment.

V1/v2 long-header/type recognition, bounded coalescing, explicit Retry/version
negotiation/unsupported outcomes, and v1 Initial key derivation, header
unprotection, packet-number reconstruction and authenticated decryption are
implemented. Bounded offset CRYPTO reassembly recovers the visible ClientHello
and exact transport-parameter TLVs. Structured reasons distinguish holes,
conflicts, malformed input, authentication failure, limits and ECH outer-only
visibility. V2 decryption, Retry following, application traffic and production
flow admission/correlation remain outside the study.

The [decision report](../research/quic-initial-feasibility.md) recommends deferring
production integration while preserving the experiment. It records implementation
and dependency cost, explicit resource bounds, one exploratory allocation/time
observation, available-packet coverage and missing representative/private QUIC
traffic. It makes no deployment-performance promise. Published redistributable
RFC client/server ciphertext and a fresh Go QUIC TLS client provide independent
and controlled correctness evidence; the available demo PCAP contains no
supported-version Initial candidate.

```sh
go test -race -tags all ./experiments/quicinitial/... -count=1
go vet -tags all ./experiments/quicinitial/...
go run -tags all ./experiments/quicinitial/cmd/inspect -dcid 8394c8f03e515708 -hex-file experiments/quicinitial/testdata/rfc9001-client.hex
go run -tags all ./experiments/quicinitial/cmd/survey testdata/pcaps/demo-mixed.pcap
```

All commands passed. Final race runs completed in 1.107 s (core) and 1.022 s
(survey); the reference client yielded packet number 2, a 241-byte ClientHello,
`example.com`, `alpn` and parameter evidence. The demo survey reported 1,800
packets, 315 UDP datagrams and zero supported-version candidates. Earlier bounded
fuzzing completed 6,648 executions. Tests cover every truncated reference prefix,
malformed lengths, authentication failure, conflicting overlap, state bounds,
packet-number wrap, ECH, parameter duplication and owned snapshots.

The existing bounded closure campaign corrected two P2 findings: survey PCAP
lengths could exceed its intended allocation bound, and authenticated Frame Type
varints accepted non-shortest encodings. An effective 128 KiB pre-allocation
record cap and frame-type-width validation now reject these inputs; ordinary
records in max-snaplen captures and legal longer offset/length encodings remain
supported. Permanent regressions, the integrated fixed-list check and final
race/vet checks passed. **CLOSED**, discovery 1/1, primary 1/1, integrated 1/1,
supplemental 0, with no remaining material finding. The original TLS roadmap's
Phase 6 spike tasks are fulfilled; its production QUIC wire task stays unchecked.

### Final completion recording — 2026-10-25

All selected implementation and shared-verification checklist items are now
fulfilled. Workstreams 1–5 retain their recorded closed decisions and commits;
W6A is `f8139502`, followed independently by W6B `0f6f5fe6`. The separate offline
ECH codec correction remains `7bdee794`. Requirement evidence, production loci,
commands/results, original-plan mappings and intentional limits are recorded in
each workstream's completion entry above. Final current-tree checks confirmed
both release commits, additive SSH contracts and actual path regressions, the
isolated experiment's passing race/vet/CLI evidence, and no production imports of
that experiment. No new performance acceptance target was introduced.

The final SSH runtime race suite passed after the supplemental HTTP-boundary fix
(2.021 s); final focused sniff, tap, hunter, processor and TUI SSH race checks all
passed. Build-matrix output covers the experiment as well as supported non-CUDA
and LI partitions. Final manual checks/builds passed with 5940/5940 current CA/DE
translations and all three editions structurally consistent. Existing CUDA-only
infrastructure, unavailable private/representative captures, and optional future
protocol/corpus work are not claimed as tested or completed.

All 41 task-owned temporary cache, log, code-generation/review and inspection
artifacts were removed, including the 9.5 GiB shared Go cache; no task temporary
owner remains. Generated manual editions remain normal ignored build outputs.
Only this final completion recording follows the independently reviewable feature
commits. The complete selected umbrella objective is achieved; deferred scope
above remains outside this implementation.

### CI contract snapshot correction — 2026-10-25

GitHub Actions [CI run 40219561310](https://github.com/endorses/lippycat/actions/runs/40219561310)
failed its `all` and `all li` unit jobs on stale CLI expectations. The hunter
persistent-flag contract and six help snapshots omitted the three intentional
SSH analysis flags. The LI tap branch retained five help hashes from before both
shared DNS-notice and SSH help additions. Non-LI tap help was already current.
All other CI jobs and the separate integration, security and manual workflows
passed on that revision.

The expected defaults and full-help hashes now cover the delivered interface.
Review reconstructs the previous help by removing only the introduced shared
flag lines and restoring the prior log-streams description; the old hashes then
match. Full snapshot equality and inherited-flag checks remain enforced.
Verification covers both affected command packages under `all` and `all li` with
the race detector and CI's atomic coverage instrumentation. This follow-up fixes
the missed contract expectations without changing production behavior.
