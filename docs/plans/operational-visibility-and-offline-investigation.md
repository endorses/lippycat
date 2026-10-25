# Operational visibility and offline investigation implementation plan

**Date:** 2026-10-25
**Status:** In progress; workstreams 1 and 2 are under implementation
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

- [ ] Record the starting commit and any existing working-tree changes for each
      workstream. Preserve unrelated work and read the applicable directory
      `AGENTS.md` files before implementation.
- [ ] Extend the shared analysis runtime and typed event contracts. Preserve
      processor authority in packet mode and edge authority in event mode; avoid
      producing the same canonical observation at both ends.
- [ ] Preserve stable event identity, origin provenance, flow identity, configured
      bounds, authorization, expiry, and existing durability semantics. Keep
      subscriber loss separate from producer loss and local retention eviction.
- [ ] Make protobuf changes additive, regenerate checked-in code through the
      repository's generator, and test capability negotiation and mixed versions.
      Keep sensitive fields subject to existing projection policy.
- [ ] Keep live packet processing independent of slow log/TUI sinks. Offline
      complete-history construction may apply bounded backpressure to its own
      analysis pipeline; storage failure must produce an explicit failure rather
      than a falsely complete result.
- [ ] Use the latest stable dependencies if a new dependency is necessary, verify
      compatibility and licensing, and prefer existing project facilities where
      they already satisfy the requirement.
- [ ] Update affected user documentation with each delivered feature. For manual
      edits, update every language in `docs/manual/languages.json`, review affected
      fuzzy translations, and run `make manual-check` and `make manual`.
- [ ] Format changed files before staging, record relevant verification evidence,
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

- [ ] Define and document the counting unit as accepted, completely framed
      ClientHello observations at the canonical analysis authority. Distinguish
      observation counts from unique connections; define retransmission and
      midstream-capture behavior explicitly. Transport retry, serialization, and
      subscriber fan-out must not increment capture observations again.
- [ ] Add explicit ECH-offer detection for the extension identified in the
      original plan and carry observation availability with the result. Preserve
      unknown/not-observed versus an observed ClientHello without that extension,
      including data received from older peers.
- [ ] Extend existing TLS domain and wire metadata, runtime mappings, and typed
      event projections as needed. Ensure handshake coalescing does not erase the
      evidence needed by the documented numerator and denominator; do not assume
      every TLS summary represents exactly one ClientHello.
- [ ] Expose ECH-offered and total-ClientHello counts in TLS summaries and the
      applicable TUI statistics/detail views. Carry sufficient typed evidence for
      equivalent reporting from sniff, tap, processor packet mode, hunter event
      mode, and offline analysis without a second counter authority.
- [ ] Test complete and segmented ClientHellos, extension absence/presence,
      malformed/truncated extension bodies, ServerHello-only input, transport
      retries, and older metadata without the new fields. Retain byte-for-byte
      JA3/JA3S/JA4 regression expectations.
- [ ] Document ECH offer visibility as an observation, without claiming acceptance
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

- [ ] Define a versioned typed security-notice event with detector/version,
      category, severity, observation time, threshold/score evidence, and bounded
      references to contributing observations. Specify notice identity,
      debounce/suppression accounting, and the initial lifecycle semantics.
- [ ] Anchor DNS notices in real observation provenance. A domain finding may
      aggregate several flows; retain bounded evidence references rather than
      inventing one synthetic flow or requiring an unrelated non-flow envelope
      redesign.
- [ ] Publish notices through existing bounded dispatch and negotiated event
      delivery. Define the detector authority in packet/event modes and hierarchy
      emission behavior so retransmission or relay does not create a new finding.
- [ ] Wire DNS notice production independently of `--tunneling-command` while
      preserving detector enablement, threshold, and debounce behavior. Use the
      offline observation clock for deterministic replay where applicable.
- [ ] Keep the current command option through an opt-in notice sink using the
      existing safe command-execution facilities. Preserve substitutions, failure
      reporting, and bounded execution; do not execute the same action again merely
      because a notice is relayed or replayed through another consumer.

### B. Durable output and interactive delivery

- [ ] Add canonical `notice.log` TSV and JSONL schemas/records and integrate
      existing rotation, queue-pressure, drain, and sensitive-field controls.
      Document file-sink durability boundaries separately from best-effort TUI
      delivery and external command success.
- [ ] Add event adapters, capability negotiation, canonical query projection,
      summaries, filtering, details, and local/remote TUI scope support.
- [ ] Expose notice emission, suppression, drop, and sink-failure observations
      without making slow subscriber queues affect hunter flow control.
- [ ] Test DNS findings with command execution disabled and enabled, threshold and
      debounce boundaries, deterministic offline production, duplicate transport
      delivery, slow subscribers, sink failure, and graceful shutdown.
- [ ] Add actual hunter-transport-to-log and tap-runtime-to-log coverage using
      generated DNS traffic. Include compatible behavior when a peer lacks notice
      support; direct calls to an event-mapping helper alone do not cover these
      paths.
- [ ] Document notice evidence, scope, retention, loss, and command compatibility
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

- [ ] Define an offline event dataset/projection with stable row identity,
      ordering, typed schema/version, paging, asynchronous queries, and detail
      lookup. Specify update/amendment and duplicate-ID behavior explicitly;
      event identity is not automatically a unique row position.
- [ ] Persist every event admitted by the configured offline analysis and
      projection policy using bounded queues/buffers and storage accounting.
      Preserve event identities and sensitive-field rules; generic event history
      must not acquire file bodies or other excluded content.
- [ ] Publish complete event storage atomically with the completed offline
      session. Define explicit behavior for disk exhaustion, malformed records,
      cancellation, and failed cleanup. A truncated event stream must never be
      labeled complete.
- [ ] Adapt EventsView to page from the offline event dataset while preserving
      viewport formatting, navigation, details, and selection. Keep the existing
      bounded store behavior for live/remote sessions.
- [ ] Evaluate event filters across the complete event dataset asynchronously,
      with cancellable work, stale-result rejection, and preservation of the last
      successful query after cancellation or error. Report total and matching
      events separately from cached/visible rows.
- [ ] Keep event and packet flow-navigation semantics consistent. Use bounded
      lookups/queries rather than loading all records to find a related flow.
- [ ] Join event readers and queries before session storage closes. Cover rapid
      reopen, file replacement, stale completion, mode switches, quit, and cleanup
      retries without blocking the Bubble Tea update loop.
- [ ] Test inputs producing more events than the current retained ring capacity,
      matches outside the old retained window, repeated/amended IDs, all supported
      event kinds, corruption, quota failure, and cancellation. Compare event
      content/identity and packet behavior with the completed-analysis baseline.
- [ ] Update completeness labels and manual text for Events only after these
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

- [ ] Refactor construction into complete normalization/order/base finalization
      followed by bounded ordered analysis. Publish an immutable complete base;
      retain stable logical packet IDs and never expose scan-time provisional IDs.
- [ ] Add analysis revision to asynchronous request/result tokens, including
      errors, query/detail/export pins, cache keys, and stale-result checks.
      Specify base-only and completed-analysis revisions explicitly.
- [ ] Apply the existing field dependency inventory to navigation, details,
      filters, statistics, and export. Permit complete base-field operations while
      analysis runs; show analysis-dependent fields and operations as pending.
      Treat Protocol and Info as dependent unless equivalence is demonstrated.
- [ ] Keep complete raw unfiltered export available from the base. Pin
      analysis-dependent queries/exports to one completed immutable revision;
      refresh active queries explicitly on publication while preserving valid
      selection IDs.
- [ ] Atomically publish finalized metadata, protocol statistics, and workstream
      4's complete event dataset as one completed analysis revision. Calls retain
      their documented bounded history. This extends the original plan's bounded
      Events-view clause only for offline sessions; live/remote retention stays
      bounded.
- [ ] Retain a valid base after analysis failure or cancellation with an explicit
      status. Release failed overlay resources while keeping revisions already
      pinned by readers alive until those readers close.
- [ ] Extend cancellation and ownership across base construction, background
      analysis, event storage, queries, and export. Close source/backing handles
      only after workers/readers join; preserve source-integrity checks, budgets,
      cleanup error reporting, and retryable cleanup ownership.
- [ ] Test pending-field filters, stale revision successes/errors, pinned exports
      across publication, analyzer EOF failures, cancellation after base success,
      replacement during analysis, source mutation, and concurrent close. Include
      workstream 4's complete-history and query invariants in these tests.
- [ ] Run the relevant original correctness/format/ownership acceptance cases.
      Measure complete-base readiness, first useful page, and completed-analysis
      time separately with reproducible generated captures; record any unavailable
      private fixtures without inventing substitutes or performance gates.
- [ ] Update progress/readiness UI, operator documentation, and original milestone
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

- [ ] Specify the supported initial cleartext SSH handshake, bounded framing,
      endpoint roles, missing/partial observation behavior, and event completion
      semantics. Use the current authoritative HASSH/HASSHServer definitions and
      verify any new dependency's stable release and license before adoption.
- [ ] Implement banner and complete initial KEXINIT parsing using shared bounded
      TCP reassembly. Preserve algorithm ordering for fingerprint calculation,
      support segmentation/coalescing, and reject invalid lengths without
      unbounded allocation. Do not treat encrypted rekey traffic as cleartext.
- [ ] Compute client HASSH and server HASSHServer only from complete eligible
      messages, retaining the evidence needed to explain them. Preserve existing
      signature detection for banner-only and unsupported observations.
- [ ] Add typed SSH production, additive negotiated transport, canonical query
      projection, and a documented `ssh.log` schema with TSV/JSONL output.
      Distinguish partial/banner observations from complete fingerprint evidence.
- [ ] Add local/remote TUI event details and offline complete-history support.
      Extend packet metadata only where packet-mode consumers require it; avoid
      speculative unused messages or a separate analysis pipeline.
- [ ] Validate independent client/server reference fingerprints with generated
      or redistributable controlled-client fixtures. Cover partial handshakes,
      malformed lists, tuple reuse, retransmission, expiry, mixed-version peers,
      producer parity, and actual transport/log/TUI integration.
- [ ] Document supported fields and intentional limits, update applicable manual
      translations, and release SSH independently of the QUIC decision.

**SSH completion:** Supported initial handshakes produce reproducible fingerprints
and typed metadata across the applicable capture/output modes; incomplete input
does not produce a fabricated fingerprint.

### B. Bounded QUIC Initial feasibility study

- [ ] Recheck the existing QUIC detector and authoritative v1/v2 packet-format
      references; define a reusable result type and bounds for the spike without
      committing to a new production protocol package or public schema.
- [ ] Parse v1/v2 long-header shapes and packet types, versions, connection-ID
      lengths, tokens, and packet lengths. Handle supported coalesced input and
      report version-negotiation/Retry/unsupported cases explicitly.
- [ ] Implement v1 Initial header-protection removal and decryption for controlled
      fixtures, with bounded CRYPTO reassembly sufficient to recover a visible TLS
      ClientHello and transport parameters. v2 decryption is outside this spike's
      required scope; do not imply it follows from v2 header recognition.
- [ ] Record structured reasons for incomplete/fragmented CRYPTO data, unsupported
      versions, malformed input, decryption failure, and ECH-limited visibility.
      Reuse TLS parsing where appropriate without claiming access to an encrypted
      inner ClientHello or application traffic.
- [ ] Test valid reference packets and malformed/truncated/bounded-state cases.
      Keep experimental code outside production analysis paths unless it meets the
      project's normal correctness and integration requirements.
- [ ] Write a reproducible report in `docs/research/` recording supported cases,
      coverage on available captures, implementation/dependency costs, resource
      observations, and a proceed/defer recommendation for production QUIC work.
      Identify unavailable real-world evidence explicitly.

**QUIC completion:** The bounded spike and decision report are complete, whether
the recommendation is to proceed or defer. A full QUIC analyzer, HTTP/3, v2 Initial
decryption, application attribution, and coherence scoring require separate scope.

## Verification and progress recording

- [ ] For each workstream, identify changed packages/build partitions, run focused
      unit and meaningful integration tests, and use race tests for changed
      concurrency/lifecycle paths. Reuse generated fixtures and existing harnesses.
- [ ] Run protobuf generation checks for wire changes and `make build-matrix` when
      shared APIs or build-tagged integrations change. Use the configured CUDA
      builder only if changed code affects that partition; CUDA infrastructure
      provisioning is not an additional workstream here.
- [ ] Run broader repository checks appropriate to the final change after focused
      checks pass. Do not rerun unrelated benchmark/soak campaigns as a substitute
      for the named correctness scenarios.
- [ ] If tests need to run outside the sandbox, request permission as required by
      project instructions. Remove task-owned temporary/cache artifacts afterward.
- [ ] Record commit IDs, commands/results, delivered limitations, and original-plan
      checklist mappings below as each release increment completes. Mark tasks
      complete only after the corresponding behavior and checks are verified.

| Workstream                   | Implementation commits                       | Verification evidence                                           | Disposition |
| ---------------------------- | -------------------------------------------- | --------------------------------------------------------------- | ----------- |
| 1. Failover integration      | `9bd9b347` + protocol fix in this checkpoint | Runtime, custody, topology, expiry, race and build checks below | Complete    |
| 2. ECH visibility            | Pending                                      | Pending                                                         | Not started |
| 3. DNS notices               | Pending                                      | Pending                                                         | Not started |
| 4. Offline event history     | Pending                                      | Pending                                                         | Not started |
| 5. Compact-index Milestone B | Pending                                      | Pending                                                         | Not started |
| 6A. SSH/HASSH                | Pending                                      | Pending                                                         | Not started |
| 6B. QUIC study               | Pending                                      | Pending                                                         | Not started |

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
