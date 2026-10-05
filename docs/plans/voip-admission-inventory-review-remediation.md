# VoIP Admission and Inventory Review Remediation

**Date:** 2026-10-05
**Status:** Complete; implementation verified and committed
**Baseline:** `0c8fd186`
**Basis:** The eBPF admission and inventory review, its accepted second opinion,
and the subsequent E2 reachability clarification.

## Objective and boundaries

Fix shared VoIP attribution regressions, remove unnecessary sniff analysis, and
make admission startup, recovery, and diagnostics reliable. Validate the remaining
compatibility concerns with focused synthetic fixtures. Investigate analysis cost
without turning exploratory measurements into performance acceptance gates.

This is a follow-up implementation plan. Existing eBPF implementation evidence
remains in [VoIP eBPF implementation evidence](voip-ebpf-implementation-results.md).
This work does not reopen the original completed plan or imply that privileged
kernel tests have never run.

Fixtures, documentation, and evidence must use synthetic data. Omit captured
payloads, real endpoint or subscriber identifiers, private deployment information,
credentials, selectors, and personal filesystem paths. Diagnostics should expose
aggregate counts and sanitized reasons. Any per-owner diagnostic correlation must
use an opaque, transient identifier rather than a network or signaling identity.

Keep authoritative selection, exact endpoint attribution, call lifetimes,
observation-domain separation, expiry, durability, and configured resource limits
intact. eBPF stays opt-in. Kernel admission never authorizes output. Broad admission
under the configured failure policy still preserves explicit capture restrictions
and userspace authorization.

Inventory defaults, inter-node event projection, and new DHCP/NTP enablement
switches remain separate product decisions. They are not required changes in this
plan. Preserve current behavior and document it accurately while completing the
independent correctness work.

## Finding disposition

| Findings | Treatment |
| --- | --- |
| E1 | Fix shared SDP endpoint recovery and expose bounded parse diagnostics. Previously learned endpoints are not necessarily erased. |
| E2 | Normalize IPv6 keys and test the real selection/output lifecycle. Neither media loss nor output from a never-matched call is established by the isolated lookup result. |
| E3 | Correct TCP capture provenance; verify limit defaults, call accounting, completion timing, and lifetime-bound match behavior before changing them. |
| E4 | Replace the permanent startup wall-clock fence with an activation boundary that remains safe after clock changes. |
| E5 | Handle selected-owner synchronization failures with explicit recovery; distinguish stale lifecycle rejection and failed control operations. |
| E6 | Make bounded shadow evidence useful at runtime and expose its uncertainty. |
| E7, E10 | Verify explicit-port and IP-selector output behavior, then document supported semantics. |
| E8, E9 | Correct platform/build documentation and fork provenance notes. |
| I2 | Preserve reproducible analysis-cost measurements and perform one bounded profiling pass. Further characterization is conditional on the claim being investigated. |
| I3 | Gate optional sniff event analysis on actual output demand. |
| I4, I6, I7 | Document inventory behavior, the off switch, CIDR scope, and spool upgrade compatibility. |
| I1, I5 | Preserve existing projection and default policy; defer policy changes and new switches to an explicit product decision. |

## 1. Restore safe shared VoIP endpoint learning

**Locations:** `internal/pkg/sip/sdp.go`, `internal/pkg/voip/rtp.go`,
`internal/pkg/voip/buffermanager.go`, `internal/pkg/voip/processor/`,
`internal/pkg/voip/admission/`, and their status adapters.

- [x] Define a bounded SDP result containing safe numeric endpoints, classified
      diagnostics, and completeness information. Separate an invalid section from
      whole-body/resource-limit failure. Do not add DNS resolution or port-only
      authoritative attribution.
- [x] Retain valid independent media sections when another section is invalid.
      Reset state on every media-section boundary before validating its contents.
      An invalid connection address must invalidate the affected scope rather than
      reuse a prior section's address. Distinguish media-level and session-level
      failures; neither may fabricate an endpoint.
- [x] Enforce existing body, endpoint, association, and diagnostic bounds. Define
      deterministic handling at capacity without bypassing configured limits or
      installing speculative endpoints.
- [x] Use consistent endpoint semantics in tracker, processor, buffer manager,
      metadata staging, and admission diagnostics. Keep partial parse information
      available to the admission recovery work in section 4.
- [x] Count failures and partial results per applicable path with sanitized reason
      categories. Do not log SDP bodies or actual endpoint values.
- [x] Test mixed-validity sections, unresolved addresses, family mismatches,
      malformed media/RTCP attributes, endpoint limits, and section inheritance.
      Cover valid endpoints before and after an invalid section, IPv4/IPv6,
      re-INVITE, intentional inactive/disabled media, and preservation of endpoints
      learned earlier in the same call lifetime.
- [x] Verify media attribution and selected output with eBPF disabled in sniff,
      hunter, tap, and processor paths. Record the intended RTCP, non-audio, and
      inactive-media behavior for the release documentation.

**Completion evidence:** A bad independent section no longer discards all valid
endpoints from that body; bounds and exact attribution remain enforced.

## 2. Normalize media keys and verify selection lifecycle

**Locations:** `internal/pkg/voip/udp.go`, `sniff_sipflow.go`,
`buffermanager.go`, `calltracker.go`, and local TCP adapters.

- [x] Build source/destination endpoint keys with the same IPv6-safe normalization
      used by authoritative registry resolution.
- [x] Add handler-level IPv4/IPv6 tests using real SIP/RTP processing sequences.
      Verify selected output, buffering behavior, and no output for an unselected
      or pending call that does not become selected.
- [x] Ensure a never-selected fixture does not manually seed authoritative tracker
      endpoints. If an unexpected output path is demonstrated, retain the actual
      registry-population sequence as the regression rather than assuming the
      disputed E2 scenario is reachable.
- [x] Check selection expiry, call retirement, Call-ID reuse, ambiguous endpoint
      ownership, and temporary-buffer expiry separately. Preserve valid selected
      media after temporary storage expires, while preventing stale lifetime or
      expired selection from authorizing output.
- [x] Fix any reproduced fallback authorization defect with explicit lifetime and
      selection checks. Keep the normalization fix independent of hypotheses
      that the lifecycle tests do not demonstrate.

**Completion evidence:** Canonical keys are consistent and the full handler tests
establish output behavior for selected and unselected lifetimes.

## 3. Make sniff analysis follow output demand

**Locations:** `cmd/sniff/structured_logs.go`, `sniff.go`, protocol adapters,
local pipeline composition, and capture observer installation.

- [x] Identify actual event consumers, including structured logs, explicit sinks,
      and requested file extraction. Distinguish event-runtime demand from protocol
      decoding/selection needed by ordinary packet and CLI outputs.
- [x] Skip optional runtime, dispatcher, and packet-observer creation when there
      is no consumer. Support a nil optional event session in callers and cleanup.
      Preserve applicable configuration validation without allocating the runtime.
- [x] Keep dedicated protocol processing independent of optional logs. In
      particular, preserve RADIUS association, selection, and ordinary output when
      its pipeline owns observations and the event session is absent.
- [x] Keep inventory enablement separate from consumer demand. Audit generic
      RADIUS observation ownership so removing the optional observer neither
      duplicates decoding nor removes packet presentation needed by normal output.
- [x] Preserve explicit sink registration, extraction, live/offline expiry,
      graceful draining, cancellation, and observer restoration when analysis is
      enabled. Do not create a second analysis or decoding pass for a consumer.
- [x] Test generic and protocol-specific sniff with logging disabled/enabled,
      requested extraction, and an explicit test sink. Verify equivalent ordinary
      output and exactly-once observations for each active consumer.

**Completion evidence:** Consumerless sniff avoids optional event analysis while
all requested outputs still receive their required analysis.

## 4. Fix admission activation and selected-owner recovery

**Locations:** `internal/pkg/capture/capture.go`,
`capture/admissionintegration/installer_linux.go`, the local gopacket binding,
`internal/pkg/mediaadmission/controller.go`, and `voip/admission/bridge.go`.

- [x] Define a per-capture-generation activation boundary that rejects retained
      pre-activation frames without comparing every future packet to a permanent
      wall-clock timestamp. Account for libpcap buffering and packet-mmap blocks.
      Do not clear the fence after one fresh timestamp without proving older
      queued frames cannot subsequently appear.
- [x] Preserve bounded draining, readiness ordering, cancellation, socket
      ownership, and reattachment behavior. Count activation-boundary discards in
      existing telemetry without changing ordinary capture-drop semantics. Keep
      this mechanism scoped to managed live capture and preserve offline timestamps.
- [x] Test retained frames, mixed timestamp ordering, clock rollback after
      activation, multiple interfaces, and socket recreation. Verify signaling
      and selected media resume without weakening startup isolation.
- [x] Distinguish intentional empty media, incomplete endpoint derivation, stale
      call rejection, and a lost update for a currently selected owner. Track
      unresolved derivation explicitly rather than treating it as no media
      expected or a successfully synchronized empty set.
- [x] Apply the configured failure policy to genuine selected-owner
      synchronization loss while preserving explicit restrictions. Pair any
      unsynchronized state with a complete current-owner reconciliation path;
      do not introduce an unrecoverable `MarkUnsynchronized` transition.
- [x] Reconcile against current lifetimes and revisions. Restore enforcement only
      after unknown derivation is resolved or the affected lifetime is retired
      and the complete eligible owner set is confirmed. A registry snapshot that
      simply lacks unknown endpoints is insufficient proof of recovery.
- [x] Keep failed control writes visibly uncertain; never claim the scope is open
      when the backend did not confirm it. Preserve bounded control operations
      and retries under both configured open and closed policies.
- [x] Test partial/failed SDP, valid later updates, owner retirement/reuse,
      concurrent registry changes, legitimate stale promotion rejection, capacity
      failures, and failed control writes. Verify userspace attribution alongside
      kernel reception; opening admission alone does not repair attribution.

**Completion evidence:** Clock changes cannot activate a permanent discard window;
genuine synchronization loss is visible and enforcement returns only after
complete reconciliation.

## 5. Add bounded operational shadow diagnostics

**Locations:** `internal/pkg/mediaadmission/shadow.go`, media diagnostics,
`capture/admissionintegration/status*.go`, eBPF decision collection, and existing
management/CLI telemetry adapters.

- [x] Make decision sampling explicit and bounded. Preserve separate accounting
      for kernel evidence loss, retained-sample overwrite, malformed samples,
      collection errors, and incomplete correlation.
- [x] Correlate historical decisions with userspace attribution, selected call
      lifetime, selection/publication boundaries, and the observed generation.
      Keep correlation state bounded and expire it with the relevant generation
      and lifetime. A later map lookup or short fingerprint alone is not proof of
      an earlier packet's identity or eligibility.
- [x] Expose classified sampled outcomes: pre-selection, publication window,
      rejected after confirmed publication, admitted, and incomplete evidence.
      Describe sampled rejection counts as sampled observations, not exact counts
      for all traffic. Ambiguity must remain explicit.
- [x] Distinguish unknown media expectation from intentionally inactive media.
      Reset or version missing-media expectations when accepted media endpoints
      change, so one earlier packet does not mask a later media move.
- [x] Add bounded, rate-limited per-owner missing-media diagnostics using only an
      opaque transient reference and sanitized state. Retain aggregate status and
      avoid automatic scope widening based only on a diagnostic alert.
- [x] Test sampling, loss, collisions/duplicates, late evidence, owner retirement,
      re-INVITE, inactive media, and generation changes. Verify additive telemetry
      compatibility and that diagnostics cannot block capture.

**Completion evidence:** Operators can inspect bounded sampled evidence and its
limitations without treating aggregate would-reject counts as parity proof.

## 6. Validate compatibility and update operator documentation

**Locations:** `cmd/tap/voip_admission.go`, tap TCP reassembly adapters,
`internal/pkg/voip/`, `processor/filtering/target_local.go`, command READMEs,
manual sources/catalogs, and `third_party/gopacket/LIPPYCAT_PATCH.md`.

- [x] Preserve actual contributing-interface provenance for reassembled TCP SIP,
      independently of observation-domain grouping. Define behavior for streams
      seen across interfaces rather than labeling every stream with the first
      configured interface. Test shared and isolated domains.
- [x] Verify default substitution and invalid-limit handling when eBPF is off/on.
      Restore intended legacy default handling where it regressed, while keeping
      configured positive limits and aggregate domain budgets enforced.
- [x] Verify TCP-signaled call accounting, completion/grace timing, and registry
      eviction/expiry behavior. Retain independent fixes; release-note confirmed
      changes rather than reverting them simply because they share a commit.
- [x] Verify explicit SIP/media port restrictions and IP-only selectors across
      disabled, shadow, enforcing, and configured degraded modes. Include relevant
      non-RTP media-port traffic. Document any supported output differences;
      never relax an explicit predicate to make parity tests pass.
- [x] Verify and document required kernel features, capabilities, memory-accounting
      considerations, supported link types, and startup errors using authoritative
      platform documentation and exercised environments. Do not infer a universal
      minimum solely from one passing kernel.
- [x] Document local-module provisioning for dependency-first builds and correct
      the gopacket checksum/provenance note. Validate the recipe with the checked-in
      fork and preserve its patch reproducibility and license.
- [x] Document current inventory defaults, runtime activation, optional streams,
      `--inventory=false`, and `events.inventory.enabled: false`. Explain that
      CIDRs scope inventory subjects rather than capture or analysis cost.
- [x] Document draining pending events-mode spool records with the prior version
      before a policy-incompatible upgrade. Preserve explicit incompatibility
      handling; do not silently delete durable pending records.
- [x] Update affected manual text in every language configured in
      `docs/manual/languages.json`, review changed fuzzy entries, and run
      `make manual-check` and `make manual` after manual changes.

**Completion evidence:** Confirmed compatibility behavior is tested and accurately
documented; the plan does not silently adopt deferred product-policy changes.

## 7. Preserve performance evidence and remove demonstrated redundant work

**Locations:** `internal/pkg/eventanalysis/`, `conntrack/`, `inventory/`, and
responsibility-named benchmarks or synthetic workload helpers.

- [x] Check in a reproducible analysis benchmark or reconstruct the unavailable
      throwaway harness. Preserve synthetic fixtures, configuration, revision
      identifiers, invocation, and raw results. Do not present a reconstructed
      run as reproduction of the original measurements.
- [x] Compare current inventory off/on with paired repeated runs; compare the
      earlier revision only where equivalent inputs/configuration can be
      established. Separate flow discovery from established-flow steady state
      and report distributions plus allocations, not just one percentage.
- [x] Perform one profiling pass that separates inventory-disabled cost from
      incremental inventory cost. Inspect scope formatting/hashing, snapshots,
      evidence checks, tracker lookups, allocations, and lock contention.
- [x] Apply small changes only where that pass identifies redundant work. Reuse
      stable scope components without merging interfaces, sources, epochs, or
      generations. Avoid unnecessary evidence checks; ensure cached admission
      state still permits inventory re-emission after eviction/expiry.
- [x] Repeat the relevant comparison after those changes and verify event contents,
      scope separation, bounds, expiry, and re-emission. Record remaining cost as
      an observation; it does not authorize repeated optimization cycles.

Application-level characterization is optional and only needed to support a
corresponding application-level claim. It is not a completion gate for these
fixes. Use the following evidence boundaries when deciding whether to run it:

| Claim | Additional evidence |
| --- | --- |
| Whole-application resource impact | Equivalent sniff, standalone tap, or events-mode hunter workloads; process CPU, CPU per processed packet, allocation/GC behavior, and peak/steady memory. |
| Live capture loss or capacity behavior | Known offered live traffic, capture and queue-drop counters, and received/processed/output accounting. Offline replay cannot establish live capture loss. |
| Contention or workload sensitivity | One/multiple interfaces, long-lived/churning flows, capacity pressure, and representative UDP/TCP/protocol mixes. |

Preserve synthetic workload details and sanitized results for any optional run.
Existing benchmark observations supply no new latency, throughput, CPU, RSS,
restart, or soak threshold. A benchmark miss alone does not block completion.

## Validation and implementation bookkeeping

Implement sections 1-3 first, then admission recovery and diagnostics. Independent
documentation work may proceed alongside fixes; final text must describe the
resulting behavior. Section 7 is bounded investigation, not a prerequisite for
fixing confirmed correctness defects.

- [x] Run meaningful focused tests after each changed path, including race checks
      for lifecycle, observers, controller recovery, and diagnostics. Verify both
      eBPF-disabled operation and hunter/tap role parity.
- [x] Run the applicable existing project checks: `make test`, `make vet`, and
      `make build-matrix`. Exercise supported role/LI partitions affected by the
      change; report unexercised environments accurately.
- [x] Run privileged kernel/command checks through `make test-ebpf` after relevant
      attachment, policy, or recovery changes. Ask before tests requiring execution
      outside the sandbox. Report unavailable support as unexercised, not passing.
      Reuse prior evidence for untouched paths instead of requiring a fresh full
      matrix solely because this review did not independently reproduce it.
- [x] Format changed files before staging. Verify each completed task before
      checking it off, record concise evidence in this plan, and commit related
      implementation changes together with their verified checklist updates.
- [x] Keep generated objects, protobuf changes, and dependency edits tied to the
      implementation that requires them. Clean temporary caches/workloads after
      use and preserve unrelated working-tree changes.

## Deferred decisions

Changing inventory defaults, conditional defaults based on deployment mode,
inter-node event redaction/projection, NTP field classification, and independent
DHCP/NTP switches require explicit product direction. They are outside required
implementation and do not block independent fixes. Any later decision must define
configuration precedence, compatibility, forwarding/analysis needs, and operator
documentation before adding implementation tasks.

## Execution record

Shared SDP recovery, exact IPv4/IPv6 attribution and selected-owner reconciliation
passed focused race tests in `sip`, `voip`, `voip/processor`, `voip/admission`,
`callregistry` and `mediaadmission`. Fixtures cover safe partial sections, configured
bounds, real pending/selected handler sequences, expiry, retirement/reuse,
ambiguity, temporary-buffer expiry and later complete endpoint recovery. Sniff
consumer-demand tests preserve ordinary output and exactly-once RADIUS observations
without allocating optional analysis when no consumer exists.

Startup socket retirement, discard telemetry, retained buffers, timestamp rollback,
readiness and recreation passed capture/binding tests and isolated live-socket
checks. Bounded shadow diagnostics passed full-identity, historical lifetime and
publication, sampling, ambiguity, generation/revision, pressure, inactive-media
and missing-media tests. The expanded BPF load was corrected after an initial
verifier rejection; both endian objects were regenerated and actual kernel tests
passed. Raw frame evidence remains transient and is not exposed in status.

TCP final-byte provenance, shared/isolated domains, legacy defaults, positive
budgets, accounting and completion/grace behavior passed focused role tests.
The bounded closure review found one selector compatibility issue: disabled
hunter's application-filter receiver signature prevented filter injection, while
disabled tap's mixed IP and identity filters retain legacy capture-but-deny
behavior for unassociated RTP. The receiver signature now matches both hunter
paths; compile assertions and real-filter UDP race tests cover IP/CIDR positives,
nonmatches and empty deny policy. Tap authorization remains intact. Corrected
command fixtures and operator documentation distinguish mixed filters from true
IP-only output. The integrated post-fix review found no further material issue.
The final isolated selector suite passed all disabled, shadow and enforcing
hunter/tap cases, including legacy mixed tap rejection and true IP-only output.

Section 7 is complete. The reconstructed `BenchmarkInventoryAnalysis` and one
inventory-off/on CPU/allocation/mutex profiling pass identified repeated scope
formatting and hashing. A single-entry exact scope/digest cache and cheap DNS
port short-circuit remove that redundant work. Five paired isolated-baseline/current
trials preserve off/on discovery and steady-state distributions plus allocations.
[Measurement evidence](../research/voip-inventory-analysis-measurements.md) and
[raw samples](../research/voip-inventory-analysis-measurements.json) record synthetic
inputs, configuration, source identity, invocation and limitations. The source
hash still matches the final formatted implementation. Analysis, inventory and
conntrack race tests pass, including expiry/eviction re-emission. No application
or live-capacity claim is made; optional characterization was not undertaken.

Final `make test`, `make vet` and `make build-matrix` passed after the receiver
repair, including supported role and LI partitions. Tests requiring host socket
and ownership semantics ran outside the sandbox with user approval. CUDA remains
unexercised because this environment lacks its configured toolchain. Final
`make test-ebpf` passed in the approved disposable privileged container: actual
kernel policy/decision tests, retained-socket startup and reattachment, command
parity/domains, capacity/partial-SDP recovery, open/closed recovery and selectors.
The optional measurement command fixture was not enabled; existing untouched
evidence is reused rather than represented as a new measurement.
`make manual-check` reports 5,516/5,516 German messages translated; `make manual`
built and verified English and German editions. Inventory defaults and projection
remain unchanged; no new DHCP/NTP switch was introduced.

The dependency-first module recipe passed offline `go mod download` using only
root manifests and the provisioned local fork. Applying the checked-in patch to
the upstream baseline reproduced all three modified binding files byte-for-byte.
All changed Go files were formatted and `git diff --check` passed. Temporary
caches/workloads were removed after preserving the sanitized measurement and
validation evidence. Closure outcome: **CLOSED**; no material findings remain.
Code and this verified plan are committed together; all checklist tasks have
verified completion evidence.
