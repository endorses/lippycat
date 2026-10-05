# VoIP Admission Observability and Recovery Follow-up

**Date:** 2026-10-05
**Status:** Complete; implemented, verified and committed
**Baseline:** `e737c169`
**Basis:** Verification of the prior remediation and the accepted second opinion.

## Objective and scope

Make the hunter filtering change explicit for upgrades, restore operator-visible
SDP diagnostics, make shadow retention respond to sampling, and prevent a complete
SDP message from clearing unrelated unresolved derivation.

This is a focused follow-up to
[the prior remediation](voip-admission-inventory-review-remediation.md).
Preserve its attribution, startup, consumer-demand and analysis-cost fixes.
Existing privileged validation is recorded there and in
[the original implementation evidence](voip-ebpf-implementation-results.md).
Reuse that evidence for unchanged paths; record new runs for changed boundaries.

Use synthetic fixtures and documentation examples only. Do not include real
packet contents, subscriber or endpoint identities, deployment selectors,
credentials, private operational details or personal filesystem paths. Runtime
diagnostics expose aggregate counts and sanitized reason categories. Exact frame
bytes used for correlation remain transient, bounded and absent from logs,
management responses and persisted evidence.

Keep selection authority, exact endpoint attribution, call lifetimes, observation
domains, expiry, explicit capture restrictions, durability and configured resource
limits intact. Kernel reception never authorizes output. Admission remains opt-in;
diagnostic pressure never opens a domain or overrides the configured failure policy.

This plan introduces no throughput, latency, CPU, RSS or packet-rate acceptance
threshold. Reported saturation rates explain the current mechanism; they are not
product requirements. Verify sampling and retention semantics with deterministic
fixtures rather than qualifying an invented deployment capacity.

## Finding disposition

| Finding | Treatment |
| --- | --- |
| H1, C8 | Required: prominent upgrade/release notes for hunter filter injection and the confirmed SDP, provenance and lifetime changes. Keep the filter repair. |
| C3 | Required: restore bounded operator-visible SDP failure/partial-result diagnostics across non-eBPF paths. |
| C2 | Required: coordinate sampling across kernel decisions and userspace correlation; retain uniqueness and historical-evidence checks. Document actual sizing and uncertainty. |
| C7 | Required: retain unresolved derivation by signaling side/negotiation context until repaired, validly superseded or retired. |
| C4 | Existing budget concern, not a new halving from `0c8fd186`: RTCP and port-only keys already consumed the registry limit. Document it; separating diagnostic storage is a later enhancement. |
| C5 | Existing conservative overflow recovery limitation: lost selection state requires an empty registry. Document it; a bounded complete-selection reconstruction is a later enhancement. |
| C6 | Conservative whole-section rejection, not established wrong attribution: malformed RTCP can discard otherwise usable RTP. Document it; finer salvage is a later enhancement. |

## 1. Document upgrade behavior and retained limits

**Locations:** `CHANGELOG.md`, `cmd/hunt/README.md`,
`docs/VOIP_EBPF_ADMISSION.md`, relevant manual sources and catalogs.

- [x] Add a prominent entry in the repository's next-release changelog location
      without bumping the version or tagging a release. Explain that the old
      receiver-signature mismatch prevented application-filter injection into
      disabled VoIP hunters, allowing legacy broad call selection. The repaired
      path applies distributed identity/IP filters and the empty-filter policy.
- [x] Explain the upgrade effect: configurations that previously forwarded
      broadly despite installed filters can now forward fewer calls. Describe
      intentional broad selection through an empty applicable filter set and
      `--no-filter-policy allow`; clarify that `allow` does not override installed
      filters and explicit capture predicates still apply. Verify this guidance
      against filter distribution and existing command fixtures.
- [x] Release-note safe partial SDP recovery and the supported RTCP, non-audio,
      inactive and mux semantics; TCP final-contributing-interface provenance;
      and the binding of hunter selection to the authoritative tracker lifetime.
      State that tracker eviction/retirement can end inherited media selection
      even if temporary buffer state remains. Do not restore stale authorization.
- [x] Describe the shared endpoint budget, retained port-only diagnostic keys,
      conservative malformed-RTCP handling and empty-registry overflow recovery.
      Attribute these accurately to their existing behavior rather than calling
      each a new regression introduced by the remediation.
- [x] Cross-reference the already recorded privileged tests, distinguishing that
      implementation evidence from verification that did not repeat those runs.

**Completion evidence:** An operator can identify the filtering change before
upgrading, select broad capture deliberately, and understand the remaining limits.

## 2. Restore usable SDP diagnostics

**Locations:** `internal/pkg/sip/sdp_stats.go`, tracker/buffer/processor parsing
paths, `internal/pkg/voip/admission/bridge.go` and their production callers.

- [x] Use the existing aggregate parse counters to restore sanitized,
      rate-limited warnings for partial, failed and resource-limited derivation.
      Wire a production consumer for sniff, hunter, tap and processor, including
      configurations without eBPF or structured-log output.
- [x] Keep warning state fixed-size and concurrency-safe per reporting path.
      Aggregate repeated failures by the existing reason categories; do not
      allocate state per call, endpoint, body or error string. Record suppressed
      occurrences so warning throttling does not discard aggregate accounting.
- [x] Avoid a warning for every parse or duplicate warning at every layer that
      processes the same observation. Define the reporting owner for each role
      and use normal logger/configuration behavior. Do not create an optional
      event runtime merely to report SDP diagnostics.
- [x] Keep bodies, identities and endpoint values out of warning fields. Ensure
      publication of warnings does not add blocking log I/O to packet handling;
      reuse bounded reporting/maintenance facilities or report from maintenance.
- [x] Test partial success, complete failure, resource limits, suppression and
      subsequent reporting, concurrent snapshots and normal valid/inactive SDP.
      Exercise actual role wiring with admission disabled. Verify successful
      endpoint learning and ordinary output remain unchanged.

**Completion evidence:** Operators receive bounded explanations of lost or partial
SDP derivation without private data or a per-packet warning flood.

## 3. Coordinate shadow sampling and bounded retention

**Locations:** `internal/pkg/capture/ebpfadmission/bpf/admission.c`,
`internal/pkg/mediaadmission/shadow_correlator.go`, capture observation and
attribution hooks, `capture/admissionintegration/`, configuration and telemetry.

- [x] Replace independent random kernel sampling for correlatable frames with
      one deterministic eligibility rule shared by kernel emission, capture
      observation and verified attribution. Include domain, full frame length
      and bounded complete frame bytes in the rule; use packet variation beyond
      endpoint headers so sampling does not select an entire RTP stream together.
- [x] Keep the current positive `shadow_sample_every` option and its default
      semantics: `1` includes every eligible identity; larger values select an
      approximately smaller share. Bind the same sampling configuration to all
      hooks for a capture generation. A mismatch or configuration ambiguity must
      produce incomplete evidence, never a confident classification.
- [x] Apply eligibility before retaining an observation/attribution entry or
      acquiring its correlation lock. Unsampled background identities must not
      fill the table or manufacture evidence-loss epochs. Document which traffic
      is eligible; retain honest incomplete accounting for oversized, truncated
      or otherwise uncorrelatable samples.
- [x] Preserve all copies of an eligible identity in duplicate accounting.
      Identical frames must share the same sampling outcome, and every observed
      or attributed copy must count. Sampling hashes only select evidence; exact
      full bytes remain the identity check. Do not independently subsample hooks
      or retain only evidence arriving after an asynchronous kernel sample.
- [x] Preserve bounded capacities, expiry, nonblocking hooks and separate loss
      counters. Actual eligible evidence loss, lock pressure, collisions,
      duplicate traffic, stale owner/revision or generation changes must still
      invalidate unsupported classifications. Do not silently evict evidence and
      classify a later duplicate as unique.
- [x] Add Go/kernel parity fixtures for the sampling rule, including boundary
      frame lengths, domains, packet variation and identical duplicates. Cover
      observation/sample/attribution arrival orders, late evidence, generation
      changes, capacity pressure and loss. Keep framing and verifier bounds valid.
- [x] Add a deterministic synthetic scenario where unsampled background small
      frames do not exhaust retention and an eligible selected-media decision
      remains classifiable. Separately force eligible pressure and verify explicit
      incompleteness. These are semantic regressions, not packet-rate gates.
- [x] Document that capacity counts distinct eligible full-frame identities,
      not all packet occurrences. Give approximate sizing from eligible identity
      arrival rate times the actual retention/maintenance window, with burst
      headroom and owner-state bounds. Explain that `pending_ttl` also controls
      pending SIP metadata; do not casually shorten it as a shadow-only knob.
      State that sampled results do not prove whole-traffic parity or live capacity.
- [x] Regenerate both endian BPF objects and any generated bindings affected by
      the implementation. Keep changes coherent with source and verify actual
      kernel loading plus command telemetry in the isolated test environment.

**Completion evidence:** Sampling reduces userspace retention coherently, while
duplicate detection, exact identity and honest uncertainty remain intact.

## 4. Preserve unresolved offer/answer derivation through recovery

**Locations:** `internal/pkg/voip/admission/bridge.go`, pending metadata,
validated SIP/pipeline metadata, registry reconciliation and recovery tests.

- [x] Add a synthetic regression for a partial selected offer followed by a
      complete opposite-side answer. Assert that the answer does not itself prove
      the offer's unknown sections repaired or disabled. Include media toward an
      unknown offer endpoint from a source not covered by the answer's known
      endpoint, so either-endpoint matching does not hide the uncertainty.
- [x] Replace the single message-overwritten unknown flag with bounded derivation
      state scoped to the current call lifetime and relevant signaling
      side/negotiation. Use validated dialog and transaction metadata already
      available in the SIP pipeline; carry missing fields through shared types
      only where required. Ambiguous or unavailable context stays unknown.
- [x] Define what repairs or supersedes an unresolved derivation. A complete
      update from the corresponding context can repair it; a validated negotiated
      rejection or supersession can retire it only when established by observed
      signaling. A complete unrelated message, opposite-side answer, timeout or
      endpoint snapshot containing only known entries is insufficient alone.
- [x] Bound current context and uncertainty under the existing owner/metadata
      limits; do not retain an unbounded negotiation history. On missing state or
      capacity loss, retain explicit uncertainty and apply the configured policy.
      Retransmission, stale responses and out-of-order messages must not clear
      current uncertainty or borrow a new lifetime's state.
- [x] Preserve promotion of independently safe endpoints during partial parsing,
      and keep known-only capture under the closed policy or scoped broad
      reception under the open policy. Preserve explicit predicates and userspace
      authorization. Keep missing-media expectations unknown until derivation is
      actually established.
- [x] Restore enforcement only when all eligible current contexts are resolved
      or retired, promotions succeed and the complete current-lifetime snapshot
      is confirmed atomically. Preserve visible failed-control-write uncertainty,
      retirement/selection expiry, Call-ID reuse and concurrency protections.
- [x] Test open/closed policy, subsequent same-side repair, valid explicit media
      rejection/supersession, inactive media, stale/retransmitted answers, repeated
      media moves, context-capacity loss, owner retirement/reuse, concurrent
      registry mutation and backend failure. Verify both kernel reception and
      userspace attribution in hunter/tap command composition.

**Completion evidence:** Recovery reports complete reconciliation only after
unresolved derivation has been accounted for across the current negotiation.

## Later enhancements outside required implementation

Keep C4-C6 documented in section 1. They do not block the independent work above.
Future implementation would need its own bounded design and focused regressions:

| Area | Required boundary for a later change |
| --- | --- |
| Diagnostic endpoint storage | Separate non-authoritative port-only keys from authoritative admission accounting while bounding both stores. Do not silently raise configured limits or erase valid lifetime-bound associations. |
| Overflow recovery | Reconstruct all current eligible selections from a bounded authoritative source before clearing lost-owner uncertainty. An empty known-owner list or removal of the empty-registry guard is insufficient. |
| RTP salvage from invalid RTCP | Preserve only independently validated numeric RTP endpoints; retain RTCP uncertainty for admission recovery. Invalid connection scope or resource exhaustion must not fabricate endpoints or permit partial proof to appear complete. |

Inventory defaults/projection, new protocol switches, general performance work,
platform expansion and the reported unrelated intermittent tests remain outside
this plan. Do not add a new optimization or broad assurance campaign for them.

## Execution and verification

Write release guidance first. Implement SDP reporting and derivation recovery;
sampling changes can proceed independently with explicit ownership. Final
documentation must describe the implemented behavior. Check off tasks only after
production wiring and applicable validation demonstrate their completion.

- [x] Run meaningful focused tests and race checks for reporting, sampling,
      lifetime/negotiation state and controller recovery, including disabled
      operation and hunter/tap role paths.
- [x] Run `make test`, `make vet` and the supported `make build-matrix` after
      applicable code changes. Report unavailable toolchains accurately. Keep
      established project checks separate from exploratory performance evidence.
- [x] Run `make test-ebpf` after kernel sampling or recovery integration changes,
      using the disposable privileged container. Follow the repository approval
      rule for execution outside the sandbox and reuse already applicable user
      authorization. Record actual results; do not report a skip as passing.
- [x] Update affected command/help contracts and generated telemetry only where
      the implementation changes them; preserve additive compatibility and
      separate exact counters from sampled observations.
- [x] Update affected English manual sources and every language configured in
      `docs/manual/languages.json`, including German catalogs. Review changed
      fuzzy entries and run `make manual-check` and `make manual`.
- [x] Preserve concise sanitized validation evidence in this plan, and reference
      prior evidence for unchanged boundaries. Verify tasks before checking them
      off. Format changed files, clean owned temporary caches/workloads and commit
      related implementation plus verified plan updates together.

## Execution record

Implemented against `e737c169` using synthetic fixtures. Required sections 1–4
are verified; the bounded closure decision is **CLOSED**. The retained C4–C6
limitations remain documented outside this implementation's required scope.

Upgrade notes explain the repaired hunter filtering behavior and deliberate
broad selection. Fixed-size SDP reporters run from maintenance in sniff, hunter,
tap and processor, including admission-disabled configurations. Warning fields
contain aggregate counters and fixed reason categories.

Kernel emission and userspace observation/attribution share deterministic frame
eligibility. Every eligible duplicate counts; exact bytes determine identity.
Unsampled traffic does not consume correlation retention. Late eligible copies,
configuration mismatch and real evidence loss invalidate unsupported conclusions.
Both endian BPF objects were regenerated; the decision record remains 344 bytes.

Negotiation state preserves uncertainty across partial offers, opposite-side
answers, unrelated messages and failed endpoint promotions. Observed rejection
restores the bounded predecessor; validated supersession can retire it. Context
storage shares configured global limits across domains. Current-lifetime registry
confirmation and successful promotions remain prerequisites for recovery.

Validation completed:

- Focused race checks passed for SDP reporting and actual role wiring, shared
  sampling, lifetime/context budgets, promotion failure, rollback and late copies.
- `make test`, `make vet` and the default supported `make build-matrix` passed
  on the final production changes. Command/help contracts passed for normal and
  LI variants. CUDA link builds were not run; the default matrix explicitly skips
  them unless a configured CUDA builder is selected.
- Full isolated `make test-ebpf` passed, including real kernel loading, sampling
  parity and hunter/tap command composition. The command package completed in
  453.291 seconds. After the final promotion repair, affected real-kernel and
  admission-session tests passed again, as did all four hunter/tap open/closed
  negotiation-recovery cases (104.276 seconds for the command package).
- `make manual-check` and `make manual` passed. German has 5521/5521 current
  messages translated; English and German editions preserve chapter paths,
  heading IDs, examples, code spans and links.

Test durations describe execution only. The opt-in measurement suite was not
run, and these checks establish no performance or deployment-capacity claim.
No sensitive source material is included in the implementation or this plan.

Changed files were formatted, owned temporary test caches were removed, and the
implementation was committed with this verified plan.
