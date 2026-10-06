# SIP endpoint retirement compatibility

**Status:** Completed and verified; implementation and plan committed.
**Date:** 2026-10-06

## Objective

Limit destructive endpoint retirement to confirmed recovery from faulty or
unresolved PRACK evidence. Preserve historical endpoint attribution for healthy
re-offers and hold/resume, and preserve userspace attribution in shadow mode.
Keep the existing reliable-provisional recovery fixes and conservative proof
validation intact.

This plan follows a verification report and a code-based second opinion. The
reported runtime cases require retained reproduction tests before implementation.
Use synthetic SIP/RTP traffic, reserved example addresses, and invented call and
dialog identifiers. Do not include private report paths, captures, subscriber
identities, deployment details, credentials, or operational logs.

## Scope and decisions

| Finding | Treatment |
| --- | --- |
| R2: endpoint retirement also affects healthy re-offers and shadow attribution | Correct the retirement eligibility and ownership boundary; retain production-path regressions. |
| R3: callee-initiated re-offers do not repair caller PRACK uncertainty | Document caller-initiated recovery explicitly; preserve the deferred implementation scope. |
| R4: duplicate CSeq invalidates ordinary negotiation evidence too | Document the broader conservative policy and its recovery limitations; preserve the current proof checks. |

Ordinary re-offers retain the registry's existing accumulate-and-cleanup behavior,
including its existing trailing-media lifecycle. Do not introduce a new endpoint
grace timer or change the call tracker expiry policy. Shadow mode may maintain
internal derivations and diagnostics; the new recovery cleanup must not delete
shared registry ownership in that mode. Normal processor associations and
authoritative call-finalization cleanup continue to operate.

Callee-initiated repair, fork resolution, identical-tag identity reuse, repeated
SDP in later reliable provisionals, and demand-driven diagnostics remain separate
work. Timing failures in unrelated integration suites are not part of this repair;
an isolated pass alone does not establish that a failure is unrelated. There are
no new throughput, latency, memory, or soak acceptance targets.

## Step 1: Retain the compatibility counterexamples

Primary locations: `internal/pkg/voip/admission/` regression tests and
`internal/pkg/voip/` processor/pipeline integration tests. Use descriptive test
filenames rather than filenames named after plan steps.

- [x] Reproduce a healthy established call moving to disjoint endpoints through
      a complete confirmed re-INVITE and UPDATE. Retain old endpoint ownership
      as the expected compatibility behavior; include repeated moves and a move
      back to previously used endpoints.
- [x] Reproduce hold using an inactive or disabled SDP description, followed by
      resume. Verify that hold contributes no new media endpoints while retaining
      previously accepted registry ownership until authoritative cleanup.
- [x] Drive the real VoIP processor with its admission bridge attached, as tap
      does. Send synthetic RTP on the old endpoint pair after the successful
      re-offer or hold and assert resolved call identity and lifetime, rather than
      checking only a bridge media set.
- [x] Create two concurrent calls sharing one exact endpoint. Keep the other
      endpoint unique to each call. Verify that trailing media from the first
      call retains its original attribution after a healthy re-offer; cleanup
      must not make the second call its sole candidate.
- [x] Exercise enforce and shadow modes, both failure policies where applicable,
      and the corresponding tap/hunter adapter paths. Compare shadow attribution
      with the existing processor behavior without destructive recovery cleanup.
- [x] Retain healthy reliable PRACK and ordinary delayed-offer/ACK cases alongside
      the faulty-PRACK cases. Successful reliable negotiation must not be mistaken
      for unresolved PRACK evidence.

## Step 2: Restrict recovery eligibility and retirement provenance

Primary files: `internal/pkg/voip/admission/derivation.go`, `reliable.go`, and
`bridge.go`; use the existing exact-lifetime registry operation.

- [x] Trace establishment, negotiation acceptance, uncertainty, endpoint
      provenance, and cleanup through the real processor and hunter entry points.
      Separate current admission requirements from historical attribution
      ownership; registry snapshots currently also feed admission reconciliation.
- [x] Make destructive retirement require explicit evidence that this confirmed
      caller-initiated negotiation supersedes faulty or unresolved PRACK context
      in the same established dialog and live call. Dialog establishment alone,
      generic uncertainty, or the existence of a PRACK slot is insufficient.
- [x] Cover mismatched RAck, PRACK SDP following an unreliable provisional,
      partial answers, and missing PRACK answers followed by ACK SDP. The last
      case may have no SDP-bearing PRACK descriptor; do not rely solely on a
      populated answer slot to recognize the repair obligation.
- [x] Retain the complete offer/answer, exact transaction, accepted response,
      dialog, and lifetime checks. A partial, rejected, stale, wrong-dialog, or
      unconfirmed replacement must not authorize retirement or false recovery.
- [x] Select obsolete endpoints from the superseded faulty context and its
      bounded retirement provenance. Preserve ownership required by current
      valid evidence, independent SDP requirements, other dialogs, and other calls.
      Do not subtract the entire registry snapshot or indiscriminately retire the
      whole previous media set.
- [x] Keep ordinary healthy re-offer and hold/resume registry ownership under
      the existing lifecycle policy. After successful faulty-context repair, a
      later healthy re-offer must not inherit destructive retirement eligibility.
- [x] Suppress the new destructive registry retirement in shadow mode while
      allowing internal proof supersession and diagnostic reconciliation. Verify
      registry ownership and RTP attribution, not merely kernel forwarding.
- [x] Keep provenance bounded and charged to existing configured metadata limits.
      Preserve conservative uncertainty on exhaustion and release accounting on
      supersession, authoritative lifetime retirement, and bridge shutdown.
- [x] Preserve exact-lifetime mutation, shared-owner resolution, callback reentry,
      publication ordering, and retry behavior. Delayed promotions or replay must
      not reinstall endpoints legitimately retired during enforce-mode repair.

## Step 3: Preserve recovery and clarify compatibility policy

Primary documentation: `docs/VOIP_EBPF_ADMISSION.md`,
`docs/manual/src/part5-advanced/voip.md`, configured translation catalogs, and
`CHANGELOG.md`.

- [x] Verify existing faulty-PRACK recovery through caller re-INVITE and
      established-dialog UPDATE still succeeds in enforce mode, with obsolete
      faulty-context ownership removed and shared valid ownership retained.
- [x] Retain chained partial replacements, response-first capture, late initial
      requests, independent uncertainty, shared independent SDP, and bounded
      accounting tests. Add shadow-mode versions of faulty-context recovery that
      verify original attribution ownership is preserved.
- [x] Clarify that supported repair is caller-initiated. Retain a callee-initiated
      re-offer case demonstrating the documented conservative limitation without
      implementing the deferred feature.
- [x] Document that duplicate CSeq also invalidates ordinary admission negotiation
      evidence, although general consumers retain the last parsed number/method.
      Retain identical and conflicting duplicates on initial INVITE and success
      responses, including a subsequent well-formed re-offer, and describe the
      actual lifetime uncertainty and failure-policy consequences.
- [x] Keep duplicate RSeq/RAck and repeated Require semantics intact. Do not
      relax ambiguous transaction proof as a documentation fix.
- [x] Explain that strict PRACK-answer matching governs admission proof; ordinary
      processor SDP association is a separate behavior. Do not claim that every
      userspace path ignores SDP in ACK.
- [x] Document the difference between faulty-context retirement and healthy
      endpoint retention, including shadow-mode ownership preservation. Add a
      sanitized changelog entry.
- [x] Update every language configured in `docs/manual/languages.json`, following
      `docs/manual/README.md`; review affected fuzzy entries and preserve examples,
      code spans, links, and heading IDs. Run `make manual-check` and `make manual`.

## Step 4: Validate and commit

- [x] Run focused regressions, then affected SIP, pipeline, call-registry, VoIP,
      media-admission, capture, processor, and tap/hunter tests with `all` tags.
      Run affected race suites and relevant `tap li` integration checks.
- [x] Verify real processor RTP metadata and call identity across the retirement
      boundary used by per-call output and identity-based content delivery.
      Preserve independent selectors and existing authorization checks.
- [x] Run the applicable privileged eBPF command suites in the authorized isolated
      runner when available. Record exactly which checks passed, skipped, or were
      unavailable; previous passes do not validate the new changes.
- [x] Compile affected standard and LI build variants and run affected-package
      `go vet`. Distinguish unrelated failures using evidence rather than repeated
      runs alone; follow the project rule for unrelated blockers.
- [x] Review the final diff for private data, unintended scope expansion, and
      weakened lifecycle, authorization, expiry, or configured resource limits.
- [x] Format changed files before staging. Check off tasks only after verification,
      record actual evidence and limitations below, and commit the implementation
      together with this updated plan.

## Acceptance criteria

- [x] Healthy re-offers and hold/resume preserve historical registry ownership and
      trailing-media attribution under the existing lifecycle policy.
- [x] A healthy re-offer cannot redirect trailing media to another concurrent call
      solely because they share an endpoint and cleanup removed the first owner.
- [x] Shadow-mode recovery cleanup preserves userspace registry attribution.
- [x] Enforce-mode confirmed faulty-PRACK repair still retires obsolete evidence
      and ownership while preserving current shared and independent requirements.
- [x] Invalid replacements, replay, exhaustion, and concurrent lifetime changes
      preserve existing authorization and proof protections. Deferred identical-tag
      identity reuse is not redesigned by this repair.
- [x] Caller-only repair and duplicate-CSeq admission behavior are accurately
      documented and covered by retained tests; deferred protocol work stays out
      of scope.
- [x] Documentation, all configured translations, validation evidence, and the
      committed implementation agree.

## Implementation evidence

The retained counterexamples reproduced premature deletion of healthy ownership
and changed shadow attribution before the production repair. Healthy re-INVITE,
UPDATE, hold/resume, matching PRACK, ordinary delayed ACK, repeated moves, and
shared-endpoint cases now preserve historical attribution. Faulty-context repair
still removes obsolete ownership in enforce mode; shadow retains registry
ownership. Generic partial SDP does not authorize destructive retirement.

`derivationState` now distinguishes unresolved PRACK recovery from ordinary
establishment, records the originating sequence, and retains bounded healthy
endpoint provenance separately from faulty provenance. Metadata accounting charges
both sets. Confirmed recovery clears destructive eligibility. Retirement selects
only the exact superseded context and protects current and independent historical
requirements; the existing exact-lifetime mutation and publication ordering remain
in place. Unconfirmed ordinary moves retain only their existing bounded rollback
history. The byte-capacity fixture budgets one descriptor using its actual charge,
then verifies that an additional answer exceeds the same configured pool.

Retained coverage:

- [x] Admission compatibility tests cover both modes and failure policies,
      healthy and faulty exchanges, shared independent dialog history, generic
      uncertainty, caller-only repair, duplicate CSeq, chained partial recovery,
      accounting release, and later faults reusing earlier healthy endpoints.
- [x] Real processor/source tests assert RTP identity, lifetime, media resolution,
      and protobuf metadata, including shared-endpoint trailing media and shadow
      comparison with ordinary processing. These are the metadata consumed by
      per-call output and identity-based delivery; no live delivery destination
      is used or claimed as end-to-end delivery qualification.
- [x] Tap and hunter tests each exercise UDP and fragmented TCP through their
      production adapters. Hunter tests also verify inherited selector provenance.
- [x] Existing proof, invalid replacement, response-first, late request, replay,
      independent uncertainty, lifetime races, callback/retry, and exhaustion
      tests pass in the affected race suites.

Completed validation:

- [x] `go test -race -tags all` for SIP, pipeline, call registry, VoIP,
      media admission, capture, processor, LI, tap, hunter, and sniff packages.
- [x] `go test -race -tags 'tap li'` for VoIP, processor, LI, and tap packages.
- [x] Focused admission compatibility race tests, including the additional
      earlier-healthy/later-faulty same-dialog sequence.
- [x] Builds: `all`, `hunter`, `processor`, `tap`, `cli`, `tui`, `all li`,
      `processor li`, and `tap li`. Temporary binaries were removed.
- [x] Affected-package `go vet` with `all` and `tap li` tags.
- [x] `make manual-check` and `make manual`: English and German editions pass;
      all 5,531 current German messages are translated, and chapter paths,
      heading IDs, examples, code spans, and links validate across editions.
- [x] Final-code privileged PRACK and negotiation command rechecks in the
      disposable isolated runner: UDP and TCP, tap and hunter, both failure
      policies pass. The container and its temporary build cache were removed.
- [x] Bounded independent discovery and integrated post-fix review: one concrete
      capture-order finding fixed and verified; no remaining material finding.
- [x] `make test-ebpf`: kernel decision/equivalence and live socket integration
      pass; all command suites pass, including domains, negotiation recovery,
      owner-capacity recovery, partial SDP, reliable PRACK, fault recovery, and
      independent selector isolation in enforce/shadow modes. After the final
      capture-order repair, the affected PRACK and negotiation command cases
      were rerun against a freshly rebuilt binary as recorded above. Optional
      performance measurement was skipped by the runner's default configuration;
      it is not a correctness gate. Disposable containers removed their caches.

The bounded independent review found one additional capture-order defect:
a response-first healthy re-offer could revalidate an old matching PRACK against
an already advanced response descriptor, falsely classifying it as faulty.
Retained bridge and real processor regressions reproduced this for both re-INVITE
and UPDATE. The fix preserves exact previously validated PRACK provenance while
requiring completeness and retaining matched-rejection protections. All eight
mode/policy/method cases pass; the processor tests additionally prove shared
endpoint ownership, RTP identity, lifetime, and protobuf metadata. Full admission
and VoIP/tap/hunter race suites passed again after the fix. The integrated
post-fix review found no remaining material issue.

No new performance acceptance threshold was introduced. Caller-only repair,
fork handling, identical-tag lifetime reuse, and repeated reliable-provisional
SDP remain the documented deferred scope.

The implementation, retained tests, documentation, translations, and this plan
were committed together after formatting and validation. The bounded closure
audit completed with no remaining material findings.
