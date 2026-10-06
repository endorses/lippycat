# SIP admission safe retirement and recovery

**Status:** Completed; implementation and verified plan committed.
**Date:** 2026-10-06

## Objective

Preserve trailing-media attribution when uncertain negotiation endpoints are
superseded, make uncertainty recoverable through valid signaling from either
participant, and expose useful aggregate recovery diagnostics. Resolve fork,
repeated-SDP, and call-lifetime proof issues identified by the updated verification
report. Preserve the healthy and shadow compatibility established by
[the completed endpoint-retirement plan](sip-endpoint-retirement-compatibility.md).

Use synthetic traffic, reserved example addresses, and invented identifiers.
Exclude private report paths, packet captures, subscriber identities, credentials,
deployment details, and operational logs from code, examples, and evidence.

## Scope and policy

| Finding | Required treatment |
| --- | --- |
| Q1: immediate faulty-context retirement loses trailing attribution | Delay exact-lifetime endpoint retirement using the applicable existing trailing-media grace policy; cancel retirement when valid negotiation reuses an endpoint. |
| Q2: duplicated headers cause permanent uncertainty | Distinguish identical from conflicting duplicates; preserve safe endpoint learning and implement bounded, recoverable uncertainty. |
| Q3: only caller negotiation repairs PRACK uncertainty | Accept complete confirmed repair from either participant using that initiator's sequence space. |
| Q4: degraded cause is not useful to operators | Publish sanitized per-domain uncertainty counts by reason and expose existing degradation timing. |
| Q5: forks, lifetime reuse, and repeated SDP | Track early dialogs independently, prevent cross-lifetime proof reuse, and recognize valid repeated SDP without reopening resolved uncertainty. |

The release-marker proposal after grace expiry is secondary hardening. Document
the existing one-sided resolution behavior after expiry and its residual risk.
Do not claim that a grace period eliminates arbitrary late-packet misattribution.
Changing that fallback requires an explicit attribution contract and separate
focused evidence; it is not an implicit prerequisite for the required grace fix.

Identical duplicate headers may supply proof only after normal validation.
Conflicting values may contribute independently valid SDP endpoints for an
authorized selected call, within existing limits, but cannot establish transaction
proof, retire ownership, or supersede uncertainty. Endpoint additions do not
authorize output or override explicit capture predicates and userspace selectors.

Common recovery applies to negotiation uncertainty that a complete exchange can
actually supersede. It does not clear unrelated dialogs, lost selection state,
resource exhaustion, missing observations, failed promotions, or failed control
writes merely because a clean SIP message arrives. Recovery requires all remaining
obligations and the current-lifetime registry/controller snapshot to reconcile.

Keep admission opt-in and preserve default paths, shadow attribution, healthy
historical ownership, existing failure policies, authorization, expiry, and
configured resource limits. Introduce no latency, throughput, CPU, RSS, restart,
or soak acceptance targets.

## 1. Retain production-path counterexamples

Primary locations: `internal/pkg/voip/admission/`, `internal/pkg/callregistry/`,
`internal/pkg/voip/`, and tap/hunter adapter tests.

- [x] Reproduce faulty-PRACK repair followed by trailing RTP on the obsolete
      pair, with and without one endpoint shared by another concurrent call.
      Assert original call identity, lifetime, and metadata during grace.
- [x] Cover endpoint reuse before expiry, expiry without reuse, repeated repair,
      call completion during grace, Call-ID reuse, stale callbacks, and shutdown.
      Verify exact ownership rather than only installed endpoint counts.
- [x] Retain identical and conflicting CSeq duplicates on initial INVITE and
      successful responses under open/closed policies. Include clean replacements
      above the conflict maximum, between conflicting values, and replacements
      containing their own conflicting headers.
- [x] Cover identical/conflicting RSeq and RAck, repeated Require, invalid
      duplicate values, and reordered duplicate lines through the real parser.
- [x] Reproduce caller- and callee-initiated recovery, including callee session
      refresh and different sequence-number ranges for the two participants.
- [x] Reproduce multiple early dialogs, winning/losing fork ownership, repeated
      SDP in later reliable provisionals, and stale PRACK after exact lifetime
      reuse with identical tags. Retain both arrival orders where they change
      proof authority.
- [x] Preserve healthy re-offer, hold/resume, delayed ACK, response-first capture,
      generic partial SDP, independent requirements, and shadow regressions.
      Use real processor RTP resolution/protobuf metadata and UDP/fragmented-TCP
      tap/hunter adapters for changed externally visible boundaries.

## 2. Bind proof and delayed work to authoritative lifetimes

Primary locations: admission derivation/pending metadata, registry lifetime
callbacks, validated pipeline metadata, and role-specific processor/tracker wiring.

- [x] Trace when a call lifetime becomes authoritative, how pending observations
      are adopted, and how capture/reassembly, selection, retries, and callbacks
      cross retirement or reuse. Identify which existing generation/provenance
      can distinguish old observations before assigning them to a new lifetime.
- [x] Bind PRACK matching, pending proof, derivation, endpoint provenance, and
      delayed mutations to the exact live lifetime and dialog/transaction.
      Invalidate old reservations, retry work, and pending proof on retirement.
- [x] Reject old-lifetime PRACK and callback replay in both capture orders,
      including identical Call-ID/tags and otherwise matching transaction fields.
      Do not merely look up the current lifetime when consuming stale evidence.
- [x] Define conservative behavior when a wire observation is indistinguishable
      from an old transaction. Do not claim a local generation can distinguish
      arbitrary identical wire messages without supporting provenance.
- [x] Preserve bounded storage/accounting, callback reentry, publication order,
      association failure handling, and concurrent lifetime replacement.

## 3. Delay obsolete endpoint retirement through existing grace

Primary locations: admission bridge, registry endpoint retirement, call tracker
and aggregator lifecycle policy, and corresponding tap/hunter configuration.

- [x] Identify the applicable existing trailing-media grace configuration for
      each role and pass that policy to recovery cleanup. Reuse its semantics;
      do not silently introduce an independent grace default or a new lifecycle
      policy.
- [x] Schedule bounded exact-lifetime retirement of obsolete uncertain-context
      ownership after confirmed supersession. Keep those endpoints attributable
      and reconciled with admission during grace, without allowing their old
      negotiation proof to repair a later exchange.
- [x] Preserve shared-owner intersection: during grace, a pair whose opposite
      endpoint belongs only to the repaired call resolves to that call.
      Preserve independently required, other-dialog, and other-call ownership.
- [x] Cancel only the relevant pending endpoint retirement when a subsequent
      valid exchange takes that endpoint back. Recheck current requirements and
      exact lifetime at execution so a stale timer cannot remove reused ownership.
- [x] On authoritative call completion, discard intermediate recovery retirement
      work and leave the call's existing completion grace in control. Cancel work
      on final removal, eviction, lifetime replacement, and bridge shutdown.
- [x] Keep shadow recovery free of destructive registry mutation. Healthy
      negotiations retain their existing accumulate-and-cleanup behavior.
- [x] Charge retirement state to existing configured limits, preserve explicit
      uncertainty on exhaustion, and release reservations on cancellation/expiry.
      Verify failed mutation/reconciliation and retry paths without losing work.
- [x] Test grace boundaries deterministically where possible, including expiry,
      cancellation races, reused endpoints, shared endpoints, and both policies.
      Document post-expiry one-sided fallback honestly; record release markers as
      secondary hardening rather than claiming they are implemented.

## 4. Normalize duplicates and represent recoverable uncertainty

Primary locations: `internal/pkg/sip/` parser/reliable-header metadata,
`internal/pkg/pipeline/`, and admission key/derivation state.

- [x] Preserve last-line singleton values for general consumers and Require list
      semantics. Add typed distinction between identical and conflicting CSeq,
      RSeq, and RAck values, with a documented comparison rule consistent with
      normal header parsing; malformed values never become valid proof.
- [x] Collapse identical duplicates for ordinary derivation and reliable matching
      after normal validation. Keep occurrence diagnostics separate from active
      unknown-call counts: an identical valid duplicate alone is not uncertainty.
- [x] For conflicting CSeq, retain bounded valid minimum/maximum sequence evidence
      in the relevant initiator's context. Track method conflicts and malformed or
      unavailable bounds explicitly; do not invent a usable range from bad input.
- [x] Conflicting reliable headers cannot supply reliable proof. Conflicting
      transaction evidence cannot retire or supersede anything. Independently
      validated SDP can still add endpoints for the exact selected lifetime,
      subject to authorization, complete parsing requirements, and capacity.
- [x] Represent negotiation uncertainty with fixed reason categories and bounded
      context/provenance. Avoid sticky lifetime-wide loss for recoverable conflicts;
      retain conservative loss states where missing evidence prevents recovery.
- [x] Verify parser-to-pipeline field propagation, normal CSeq consumers, terminal
      call detection, and identity-based output metadata remain compatible.

## 5. Apply complete confirmed recovery from either participant

Primary locations: admission derivation/reliable proof and retirement provenance.

- [x] Define one supersession rule for conflicting transaction evidence, faulty
      PRACK, unresolved delayed offers, and partial SDP. Require exact dialog and
      lifetime, complete offer/answer, valid unambiguous transaction headers, and
      confirmation through matching 2xx or the existing supported ACK-answer path.
- [x] Compare freshness within the repair initiator's sequence space. Require a
      repair above that side's applicable uncertainty maximum/watermark, never a
      comparison between caller and callee CSeq. Define the evidence needed when
      the opposite participant first initiates a repair; absence of a watermark
      alone must not authorize a stale transaction.
- [x] Allow caller and callee re-INVITE/established-dialog UPDATE to supersede the
      affected context, including session refresh. Request alone, partial/rejected
      response, conflicting headers, wrong dialog, and stale replay cannot repair.
- [x] Maintain existing strict reliable-offer answer rules: ACK cannot substitute
      for a missing required PRACK answer. Ordinary supported delayed-offer ACK
      remains distinct, including normal processor SDP association.
- [x] Advance current negotiated media/proof, preserve independent and healthy
      historical requirements, and schedule only obsolete uncertain-context
      ownership for grace retirement. Clear only uncertainty actually superseded.
- [x] Report enforcement restored only after all active relevant uncertainty,
      promotions, configured-limit obligations, and controller writes reconcile.
      Retain response-first, late-request, partial-replacement, rejection, replay,
      concurrent lifetime, and backend-failure regressions for both initiators.

## 6. Resolve forks and repeated reliable SDP

- [x] Track offer/answer proof per early dialog under bounded existing metadata
      limits. Shared call-level state must not mix branch/tag/transaction evidence.
- [x] Confirm the winning dialog using observed signaling. Retire losing-dialog
      requirements and schedule their exclusive endpoint ownership through grace;
      preserve shared endpoints and independent selected evidence. Cover multiple
      successful forks conservatively rather than arbitrarily choosing a winner.
- [x] Treat identical repeated SDP in a valid later reliable provisional as
      repeated content rather than a new unresolved body. Preserve the new
      reliable transaction's required matching/acknowledgment semantics; identical
      bytes alone cannot authorize unrelated RSeq, RAck, dialog, or lifetime proof.
- [x] Cover changed SDP, response/PRACK reorder, reliable 180 without SDP,
      retransmission, rejection, and budget exhaustion. Verify cleanup and
      accounting release for losing forks, completed calls, and shutdown.

## 7. Expose sanitized uncertainty and degradation timing

Primary locations: admission bridge/controller status, `internal/pkg/admissiontelemetry/`,
management protobufs, and current CLI/TUI status consumers.

- [x] Publish per-domain active unknown-call counts by fixed reason categories,
      including conflicting headers, faulty PRACK, partial SDP, unresolved delayed
      offer, fork ambiguity, and resource/lifecycle evidence loss. Define unique
      unknown-call totals and overlapping reasons so counts cannot be mistaken
      for separate calls.
- [x] Publish identical/conflicting duplicate occurrence counters separately
      from current uncertainty, without per-call identifiers or unbounded labels.
- [x] Reuse existing degradation timestamps and duration accounting; expose
      elapsed degradation in status and verify reset on successful enforcement.
      Include closed and control-failure states, not only degraded-open duration.
- [x] Preserve additive management compatibility and generate affected bindings.
      Wire actual tap/hunter telemetry and CLI/TUI consumers, retaining sanitized
      output without endpoints, identities, Call-IDs, or raw parser errors.
- [x] Test concurrent snapshots, multiple domains/reasons, recovery, retirement,
      disabled admission, and control/resource failures through real status paths.

## 8. Document, validate, and commit

- [x] Update `docs/VOIP_EBPF_ADMISSION.md`, affected command/status documentation,
      and `CHANGELOG.md` with the final grace, duplicate, recovery, fork, repeated
      SDP, lifetime, and diagnostic behavior. Remove superseded caller-only and
      permanent-duplicate-uncertainty descriptions without rewriting old evidence.
- [x] Update affected English manual sources and every translation configured in
      `docs/manual/languages.json`. Review fuzzy entries, preserve examples/code
      spans/links/heading IDs, and run `make manual-check` and `make manual`.
- [x] Run focused regressions and affected race suites with `all` tags; run
      relevant `tap li` processor/VoIP/LI integration checks. Verify RTP identity,
      lifetime, selector provenance, and metadata used by per-call output and
      identity-based delivery; do not equate metadata tests with live delivery.
- [x] Run current privileged `make test-ebpf` and affected command tests in the
      disposable isolated runner. Record passes, skips, and unavailable checks
      accurately; earlier suite passes do not qualify changed boundaries.
- [x] Compile affected standard and LI variants and run affected-package vet.
      Diagnose unrelated failures using evidence and follow the repository rule
      for unrelated blockers; do not repeatedly rerun unchanged failures hoping
      for a pass or weaken ownership checks for the sandbox.
- [x] Perform one bounded final review against this implemented scope, with
      concrete finite findings and applicable verification. Preserve configured
      bounds and authorization; do not reopen unrelated completed work.
- [x] Verify every task before marking it complete. Record sanitized evidence
      and limitations below, format files before staging, clean task-owned
      temporary caches, and commit the implementation with the updated plan.

## Acceptance criteria

- [x] During recovery grace, trailing media retains original exact-lifetime
      attribution even with an endpoint shared by another call; expiry and
      endpoint reuse cannot delete current or other-call requirements.
- [x] Identical valid duplicates are usable; conflicts remain add-only uncertain
      evidence until a complete valid fresh negotiation supersedes them.
- [x] Either participant can repair affected uncertainty within its own sequence
      space; stale, partial, ambiguous, wrong-dialog, and old-lifetime proof fail.
- [x] Fork proof remains per dialog; winning/losing ownership is reconciled
      through grace, and valid repeated SDP does not reopen resolved body state.
- [x] Status shows sanitized active uncertainty reasons and degradation duration
      across real role/management consumers, with bounded accounting.
- [x] Healthy and shadow attribution, independent uncertainty, failure policies,
      authorization, configured limits, default paths, and lifecycle cleanup remain
      intact. Required tests, builds, manuals/translations, and commit are verified.

## Implementation evidence

Implementation and required verification are complete. Focused admission race checks pass for semantic
identical/conflicting duplicates, complete confirmed recovery from both
participants, partial and delayed-offer recovery, independent dialog preservation,
sequence freshness, exact-lifetime replay guards, fork confirmation, and repeated
reliable SDP. These focused checks do not establish completion of the full plan.

Retired replay guards remain charged to the existing shared metadata context and
byte limits until bridge shutdown. Malformed sequence bounds block the affected
hashed initiator; missing retired context blocks the affected hashed call. If the
configured pool cannot retain a required guard, subsequent evidence remains
conservatively uncertain. A clean registry snapshot cannot recover missing proof.
Retirement releases live negotiation descriptors, but does not erase replay
protection merely to make accounting appear empty.

All affected race suites pass under `all`, including SIP/pipeline, registry,
admission/telemetry/status, remote conversion, TUI, production VoIP, and tap/hunter
adapters. Broad `tap li` VoIP/processor/LI checks pass; affected post-review
processor/admission/tap checks also pass. Nine builds (`all`, `hunter`,
`processor`, `tap`, `cli`, `tui`, `tap li`, `processor li`, `all li`) and affected
package vet pass on the final production tree. English/German manual checks and
both edition builds pass (all 5,536 German catalog messages translated).

One bounded review found and fixed late second-fork ownership restoration,
monotonic unusable sequence bounds, and supported ordinary delayed-ACK recovery.
The single integrated review confirmed those fixes and identified a missing owned
copy of the retained ACK branch; that correction and a parser-backed storage
regression pass. No additional review round is required.

The first privileged run passed kernel/admission checks and other command suites,
but its negotiation test still required request-only recovery. That fixture now
asserts continued uncertainty until a complete matching answer confirms recovery;
existing output and capture restrictions remain. The fresh final `make test-ebpf` run passes in the disposable privileged runner:
kernel eBPF and libpcap admission integration, command domains, negotiation
recovery, owner-capacity recovery, disabled admission, reliable provisional
answers over UDP/TCP, recovery, and independent selectors. Both tap and hunter
policies/modes covered by those suites pass. The optional measurement suite is
skipped because its opt-in flag was not enabled; no performance qualification is
claimed.

Ordinary race suites retain their existing skips for opt-in live/network/private
fixtures and helper processes. Those skips are not reported as passes. Real
processor/tap/hunter regression fixtures verify RTP call identity, exact lifetime,
shared ownership and protobuf metadata; this does not claim a new live LI delivery
qualification. Required affected LI suites pass.

Closure decision: **CLOSED** after one discovery batch, one primary remediation
batch, one integrated review, and one supplemental storage-ownership correction.
All four finite findings are fixed and affected checks pass. The configured
resource limits, default/shadow behavior, independent evidence, and authorization
checks remain covered. The implementation and plan are committed together. Changed Go files were
formatted, the staged diff passed whitespace checks, and task-owned temporary
evidence and build artifacts were removed. Final workspace verification is clean. The post-grace release marker remains secondary hardening.
