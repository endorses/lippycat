# SIP reliable provisional recovery regressions

**Status:** Complete. Implementation verified, closure audit closed, and changes committed.
**Date:** 2026-10-06

## Objective

Restore recovery through a later complete, confirmed negotiation after a faulty
PRACK exchange, and prevent duplicate SIP headers from corrupting parsed methods.
Keep reliable offer/answer matching conservative and preserve authorization,
expiry, lifecycle isolation, and configured resource limits.

This plan translates a verification report and its second opinion into bounded
implementation work. Reported failures were treated as hypotheses to reproduce with retained
tests before implementation. The reported changes concern SIP
parsing and VoIP admission; this work does not alter TUI pane resizing.

Use synthetic SIP messages, reserved example addresses, and invented identifiers.
Do not copy private report paths, production captures, subscriber identities,
deployment addresses, credentials, or operational logs into repository artifacts.

## Scope and decisions

| Finding | Planned treatment |
| --- | --- |
| S1: duplicate singleton headers corrupt parsed CSeq methods | Combine repeated `Require` lines only. Preserve ordinary CSeq parsing while explicitly handling duplicate singleton evidence. |
| P1: unresolved PRACK evidence prevents later recovery | Allow a later complete, confirmed negotiation on the same dialog to supersede obsolete unresolved PRACK evidence and its endpoint ownership. |
| P3: UPDATE guard blocks recovery after establishment | Restrict the outstanding-offer guard to the early exchange it protects. A complete, confirmed UPDATE after establishment must recover. |
| P2: ACK answer following a bodyless PRACK is rejected | Default to documenting the existing protocol-strict behavior and testing recovery through a later valid negotiation. Add ACK-answer compatibility only if explicitly selected. |

Fork resolution and losing-fork cleanup, same-tag call identity reuse, repeated
SDP handling in later reliable provisionals, demand-driven SDP diagnostics, and
callee-initiated caller repair are separate work. Preserve existing protections
in these areas without expanding this task into their redesign.

## Step 1: Reproduce and define the recovery boundary

- [x] Retain deterministic synthetic regressions in
      `internal/pkg/sip/reliable_test.go` and the existing
      `internal/pkg/voip/admission/reliable_*_test.go` test suites, or descriptively
      named companion files. Do not name files after plan steps.
- [x] Reproduce S1 using identical and conflicting duplicate `CSeq` lines.
      Include duplicated `RSeq` and `RAck`, plus repeated list-valued `Require`.
- [x] Reproduce P1 for mismatched RAck, PRACK SDP after an unreliable provisional,
      and a partial PRACK answer. Follow each case independently with a complete
      re-INVITE and a complete UPDATE after dialog establishment.
- [x] Reproduce P3 with a reliable provisional offer, bodyless PRACK, final
      success response and ACK, then a complete UPDATE and matching success
      response. Contrast with an UPDATE while the early offer is outstanding.
- [x] Record the controller state, unknown-derivation accounting, selected
      endpoint set, and endpoint ownership before and after each exchange.
- [x] Trace dialog establishment, transaction acceptance, rollback evidence,
      and PRACK-slot cleanup in `derivation.go` and `reliable.go`. Define the
      exact evidence required to supersede the old slot; neither a new request
      alone nor a partial or rejected exchange establishes recovery.
- [x] Check the relevant RFC 3261, RFC 3262, and RFC 3311 requirements against
      primary specifications before documenting the chosen P2 behavior.

## Step 2: Correct duplicate-header parsing (S1)

Primary files: `internal/pkg/sip/parser.go`, `internal/pkg/sip/reliable_test.go`,
`internal/pkg/sip/parser_test.go`, and `CHANGELOG.md`.

- [x] Combine only repeated `Require` header lines as list-valued input.
- [x] Preserve the previous last-line CSeq number and method behavior for
      general consumers, or explicitly reject duplicates without exposing a
      comma-corrupted method. Choose and document one consistent parser contract.
- [x] Handle duplicate `RSeq` and `RAck` without concatenating singleton values.
      Prefer explicit duplicate-invalid evidence for reliable matching so a
      conflicting later line cannot supply false proof. Apply the same protection
      to duplicate CSeq evidence where it participates in reliable matching.
- [x] Test identical and conflicting duplicates, header-name case variations,
      ordinary singleton parsing, and repeated `Require` capability detection.
- [x] Verify that response consumers retain usable INVITE/BYE/CANCEL method
      classification under the chosen duplicate-header contract.
- [x] Add a changelog entry describing malformed-header compatibility and
      reliable-proof handling without including incident details.

## Step 3: Supersede unresolved PRACK evidence (P1)

Primary files: `internal/pkg/voip/admission/derivation.go`,
`internal/pkg/voip/admission/reliable.go`, and their regression tests.

- [x] Retire obsolete unresolved PRACK state only after a later complete offer
      and answer is confirmed for the same established dialog and live call.
      Match the confirmed transaction using the existing identity contract.
- [x] Remove the superseded slot's endpoint ownership through existing accounting
      helpers. Shared endpoints must retain ownership from current valid evidence;
      endpoints owned solely by the obsolete PRACK must disappear.
- [x] Ensure `derivationSummary` no longer reports uncertainty solely because of
      the retired slot. Preserve independent uncertainty from missing context,
      another unresolved exchange, or a different dialog.
- [x] Cover all three faulty-PRACK cases with both re-INVITE and UPDATE recovery.
      Assert that only the current negotiation's endpoints remain when disjoint
      synthetic endpoint sets are used.
- [x] Test incomplete, unconfirmed, rejected, wrong-dialog, and stale replacement
      exchanges: these must not retire unresolved evidence or falsely recover.
- [x] Preserve bounded rollback behavior, expiry and budget enforcement, and
      ensure replayed superseded PRACK evidence cannot restore obsolete endpoints.

## Step 4: Narrow the UPDATE guard (P3)

Primary files: `internal/pkg/voip/admission/derivation.go`,
`internal/pkg/voip/admission/reliable.go`, and their regression tests.

- [x] Distinguish an outstanding early reliable offer from unresolved historical
      evidence after the initial dialog has been established. Use observed
      lifecycle and transaction evidence rather than the mere presence of SDP.
- [x] Keep an early UPDATE from acting as the answer to an outstanding reliable
      provisional offer.
- [x] Permit a later complete UPDATE and matching successful response after
      establishment to replace the old context and recover under Step 3's rules.
- [x] Test the early and established cases side by side, including a rejected
      or partial UPDATE, a missing establishment observation, and retransmissions.
- [x] Preserve the successful reliable PRACK path and existing re-INVITE recovery.

## Step 5: Document the P2 compatibility policy and recovery contract

Primary documentation: `docs/VOIP_EBPF_ADMISSION.md`,
`docs/manual/src/part5-advanced/voip.md`, and `CHANGELOG.md`.

- [x] Document the default choice: an ACK answer does not substitute for a
      missing answer in PRACK after a reliable provisional offer. Such an exchange
      stays uncertain until a supported complete negotiation proves recovery.
- [x] Retain a test for the bodyless PRACK followed by SDP in ACK, then verify
      subsequent confirmed re-INVITE and UPDATE recovery. Documenting the invalid
      exchange must not conceal failure to recover after a valid replacement.
- [x] Retain the protocol-strict P2 policy. ACK-answer compatibility was not
      selected or added; enabling it later requires a revised decision and exact
      dialog/transaction matching and stale-input tests.
- [x] Explain which malformed or partial exchanges remain uncertain and which
      later confirmed exchanges supersede them. Avoid promising recovery for
      pre-existing unsupported fork or identity-reuse cases.
- [x] Update affected translations for every language in
      `docs/manual/languages.json`, following `docs/manual/README.md`. Review fuzzy
      entries and preserve examples, code spans, link targets, and heading IDs.
- [x] Run `make manual-check` and `make manual` for the changed manual content.

## Step 6: Validate and complete

- [x] Run focused SIP parser and admission tests, followed by affected SIP,
      VoIP, media-admission, capture, and processor tests with `all` tags.
- [x] Exercise the recovery scenarios through UDP and fragmented TCP in
      `internal/pkg/voip/reliable_pipeline_test.go`; assert recovery and endpoint
      replacement, not merely successful parsing.
- [x] Run affected race tests and relevant `tap li` integration tests using
      synthetic data. Verify existing authorization and lifecycle checks remain
      intact.
- [x] Compile affected `all`, `hunter`, `processor`, `tap`, `cli`, and `tui`
      variants, plus LI variants where shared parser or metadata changes apply.
      Run `go vet` for affected packages and tags.
- [x] Run privilege-dependent eBPF tests only with the required authorization
      and environment. If unavailable, record the unverified kernel behavior
      separately; userspace tests do not establish kernel enforcement correctness.
- [x] Review the final diff for private data and confirm deferred work was not
      pulled into scope. No new performance targets or optimization gates are
      part of this correctness task.
- [x] Format changed files before staging. Mark plan tasks complete only after
      verifying them and record actual validation results and limitations below.
- [x] Commit the implementation together with the updated plan.

## Acceptance criteria

- [x] Duplicate singleton headers do not produce comma-corrupted CSeq methods;
      repeated `Require` capabilities are preserved and malformed reliable proof
      cannot falsely resolve uncertainty.
- [x] Each faulty-PRACK case recovers through a later complete, confirmed
      re-INVITE and through a complete, confirmed established-dialog UPDATE.
- [x] Superseded PRACK endpoints and uncertainty are removed without deleting
      current shared ownership or independent uncertainty.
- [x] Early UPDATE, partial or rejected replacement, wrong-dialog input, and
      stale replay cannot falsely recover or widen authorization.
- [x] Valid reliable PRACK recovery and existing independent lifecycle, expiry,
      and resource-limit checks remain intact.
- [x] Documentation, translations, retained tests, and recorded validation
      agree with the selected P2 compatibility policy.

## Implementation evidence

Synthetic regressions reproduced the parser and admission failures before
correction. Duplicate singleton evidence is carried from the parser through the
pipeline independently of the last header value. The admission implementation
separates established-dialog evidence from acceptance of the current transaction,
retires obsolete PRACK state after a complete confirmed replacement, and removes
obsolete endpoint ownership with an exact registry lifetime check. Publication
is serialized through endpoint mutation and released before snapshot confirmation.

One bounded closure campaign found and corrected two additional reachable cases:
multiple accepted partial replacements could lose older endpoint retirement
provenance, and a late initial untagged request could fail to establish the
recovery boundary. A bounded, budget-charged endpoint retirement set now survives
the single rollback predecessor. Request completion uses the existing dialog
binding rules. The integrated check also corrected preservation of endpoints
shared with independently safe non-negotiation SDP: those requirements now have
bounded, charged descriptors that cannot supply transaction proof. No transaction
history or unbounded endpoint list was introduced.

Retained tests cover both failure policies and replacement methods, response-first
capture, rejected and partial replacements, ambiguous fork binding, valid and
malformed stale replay, independent uncertainty, shared endpoint ownership,
provenance exhaustion, accounting release, UDP, and fragmented TCP. ACK SDP does
not substitute for the required PRACK answer. Fork resolution and the other
listed follow-ups remain outside this implementation.

Verified checks:

- [x] SIP, pipeline, call-registry, VoIP, media-admission, and capture race tests
      with `all` tags, plus affected processor subpackages and tap/hunt commands.
- [x] Final affected VoIP, processor, and tap/hunt race suites with `all` tags
      after the closure repairs.
- [x] Final affected VoIP, processor, and tap race suites with `tap li` tags
      after the supplemental shared-endpoint repair.
- [x] Builds with `all`, `hunter`, `processor`, `tap`, `cli`, `tui`, `all li`,
      `processor li`, and `tap li`, repeated after the closure repairs.
- [x] Affected-package `go vet` with `all` and `tap li` tags.
- [x] `make manual-check` and `make manual`; German coverage is 5530/5530
      current messages. Chapter paths, heading IDs, examples, code spans, and
      link targets were verified across both editions.
- [x] `make test-ebpf` through the isolated privileged container runner: kernel,
      live-socket, tap/hunter command recovery, PRACK UDP/TCP, and selector
      compatibility checks passed. Optional performance measurement was skipped;
      no performance acceptance target is part of this task.
- [x] Go formatting, final scope/private-data review, and `git diff --check`.

Initial processor race attempts inside the sandbox failed because root-owned
ancestors appeared as an unmapped user. An isolated archive of committed `HEAD`
reproduced the same failure without these changes. Both processor suites passed
once authorized outside-sandbox execution was restored. Secure-store ownership
and authorization checks were preserved. Temporary build outputs were removed;
the container runner removes its container and temporary cache on exit.

The closure campaign used one discovery round, one primary repair batch, one
integrated check, and one supplemental repair batch. Both finite findings are
resolved, including their shared-ownership preservation condition. A retained
negative check also verifies that independently safe SDP does not establish
knowledge of an unobserved negotiation. All required validation passed. The terminal closure decision is **CLOSED**.
The implementation and this plan were committed together. Deferred follow-ups
listed in the scope are unchanged and do not belong to this implementation.
