# SIP admission bounded replay and recovery follow-up

**Status:** Completed; implementation and verified plan committed. Closure CLOSED.
**Date:** 2026-10-06

## Objective

Resolve the remaining correctness defects identified after
[safe retirement and recovery](sip-admission-safe-retirement-and-recovery.md):
permanent replay-history exhaustion, repeated reliable answers, malformed
single-header classification, and retention of endpoints learned only from
uncertain exchanges. Make tap grace normalization explicit and correct the
associated documentation.

This is a new follow-up scope. Preserve the completed plan and its recorded
validation history; earlier passing checks do not qualify these new changes.
Use synthetic SIP messages, reserved example addresses, and invented identifiers.
Exclude private report paths, captures, subscriber information, credentials,
deployment details, and operational logs from committed artifacts.

## Scope and acceptance

| Item | Required result |
| --- | --- |
| T1: retired proof history accumulates permanently | Separately bounded replay protection with a defined window, explicit overload behavior, automatic recovery, and aggregate diagnostics. |
| T2: repeated reliable answer only works for delayed offers | Also recognize identical SDP answers to an INVITE offer, requiring each new reliable provisional's own matching PRACK. |
| T3: malformed singleton RSeq/RAck is treated as a conflict | Invalidate that message's reliable proof without poisoning an ordinary offer/answer; expose separate malformed-header counters. |
| T4: uncertain endpoints become protected history | Retire uncertainty-only endpoints through grace while preserving endpoints required by healthy exchanges or the repair. |
| T5: tap grace relies on construction order | Normalize the effective role grace explicitly and verify both direct construction and real startup. This is hardening, not a demonstrated CLI regression. |
| T6: inaccurate hunter grace documentation | Describe configured PCAPGracePeriod with its existing fallback; document why the validated CSeq minimum is retained. |

Keep admission opt-in, default capture paths, shadow behavior, open/closed failure
policies, authorization, exact lifetime binding, and configured resource limits
intact. Do not clear unrelated uncertainty when repairing a negotiation. Do not
introduce new latency, throughput, CPU, RSS, or soak acceptance targets.

## 1. Retain counterexamples through production paths

Primary locations: `internal/pkg/sip/`, `internal/pkg/voip/pipeline/`,
`internal/pkg/voip/admission/`, processor/scoped completion tests, and
`cmd/tap/` and `cmd/hunt/` adapter tests.

- [x] Reproduce replay-history exhaustion with sequential independent completed
      calls and a deliberately small configured capacity. Verify the current
      failure and retain the regression for the replacement behavior.
- [x] Reproduce an INVITE carrying an offer, reliable provisional carrying an
      answer, bodyless matching PRACK, and a later reliable provisional carrying
      the identical answer with a new RSeq. Include the final 200 and ACK.
- [x] Reproduce malformed single RSeq and RAck on ordinary successful answers
      and on reliable provisionals through the real parser and pipeline.
- [x] Reproduce partial initial SDP followed by repair, and a healthy exchange
      followed by a conflicting re-offer and repair. Track exact endpoint owners
      before repair, during grace, and after expiry.
- [x] Retain zero/negative grace constructor coverage and startup coverage with
      and without per-call PCAP. Assert the effective bridge and completion
      grace, rather than assuming constructor invocation order.
- [x] Exercise applicable counterexamples under open/closed policies and
      enforce/shadow modes; assert attribution and lifetime as well as status.

## 2. T1: define and implement bounded replay protection first

Primary locations: `internal/pkg/voip/admission/lifetime_proof.go`, bridge
lifecycle/retry handling, admission configuration, and tap/hunter configuration
wiring. Finish the storage contract below before implementing its replacement.

### Replay-window contract

- [x] Trace authoritative lifetime assignment, pending metadata, SIP
      retransmission, capture/reassembly, buffering, and forwarding delays.
      Identify which bounds are configured or specified and which are unknown.
- [x] Define a configurable supported replay window. Record the rationale for
      its default using applicable SIP transaction timing, including the
      64-times-T1 horizon where relevant, pending-metadata TTL, and available
      configured delivery-delay bounds. Do not claim an unbounded queue or an
      arbitrary replay is covered by a finite default.
- [x] Measure retirement age using the bridge's monotonic clock, independent of
      packet timestamps. Specify behavior for repeated retirement, lifetime
      replacement, configuration validation, expiry, and shutdown.
- [x] Preserve rejection of explicitly bound old session/generation evidence
      regardless of age. Do not replace exact lifetime checks with TTL checks.
- [x] Document that after protection expires, identical reused wire identities
      cannot distinguish fresh evidence from an old capture or delayed message.
      Keep this residual risk separate from explicit lifetime binding.

### Storage and overload contract

- [x] Select and record the storage design, its configured count/byte bounds,
      accounting, expiry mechanism, and guarantees under each overload stage.
      Replay history must not consume live selected-derivation capacity.
- [x] Preserve protection for the full window: do not evict an unexpired guard
      without a conservative replacement that preserves its protection.
- [x] Specify overflow handling. A probabilistic structure is optional; if used,
      define hash scope, occupancy/saturation criteria, and rotation retention.
      False positives may introduce uncertainty; false negatives within the
      supported window must not authorize old proof.
- [x] Specify the safe fallback for an unrecordable retirement. Do not promise
      Call-ID-local impact without storage that remembers the affected identity.
      If only domain-wide uncertainty is safe, give it an expiry based on the
      last unrecorded retirement plus the supported window.
- [x] Specify automatic recovery for exact capacity pressure, overflow
      saturation, and unrecordable retirements. Recovery is bounded after the
      last overload event; sustained overload may extend degradation. Remove
      permanent bridge-wide `proofHistory.lost` behavior.
- [x] Specify how already-active lifetimes recover when the replay-pressure
      reason expires. Reconcile their remaining evidence and uncertainty; do not
      leave a sticky lifetime-ambiguity flag or blindly declare them known.
- [x] Implement the contract using bounded maintenance and the existing worker
      where appropriate. Preserve lock ordering and exact-lifetime callbacks;
      release all replay allocations on Close.

### Replay regressions

- [x] Replace the test accepting permanent watermark exhaustion with sequential
      calls exceeding capacity over time that remain enforced when in-window
      demand fits. Distinguish cumulative volume from simultaneous window load.
- [x] Cover expiry boundaries, repeated retirement, and independent calls while
      exact guards have capacity; verify live derivation capacity is unaffected.
- [x] Reject reused-identity old proof within the window through exact guards
      and any chosen overflow path; cover relevant capture orders.
- [x] Accept valid fresh proof after the window and explicitly assert the
      documented behavior for unbound old wire evidence arriving afterward.
- [x] Reject explicitly bound old-lifetime evidence even after expiry.
- [x] Cover overload, saturation, unrecordable retirement, sustained overload,
      recovery after the last event, and recovery of existing active calls.
- [x] If probabilistic overflow is selected, cover collisions and full-window
      retention across rotation. Verify accounting and cleanup under races.

## 3. T2: complete repeated reliable-answer handling

Primary locations: `repeated_reliable.go`, reliable negotiation derivation, and
early-dialog proof handling in `internal/pkg/voip/admission/`.

- [x] Separate the canonical accepted offer/answer from the pending acknowledgement
      of each subsequent reliable provisional. Support both an answer in PRACK
      for a delayed offer and an answer in the reliable response to an INVITE offer.
- [x] Require the same authoritative lifetime and early dialog, identical SDP
      according to the existing comparison contract, valid sequence progression,
      and the new provisional's own matching RAck/PRACK proof.
- [x] Keep changed SDP conservative and add-only until a valid recovery exchange;
      do not let unrelated, stale, malformed, or mismatched acknowledgements prove
      a repeated answer.
- [x] Cover identical and changed repeated SDP, same-RSeq retransmission, missing
      and wrong PRACK, separate forks, and final 200 repeating the answer. Preserve
      existing delayed-offer regressions.

## 4. T3: separate malformed reliable headers from conflicts

Primary locations: `internal/pkg/sip/reliable_evidence.go`, pipeline evidence,
bridge header classification, and diagnostics.

- [x] Represent malformed singleton RSeq/RAck separately from duplicate conflicts.
      Define mixed valid/malformed duplicate handling explicitly; preserve existing
      conservative conflict and CSeq-bound behavior.
- [x] Ensure malformed reliable headers cannot supply reliable proof. Allow an
      otherwise valid ordinary offer/answer to proceed without unrelated reliable
      header uncertainty.
- [x] Test malformed singleton RSeq/RAck on ordinary 200 responses and reliable
      provisionals, including repair responses. Preserve identical/conflicting
      duplicate, whitespace, numeric normalization, and method-case coverage.
- [x] Add bounded aggregate malformed-header counters separate from conflicts,
      with documented counting semantics and no content-bearing labels.

## 5. T4: preserve endpoint provenance during repair

Primary locations: `derivation.go`, `negotiation_recovery.go`, and
`endpoint_retirement.go` in `internal/pkg/voip/admission/`.

- [x] Distinguish healthy historical requirements from endpoints observed only in
      partial, conflicting, or otherwise uncertain exchanges. Retention alone
      must not promote uncertain endpoints into healthy provenance.
- [x] On complete repair, schedule uncertainty-only endpoints for existing grace
      retirement. Protect endpoints still required by a healthy same-call exchange,
      the repair, or an independent obligation.
- [x] Preserve cancellation on valid reuse, non-extension of existing due times,
      completion handover, exact-lifetime expiry, and shadow non-mutation.
- [x] Verify both retained-endpoint counterexamples, healthy historical endpoints,
      shared endpoints with another call, overlapping requirements, and trailing
      RTP attribution before and after grace using the real processor resolver.

## 6. T5: make role grace normalization explicit

Primary locations: `cmd/tap/voip_admission.go`, tap startup, hunter admission
configuration, and scoped completion integration.

- [x] Normalize nonpositive role grace to the existing completion default at the
      routing configuration boundary. Use the same effective value for admission
      retirement and completion; preserve positive configured values.
- [x] Avoid relying on processor construction mutating a shared configuration.
      Document any intentional low-level bridge support for immediate retirement
      rather than accidentally changing unrelated constructor semantics.
- [x] Verify zero, negative, and positive values in direct routing tests and the
      production startup path, with and without per-call PCAP. Preserve hunter
      fallback behavior and trailing-media attribution.

## 7. Diagnostics and documentation

Primary locations: media admission status, admission telemetry, management proto
and generated code, remote status/types, CLI JSON, TUI, and VoIP admission docs.

- [x] Publish aggregate replay guard usage/bounds, effective window, overflow
      occupancy if applicable, saturation/unrecordable counts, and remaining
      degraded-proof time. Define gauge/counter semantics and overlap with existing
      unique unknown-call counts.
- [x] Carry replay and malformed-header diagnostics through controller status,
      telemetry, additive protobuf fields, remote conversion, actual CLI JSON, and
      TUI. Retain compatibility with older peers and absent optional fields.
- [x] Log failures to record replay protection at warning level with bounded
      frequency. Include useful aggregate context without wire identities,
      endpoints, tags, branches, or subscriber information.
- [x] Update `docs/VOIP_EBPF_ADMISSION.md` and affected command documentation with
      replay-window configuration, overload/recovery behavior, residual risk,
      malformed-header handling, and explicit grace normalization.
- [x] Correct hunter documentation: it uses configured `PCAPGracePeriod` with the
      existing five-second fallback, and has no `--pcap-grace-period` flag.
- [x] Document the retained validated `CSeqMin` range and that only its maximum
      currently bounds recovery. Preserve existing JSON reason-overlap guidance.
- [x] Update affected manual source and every language in
      `docs/manual/languages.json`, including the matching German PO entries;
      review changed fuzzy entries and preserve examples and links.

## 8. Integrated validation and completion

- [x] Run focused race tests for changed parser, pipeline, admission, registry,
      processor/scoped adapter, telemetry/status, remote capture, TUI, and command
      packages under applicable `all` and `tap li` tags. Exercise UDP and fragmented
      TCP adapter paths where evidence propagation changes.
- [x] Build `all`, `hunter`, `processor`, `tap`, `cli`, `tui`, `tap li`,
      `processor li`, and `all li`; run affected vet and the CI lint configuration.
- [x] Run `make manual-check` and `make manual` for every configured edition.
- [x] Run `make test-ebpf` and applicable `test/voip_ebpf_*` suites in an authorized
      privileged environment. Record actual outcomes and skips; do not substitute
      earlier privileged results for validation of this implementation.
- [x] Review the final changes against this fixed T1–T6 scope, especially replay
      expiry/overload guarantees and endpoint ownership. Fix concrete findings
      without introducing unsourced performance gates or an open-ended audit.
- [x] Record sanitized validation evidence here; check off only verified tasks.
      Format changed files, clean task-owned temporary caches/artifacts, and commit
      the implementation together with this updated plan.

## Implementation evidence

Implementation and required validation are complete. Closure outcome: **CLOSED**.

The selected replay design uses exact hashed initiator guards only, with a
separate process-wide count/byte budget shared by domain bridges. There is no
probabilistic overflow or early eviction. An unrecordable guard degrades its
domain conservatively until one replay window after the last failed insertion.
Sustained overload may extend that deadline; expiry reclaims storage and reconciles
remaining active-call evidence without a restart. Explicit session/generation
checks remain independent of the window. Guard insertion failures are counted
and warnings are rate-limited by the configured retry interval.

The initial configurable window is two minutes, an engineering margin over the
usual 32-second SIP transaction horizon and the existing 30-second pending TTL.
The timing references are [RFC 3261 section 17.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.2),
its non-INVITE transaction timing for PRACK, and
[RFC 3262 section 3](https://www.rfc-editor.org/rfc/rfc3262.html#section-3)
for reliable provisional retransmission. These use 64 times T1 where applicable;
T1 defaults to 500 milliseconds and may be configured larger by peers.
This is not a guarantee that all forwarding delays are bounded: deployments must
configure the window for their buffering/reassembly conditions. Evidence arriving
after expiry remains subject to the documented identical-wire ambiguity. Defaults
are 10,000 guards and 2 MiB of separate accounted storage, enforced across domains.

Verified evidence so far:

- [x] Full `all` race suites pass for SIP, pipeline, VoIP and its subpackages,
      call registry, media admission, command configuration, telemetry, status,
      remote capture, and TUI components. Focused `tap li` suites and direct tap
      routing/grace tests pass. Production processor/scoped RTP tests cover both
      uncertainty-only endpoint counterexamples, shared owners, expiry, and shadow.
- [x] Replay regressions cover finite capacity, separate/global accounting, window
      expiry, explicit old lifetimes, overload extension/recovery, newly selected
      and established calls, and pressure-affected retirement. Scoped review found
      two defects: rejected SDP reaching a fallback and missing bounds discarded
      at later retirement. Both were fixed and their regressions pass. Cached
      pre-pressure answers cannot clear missing-proof uncertainty.
- [x] Nine required role/feature variants build; affected host and CI-toolchain vet
      pass. The full CI-pinned linter now reports zero issues after the startup
      fixture correction.
- [x] Manual validation reports 5549/5549 current German translations, and both
      English and German manuals build after the final wording corrections.

Final closure evidence:

- [x] Real tap startup race tests now pass outside the sandbox for zero, negative,
      and positive grace, with and without per-call PCAP. The test-owned filter
      directory is explicitly private (0700); production ownership checks remain
      intact. Full tap and hunter race suites and processor subpackages pass with
      `all`; tap, processor and LI subpackages pass with `tap li`.
- [x] The exact CI-pinned golangci-lint 2.5.0 check with Go 1.25.13 reports zero
      issues, including its govet checks. The temporary linter download is removed
      automatically after execution.
- [x] Privileged `make test-ebpf` completed successfully in the isolated runner,
      including kernel admission, admission integration and all applicable
      `TestVoIPEBPF` command suites. Command tests completed in 517.279 seconds.
      The optional measurement test was skipped because its opt-in variable was
      disabled; no performance qualification is claimed.
- [x] Record the terminal closure decision, format and commit code plus this plan.
      Code and the verified plan are committed; task-owned temporary evidence and
      linter downloads have been removed. Prior environment limitations were
      resolved by authorized unrestricted execution.

One bounded closure campaign (`replay-followup-2026-10-06`) independently reviewed
T1–T6. Its single discovery found one fixture issue (CF1: filter-store directory
mode), fixed in one primary batch. The one integrated review is clear, and the
startup regressions pass under both tags. No additional material production
finding or supplemental batch. All required gates passed; terminal outcome CLOSED.
No remaining scoped deferral. Optional live/private deployment and performance
qualification beyond these tests are not claimed.
