# VoIP Reliable Provisional Answer Recovery

**Date:** 2026-10-05
**Status:** Implemented, verified and committed locally
**Baseline:** `fa87a86b`
**Basis:** Targeted verification findings and the code-checked second opinion.

## Objective

Restore admission recovery for a delayed offer answered in PRACK, and correct
operator guidance about hunter selection, shadow sizing and retained SDP limits.
Preserve the completed work in
[the observability and recovery follow-up](voip-admission-observability-and-recovery-follow-up.md).
This plan addresses newly identified boundaries without reopening that entire
implementation or replacing its recorded validation.

Use synthetic signaling and traffic fixtures. Include no private report paths,
real packet contents, subscriber identities, deployment details or credentials.
Retained signaling descriptors must be bounded and absent from logs and status.

## Scope and disposition

| Area | Treatment |
| --- | --- |
| Delayed offer answered in PRACK | Required implementation and focused regressions. |
| UPDATE interpretation | Required standards-correct documentation and tests; UPDATE already participates in negotiation. |
| Hunter empty-filter default | Required release/manual wording correction. |
| Shadow default sizing | Required prominent warning and practical sizing guidance; preserve current defaults. |
| Ordinary-path endpoint limits and port 65535 | Required documentation corrections; preserve existing limits and parsing behavior. |
| Processor diagnostic decoding | Bounded investigation only; retain diagnostics without output demand. Any optimization is separate work. |
| Answer to a peer-initiated re-INVITE | Separate recovery design question; no cross-initiator state clearing in this implementation. |

No latency, throughput, CPU, RSS, scan-duration or packet-rate acceptance gate is
introduced. Measurements remain observations, not deployment guarantees or
mandatory optimization work. Preserve selection authority, exact endpoint
attribution, call lifetimes, observation domains, expiry, explicit capture
restrictions, durability and configured resource-limit enforcement.

## 1. Establish the reliable offer/answer contract

**References:**
[RFC 3262 sections 3, 5 and 7](https://www.rfc-editor.org/rfc/rfc3262.html),
[RFC 3311 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc3311.html).

- [x] Add a synthetic failing regression for a bodyless INVITE, a reliable
      tagged 183 with an SDP offer, a matching PRACK with a complete SDP answer,
      the successful final INVITE response and a bodyless ACK. Exercise both
      failure policies. The domain remains uncertain before the matching answer
      and can recover afterward when other recovery prerequisites are satisfied.
- [x] Specify the normalized proof linking the PRACK to the observed reliable
      provisional response: dialog/fork identity, RAck response number matching
      RSeq, and RAck CSeq number/method matching the response's CSeq. Validate
      numeric bounds and method semantics from the applicable SIP contract.
      PRACK has its own CSeq and Via branch; do not require them to equal the
      original INVITE's transaction identifiers.
- [x] Distinguish an answer to a delayed offer from a new offer carried in
      PRACK. A method name or complete SDP body alone cannot establish the role.
      Unimplemented or ambiguous exchanges preserve uncertainty and independently
      safe endpoint promotion rather than claiming complete negotiation support.
- [x] Correct the UPDATE requirement: a valid UPDATE carries a new offer and
      receives its answer in the response. In the delayed-offer early-dialog
      sequence, the preceding offer must first be answered in PRACK. Define tests
      for a subsequent valid UPDATE exchange; do not reinterpret an arbitrary
      UPDATE body as the answer to the outstanding 183 offer.

## 2. Retain bounded linkage and integrate recovery

**Locations:** `internal/pkg/sip/`, `internal/pkg/pipeline/sip_result.go`,
`internal/pkg/mediaadmission/metadata.go`,
`internal/pkg/voip/admission/bridge.go` and `derivation.go`.

- [x] Trace reliable-response headers through actual parser, UDP/TCP pipeline,
      pending metadata and selected-call paths. Raw lowercase headers already
      exist in `SIPResult.Headers`; retain only validated normalized linkage
      fields required by recovery. Carry extra shared fields only where needed.
- [x] Retain the relevant reliable-response/answer descriptors within existing
      pending and selected-context limits. Charge additional retained fields,
      preserve global accounting across domains, and bound predecessor and
      retransmission state. Do not create an unbounded reliable-response history.
- [x] Extend negotiation recovery using exact reliable-response linkage, rather
      than adding PRACK to the method allowlist. Bind proof to the current
      selected registry lifetime, capture session, domain and dialog fork.
      Missing, malformed, conflicting or ambiguous proof remains unknown.
- [x] Resolve the initiating bodyless INVITE's missing answer only from its
      complete validated matching PRACK answer. The 183 offer alone, a bodyless
      final response or ACK, and complete SDP in unrelated transactions must not
      clear it. An incomplete matching answer remains incomplete while its
      independently validated endpoints can still be promoted.
- [x] Preserve uncertainty for other unresolved contexts, pending failed
      promotions and control-write failures. Restore enforcement only after the
      complete current-lifetime registry snapshot is confirmed atomically and
      required endpoint associations succeed. Kernel reception never grants
      userspace output authority.
- [x] Ensure retransmission, stale arrival, descriptor expiry/eviction, capacity
      loss, retirement, Call-ID reuse and shutdown cannot borrow reliable proof
      from another lifetime or silently turn lost proof into completeness.

## 3. Verify the changed signaling boundaries

**Locations:** existing admission derivation/budget/promotion tests and
`test/voip_ebpf_negotiation_test.go` or a meaningfully named adjacent fixture.

- [x] Exercise the successful delayed-offer sequence under open and closed
      policies, including actual parsed reliable-response headers and both UDP
      and TCP signaling paths. Verify known endpoint learning before recovery,
      missing-media uncertainty and eventual complete reconciliation.
- [x] Cover missing/malformed/mismatched RAck and RSeq, mismatched referenced
      CSeq/method, wrong dialog fork/domain/lifetime, unreliable provisional
      responses, conflicting retransmissions and stale evidence. None may clear
      unresolved derivation or widen output authorization.
- [x] Cover duplicate and out-of-order response/answer observations. Recovery
      requires both matching observations while their bounded proof remains
      available; missing or discarded observations remain uncertain. Test repeated
      provisional responses and final-response SDP so they cannot erase the
      validated answer or introduce unsupported recovery.
- [x] Preserve an exact PRACK rejection captured before its request and across
      a rejected UPDATE rollback. Retain bounded rejection provenance, prevent
      retransmissions from reviving rejected proof, and ignore failures that
      belong solely to an accepted superseded negotiation. Verify accounting
      and retirement under both failure policies.
- [x] Allow a bodyless final-response descriptor captured before the reliable
      provisional offer to acquire its first validated offer linkage. Preserve
      uncertainty for genuinely conflicting offer/linkage or final SDP bodies.
- [x] Exercise partial answers, safe endpoint promotion failures, configured
      context/byte/endpoint limits, owner retirement/reuse and concurrent registry
      mutation. Preserve the existing rollback, unrelated-message and opposite-
      side-answer regressions.
- [x] Verify a standards-valid PRACK exchange followed by UPDATE/new-offer and
      matching answer. Separately show that unrelated UPDATE signaling cannot
      be treated as a matched PRACK answer. Preserve valid UPDATE supersession
      through the existing observed-negotiation rules.
- [x] Add focused hunter/tap command cases for both failure policies. Verify
      domain status, actual kernel reception, exact userspace attribution and
      unselected/explicit-predicate negatives through recovery. Use synthetic
      source endpoints that prevent either-endpoint matching from hiding unknown
      media. Retain admission-disabled and offline behavior.

## 4. Correct operator documentation

**Locations:** `CHANGELOG.md`, `cmd/hunt/README.md`,
`docs/VOIP_EBPF_ADMISSION.md`, affected manual sources and translations.

- [x] State prominently that `--no-filter-policy` defaults to `deny`. Explain
      that, with the repaired hunter filter wiring, an empty applicable filter
      set forwards no calls by default. Deliberate broad selection requires
      `--no-filter-policy allow`; installed filters and explicit capture
      predicates continue to apply.
- [x] Add a prominent shadow sizing warning: the default 1024 identities,
      sampling interval 1 and roughly 60–61-second retention leave little room
      for distinct eligible background identities. Explain the approximate
      capacity/retention calculation and burst headroom as sizing guidance, not a
      supported packet-rate limit or acceptance gate. Preserve default settings.
- [x] Explain the practical tradeoff between sampling and increasing capacity.
      Maintenance scans retained entries while holding the correlation mutex;
      hooks use `TryLock`, so concurrent eligible observations can become evidence
      loss. Larger capacity increases retained memory and scan work. Recommend
      considering sampling first as eligible identity volume grows, while
      preserving honest incomplete accounting and all eligible duplicate copies.
- [x] Describe separate correlation, diagnostic-history, owner-history and
      kernel-ring storage costs. Include exact per-entry byte estimates or scan
      timings only with a reproducible method, workload, architecture and
      toolchain. If those data are unavailable, document the components and
      scaling behavior without adding a benchmark task or numerical promise.
- [x] Replace blanket advice to "configure limits" with path-specific guidance.
      The ordinary tracker and local VoIP processor have library defaults of 64
      and 32 endpoints respectively, without an operator endpoint-limit setting
      in their current command wiring. Distinguish admission settings from those
      registry limits. Do not add new configuration controls in this plan.
- [x] Document why audio RTP port 65535 cannot derive an implicit RTCP port,
      including the supported mux/explicit-RTCP cases verified against parser
      fixtures. Describe retained conservative parsing behavior accurately.
- [x] Document the supported delayed-offer PRACK sequence and corrected UPDATE
      semantics after implementation. Keep unresolved proof and unsupported
      exchanges visible; do not claim unrestricted PRACK negotiation support.
- [x] Update affected English manual sources and every language configured in
      `docs/manual/languages.json`. Translate changed German entries, preserve
      examples/link targets/heading IDs, and run `make manual-check` and
      `make manual`.

## Separate investigation and later work

These questions do not block the required PRACK repair and documentation work.
Complete the bounded decoding investigation with a recorded recommendation;
implementation of either area requires separate scope.

- [x] Trace processor diagnostic decoding before the consumer-demand guard and
      determine whether existing metadata or a safe SIP candidate check can
      avoid unnecessary decoding. Preserve warnings without output/event demand,
      nonstandard SIP ports, supported framing/link types and single reporting
      ownership. Moving diagnostics behind the demand guard is insufficient.
      Record a concrete option or explain why no safe local change was found;
      do not start an optimization or benchmark campaign.

Cross-initiator recovery remains a later design question: a complete answer to a
peer-initiated re-INVITE currently belongs to another initiator context. Any future
repair must prove that the completed negotiation supersedes the earlier unresolved
context, including rejection, glare, forks and stale responses. Endpoint
completeness alone cannot supply that proof. This plan leaves that behavior intact.

Separate diagnostic endpoint storage, reconstruction after owner overflow, finer
RTP salvage, shadow data-structure redesign and new resource defaults remain
outside scope.

## Execution and validation

- [x] Run focused tests and race checks for reliable linkage, bounded metadata,
      derivation, promotion and lifecycle handling through production role paths.
      Check tasks only after the applicable implementation and evidence exist.
- [x] Run `make test`, `make vet`, the supported `make build-matrix` and
      `golangci-lint run --timeout=5m --build-tags=all`. Use the workflow's pinned
      toolchain/linter when reproducing CI; report unavailable partitions.
- [x] Run changed privileged hunter/tap recovery fixtures in the disposable
      eBPF test container. Run the full `make test-ebpf` gate for the integrated
      recovery change, following repository approval rules and reusing applicable
      authorization. Record actual passes and skips separately.
- [x] Reuse prior kernel/sampling evidence for unchanged boundaries. No BPF
      object regeneration is required unless BPF source or generated contracts
      change; if needed, use the repository toolchain and regenerate both endians.
      A rebuild with another compiler need not produce byte-identical objects.
- [x] Record concise sanitized results and the decoding recommendation here.
      Format changed files, clean owned temporary caches/workloads, verify task
      completion and commit implementation together with the updated plan. Do not
      publish to a remote branch without applicable user authorization.

## Execution record

The delayed-offer recovery regression failed under both failure policies before
implementation. Normalized RAck/RSeq proof now travels through the existing UDP
and TCP parser paths, with bounded selected-context storage and exact lifetime,
dialog and domain ownership. UPDATE remains a separate offer/answer exchange.

One bounded closure discovery found two additional ordering defects: an exact
PRACK rejection captured before its request or across rejected UPDATE rollback,
and a bodyless final response captured before its reliable offer. Eight synthetic
reproductions failed before the primary repair and pass afterward. Rejection
provenance is now cloned and charged in the current negotiation and its single
rollback predecessor; early rejection uses one bounded transaction watermark.
The integrated review resolved both findings with no supplemental finding.

| Validation | Verified result |
| --- | --- |
| Focused admission, SIP and metadata race checks | Passed after the final repair, including proof ambiguity, rejection, rollback, expiry, limits, release, promotion/control failures and lifetime races. |
| Production parsed signaling | UDP and fragmented TCP passed with both failure policies under the race detector. |
| Project checks | `make test`, `make vet` and `make build-matrix` passed after the final repair. The matrix includes six ordinary roles and three LI combinations; optional CUDA link builds were skipped. |
| Workflow-pinned lint | Go 1.25.13 with golangci-lint 2.5.0: zero issues after the final repair. |
| Full privileged eBPF gate | `make test-ebpf` passed kernel, live-socket and all hunter/tap command fixtures. Its opt-in measurement fixture was skipped. |
| Final affected privileged verification | Rebuilt the final source in the disposable container; real-kernel admission packages and tap/open/UDP, tap/closed/TCP, hunter/open/TCP and hunter/closed/UDP PRACK fixtures all passed. Verified kernel reception, exact selected output, explicit/unselected negatives, complete reconciliation and retained enforcement after bodyless final response/ACK. |
| Manual | `make manual-check` and `make manual` passed for English and German; all 5528 current German messages translated. |

The full privileged gate compiled before the final stale-evidence guard and the
two closure repairs; the final affected-container run verified those changes.
BPF sources, generated contracts and committed objects were unchanged, so no
object regeneration was performed. The isolated test toolchain uses Clang 18.
No performance benchmark, new resource default or decoding optimization was
introduced. The previous follow-up remains complete, with its evidence preserved
in its own plan.

Closure decision: **CLOSED** for the required scope, with no unresolved mandatory
finding. Cross-initiator recovery and diagnostic optimization remain outside this
implementation. Changed Go files were formatted, diff checks passed, owned
temporary caches and container workloads were cleaned, and implementation and
plan were committed locally. No remote publication was performed.

### Processor decoding investigation

`processBatch` invokes SDP diagnostics before the output/event-demand guard.
`completeSDPBody` calls the envelope's cached `Packet()` before testing the SIP
start line. Distributed metadata supplies protocol hints and ports, but no
authoritative SDP-completeness result. Already decoded packets are reused, and
the local tap VoIP reporting owner suppresses duplicate central reporting. The
existing central-ingress regression deliberately verifies warnings without
admission, an event runtime or an output consumer.

A separate change could add a bounds-checked transport-payload candidate check
for explicitly supported framing/link types, retaining the current decoder as
a fallback for unhandled forms. It must recognize SIP start lines independently
of standard ports and preserve complete TCP framing, truncation/error rejection
and reporting ownership. Metadata labels or port 5060 alone cannot safely justify
skipping diagnostics. Record semantic equivalence with the existing observer
before adopting such a change. No decoding optimization or benchmark was performed
in this plan's implementation.
