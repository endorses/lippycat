# Reliability Contracts and Keepalive Test Stabilization

**Date:** 2026-10-09
**Status:** complete; implemented, committed and verified locally and in GitHub

## Objective

Make the existing LI shutdown and SIP admission observation contracts precise,
and remove an asynchronous completion assumption from the X1 connectivity
test. Preserve the existing runtime behavior and previously completed
reliability fixes.

This plan stands on its own. Use synthetic messages, invented identities,
reserved example addresses and local test servers. Exclude private verification
artifacts, their filenames or paths, subscriber information, deployment details,
operational logs, captures, credentials and key material.

## Scope and acceptance

| Area | Required result |
| --- | --- |
| Processor shutdown | Documentation states that producer cancellation precedes correlation close and that correlation-held products are not gracefully drained after cancellation. |
| Standalone correlator close | Documentation states that close suppresses retained callbacks even when their individual caller contexts remain live. |
| Backlog bounds | Documentation distinguishes packet/byte limits from the adoption wait deadline; it does not describe the deadline as a strict bound on shutdown loss or residence time. |
| SIP observation time | Documentation defines receipt as the first admission observation of a complete, validated SIP message, after any framing or reassembly. |
| Media proof | Documentation distinguishes proof-bearing messages and outstanding obligations from confirmed authorization. |
| X1 connectivity test | Successful asynchronous keepalive completion is observed explicitly, without a fixed sleep; never-connected and stale-keepalive cases remain covered. |
| Manual consistency | English and every configured translation describe the same contracts and pass the existing manual checks. |

Graceful draining of correlation-held product is outside this scope. It would
require a separate design that keeps authorization, the delivery context and
call lifetime available through a bounded drain. Allowing callbacks after close
alone would not achieve it.

Do not change shutdown ordering, callback cancellation, correlation matching,
uncertain-group join eligibility, pinned IDs, replay-window timing, receipt
binding, authorization, product expiry, persistent storage ownership, configured
resource limits or keepalive behavior. Do not add telemetry, CLI flags,
dependencies, workflow jobs or a new clock abstraction for this work.

The existing CI timeout is an operational limit. Do not invent performance or
soak gates, increase timeouts to mask a flaky test, or reopen completed work
without a concrete defect relevant to these changes.

## 1. Clarify LI shutdown and retained-product bounds

Primary documentation: `docs/LI_INTEGRATION.md` and
`docs/manual/src/part5-advanced/lawful-interception.md`.

Behavior references: `internal/pkg/processor/processor_lifecycle.go`,
`processor_li.go`, `processor_li_correlation.go`, and
`internal/pkg/li/call_correlation.go`.

- [x] Explain that processor and tap shutdown cancel the producer context before
      closing correlation. Products still retained by correlation can be
      discarded before reaching the downstream delivery queue or journal.
- [x] Distinguish this cancellation behavior from the live-operation guarantee:
      an eligible handoff is released with its pinned uncertain ID at the
      adoption deadline or on deferred-queue pressure, subject to authorization,
      lifetime, expiry, cancellation and downstream acceptance checks.
- [x] Explicitly document standalone `CloseContext`: new work stops and pending
      handoffs are suppressed even if their individual contexts remain live.
      Preserve the existing regression that prohibits publication after close.
- [x] State the global deferred-packet bounds: `max_candidates` packets, with a
      default of 10,000, and 32 MiB of accounted packet data. Distinguish these
      limits from capture buffers, reorder buffers and delivery queues. Do not
      present accounted bytes as an exact process RSS limit.
- [x] Explain that `wait_timeout` fixes the logical adoption decision deadline;
      scheduling and callback draining can extend residence beyond it. Do not
      claim that shutdown can lose at most a fixed duration of captured traffic.
- [x] Keep the existing shared `shutdown_timeout`, eventual exactly-once cleanup,
      exclusive writer ownership and retained storage-resource descriptions
      consistent. Clarify that bounded caller return does not cancel physical I/O.

## 2. Define SIP observation time and proof obligations

Primary documentation: `docs/VOIP_EBPF_ADMISSION.md` and
`docs/manual/src/part5-advanced/voip.md`.

Behavior references: `internal/pkg/sipflow/orchestrator.go`,
`internal/pkg/voip/admission/bridge.go`, `lifetime_proof.go`,
`replay_recovery.go`, and the TCP framing/reassembly paths.

- [x] Define an observation as a complete SIP message validated and handed to
      the admission observer. Distinguish this point from raw packet capture,
      initial TCP segment receipt and later call selection.
- [x] State that replay eligibility uses the admission observation clock.
      Capture timestamps remain provenance; they are not substituted for the
      authoritative replay clock.
- [x] Explain the finite-window boundary: a message captured during protection
      but first reassembled and validated after expiry can obtain post-window
      eligibility, subject to the remaining lifetime and proof checks. Elapsed
      time alone does not authorize media.
- [x] Explain that a rejection already stamped on the immutable receipt survives
      delayed registry handoff, selection, staging expiry or eviction, and later
      pressure intervals. Such delays cannot restamp rejected evidence as fresh.
- [x] Use precise proof language: an ACK carrying SDP or a provisional response
      with changed SDP remains proof-bearing or uncertain and must satisfy the
      applicable offer/answer and transaction checks. SDP presence alone does
      not establish media authorization. Retain the exact bodyless-message
      exclusions and reliable/delayed-offer obligations.

## 3. Stabilize the X1 connectivity regression

Primary file: `internal/pkg/li/x1/client_test.go`.
Behavior reference: `internal/pkg/li/x1/client.go`.

- [x] Replace the fixed 10 ms sleep in the successful-keepalive case of
      `TestClient_IsConnected` with bounded synchronization that observes
      successful client-side completion. Receiving an HTTP request at the test
      server alone is insufficient: the client records success after the
      response completes.
- [x] Use existing synchronized client state or a test-local completion barrier.
      Check that a successful keepalive and its timestamp have been recorded.
      Avoid introducing another race between an eventual completion assertion
      and a separate assertion against an artificially tiny freshness window;
      separate freshness-state checks from loop-completion checks if needed.
- [x] Retain coverage for no successful keepalive, recent success and stale
      success. Derive stale state from explicit test timestamps instead of
      waiting for a real-time expiry. Do not weaken connectivity assertions or
      mutate shared client configuration while its loop is running.
- [x] Register cleanup immediately after starting the client and release any
      test barriers on all exit paths. Preserve shutdown and error handling;
      leave production keepalive intervals, retries and freshness rules unchanged.

## 4. Translate, verify and record completion

- [x] Update all affected entries in the catalogs configured by
      `docs/manual/languages.json`, currently `docs/manual/po/de.po` and
      `docs/manual/po/ca.po`. Follow `docs/manual/README.md`; translate changed
      content, resolve affected fuzzy entries, and preserve examples, code spans,
      link targets and explicit heading IDs.
- [x] Run the affected connectivity regression repeatedly with race detection
      and atomic coverage, then run the X1 package suite. Repetition exercises
      scheduling; it is not a new latency or throughput requirement.
- [x] Reuse the existing shutdown and receipt-provenance regressions to check
      the documented boundaries. Add a regression only if a relevant behavior
      lacks coverage; do not duplicate tests or introduce a broad new audit.
- [x] Run `make manual-check` and `make manual` to validate translations and
      build every configured edition. Review the changed contract passages in
      each edition.
- [x] Format changed Go files with `gofmt`, format Markdown consistently with
      repository conventions, and check whitespace and sanitized content before
      staging. Do not modify generated manual HTML or unrelated files.
- [x] Record applicable existing CI results for the implementation revision,
      including the LI test configuration and manual build. Preserve both scan
      configurations and existing workflow timeouts. Separate any actual CI
      failure from speculative runtime concerns; no extra privileged local
      qualification is required solely for documentation and X1 test changes.
- [x] Check off tasks only after verification, record concise evidence and
      limitations in this plan, and commit the implementation and updated plan
      together. Do not reclassify previously completed plans as incomplete.

Suggested focused commands, run from the repository root:

```bash
go test -race -tags 'all li' -run '^TestClient_IsConnected$' -count=20 \
  -covermode=atomic -coverprofile=coverage-keepalive.txt ./internal/pkg/li/x1
go test -race -tags 'all li' ./internal/pkg/li/x1
make manual-check
make manual
git diff --check
```

Keep coverage files, temporary fixtures and caches out of commits and clean up
task-owned temporary resources. Broaden validation only if the implemented
changes or a concrete failure require it.

## Verification record

The implementation changes the two operator guides and matching English manual
chapters, adds six updated passages to each German/Catalan catalog, and stabilizes
`TestClient_IsConnected`. Successful loop completion is observed through synchronized
client statistics; recent and stale connectivity are checked independently with
explicit timestamps. Client cleanup is registered immediately after startup.
Production code, workflows, dependencies and configuration defaults are unchanged.

| Check | Evidence |
| --- | --- |
| Connectivity regression | 20 repetitions with Go 1.27.2, race detection and atomic coverage pass; the full X1 package race suite passes. |
| Existing contract regressions | Correlation wait/pressure/close and authenticated-store ownership tests pass under race detection; real processor deadline/shutdown integration and receipt-provenance tests, including the real orchestrator handoff, also pass. |
| Manual | `make manual-check` passes all tool checks with 5,586/5,586 current messages translated in both catalogs. `make manual` builds and verifies English, German and Catalan chapter paths, headings, examples, code spans and links. Changed rendered contract passages were reviewed in every edition. |
| Formatting and privacy | Go formatting and whitespace checks pass; translations preserve inline code and source keys; changes contain no private artifact references or deployment data. |
| Bounded closure review | One independent review of this scope found no material issue. Previously completed runtime reliability work was not reopened. |
| GitHub | Implementation revision `3e46aa79eb8e42fb80c0022509fb5aaa6536c416`: [CI](https://github.com/endorses/lippycat/actions/runs/37987093507), [Security](https://github.com/endorses/lippycat/actions/runs/37987093573), [Integration Tests](https://github.com/endorses/lippycat/actions/runs/37987093551), and [Deploy Manual](https://github.com/endorses/lippycat/actions/runs/37987093683) all pass. Both full race/coverage suites and the manual check executed successfully; both scan configurations remain enabled; ordinary, Docker and privileged eBPF integration passed. |

The existing Mermaid preprocessor emits its mdBook 0.5.2/0.5.4 compatibility
warning; all editions build and cross-edition verification succeeds with the
project-pinned mdBook. No tool version or workflow policy changes were needed.
Graceful draining of correlation-held product remains outside this plan; the
finite observation boundary and existing cancellation behavior are now explicit.

The final completion-record commit changes only this plan. The operator guides,
manual sources/catalogs, keepalive test and workflow files remain identical to
the verified implementation revision. The bounded closure decision is CLOSED,
with no unresolved item in this scope.
