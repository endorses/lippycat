# SIP LI coverage, TCP tuple reuse, and ADMF startup recovery

**Status:** Complete

**Baseline:** main at `8f4cfd19` (TCP SIP stream retention complete)

**Implementation baseline:** `a42514e3` (TCP SIP direction and LI payload framing
also complete).

**Sources:** `/home/grischa/2026-09-28-tcp-sip-direction.md`, especially
sections 7–8 and the stopgap patch results; [ETSI TS 102 232-5 V3.22.1,
clauses 5.2.1, 5.2.6, and 5.4](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223205/03.22.01_60/ts_10223205v032201p.pdf).

## Objective and ownership

Close three findings that remain outside the TCP SIP direction plan:

1. Deliver admitted target SIP messages through X2 when the message is a
   provisional or redirect response, or uses an extension method. The current
   `X2Encoder.EncodeIRI` gate suppresses all `1xx`, all `3xx`, and request
   methods not listed in `classifyIRIType`. Keep task admission and the applicable
   IRI-only content policy intact.
2. Prevent teardown remnants and missed teardown from making a subsequent TCP
   SIP connection on the same 4-tuple lose one direction. Cover SIP data that
   overtakes its handshake across the capture lanes.
3. Recover from a transient ADMF outage during startup without waiting for a
   full periodic reconciliation interval, while keeping tasks disarmed until
   the ADMF confirms them.

The separate `tcp-sip-direction-correction.md` plan owns per-half SIP parsing,
correct packet addresses, CRLF-prefixed rearm, and `FindSIPStart`/`RawSIP`.
The completed `tcp-sip-stream-retention.md` plan owns retired pool references
and `MaxStreams` admission.
Their tests remain relevant, but completion of either plan does not close the
three findings above. Build-time v0.11.8 patches are deployment evidence;
they have not changed main. The final-ACK patch has not been verified in
production.

## Constraints

- [x] Keep the retention fix's pool pin/recycle lifecycle, one completion per
      retired stream, bounded queued pages, and configured `MaxStreams` limit.
- [x] Keep X2 delivery behind the existing task/filter admission and delivery
      type checks. A broader SIP emission rule must not create an unauthorized
      intercept or expose message body content forbidden for an IRI-only task.
- [x] Keep ADMF authority over arming persisted tasks. A failed, unsupported,
      or incomplete startup snapshot must not arm candidates from local state
      alone or authorize delivery to an unconfirmed destination.
- [x] Use synthetic SIP traffic, fake ADMF responses, and deterministic queue
      ordering for tests. Treat operational timing and memory observations as
      diagnostic evidence without a new numerical performance gate.

## 1. Complete SIP X2 emission coverage

- [x] Trace SIP metadata creation through the processor and `EncodeIRI` for
      `100`, `180`, `183`, `3xx`, and an extension request method. Distinguish
      valid but unlisted SIP from malformed or incomplete packets and confirm
      the existing target admission checks still run before encoding.
- [x] Replace the use of `classifyIRIType` as an allowlist for X2 emission.
      Emit a Payload Format 9 PDU for each valid, admitted target SIP message
      with the required correlation data. Keep request/response semantics in
      the raw SIP payload for the MDF; update comments and tests that currently
      claim provisional responses require no IRI.
- [x] Review X2-only/IRI-only task behavior for SIP bodies before broadening
      emission. Define and test the applicable content handling for newly
      emitted body-bearing methods and responses, including SMS `MESSAGE`.
      Preserve a parseable SIP message and its length fields if content must
      be modified or withheld under the configured policy.
- [x] Add encoder and processor-path tests for `1xx`, `3xx`, extension
      requests, existing `2xx`/failure responses, and invalid SIP. Assert
      payload bytes, source/destination attributes, Call-ID correlation,
      sequence behavior, task admission, and absence of X2 for unauthorized
      or malformed input. Update the current `180 Ringing` suppression test.

## 2. Make TCP connection reuse safe after teardown

- [x] Add a real-assembler regression that closes both halves, then feeds a
      trailing RST, duplicate FIN, or final ACK before a new SYN and INVITE on
      the same 4-tuple. Cover both tuple orientations and new initial sequence
      numbers. Assert the second connection's requests and responses reach
      separate half-streams.
- [x] Prevent an unmatched control-only segment without SYN from creating a
      new pool connection. A SYN must still create a connection, and a data
      segment must still support passive midstream capture. In VoIP `Accept`,
      prevent bare ACK/FIN/RST from forcing a start when the half has no
      sequence state. Count rejected orphan controls without allocating a SIP
      worker for them.
- [x] Handle a credible new SYN on a reused 4-tuple when the prior connection
      remains in the pool because FINs were missed or only one half closed.
      Distinguish SYN retransmission from a new connection. Retire old state
      safely, notify its stream once, release queued pages, and create fresh
      sequence state and stream ownership under the retention fix's locks and
      pins. Preserve `MaxStreams` admission and both tuple orientations.
- [x] Reproduce the capture-lane ordering case: a regular-lane SYN queued
      before SIP-lane data but delivered to reassembly after that data. Choose
      and implement a bounded per-flow ordering or late-SYN policy that keeps
      the first message and the following connection usable. Preserve the
      existing SIP-priority behavior for other flows.
- [x] Add deterministic capture-to-assembler and real-assembler tests for
      orphan controls, clean close, missed FIN, closed-half reuse, SYN
      retransmission, late SYN, and idle flush. Run the relevant tests with
      the race detector; verify pool/worker counts and completion behavior
      after shutdown.

## 3. Retry ADMF startup synchronization without arming by inference

- [x] Model startup sync as pending, succeeded, unsupported, or retryable
      failure. Keep `GetAllDetails` unsupported as a terminal capability
      outcome. Distinguish transport/timeouts from per-destination and
      per-task conversion/activation failures; the current startup sync logs
      those entry failures but returns nil, so they cannot silently mark the
      snapshot fully recovered.
- [x] Add a manager-owned, cancellable retry after a transient startup sync
      failure, with bounded backoff and the configured per-attempt timeout.
      It must work when `ReconcileInterval` is zero, serialize with periodic
      reconciliation and X1 task changes, stop after a confirmed complete
      recovery, and join cleanly during `Manager.Stop`.
- [x] Preserve authoritative reconciliation: persisted active tasks stay
      candidates until ADMF confirmation; incomplete snapshots do not remove
      possible orphans, and repeated snapshots do not duplicate task
      activation, delivery destinations, generations, or filter state.
- [x] Expose a useful startup-sync pending/recovery state through existing
      manager status or telemetry, including the last failure and successful
      recovery. Log retries and recovery without logging target content.
- [x] Review the separately sent X1 startup notification that also timed out
      in the incident. Determine whether its protocol semantics require an
      idempotent retry; implement and test that retry if needed without making
      notification success a substitute for authoritative state sync.
- [x] Test a first sync timeout followed by ADMF recovery, including
      `ReconcileInterval = 0`; unsupported operation; partial snapshot errors;
      persisted candidates; concurrent periodic reconciliation; shutdown
      during backoff/request; and repeated successful snapshots. Assert no
      task delivers X2/X3 before ADMF authorization and that status changes
      from pending to recovered only on the defined success condition.

## Verification and closure

- [x] Run focused reassembly/capture/VoIP tests and race tests for connection
      replacement. Run LI encoder, processor, manager, persistence, and X1
      tests with the `li` build tag; build processor and tap with and without
      LI support. Record commands and results in the implementation review.
- [x] Replay synthetic normal-close and trailing-RST pcaps through the
      processor/tap path. Confirm the next same-tuple call retains both
      directions, and admitted `1xx`/`3xx` SIP messages appear as X2 PDUs
      without changing X3 attribution or task admission.
- [x] Review operator-facing status and documentation, format changed files,
      mark only verified checklist items complete, and commit the code and
      updated plan. Keep independently reviewable commits for the three
      workstreams if they are implemented separately.

## Implementation evidence

The [implementation review](sip-li-and-tcp-reuse-implementation-review.md) records
production paths, content policy, command results, the corrected ADMF fixture,
and the bounded closure decision. All scoped requirements are verified; no
required gate is deferred.
