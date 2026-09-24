# Retried INVITE call continuity after a 503

**Status:** Implemented with two unresolved provenance obligations; closure audit complete
**Baseline:** `v0.12.1` checkout, 2026-09-24

## Objective

Preserve signalling, answered media, per-call PCAP output, and authorized LI X3
delivery when a B2BUA retries an INVITE under the same Call-ID after a 503.
Keep failed calls bounded and preserve the existing protection against stale
packets reopening a finalized writer.

The motivating incident is described in
`/home/grischa/retried-503-finalises-call-losing-answered-leg.md`. Its production
trace is from an older build. Synthetic current-build regression tests cover the
88-second decision-clock gap, PCAP continuity, and loopback-TLS LI X3 receipt.

## Implemented transaction and lifecycle contract

The parser carries the numeric CSeq and top Via branch through UDP/TCP hunter
forwarding, tap, and processor metadata. The attempt key is `(CSeq number, Via
branch)` within a Call-ID. Older peers without those fields retain ordinary
terminal handling, but cannot open a retry hold or restart a finalized call.
Only a matched 503 for an INVITE opens the hold; 408, 500, and 502 remain
ordinary failures. A failed in-dialog re-INVITE does not fail the established
call. Up to eight attempts and sixteen SDP media ports are kept per aggregate;
retired fingerprints cap Call-ID reuse and are removed on eviction.

| Input | Live-generation transition | Completion and output effect |
| --- | --- | --- |
| Initial INVITE, provisional response | NEW → TRYING | Keep one call and writer set. |
| Matched INVITE 503 | TRYING → FAILED until retry deadline | Keep PCAP and LI admission open; preserve early RTP. |
| Distinct INVITE before deadline | FAILED → TRYING | Clear failure end time and cancel version-fenced pending close. |
| Matching 2xx and ACK | TRYING → ACTIVE | Associate SDP ports and answered media; retain the writer. |
| BYE/CANCEL | Terminal path | Complete by existing timewait/completion policy. |
| Retry deadline without answer | FAILED → finalized | Close once; failure expiry does not add PCAP trailing grace. |
| Verified INVITE after finalization | New lifecycle generation | Replace tombstone explicitly, reset aggregate and endpoint ownership. |

Overlapping INVITEs remain pending independently: one 503 cannot fail a call
while another known attempt may answer. The processor monitor serializes retry
admission with finalization; the shared lifecycle generation fences PCAP and LI
admissions and their completion callbacks. Shutdown discards pending completion
instead of misreporting an incomplete call as protocol-complete. Idle writer
timeouts retain their separate existing behavior, except that a writer cannot
idle-finalize a matched-503 call before its retry deadline.

Media provenance is necessarily conservative: after a generation restart,
RTP is admitted only after an answer advertises its port. Prior-generation
SDP ports, observed RTP port pairs, and observed SSRCs are rejected. A
legitimate new attempt that reuses them is therefore rejected. Retired SDP
ports and RTP port pairs are each bounded to 128 entries; overflow blocks
media conservatively.
Retired dialog tags are capped at eight, with further Call-ID restart denied
if that history is exhausted.
Post-restart ACK/BYE requires matching dialog tags, and CANCEL requires the
current INVITE branch/CSeq. An INVITE reusing a known old From tag is rejected.
Missing tags cannot terminate a restarted call. Packet metadata still has no
cryptographic generation marker: old media on a port not previously advertised
and a port pair not previously observed is indistinguishable if it matches
the new SDP. The rejected counters
expose the conservative policy, not universal stale-packet provenance.

## Design contract

- [x] Treat a 503 response to an INVITE as failure of that INVITE attempt, not
      proof that every attempt under the Call-ID has ended. Match the response
      to its INVITE transaction using available CSeq and branch/leg identity;
      do not apply this policy to a 503 for another SIP method.
- [x] Start with 503. Review 408, 500, and 502 separately against SIP retry
      behavior and observed metadata before adding them to the retryable set.
- [x] Keep one live call generation through a retry inside a bounded retry
      window. Retain caller/callee identity, early media, SDP associations, and
      the original PCAP writers; produce one completion hook for that call.
- [x] Use a dedicated, configurable retry window, defaulting to two minutes.
      Its expiry makes an unanswered failed attempt eligible for ordinary
      finalization. Keep `--pcap-grace-period` scoped to trailing traffic after
      genuine call completion.
- [x] A later INVITE within the window cancels the pending failure close and
      restores an aggregatable call state. A matching 2xx must make the call
      active and permit its SDP endpoints and RTP to be associated.
- [x] After finalization, admit a genuinely new INVITE attempt under a retained
      Call-ID only through an explicit, generation-safe restart. Reject delayed
      responses, media, and stale callbacks from the previous generation.
- [x] Preserve the shared lifecycle admission boundary for PCAP and LI. A
      retry in the live generation must retain X3 coverage; a validated new
      generation must receive fresh authorization and attribution.
- [x] Keep failed calls with no retry bounded. Define and test behavior for
      shutdown, idle timeout, a late retry after the window, and Call-ID reuse.

## Phase 1: Identify the authoritative attempt and lifecycle state

- [x] Trace where SIP method, CSeq number and method, Via branch, Call-ID,
      response code, and SDP arrive in processor and tap paths. Record which
      fields survive hunter forwarding, TCP reassembly, and older peers.
- [x] Define an attempt key from the fields actually available. Make missing
      transaction fields conservative: do not revive a call on an ambiguous
      response or attach old media to a new generation.
- [x] Map call state, completion scheduling, PCAP writer admission, RTP endpoint
      ownership, completion hooks, and LI admission/cleanup in one sequence.
- [x] Specify the transition table for initial 503, retry INVITE, provisional
      response, 200/ACK, BYE/CANCEL, retry-window expiry, and post-finalization
      new INVITE. Cover overlapping/forked attempts and out-of-order packets.

Primary files: `internal/pkg/voip/call_aggregator.go`,
`internal/pkg/voip/processor/processor.go`,
`internal/pkg/processor/call_completion_monitor.go`,
`internal/pkg/processor/call_lifecycle.go`, and the SIP metadata contracts.

## Phase 2: Implement retry-aware state and bounded completion

- [x] Track bounded INVITE-attempt state per Call-ID, with explicit cleanup on
      completion, expiry, eviction, and shutdown. Set limits on attempts and
      retained metadata so retry traffic cannot grow state indefinitely.
- [x] Keep the aggregate call eligible for retry after a 503 to its active
      INVITE attempt. Clear a stale failure `EndTime` when a retry begins, and
      allow the matching answer to transition to active.
- [x] Cancel or replace the monitor's pending close when a validated retry
      starts. Make timer decisions conditional on call generation and attempt
      version so a close already queued cannot finalize the resumed call.
- [x] Finalize an unanswered failed call when its retry window expires, then
      apply the existing trailing-packet grace only where appropriate. Keep
      terminal BYE/CANCEL and non-retryable outcomes on their intended paths.
- [x] Keep early RTP admission during the retry window; do not use
      `rtpExpected` as a substitute for retry eligibility.
- [x] Expose bounded counters for retries seen, recovered calls, retry-window
      expiries, and rejected ambiguous or late attempts without logging every
      packet or sensitive SIP values.

Primary files: `internal/pkg/voip/call_aggregator.go`,
`internal/pkg/processor/call_completion_monitor.go`, and their callers.

## Phase 3: Make restart and media ownership generation-safe

- [x] Add an explicit lifecycle operation for a verified new INVITE after
      finalization. It must atomically replace the tombstone with a fresh
      generation, without weakening ordinary `Admit` or `AdmitGeneration`.
- [ ] Reset or recreate aggregator state and SDP-derived RTP endpoint ownership
      for that generation. Prevent old-generation endpoint mappings and delayed
      packets from being attributed to the new attempt.
- [x] Preserve collision-safe PCAP names and generation-bound writer handles.
      Ensure the old completion hook fires once and the new generation has
      populated caller/callee metadata before its hook fires.
- [x] Carry generation identity through LI admission, direction mapping, and
      X3 delivery callbacks. Verify authorization for the new generation and
      prevent queued old-generation X3 from attaching to it.
- [x] Keep processor and tap behavior aligned, including deployments without
      per-call PCAP enabled.

Primary files: `internal/pkg/processor/call_lifecycle.go`,
`internal/pkg/processor/pcap_writer.go`,
`internal/pkg/processor/processor_packet_pipeline.go`,
`internal/pkg/processor/processor_li.go`, and VoIP RTP ownership code.

## Phase 4: Verification and operator contract

- [x] Add deterministic synthetic tests for 503 → later INVITE → 200/ACK →
      RTP → BYE with an 88-second retry delay. Assert one continuous call,
      retained metadata, captured answered media, one hook, and no premature
      tombstone.
- [x] Test 503 with no retry, 503 on a non-INVITE transaction, late retry after
      finalization, overlapping INVITEs, stale 200/ACK/RTP, missing transaction
      identifiers, and concurrent finalization versus retry.
- [x] Exercise the same sequence through processor and tap packet paths, with
      PCAP enabled and disabled. Under the `li` tag, assert authorized X3
      continuity and generation isolation without weakening admission checks.
- [x] Run focused processor and VoIP tests, race tests for lifecycle/monitor
      concurrency, and relevant `processor`, `tap`, `all`, and `li` builds.
- [x] Document the retry-window setting and its distinction from PCAP grace,
      idle timeout, and the closed-call tombstone TTL. Use synthetic identifiers
      and traffic in tests and documentation.

## Completion criteria

- [x] The 88-second retry scenario retains the answered leg and media on a
      current build, with valid completion metadata and LI X3 where authorized.
- [ ] Failed calls without retries close within the documented bound; stale
      packets cannot resurrect or contaminate a finalized generation.
- [x] Relevant tests and build variants pass, and the operator documentation
      matches the implemented behavior.

## Verification evidence

- [x] Focused processor/VoIP tests cover the 88-second injected-clock retry,
      PCAP continuity and completion metadata, idle-sweep precedence, failed
      re-INVITE, overlap, missing identity, bounded media history, same-tag
      reuse, delayed ACK/BYE, and concurrent retry/finalization.
- [x] `go test -tags 'processor tap all'` passed the SIP, pipeline, VoIP,
      processor, process-command, and tap-command packages.
- [x] `go test -tags 'all li'` passed focused processor and command packages;
      the LI regression delivered two X3 PDUs to a loopback TLS MDF receiver
      with PCAP enabled and disabled.
- [x] Re-run focused `go test -race -tags 'all li'` with the loopback receiver
      permitted by the test environment after the final challenger fixes.
- [x] Re-run `go build` with `processor`, `tap`, `all`, and `all li` tags after
      the final challenger fixes.
- [x] Verify a restarted Call-ID creates a distinct PCAP artifact and writer
      generation, and both completion hooks retain their own caller/callee
      metadata (`TestVerifiedCallIDRestartCreatesDistinctPcapAndCompletionMetadata`).
- [x] Retire bounded observed RTP port pairs even when the old SDP was absent;
      reject exact old pairs without dropping fresh media that shares only one
      port. Verify conservative blocking on history overflow.

## Closure audit result

The bounded review found and fixed five edge cases: old-generation BYE/CANCEL,
same-CSeq stale ACK, ninth-SSRC old media on a reused port, an idle PCAP sweep
shorter than the retry window, and a failed in-dialog re-INVITE on an active
call. Retired media ports and dialog tags now have fixed bounds and
conservative overflow behavior. Focused and full affected tests passed under
`-tags 'all li'`; processor and VoIP race suites passed; and `go build` passed
for `processor`, `tap`, `all`, and `all li` after these fixes.

A subsequent audit narrowed the provenance gap by retaining observed RTP port
pairs when SDP was absent. A first attempt that saw `35448/18000` now rejects
that same pair after restart, while fresh media on `35448/19000` remains
eligible.
The observed-pair history is bounded to 128 and blocks restarted media on
overflow. The full VoIP/processor race suites and all four build variants
passed again after this change.

The two unchecked obligations above are deliberately not claimed as complete.
SIP/RTP metadata has no trusted generation marker. A delayed old RTP packet
whose port was not previously advertised and whose port pair was not observed
can be indistinguishable from new RTP when it matches the new SDP. The
implementation rejects known old SDP ports, RTP port pairs, and SSRCs, delays
new media until an answer, and conservatively rejects reused
ports or ambiguous dialog tags. Closing the remaining absolute attribution
guarantee requires an explicit operator policy choice or a broader provenance
protocol change; it cannot be inferred from the existing packets.
