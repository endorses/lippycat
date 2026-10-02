# TCP SIP and task drift verification follow-up

This plan incorporates the findings from the 2026-10-01 verification of
`29868784`. The findings, required behavior, and verification scope are recorded
below so implementation and review require no files outside this repository.
Preserve authorization, replay, expiry, cryptographic, and configured resource
bounds. No new performance acceptance gates are introduced.

## Findings and implementation decisions

The D1/D5 retained-authority decisions and their completion record below describe
the historical implementation at `702c2c3f`. They are superseded by
[LI conflict authorization and X1 reporting](li-conflict-authorization-and-x1-reporting.md):
complete conflicts enforce only common authorized scope, disarm empty or expired
results, withhold replay, and retry schema-valid conflict reports until acknowledged.

### LI task definitions

**D1 — restored push-owned tasks become unarmed on definition conflicts.**
With `--li-state-file`, a complete startup snapshot differing from the persisted
X1 definition leaves that task outside the registry without filters. A missed
`ModifyTask` renewing the end date is one trigger. Re-arm the persisted X1
definition when the snapshot confirms the task and its retained destinations,
preserving its original expiry and flagging the conflict. A conflicting snapshot
must not confirm replay. Change the regression that previously expected the
task to remain unarmed and test restart with a renewed ADMF end date.

**D2 — strict mode incorrectly requires an optional implicit-deactivation flag.**
The ADMF sends open-ended tasks with a mediation start and no end or
`implicitDeactivationAllowed` element. The schema allows omission of that flag.
Treat omission as false when the mediation window is present, including strict
startup validation. A missing mediation window remains unknown. Cover pull,
raw XML push, and startup in compatibility and strict modes; ensure open-ended
tasks no longer inflate the incomplete-definition gauge.

**D3 — open-ended push after partial pull returns error 300.**
The completeness check prevents promotion and leaves the task's start unset.
With D2 corrected, a complete open-ended push must promote the pull-owned task.
Exercise the X1 server with raw XML, not only constructed presence metadata.

**D4 — first push after a complete but stale pull returns error 300.**
Reconciliation holds `snapshotMu` across its fetch. A waiting X1 push can follow
a stale complete snapshot and be rejected because promotion currently requires
the held definition to be incomplete. Allow the first complete push to promote
any active or pending pull-owned definition. Test a blocked snapshot fetch and
a concurrent push, while preserving ownership against later stale pulls.

**D5 — push-owned conflicts repeat warnings and never notify the ADMF.**
The lack of a revision field prevents proving a conflicting pull is newer.
Retain X1 authority and report the conflict to the ADMF so an authenticated
`ModifyTask` can resolve it. Emit the warning and notification on entry into
conflict, without repeating them on every reconciliation. Retaining the old
definition means its original expiry still applies until an explicit change.

**D6 — legacy scheme-less plus-prefixed TEL values fail XSD read-back.**
A persisted value such as `+15551234567` currently becomes an invalid bare
`telUri`. Read it back as `tel:+15551234567` or a digit-only `e164Number`, with
schema validation. Keep rejection of plus-prefixed E.164 input intact.

### TCP SIP and startup recovery

**T1 — data arriving before its SYN on a stale tuple can be discarded.**
A new SYN retires the stale connection and drops its queued pages, which may
contain the new connection's first INVITE. Later data can wait for idle flush.
Normal capture-lane ordering prevents this within one capture buffer, but not
across independently ordered inputs. Count queued bytes discarded by replacement
and expose the counter. Do not guess which generation owns ambiguous bytes.
This provides the report's explicitly permitted loss-accounting remedy; it
does not promise to preserve the early INVITE or eliminate the possible stall.

**T2 — startup synchronization is invisible to remote operators.**
Map manager startup state, attempt count, sanitized failure, last attempt, and
recovery time into `ProcessorStats` and `lc show status` JSON. Pending recovery
may leave tasks unarmed; a partial snapshot may already have armed valid tasks.
Keep the object absent when LI is disabled.

**T3 — keepalive and control counters are missing from telemetry.**
Export existing rearm keepalives and orphan controls, add counting for `Accept`
rejections of controls starting an uninitialized half, and carry these and T1
loss bytes through tap heartbeat, source statistics, protobuf, and status JSON.
Keep harmless controls distinct from discarded data.

**T4 — one failing snapshot entry prevents periodic reconciliation.**
Startup remains in `retryable_failure` and periodic reconciliation keeps taking
the startup path. After a usable partial snapshot, allow ordinary reconciliation
alongside bounded startup retries. Preserve incomplete-snapshot guards against
orphan removal. Identify failing entries by index and validated UUID in logs,
without publishing target selectors or arbitrary remote error text.

**T5 — two TCP halves increase per-connection memory by design.**
Each connection has two reader workers and two 64-chunk queues while consuming
one `MaxStreams` slot. Retain this documented architecture and stream retention;
this is an operational sizing consideration, not an implementation defect.

**T6 — old cleanup can erase new raw buffers on a reused tuple.**
The legacy packet buffer is keyed by the TCP tuple, so a delayed old worker can
discard a new generation's buffered packets. Production handlers already use
synthesized per-message packets with reassembly timestamps. Remove unnecessary
raw buffering from those capture paths, retain the legacy explicit buffer API,
and verify local per-call PCAP payload and timestamp behavior.

### Test stability

The full race run reported failures in
`TestRADIUSTapPOITLSFixtureAndShutdown`,
`TestProcessorX3CommittedTimingPolicy`, and
`TestProcessorX3ExplicitDeactivationHeldReplay`; all passed in isolation.
Remove avoidable races between fixture startup and narrow task windows, use
observable synchronization, and allow TLS/drain checks appropriate time under
race instrumentation without weakening the authorization assertions.

The elapsed-window regression exposed a root cause in state restoration:
`restorePersistedStateLocked` classifies a persisted task with an elapsed `EndTime` as
historical even when `ImplicitDeactivationAllowed` is false. This drops the
persisted active generation, so restart advances it and rejects held replay.
Apply end-time expiry during restore only when implicit deactivation is allowed.
Verify that an explicit-deactivation task retains its generation and that
equivalent ADMF confirmation permits replay after its end time; keep implicit
expiry disarmed.

## Implementation checklist

- [x] D1: keep restored push-owned tasks armed on conflicting startup snapshots,
      retain conflict visibility, and test a restart with a renewed end date.
- [x] D2–D4: accept the omitted optional implicit-deactivation flag, promote the
      first complete push over any pull-owned definition, and cover production
      XML, strict/compatibility startup, and concurrent stale snapshots.
- [x] D5–D6: bound repeated conflict warnings, notify the ADMF of conflicts, and
      normalize legacy scheme-less plus-prefixed TEL identifiers on read-back.
- [x] T1: account for queued bytes discarded when a late SYN replaces a stale
      connection; do not misattribute old connection data to the new connection.
- [x] T2–T3: export startup sync state and TCP keepalive, orphan-control,
      rejected-control, and replacement-loss counters through telemetry/status.
- [x] T4: allow reconciliation during partial startup failure and identify failing
      snapshot entries without exposing selectors in public telemetry.
- [x] T6: prevent an old connection's cleanup from deleting a new connection's
      buffered packets on the same tuple. T5's documented memory tradeoff remains.
- [x] Stabilize the three processor tests named above using observable
      synchronization and appropriate test isolation.
- [x] Run focused regressions and affected-package race checks, document actual
      results and limitations, format the changes, and commit code and this plan.

## Verification record

All fixtures use synthetic traffic and local endpoints; no production ADMF state
was changed. Tests requiring local HTTP/TLS/gRPC listeners ran outside the
sandbox because it blocks socket creation.

The final full LI package race run also passed after both related fixture
corrections and the explicit-deactivation restoration fix were present.

| Check                                                                                                                                                             | Result                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Full race tests, `all,li`: reassembly, VoIP, capture                                                                                                              | Passed                                                                 |
| Full race tests, `all,li`: processor and all processor subpackages, statusclient, tap/process commands                                                            | Passed; processor rerun after correcting explicit-deactivation restore |
| Full race tests, `all,li`: LI delivery, X1, X2/X3                                                                                                                 | Passed                                                                 |
| Explicit/implicit elapsed-window restore and held X3 replay regressions, `tap,li`, race, three repetitions                                                        | Passed                                                                 |
| Raw X1 mTLS push-after-pull, strict/compatibility open-ended startup, conflicting restored renewal, concurrent stale snapshot, retained destination authorization | Passed                                                                 |
| Startup status mapping, protobuf/JSON telemetry, TCP counter resets and production factory forwarding                                                             | Passed                                                                 |
| E.164 and legacy TEL read-back against bundled XSD                                                                                                                | Passed                                                                 |
| Non-LI `tap` and `processor` builds                                                                                                                               | Passed                                                                 |

Initial full runs exposed the explicit-deactivation restore defect described
above and two fixtures that encoded the superseded semantics (mandatory
implicit flag and unconditional end-time expiry). The implementation and
fixtures were corrected; those initial failures are not unrelated blockers.

The remaining T1 limitation is deliberate: queued bytes lost on SYN replacement
are counted, not recovered. The original full-definition retention policy for
push-owned conflicts was found to permit excessive scope and is superseded by
the linked common-authorization plan. T5 remains an operator sizing consideration.
