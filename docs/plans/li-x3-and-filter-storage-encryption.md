# Encrypted X3 buffering, managed filters, and LI administrative state

Drafted: 2026-09-26. Code baseline: `77f7abfe`.

Status: Implementation in progress. Phases 1, 3, and 4 are complete. Phase 2
still awaits the four-store key-independence check with X3. Administrative state,
transaction recovery, managed filters, explicit snapshot initialization/migration,
and actual-owner filter/state/X2 key checks are implemented and verified. X3
layout calibration has rejected the per-record protocol and all three measured
immutable batch/head prototypes on the current ext4 platform. A fixed-segment
kernel passes the corrected small callback-latency probe, but phase 5 still has
no qualified production layout. Offline filter/LI-state snapshot key rotation is
implemented and verified. Durable X3, replay, journal rotation, X3 telemetry, and
final qualification remain open.

Source: [encryption research](../research/li-x3-and-filter-storage-encryption.md).
This plan extends the implemented
[delivery buffer and X2 persistence plan](li-delivery-buffer-limits-and-persistence.md).
Its historical X3-memory-only and call-finalization cancellation decisions are
superseded only where explicitly described below.

## Objective and scope

Add optional encrypted X3 buffering with bounded storage and safe recovery.
Offer encrypted managed filter storage in all processor/tap builds, require it
when LI is enabled, and preserve editable YAML by default when LI is disabled.
Encrypt persisted LI tasks, destinations, cleanup obligations, and generation
state. Reuse cryptographic and durable-file primitives, while retaining separate
transaction and authorization rules for each store.

The following scope decisions were confirmed by the user:

| Decision                              | Required behavior                                                                                                                                        |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delivery after normal call completion | Already admitted X3 may remain deliverable after a call ends. Capture closure must be distinct from authorization revocation.                            |
| LI administrative-state encryption    | Include it in this implementation, alongside X3 buffering and filter encryption.                                                                         |
| Non-LI filter editing                 | Keep editable YAML as the default, with encryption optional. Require encrypted filter storage when LI is enabled. Keep `--filter-file` in both contexts. |

The following are the implementation defaults selected for this plan:

| Area                         | Contract                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| X3 persistence               | Disabled by default. Enabling it requires an explicit positive disk budget, positive `li-delivery-x3-max-age`, an independent key, encrypted LI state, and startup ADMF reconciliation. No implicit retention duration.                                                                                                                                                        |
| Memory-only X3               | Preserve existing limits, optional zero-age behavior, and call-end cancellation. Post-call retention is enabled with X3 journaling; test both modes explicitly.                                                                                                                                                                                                                |
| Recovered X3                 | Held until explicit record approval and current authorization checks succeed. Normal completion permits historical delivery; task withdrawal, task expiry/failure, relevant task modification, destination replacement/removal, and explicit cancellation revoke it.                                                                                                           |
| Revoked data                 | Immediately ineligible; reclaim asynchronously after durable revocation. Never transfer it to a replacement task, call, or destination.                                                                                                                                                                                                                                        |
| Managed filters              | Retain `--filter-file` as the path override. Add `--filter-store-mode=auto\|yaml\|encrypted`: `auto` selects YAML when LI is disabled and encrypted storage when LI is enabled. Explicit YAML with LI enabled is a startup error. Defaults are `~/.config/lippycat/filters.yaml` for YAML and `~/.config/lippycat/filters.enc` for encrypted storage. No new memory-only mode. |
| LI state                     | Preserve `--li-state-file=""` as disabled when X3 journaling/replay does not require it. Configured state persistence requires encryption; operators choose its path.                                                                                                                                                                                                          |
| Initialization and migration | Encrypted snapshots require explicit offline initialization/migration; missing encrypted snapshots are startup errors. YAML mode preserves existing first-run behavior: an absent file starts an empty store, persisted on mutation. Existing unreadable or invalid files are never treated as empty.                                                                          |
| Keys                         | Independently provisioned raw 32-byte keys for each enabled encrypted store: filters, LI state, X2, X3. YAML filters need no key. One active write key and at most four prior read keys per encrypted store; configuration contains references, never key bytes. No master-key/HKDF mode.                                                                                      |
| Rotation                     | Offline, locked, resumable rewriting under the new active key; prior read keys remain available until all objects and required backups have been accounted for.                                                                                                                                                                                                                |
| Existing X2                  | Preserve `LCX2` v1 reading, the original raw key semantics, sequence state, and existing X2 authorization policy. X3 must not inherit X2's post-task replay exceptions.                                                                                                                                                                                                        |

Ordinary non-LI processor/tap deployments retain their YAML path and editing
workflow without a key or migration requirement. Enabling LI, or explicitly
selecting encrypted filter storage, requires an initialized encrypted store and
key. Ship migration tooling and updated deployment examples with that requirement.
This supersedes the research's recommendation to require encryption for every
managed filter store.

This scope does not encrypt PCAPs, structured logs, upstream event spools, CLI
batch-input files, or the separate RADIUS correlation allocator sidecar. Replay
manifests remain explicit private exports. It does not provide trusted rollback
detection, physical secure erasure, MDF application acknowledgements, or exactly-once
delivery. Encryption protects stored copies only when their keys are separately
controlled; it does not remove plaintext from authorized process memory.

## Required storage and lifecycle contracts

### Shared storage foundation

Create a small untagged `internal/pkg/securestore` package for bounded key loading,
authenticated envelopes, private file handling, ownership locks, and durable
replacement. It must not import LI, protobuf, filter-manager, or delivery policy.

New envelopes authenticate the complete header: format version, algorithm,
purpose, key ID, and framing lengths. Bind store/object identity as appropriate;
encrypt sensitive identities, metadata, and payloads. Separate purposes include
filter snapshots, LI state, X2/X3 products, sequence checkpoints, journal state,
and call/revocation controls. Cross-purpose and cross-store substitution must fail.

Use standard-library AES-256-GCM with a specified nonce strategy and enforced
per-key usage bounds. Define limits for headers, plaintext/ciphertext, decoded
collections, pending operations, and recovery memory before implementing readers.
Size checks must precede allocations, decryption, and schema decoding.

Open and validate files through descriptors; reject symlinks, nonregular files,
unexpected ownership, and insecure permissions. Define permitted ancestor
directories separately from the private store directory so standard deployment
paths remain usable. Use exclusive temporary files, complete-write handling, file
sync, rename, then directory sync. Encrypted stores encrypt before temporary
output; YAML mode deliberately writes private plaintext YAML through the same
durable-file primitives. A store lock covers runtime ownership, migration, and
rotation, including aliases of the same underlying file.

Expose three outcomes to owners: committed, definitely not committed, and commit
uncertain. A failure after rename cannot be treated as an ordinary rollback.
Owners must block affected mutations/admission and reconcile or restart on an
uncertain result. Report cleanup failures without replacing the primary error.

### Filter format selection and editing

Resolve the filter-store mode from effective runtime LI enablement, not whether
the binary was compiled with the `li` tag. A LI-capable binary running with LI
disabled has the same default YAML workflow as a non-LI binary. Enforce this in
the processor core as well as the CLI so embedded callers cannot enable LI with
plaintext managed persistence.

In YAML mode, users stop the node, edit the file selected by `--filter-file`, and
restart it to load the changes. Preserve the existing schema and startup-only
loading; do not introduce a file watcher. While the node is running, users can
apply changes through `lc set filter`/`lc rm filter` or import a separate YAML
batch using `lc set filter --file`. Document that direct edits during operation
are unsupported and can be overwritten by subsequent management mutations.

Encrypted mode uses the same management/import commands but does not expose a
directly editable persistence file. Switching into it is an explicit offline
migration or initialization. Never infer a mode from a filename, a failed decrypt,
or the presence of a key. Reject key options in YAML mode with instructions to
select encrypted mode; wrong-format files fail rather than triggering fallback.
Enabling LI must validate encrypted persistence before admitting any LI task or
writing an LI-generated selector.

### Separate transactions with conservative recovery

Filters, administrative state, and journals are separate transactions. Do not
claim atomic commit across their files. Use durable intent/generation reservation,
revocation, cleanup obligations, and startup reconciliation to resolve incomplete
operations. Persist revocation before acknowledging its durable boundary; a later
failure must never restore the old generation's authorization.

New LI state has a stable encrypted store incarnation. X3 control/product records
bind to that incarnation and exact task/destination generations. Migration and
key rotation preserve it. An independently initialized/replaced state store cannot
authorize an old X3 journal by coincidentally matching numeric generations. This
binding detects mismatched stores, not restoration of an older coherent backup.

Startup order is: resolve and validate filter mode; lock/validate configured stores
and authenticate encrypted stores without side effects; recover lifecycle
watermarks, revocations, and cleanup obligations;
reconcile LI-owned filters and current ADMF state; restore sequence checkpoints;
then enable new capture/delivery and approved replay. Transport needed to contact
ADMF is not permission to expose incomplete policy to capture or delivery.

### X3 admission, completion, and replay

Memory admission is not durability. Persist immutable encoded X3 after reorder;
only a successful persistence callback makes it transport-claimable. Carry the
original admission time, capture time, absolute expiry, task/destination identity,
call incarnation where present, and exact product identity throughout the path.
Retries, completion, and restart never reset retention.

Assign a unique call incarnation for each lifecycle generation. Preserve the
numeric generation for local stale-callback checks, but never use it alone as a
cross-process identity. A bounded internal backlog permit allows only previously
accepted reorder content to move to delivery after capture closes; it cannot admit
new packets. Do not retain ordinary `CallAdmission` references until reorder drain:
finalization waits for those references before invoking its subscribers.

| Event in persistent-X3 mode                                      | Capture/reorder behavior                                                                | Already accepted delivery                                           |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Protocol completion, including SIP failure/CANCEL termination    | Close admission and drain accepted reorder entries                                      | Remains eligible until expiry or authorization revocation           |
| Idle timeout or capacity eviction                                | Close that capture incarnation and drain its accepted entries                           | Remains eligible; resource pressure is not authorization withdrawal |
| Generic writer close (`manual`)                                  | Classify existing callers; output cleanup alone is not LI cancellation                  | Retain unless an explicit authorization-revocation action applies   |
| Service shutdown                                                 | Close capture; drain accepted bounded work before stopping authorization infrastructure | Retain durable unsent records; separately account volatile losses   |
| Task withdrawal/expiry/failure or relevant modification          | Block affected generation and discard its reorder entries                               | Revoke pending, queued, claimed, and held records                   |
| Destination removal/replacement or explicit LI call cancellation | Block affected identity and discard its accepted backlog                                | Durably revoke; no UUID/Call-ID fallback                            |

On restart, a recovered completed call is historical, not active. A previously
open incarnation is capture-closed after process loss; its already durable product
can also be historically eligible. Never attach new capture to either incarnation.
Missing or invalid call-control state fails recovery rather than implying permission.
Non-call X3 uses an explicit provenance variant without a fabricated call identity.

Approval binds journal UUID, interface, immutable record/content identity, LI-state
incarnation, task/destination generations, call provenance, timestamps, and deadline.
It also requires current ADMF-confirmed unchanged task activation, active X3
authorization, exact destination membership/incarnation, and no revocation.
Revalidate at replay admission and transport claim. An approval file or completion
marker alone grants nothing. Preserve destination/interface FIFO prefixes when
only some records are approved.

## Implementation sequence

| Phase                                           | Dependencies                           | Deliverable                                                                      |
| ----------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------- |
| 1. Contracts and format fixtures                | None                                   | Frozen storage/lifecycle contracts and failure matrix                            |
| 2. Shared encrypted storage                     | 1                                      | Reusable primitives plus X2 compatibility fixtures                               |
| 3. Managed filter transactions                  | 2                                      | Editable YAML, optional/LI-required encryption, and consistent durable mutations |
| 4. LI administrative state                      | 2, 3                                   | Encrypted state and recoverable lifecycle transactions                           |
| 5. X3 layout and journal generalization         | 1, 2; benchmark before layout adoption | Measured layout, separate bounded X2/X3 stores                                   |
| 6. Durable X3 lifecycle and post-call delivery  | 4, 5                                   | Admission, drain, revocation, expiry, and shutdown                               |
| 7. Recovery, approval, and sequence continuity  | 6                                      | Authorized historical replay across restart                                      |
| 8. Operator interface, migration, and telemetry | Build alongside 3–7; complete after 7  | Usable configuration, upgrade/rotation tools, status                             |
| 9. Qualification and rollout documentation      | All preceding phases                   | Verified release and operator runbooks                                           |

Phases 3 and 5 can proceed independently after the shared contract stabilizes.
Do not release LI's encrypted-startup requirement before its migration/initialization
tooling, or enable X3 replay before durable revocation and authorization are complete.
Use descriptive source filenames rather than phase-number filenames. Update the
checkboxes only after their exit criteria pass, and commit code plus this plan as
implementation work completes.

### 1. Freeze contracts and compatibility fixtures

Primary areas: `internal/pkg/li/delivery`, `internal/pkg/li/persistence.go`,
`internal/pkg/processor/filtering`, `internal/pkg/processor/call_lifecycle.go`.

- [x] Write the envelope/schema specification, including purpose/version dispatch,
      object/store identities, size/count bounds, key IDs, nonce usage accounting and
      rotation thresholds. Separate legacy decoding from new-format decoding; do not
      guess formats or try arbitrary keys until one decrypts.
- [x] Define typed definite/uncertain storage outcomes and how each public mutation,
      X1 callback, background lifecycle action, and startup path reports or latches them.
- [x] Freeze the filter-mode matrix: runtime LI on/off, `auto`/`yaml`/`encrypted`,
      default/custom paths, keys, missing files, opposite-format files, and competing
      defaults. Include LI-capable binaries with LI disabled and processor-core callers.
- [x] Document lock ordering among filter mutations, task admission/lifecycle,
      destination changes, call finalization, journal control, queue ownership, and
      persistence workers. No queue mutex may be held during disk I/O or callbacks.
- [x] Audit all call-finalization reasons/callers against the policy table; define
      explicit LI revocation separately from writer cleanup. Record the mode-dependent
      behavior so memory-only X3 retains its current contract.
- [x] Add synthetic legacy fixtures for X2 `.x2`, `.seq`, and `.state` objects,
      full filter YAML (including RADIUS compound criteria/revisions), and LI state JSON
      with active, pending, retained, removed-destination, cleanup, and watermark cases.
- [x] Define the fault/crash matrix and X3 performance workload/acceptance thresholds
      before running the layout comparison in phase 5.

Exit: schemas, state transitions, acknowledgement semantics, and numeric resource
bounds are explicit enough to implement without another product-policy decision.

### 2. Implement shared encrypted storage and preserve X2 compatibility

Primary areas: new `internal/pkg/securestore`; existing
`internal/pkg/li/delivery/{journal,journal_sequence}.go` file/codec helpers.

- [ ] Implement key loading and bounded keyrings with exact key lengths, private
      files, unique IDs, active/prior lookup, and separate purpose configuration. Reject
      accidental reuse of the same configured key across the four stores without
      logging key material or fingerprints.
- [x] Implement authenticated bounded envelopes, strict header/version/purpose
      validation, fresh nonces and enforced usage limits. Key-use accounting must
      survive restart/rewriting sufficiently to enforce the selected limit; document
      how journal rotation capacity prevents reaching a limit with no recovery path.
- [x] Implement descriptor-based private reads, stable ownership locks, exclusive
      temporary writes, durable replacement, and typed uncertain-commit errors. Close
      handles/release locks on construction failures as well as normal shutdown.
- [x] Test wrong keys, changed headers/tags, cross-purpose/store substitution,
      truncation, oversized input, symlink/hardlink aliases, insecure files/directories,
      competing owners, short writes, full disk, rename failures, and directory-sync
      failures. Verify encrypted stores create no plaintext temporary files or decrypted
      error output; YAML writes remain private and use the same durability guarantees.
- [x] Integrate the primitives into X2 without changing its delivery policy. Keep
      explicit `LCX2` v1 readers and original raw-key semantics for products, sequence
      checkpoints, and journal state. Existing key-file-only configuration remains
      readable; once the active key changes, retain an explicit legacy read-key mapping.
- [x] Verify mixed old/new recovery and interruption during encrypted replacement.
      Unknown versions and ambiguous legacy-key selection must fail closed.

Exit: common primitives pass boundary/fault tests, and existing X2 recovery,
sequence, capacity, and delivery tests still pass.

### 3. Add filter storage modes and transactional persistence

Primary areas: `internal/pkg/filtering/{parser,conversion,validation}.go`,
`internal/pkg/processor/filtering/{persistence,manager,target_local}.go`,
`processor.go`, `processor_lifecycle.go`, `processor_grpc_handlers.go`, and
`processor_li.go` under `internal/pkg/processor`.

- [x] Separate in-memory filter serialization from plaintext CLI file import.
      Strict managed loading/migration must reject invalid entries, duplicate IDs,
      unknown fields/types, trailing documents, and partial parsing. Preserve every
      supported field, including revisions, disabled state, scoping, descriptions,
      LI ownership, and compound RADIUS criteria.
- [x] Retain `YAMLPersistence` and add encrypted persistence behind the same manager
      contract, with explicit store ownership/lifecycle and durable writes in both.
      Resolve `auto` from runtime LI enablement; reject YAML mode when LI is enabled
      in the processor core before policy application, listeners, or capture/delivery.
- [x] In encrypted mode, missing/wrong keys, plaintext, malformed ciphertext, and a
      missing initialized store abort startup. In YAML mode, require no key and preserve
      absent-file first-run behavior. Invalid/unreadable existing files and lock/path
      failures abort startup in both modes. Preserve `lc set filter --file` import and
      stopped-node YAML editing/restart; do not add automatic format conversion.
- [x] Under manager mutation ordering, stage and validate a detached complete
      candidate; persist it; then publish committed maps/revisions and ordered updates.
      Definite save failure leaves published state and subscribers unchanged and returns
      an error. Do not mutate caller-owned protobuf values or consume revision state
      for failed candidates. Preserve current deleted-RADIUS-revision semantics rather
      than silently promising new restart-persistent deletion history.
- [x] Introduce one processor mutation entrypoint for direct RPCs, processor-scoped
      local RPCs, and the LI filter pusher. Remove local target application before save,
      scoped-handler bypasses, and LI target application after manager failure. Avoid
      applying the default hunter target twice.
- [x] Validate local policy before commit where possible; after commit, apply under
      the existing tap capture/reconcile boundary. A post-commit target failure keeps
      the committed desired policy, blocks affected processing, and reports a distinct
      reconciliation fault. Do not pretend restoring memory rolls back disk.
- [x] Preserve `SubscribeSnapshot`/update ordering and separate durable acceptance
      from remote hunter application. Map storage, uncertain-commit, not-found, and
      distribution failures accurately in RPC responses.
- [x] Remove raw selectors from update/normalization/local-target logs and nested
      errors, including phone numbers, invalid IP/CIDR values, and BPF expressions.
      Review LI-derived filter IDs as sensitive identifiers; retain useful redacted
      operation/error classifications.
- [x] Exercise concurrent update/delete/subscribe; direct/scoped/LI/local target
      parity; definite and uncertain save faults; local application faults; startup
      rejection; failed-start lock release; and full schema round trips. Capture logs
      with distinctive target markers and assert they are absent.
- [x] Test both stores and the complete mode matrix, including unchanged non-LI
      startup without keys, editing YAML while stopped and loading it on restart,
      non-LI opt-in encryption, LI-disabled operation of LI builds, and rejection of
      LI with YAML before any LI selector is persisted. Verify encrypted content can
      never be overwritten as YAML through a mode/path mismatch.

Exit: no failed definite save changes effective policy or reports success, and
no unreadable existing store starts an empty-policy processor/tap. Ordinary YAML
editing remains available with LI disabled; LI requires encrypted persistence.

### 4. Encrypt LI state and make lifecycle failures recoverable

Primary areas: `internal/pkg/li/{persistence,manager,registry}.go`, destination
mutation code, `internal/pkg/processor/{processor_li,processor_radius_li}.go`.

- [x] Store the complete administrative snapshot under its independent purpose/key,
      with store incarnation, task definitions/status/timestamps, activation generations,
      destination creation identities/revisions, cleanup IDs, and generation watermarks.
      Validate a detached complete snapshot before registry mutation or filter cleanup.
      Preserve legitimate retained tasks whose destination has since been removed.
- [x] Add exclusive state-store ownership, strict bounded decode, explicit encrypted
      initialization, and fail-closed startup. Preserve restore-as-unconfirmed behavior:
      decryption must not turn persisted active tasks into current authorization.
- [x] Serialize committed administrative snapshots consistently across task changes,
      destination changes, pending promotion, expiry, purge, and background reconciliation.
      Prevent snapshots from observing another operation's provisional registry state.
- [x] Define and implement activation/modification transactions: reserve generation
      durably; record recoverable intent/cleanup obligations; reconcile committed filter
      policy; persist final state before releasing effective admission. A failed final
      save faults the affected task. Equivalent retries must not report success while
      a previous failed/uncertain commit remains unresolved.
- [x] For deactivation/expiry/failure, keep authorization blocked once withdrawn;
      durably record cleanup/revocation and propagate failures. Retain generation
      watermarks and outstanding cleanup through task/tombstone purges.
- [x] Correct destination mutation rollback: restore the old candidate only after
      definite pre-replacement failure; on uncertainty, gate delivery/replay and require
      reconciliation. Preserve destination revision identity during recovery.
- [x] Define the fault-returning journal revocation hook and registration points
      for task/destination changes. Verify administrative/filter recovery using a
      controllable test implementation, including rejection and uncertainty. Wire the
      real journal controls and prove the combined acknowledgement boundary in phase 6.
- [x] Preserve `persistedActive`, `persistenceCandidates`, `replayConfirmed`, startup
      ADMF reconciliation, orphan LI-filter cleanup, and non-LI filters. RADIUS tasks
      currently require fresh activation and cannot inherit unchanged-generation replay;
      keep that restriction explicit rather than bypassing it for X3.
- [x] Preserve the RADIUS correlation sidecar's reservation watermark. Changing the
      administrative state path must pin the old sidecar path or migrate it under its
      own ownership contract; never silently derive a fresh allocator from the new path.
- [x] Extend persistence/destination/generation/idempotency/expiry tests with failure
      at each activation checkpoint, final modification, promotion, reconciliation,
      destination rename/sync, and cross-store cleanup boundary. Crash/restart must not
      reuse a generation, revive authorization, or silently reset the RADIUS allocator.

Exit: administrative startup and mutations have explicit durable/uncertain/fault
outcomes; retries and restart cannot activate uncommitted or revoked generations.
The X3 journal integration remains gated on phase 6; this phase establishes its
administrative transaction and error-propagation foundation.

### 5. Measure the X3 layout and generalize journal ownership

Primary areas: `internal/pkg/li/delivery/{audit_journal_bench_test,journal,
client_journal,config_limits,journal_sequence}.go`.

- [ ] Extend `BenchmarkAuditJournalAdmissionAndSync` for RTP-sized packets, multiple
      destinations, healthy delivery, outage accumulation, recovery with live traffic,
      and simultaneous X2/X3 on one filesystem. Measure durability latency, persisted
      PDU throughput, allocated disk growth, CPU/allocations/RSS, revocation/expiry
      latency, recovery time, and backlog drain rate.
- [ ] Commit a report in `docs/research/li-x3-storage-benchmarks.md` recording workload,
      filesystem/device, supported load and pass/fail thresholds. The current per-record
      JSON/base64/multiple-sync format is acceptable only if it meets that workload.
      If not, specify bounded batching/segments with per-record durability acknowledgement,
      torn-tail recovery, compaction, and cancellation boundaries before proceeding.
- [ ] Replace singular `Client.journal` ownership with explicit X2/X3 instances:
      separate directories, workers, pending queues, replay workers, indexes, budgets,
      fault state, and statistics. Roll back partial initialization and close both stores.
- [ ] Generalize journal records/recovery to an expected interface, stable journal
      UUID, immutable record identity, state/call provenance, original timestamps and
      absolute deadline. Validate actual encoded PDU type, not only an outer label.
- [ ] Bound record/control indexes, callbacks, pending operations, decoding and
      recovery memory. Include both journals in memory reservation estimates; charge
      allocated filesystem blocks, pending writes, sequence/control metadata, and
      temporary rewrite/rotation/recovery space against explicit budgets.
- [ ] Reserve control capacity for revocation, closure, faults, and sequence updates
      even when data admission is full. Define bounded control garbage collection that
      cannot forget revocations while covered records or pending writes remain.
- [ ] Verify independent capacity/workers and that X3 exhaustion cannot consume X2's
      reserved budget. Quantify shared-device contention; separate workers alone are
      not a disk-I/O isolation guarantee.

Exit: a measured layout decision and two bounded journal instances exist; X2
behavior remains compatible. X3 replay stays disabled until phase 7.

### 6. Implement durable X3 admission, post-call delivery, and revocation

Primary areas: `internal/pkg/li/delivery/{client,client_journal,reorder}.go`,
`internal/pkg/li/delivery_metadata.go`, `internal/pkg/processor/{call_lifecycle,
processor_li,call_completion_monitor,pcap_writer,session_output_manager}.go`.

- [ ] Carry unique call incarnations and immutable provenance through admission,
      finalization events, reorder entries, fan-out, and journal controls. Create the
      necessary authenticated call control and reserve its capacity before confirming
      the first corresponding product durable. Bound controls by live/held product limits.
- [ ] Issue bounded exact-product backlog permits on successful pre-close reorder
      insertion. Add `DrainCall` for an exact incarnation, coordinating timers and the
      existing callback serialization chain. Drain must not reopen capture admission,
      deadlock on ordinary admission references, or disturb other calls in the buffer.
- [ ] In persistent mode, normal finalization drains accepted reorder entries,
      records completion, and preserves eligible queued/held/in-flight delivery. Keep
      direction/pinned-call cleanup. A concurrent task/destination revocation dominates
      the drain and discards affected entries instead. Keep memory-only behavior tested.
- [ ] Remove X2-only persistence gates and generalize queue preservation. Journal
      X3 after reorder; send only after durable callback. Reject new data on capacity
      exhaustion instead of dropping durable queue heads. Account oversized/rejected
      product and pending reservations exactly once per destination copy.
- [ ] Add durable task/destination/call revocation: close admission, stop affected
      transport claims, write authenticated control through reserved capacity, then
      acknowledge the boundary and reclaim data asynchronously. Cover pending writes,
      held records, and callbacks; none may resurrect a revoked generation.
- [ ] Replace void-only cancellation/lifecycle callback contracts or add an explicit
      fault-returning durability hook. Logging a failed revocation is insufficient.
      Automatic expiry and failure paths must latch blocked delivery and report faults;
      synchronous management paths must return failure/uncertainty accurately.
- [ ] Wire the phase-4 administrative hook to journal revocation. Acknowledge the
      durable task/destination boundary only after both relevant journal controls and
      administrative state are durable. Test idempotent recovery from partial completion
      and failures in either store; never reactivate an old generation as rollback.
- [ ] Enforce the original absolute deadline during live/retry ownership, held
      recovery, replay admission, and immediately before transport write. Add a bounded
      online sweeper independent of MDF connectivity/approval; never refresh age.
- [ ] Change shutdown ordering to close capture, drain accepted reorder while
      authorization infrastructure remains available, resolve pending persistence,
      retain durable backlog, then close journals/locks. Distinguish retained-on-disk,
      volatile loss, expiry, revocation, and partial/uncertain transport writes.
- [ ] Test timer/drain/finalization races, reused Call-IDs, task changes during drain,
      persistence callbacks after revocation, full-spool control writes, failed control
      sync, held records, in-flight cancellation, and shutdown at each ownership state.

Exit: normal call completion preserves eligible admitted persistent X3, while
revocation reliably blocks it across memory/disk/callback boundaries.

### 7. Enable authorized historical replay and sequence continuity

Primary areas: `internal/pkg/li/delivery/{journal_replay,journal_manifest,
journal_sequence,client_journal}.go`, `internal/pkg/li/x2x3/sequence_restore.go`,
`internal/pkg/li/persistence.go`, `internal/pkg/processor/processor_li.go`.

- [ ] Recover revocation/control state before product eligibility; enforce overdue
      expiry before exposing records. Treat previously open call incarnations as
      capture-closed and never reconstruct them as active calls.
- [ ] Version X3 approval/export schemas with exact journal, record, state, task,
      destination, call, content, and deadline binding. Preserve legacy X2 manifest
      compatibility separately; do not copy its historical post-task policy into X3.
- [ ] Require current startup ADMF reconciliation and unchanged authorized activation
      plus exact destination membership/incarnation at feeder and transport boundaries.
      Missing admin state, mismatched incarnation, failed sync, RADIUS reactivation,
      revocation, or elapsed deadline prevents replay even with an approval file.
- [ ] Generalize hardcoded X2 queue indexes/metadata reconstruction to the correct
      interface. Maintain bounded lazy payload reads and FIFO-approved prefixes per
      destination/interface; an unapproved head cannot be skipped except by a recorded
      terminal action such as expiry, revocation, or explicit purge.
- [ ] Generalize sequence checkpoint extraction/restoration to expected X2/X3 type;
      restore before live encoding, preserve interface separation and fan-out semantics,
      and retain checkpoints after completion, expiry, purge, or revocation. Update
      `ClearX3XID` cleanup so durable X3 continuity is not discarded.
- [ ] Replay original encoded bytes and sequence numbers. Test wrap behavior and
      crashes between product/control/sequence writes and completion checkpoints;
      document possible duplicate delivery after uncertain transport/completion state.
- [ ] Run an end-to-end scenario: admit RTP during MDF outage, finish the call,
      restart, reconcile ADMF, approve backlog, reconnect MDF, and verify exact original
      product delivery while late/new packets for the closed incarnation are rejected.
      Repeat with task withdrawal, destination replacement, wrong state incarnation,
      call revocation, and expiry; each must yield zero unauthorized replay.

Exit: completed and process-interrupted calls can safely deliver eligible historic
content without weakening authorization, expiry, FIFO, or sequence guarantees.

### 8. Finish configuration, offline tools, rotation, and telemetry

Primary areas: `cmd/process`, `cmd/tap`, new `cmd/migrate`, build-tagged root files,
`internal/pkg/processor/processor_li_delivery_stats.go`,
`api/proto/management.proto`, and `internal/pkg/statusclient`.

Use this operator surface consistently; validate names against existing flags
before implementation and update all references if an adjustment is necessary.

| Surface                             | Planned options/behavior                                                                                                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Managed filter store, common builds | Existing `--filter-file`; new `--filter-store-mode=auto\|yaml\|encrypted`, `--filter-store-key-file`, `--filter-store-key-id`, repeatable `--filter-store-read-key=id=path`; keys apply only to encrypted mode                                                     |
| LI state                            | Existing `--li-state-file`; new `--li-state-key-file`, `--li-state-key-id`, repeatable `--li-state-read-key=id=path`                                                                                                                                               |
| X3 journal                          | `--li-delivery-x3-spool-dir`, `--li-delivery-x3-spool-max-bytes`, `--li-delivery-x3-spool-key-file`, key-ID/prior-read-key options, `--li-delivery-x3-spool-replay-policy=hold\|purge`, replay/export manifest paths; existing positive `--li-delivery-x3-max-age` |
| X2 key rotation                     | Add corresponding key-ID/prior-read-key options without changing existing raw key-file meaning                                                                                                                                                                     |
| Offline snapshots                   | `lc migrate filter-store` and LI-only `lc migrate li-state`; explicit source/destination and source format, plus an exclusive empty-initialization mode                                                                                                            |
| Offline journal rewrite             | LI-only `lc migrate li-journal` selecting X2 or X3; version migration/rotation without sending product                                                                                                                                                             |

- [x] Add a common filter-store config and resolver, outside LI-tagged files.
      Apply tap settings once in `cmd/tap/runtime.go:newTapRuntime` before processor
      construction, covering generic, DNS, TLS, HTTP, email, VoIP, and RADIUS commands.
      Preserve `processor.filter_file`/`tap.filter_file`; bind mode/key options under
      each role's `filter_store` configuration section. Resolve the default filename
      after effective LI enablement and mode, preserving an explicit `--filter-file`.
- [ ] Wire LI state/X3 options through both `flags_li.go` and matching stub config
      structures, `processor.Config`, LI `ManagerConfig`, process mapping and tap's
      centralized LI configuration helper. Bind explicit environment references for
      `LIPPYCAT_PROCESSOR_*`/`LIPPYCAT_TAP_*`; verify CLI > environment > YAML > defaults,
      including explicit empty/zero values. Do not add raw-secret configuration fields.
- [ ] Reject missing encrypted-store keys, keys supplied in YAML mode, LI enabled
      with explicit YAML mode, nonpositive X3 capacity/age, absent state/ADMF
      requirements, duplicate key IDs, and aliased/conflicting paths.
      Check both journal directories, snapshots, keys, manifests, lock/control files,
      temporary paths, and RADIUS sidecar; prevent exports from overwriting any store.
- [ ] Register common migration commands in all/cli/processor/tap binaries, not just
      `cmd/filter` or `cmd/set` (currently CLI/all only). Add LI migration subcommands
      only in LI builds; verify non-LI binaries contain no LI implementation symbols.
- [x] Implement strict offline YAML→encrypted filter and JSON→encrypted LI-state
      migration under source/destination ownership locks acquired in stable order.
      Validate the entire input before writing; preserve identities/watermarks; encrypt
      before temporary output. No skipped records or automatic plaintext backups.
- [x] Make encrypted initialization refuse existing files and ambiguous defaults.
      YAML-mode startup uses `filters.yaml` normally. Encrypted-mode startup finding
      only `filters.yaml` explains migration; YAML mode finding only `filters.enc`
      requires explicit mode/path selection rather than silently starting empty.
      If both default files exist, require explicit path selection. An explicit custom
      path is authoritative but must match the resolved format; never overwrite an
      opposite-format store or automatically convert it when LI enablement changes.
- [ ] Define no-clobber and explicit in-place rewrite modes, interruption/resume
      behavior, and uncertain-result diagnostics. Offline commands must never activate
      filters/tasks or send product. Preserve the original on definite migration failure.
- [ ] Implement key rotation with active/prior keys and resumable encrypted rewrites
      of all data, sequences, state, and controls. Preserve store identities and deadlines;
      reserve working space, reject insufficient capacity, and prove recovery at each
      interruption point. Report remaining old-key objects before key retirement.
- [x] Complete the snapshot portion of rotation: Linux same-parent filter and LI-state
      rewrites, exact payload/identity preservation, fresh keys, bounded working space,
      authenticated resume and outcome reporting. Journal rotation and the complete
      all-store gate above remain open.
- [ ] Add `x3_journal` as a new management protobuf field without renumbering existing
      fields. Expose independent pending, persisted, held, approved, retained, expired,
      revoked, rejected, bytes/limits and fault metrics. Distinguish persistence commit
      uncertainty from transport uncertainty, and expose actionable snapshot-store faults
      without sensitive metadata.
- [ ] Regenerate with `make -C api/proto`; review generated changes for unrelated
      churn. Update `lc show status`, status-client tests, and per-store accounting
      invariants; gauges must converge after drain, purge, expiry, and shutdown.

Exit: every supported node binary has a complete startup/migration/rotation path,
consistent configuration, and enough status to distinguish held, lost, retained,
revoked, and faulted data.

### 9. Qualify the change and document rollout

- [ ] Extend existing delivery crash/lifecycle/reorder/queue-limit suites, filter
      manager/local-target/RADIUS suites, administrative persistence/generation suites,
      processor LI integration, and process/tap configuration tests. Use targeted race
      tests for the new synchronization boundaries, not encryption round trips alone.
- [ ] Inject process death and I/O faults before/after product sync, rename,
      directory sync, control/sequence updates, admin/filter commits, replay approval,
      and completion checkpoints. Verify definite vs uncertain outcomes and idempotent
      startup cleanup, including revoked product with otherwise valid old approvals.
- [ ] Validate snapshot/key migration and rotation, strict malformed input, secure
      path ownership, missing store recovery, coherent backup restoration, and rejection
      of an unrelated LI-state incarnation. Verify encrypted-store temporary files,
      logs, and diagnostics do not contain chosen plaintext target/payload markers;
      verify YAML mode intentionally preserves its editable plaintext representation.
- [ ] Re-run the phase-5 workload against the final implementation, including backlog
      drain faster than continuing arrivals at the declared supported load. Record
      resource ceilings and X2 impact, plus any deployment sizing constraints.
- [ ] Update `docs/LI_INTEGRATION.md`, `docs/SECURITY.md`, processor/tap/show READMEs,
      manual command/config/filter/LI references, `example-config.yaml`, and deployment
      examples. Preserve stopped-node YAML editing guidance for LI-disabled operation;
      explain restart-based loading and management API/import while running. Document
      non-LI encryption opt-in and mandatory migration/key setup when enabling LI.
- [ ] Document key provisioning, first initialization, maintenance upgrade, same-path
      and changed-path migration, sidecar preservation, bounded retention, historical
      replay approval, fault recovery, full-spool operation, rotation and backup restore.
      State that stopped processes cannot perform expiry deletion and capture/retention
      timestamps are distinct.
- [ ] Document downgrade constraints for encrypted stores: old binaries cannot read
      new envelopes and must not open a new store. Require a coordinated compatible backup restore or an
      explicit separately designed export; never offer automatic plaintext fallback.
      Explain old plaintext copies/operator cleanup without promising physical erasure.
- [ ] Run the applicable commands below, record results and benchmark evidence in
      the implementation record, format changes, then commit code/docs and verified
      checkbox updates. Resolve related failures before marking the phase complete.

## Validation commands and completion evidence

Run package-level checks during each phase; run the broader matrix once the
integrated change is ready. `make test` alone does not cover processor/tap LI
integration. Use the repository's sandbox escalation process if tests require it,
and clean any task-created `/tmp` caches afterward.

```bash
go test ./internal/pkg/securestore/...
go test -tags all ./internal/pkg/filtering/... ./internal/pkg/processor/filtering/...
go test -tags li ./internal/pkg/li/...
go test -tags 'all li' ./internal/pkg/processor/... ./cmd/process/... ./cmd/tap/... ./cmd/migrate/... ./internal/pkg/statusclient/...
go test -race -tags 'all li' ./internal/pkg/securestore/... ./internal/pkg/li/... ./internal/pkg/processor/...
make test
make vet
go vet -tags 'all li' ./internal/pkg/processor/... ./cmd/process/... ./cmd/tap/... ./cmd/migrate/...
make build-matrix
make verify-no-li
git diff --check
```

Benchmark invocations must select the added X3/storage benchmarks and identify the
actual storage device; `/tmp` measurements alone cannot establish production disk
performance. No benchmark numbers or implementation test results are claimed by
this planning document.

Completion requires a recorded successful migration/rotation rehearsal, the
post-call outage/restart/replay scenario and its revocation variants, the final
performance report, passing relevant tests/build partitions, and all verified
implementation tasks checked off. Until then, the feature remains unfinished.

## Implementation record

### Storage contracts, fixtures, and common primitives (2026-09-26)

The frozen contract is [encrypted managed storage](../design/li-encrypted-storage.md).
It specifies LCS1 and LCUS framing, numeric limits, filter mode selection,
transaction outcomes, lock ordering, complete call-finalization producer paths,
and the crash/performance qualification gates. The X3 workload requires room for
at least 1.2 million destination copies during the specified outage; the contract
sets the X3 index ceiling to two million while retaining a one-million X2 ceiling.
No production storage performance result is claimed yet.

Synthetic legacy fixtures preserve original LCX2 product/sequence/state bytes,
all 22 managed filter types with complete RADIUS criteria/revisions, and LI JSON
including unconfirmed activation, pending/retained tasks, removed destinations,
cleanup obligations, and watermarks. The LCX2 fixture generator is independent
of the production codec and reproduces the committed bytes.

The untagged `internal/pkg/securestore` package now provides bounded private key
loading, independent bounded keyrings, purpose/store/object-bound AES-256-GCM
envelopes, authenticated restart-persistent usage reservations, descriptor-based
private file operations, durable replacement, no-clobber initialization, and
stable ownership locks. Fault outcomes separate auxiliary usage reservations
from the enclosing object: a failed seal never reports an object commitment.
An interrupted no-clobber create can leave its private temporary hardlink; readers
reject it until explicit owner reconciliation. Integration and offline recovery
remain later deliverables; no runtime feature or startup requirement is enabled
by this increment.

Verified commands (outside the sandbox where ownership mappings or test sockets
required it):

```bash
go test ./internal/pkg/securestore/...
go test -race ./internal/pkg/securestore/...
go vet ./internal/pkg/securestore/...
go test -tags 'all li' ./internal/pkg/li/... ./internal/pkg/filtering/... ./internal/pkg/processor/filtering/...
```

All commands passed. Independent reviews covered fixture completeness and the
crypto/files/usage boundary. Overlay mutation checks demonstrated that removing
initial inode locking, durable usage reservation, or encrypted store binding
causes the corresponding regression to fail; production files were not altered
by those checks. Phase 2 remains open until X2 consumes the shared primitives and
mixed-format/interrupted-replacement compatibility is verified. All broader
qualification, migration/rotation rehearsal, historical replay scenarios, and
benchmark evidence remain required by the original completion contract.

### X2 integration and transactional managed filters (2026-09-26)

X2 journals now use the shared descriptor, ownership, envelope, usage, and typed
commit primitives. Explicit legacy readers preserve LCX2 products, sequence
checkpoints, and journal state. A legacy key-file-only journal opens for read-only
recovery/export; live writes require explicit upgrade with a fresh independent
active key and the legacy read-key mapping. Mixed recovery retains original
product bytes and sequence values. Missing usage accounting fails closed. Journal
capacity includes actual metadata allocation and fixed recovery working space.

Strict managed YAML and encrypted JSON codecs preserve all 22 filter types and
complete RADIUS criteria. Bounded decoding rejects partial/ambiguous documents.
YAML and encrypted backends use lifetime ownership and durable whole snapshots;
encrypted initialization is explicit. The common `lc migrate filter-store`
command supports empty initialization, strict YAML migration, no-clobber or
explicit in-place operation, and authenticated interruption/resume bookkeeping.
Its registration is verified for all/cli/processor/tap binaries. LI-state and
journal migration/rotation commands remain open.

Manager mutations validate detached candidates, commit snapshots, then publish
maps, revisions, and ordered updates. Direct/scoped RPCs and LI mutations use one
processor path. Definite failures preserve effective policy; uncertain commits
and post-commit application faults block processing. Capture readiness confirms
all interfaces and BPF installation before policy application succeeds. LI
filter lookups remain available while capture drains, with residual cleanup IDs
tracked separately from authorization. Diagnostics omit raw selectors and
LI-derived filter identifiers.

Verified checks include the complete processor/delivery/tap integration suites,
shared storage and managed codec/backend tests, common migration CLI and build-tag
registration tests, and focused race tests for manager ordering, processor
mutations, capture readiness, LI filter transactions, journal recovery, and
bootstrap boundaries. Shared/backend/CLI vet checks passed. Maximum-schema
allocation measurements are recorded in the design contract; they are decoder
bounds, not the required X3 production-storage benchmark.

Core runtime filter-mode selection and the CLI mode/key flags are not wired in
this checkpoint, so mandatory encrypted LI startup is not yet enabled. Phase 2's
cross-store configured-key independence check remains open until all four runtime
stores exist. The new storage foundations do not close phase 4 lifecycle
transactions or phases 5–9; final migration/rotation rehearsal, historical replay,
performance qualification, and release build matrix are still required.

### Managed filter runtime and CLI integration (2026-09-26)

The processor constructor now resolves storage using effective runtime LI
configuration and authenticates/loads the complete snapshot before constructing
capture, outputs, listeners, or LI state. Both CLI and embedded callers reject
LI with YAML, missing encrypted initialization, wrong keys/formats, malformed
snapshots, competing ownership, and invalid mode/key combinations. Constructor
failure releases snapshot ownership; worker creation follows authentication.
Ordinary non-LI YAML first-run behavior and stopped-node editing/restart remain
supported. The processor stores its resolved path/mode for subsequent lifecycle
operations; shutdown closes ownership without rewriting stale policy.

Common flags and explicit environment bindings cover process and every tap
protocol through centralized runtime application. Precedence is CLI, environment,
YAML, then constructor/default values; explicit empty values clear lower-priority
values. Prior keys use repeatable `id=path`, YAML lists, or one CSV environment
record. Process/tap READMEs describe modes, key provisioning, migration, and
stopped-node editing. The filter migration CLI was delivered in the preceding
checkpoint, so mandatory encrypted LI filter startup has an offline setup path.

Verification passed for the full `all li` processor package tree; focused
processor mutation/store race tests in both `all` and `all li`; cmdutil/process/tap
race suites in both builds; specialized processor/tap command tests; and vet of
the processor and affected CLI package trees. The runtime matrix exercises
persistent round trips, stopped-node edits, ciphertext/plaintext mismatch
preservation, wrong-key/corruption failures, exclusive ownership, and ownership
release after subsequent constructor failure. A bounded independent review of
the initialization seam found and resolved a pre-authentication correlator worker
leak and a latent tap factory-error ownership leak. Phase 3 is implemented; full
release qualification remains phase 9.

### Encrypted administrative state and bounded recovery closure (2026-09-26)

Phase 4 now uses an independently encrypted, exclusively owned, strictly decoded
complete snapshot. Administrative operations reserve generations and durable
intents before policy effects, publish only committed candidates, and retain
failed/uncertain cleanup and revocation obligations for recovery. Destination
changes preserve exact endpoint identity. Restored pending tasks remain queryable
but cannot promote or gain authority from a modification without fresh activation;
legacy generation-zero reactivation advances the retained watermark.

The bounded closure review fixed cleanup ownership checks, withdrawal planning
failure admission, exact intent/control references, purge eligibility, and
constructor effects preceding storage authentication. Its one supplemental fix
binds unfinished destination controls to the retained prior endpoint's exact
revision and delivery hash; finished historical controls remain inert. Processor
construction now retains authenticated owners before creating outputs; failed
preparation releases them without ADMF notification or disturbing an existing
runtime. Current ADMF reconciliation still precedes capture and remote serving.

Offline JSON migration and explicit empty initialization preserve task/destination
identities, generation watermarks and the original RADIUS allocator pin, including
changed-path and explicit in-place modes. Authenticated resume metadata binds the
source, destination, keys and pin. Process/tap CLI, environment and YAML references
support independent state/X2 active and prior keys, with explicit-empty precedence.
Cross-store checks use the immutable rings retained by actual owners. This does
not yet implement X3 configuration or encrypted key rotation.

Verification passed: full LI race suite (32.601s), supplemental administrative/
codec race suite (8.655s), affected all+li LI/processor/CLI/migration suites and vet,
non-LI processor/process/tap suites, and the full shared-storage race suite
(1.489s after the experimental helpers). CLI+li, processor+li, tap+li and non-LI all
variants compile and pass migration registration/initialization checks. A real
RADIUS allocator integration preserves its watermark across a state-path change.
Isolated overlay mutations demonstrate sensitivity to startup ordering, cleanup,
withdrawal, restored-pending authority, purge references and endpoint identity.

The independent scope reconciliation covers 22 obligations, 64 union production
loci, 48 field rows and 43 branch rows, including all 204 author persisted-field
boundary rows and seven configuration rows. Zero unmatched loci or unresolved
material findings remain in phase 4. Temporary inspectable closure evidence stays
under `/tmp/li-admin-closure*.md`; no audit framework was added to the repository.
Actual journal revocation/product acknowledgements remain phase 6; historical X3
replay remains phase 7; process-kill/power-loss and full release qualification
remain phase 9. Local injection/reopen tests do not substitute for those checks.

### X3 layout calibration: no qualified layout yet (2026-09-26)

The reproducible [measurement report](../research/li-x3-storage-benchmarks.md)
records real encryption, usage reservations, product/control/head durability,
filesystem/device details and callback timing. The original per-record X2
protocol, used as an explicit size-equivalent X3 storage proxy, sustained only
18.50 durable copies/s under a 200-copy/s offered calibration and accumulated a
large backlog. It is not suitable for the frozen X3 workload on this device.

Three benchmark-only alternatives were specified and tested in the
[batch-layout design](../design/li-x3-batch-layout.md): separate immutable batch
and head publication; grouped publication with parallel file syncs; and a single
head-container inode with descriptor-owned exchange/archive publication. Their
2/200-record probes all missed the frozen 25ms median durability gate. The final
container prototype measured exact medians of 28.608/29.516ms, including actual
usage renewal in the 200-record probe. None was adopted by production X2 or X3.

The bounded helpers and kernels include fault, ownership, callback, malformed
frame and interrupted-publication checks. Missing selected prerequisites stop
recovery; no older-head fallback or generic cleanup deletes committed evidence.
The exchange prototype only classifies staged evidence; its offline reconciliation
is deliberately unsupported. Raw final measurements were retained for handoff,
and owned disposable stores/caches were removed. The full 20,000-copy/s workload,
40,000-copy/s recovery, simultaneous X2 contention, compaction/expiry, million-record
startup and soak gates remain unrun. A new reviewed layout or supported durable
platform is required before production layout selection and phases 5–7 proceed.

### Fixed-segment kernel and rotation I/O foundations (2026-09-26)

The [fixed-segment design](../design/li-x3-segment-layout.md) now has a Linux
descriptor-owned helper and benchmark-only codec/recovery implementation. It
fully initializes a fixed 32 MiB inode, requires two authenticated adjacent head
slots, appends one bounded encrypted batch, and acknowledges each product only
after one definite `fdatasync`. Invalid peer heads or selected data fault recovery;
there is no older-head fallback. A bounded unselected tail is classified without
mutation. Production journal adoption, tail repair, segment succession, control
priority, compaction, and full-load qualification remain outstanding.

Focused race checks passed for securestore (3.409 s) and delivery (10.289 s),
including helper-process death and separately constructed authenticated corrupt
states. A tightened child-write check passed again (1.593 s), an independent
original-byte oracle passed (1.273 s), and focused vet passed. These compose
syscall/crash and codec checks; they are not an integrated cryptographic
process-crash test or physical power-loss evidence.

The corrected real-ext4 2/200-record ×40 probes measured actual admission-to-callback
p50/p99/max of 13.718546/18.682567/18.682567 ms and
14.767265/39.836771/39.838384 ms. Both pass the small frozen latency gate. The
larger probe renewed actual usage reservations from 4,096 to 8,192, verified all
8,000 original PDUs after reopen, and retained 33,570,816 allocated bytes within
its 96 MiB cap. Its sequential 12,769.94 copies/s is not the 20,000/s workload
qualification. Full initialization costs and shared-host limitations are recorded
in the [measurement report](../research/li-x3-storage-benchmarks.md).

Two harness corrections remain explicit in that report. Synthetic PDUs now use
`SetPayload`, so their header describes the entire RTP payload; earlier raw logs
do not establish protocol-validity of those malformed fixtures. The first segment
run also subtracted modeled arrival offsets; its raw log is preserved as
superseded evidence, and the corrected run uses actual elapsed time for every
record. Prior failed-layout numbers remain historical observations. Raw corrected
measurements are retained in `/tmp/li-fixed-segment-actual-admission.log`, with
fault/oracle/vet logs in `/tmp/li-fixed-segment-*.log`; owned stores and caches
were removed.

Separately, the [snapshot rotation proposal](../design/li-snapshot-key-rotation.md)
has attributed per-write `RotationIO`/usage helpers with physical preallocation,
bounded inventory, descriptor/alias checks, atomic no-clobber publication,
replacement-inode ownership handoff and typed outcomes. Full securestore race
(3.407 s), vet, and an independent bounded review passed; evidence remains in
`/tmp/li-rotation-io-{race,vet}.log` and `/tmp/li-rotation-io-review.md`. This helper
does not itself reserve an entire remaining rotation attempt or implement a
coordinator/CLI. The separately reviewed
[whole-attempt workspace design](../design/li-snapshot-rotation-workspace.md)
defines that next requirement. No phase-5 or rotation completion checkbox is
closed by these foundations.

The subsequent finite `RotationWorkspace` helper now reserves and syncs the
entire caller-selected remaining stage set before becoming ready. Up to fourteen
stage inodes are consumed once through write/rename; no file allocation or refill
occurs after readiness. Retained source/destination/usage ownership, exact
allocated-block accounting, bounded authenticated-caller cleanup, and a borrowed
usage adapter enforce that boundary. Every seal, including one that needs no
ledger extension, checks readiness and the finite ordinary-usage allowance.
The peak is measured retained allocation plus held locks plus the remaining
stage pool. Successful sync of a verified prior output advances its snapshot
outcome even if later workspace allocation fails.

[Rotation record codecs](../design/li-snapshot-rotation-records.md) implement
canonical bounded request, HMAC bootstrap, and encrypted planned/prepared/complete
progress records. They bind the exact original ciphertext/payload, loaded source
ring, new key, filesystem identity, destination, and predecessor receipt. Progress
uses ordinary new-key capacity. Independent binary/HMAC vectors and adversarial
tests cover entire-record authentication, malformed/trailing input, key reuse,
immutable loaded keys and correctly encrypted mismatched requests.

Full securestore race passed (6.108 s), then the final affected workspace/codec
race passed (3.234 s); vet and diff checks passed. Review found and fixed a
post-sync verification-descriptor close error that could mislabel a committed
stage as uncertain. Its regression covers publication, later metadata, recovery,
settlement and readiness. Other tests cover every stage's I/O failure cuts,
physical allocation drift, aliases/locks, ledger extensions, partial workspace
rebuilding and helper-process death. Evidence is retained in
`/tmp/li-rotation-workspace-{race,final-race,vet}.log`; task caches were removed.
At this foundation checkpoint the coordinator, owner adapters and CLI were still
outstanding. The following increment completes that snapshot scope.

### Offline snapshot key rotation (2026-09-26)

The Linux coordinator, filter/state owner wrappers and `lc migrate` commands now
rotate encrypted snapshots in place or to an unoccupied basename in the same
descriptor-identified private directory. They preserve exact validated payload
bytes and store identity, including the optional LI allocator pin. Loaded keyrings
are immutable; the new key must differ from every supplied source key. Historical
usage ledgers remain intact. Owner decoders receive the remaining share of one
256 MiB memory allowance after coordinator buffers and scratch are charged.

Authenticated bootstrap/progress selection precedes bounded full-attempt physical
reservation. Resume never resets usage, refills a ready workspace, or treats a
visible replacement as proof of directory synchronization. A completed receipt
preserves lineage while permitting legitimate subsequent runtime saves. Reports
retain the snapshot's committed/uncertain outcome if auxiliary cleanup fails;
bounded inventory identifies unknown dependencies and excludes external backups.
No key retirement, journal rewrite, runtime configuration change or policy/network
action is performed.

Coordinator race checks passed (12.479 s), including sixteen injected durable
cuts in both publication modes and eleven subprocess-death cuts. Additional I/O,
ownership, usage-reserve and retained-source regressions passed (1.071 s). These
are process/fault tests, not physical power-loss qualification. Full affected
filter/LI owner suites, focused race checks, non-LI filter suites and vet passed.
The command suite passed with LI/race (1.057 s), without LI (0.014 s), and after
the final coordinator fixes (focused race, 1.053 s). Command vet also passed.

The bounded review found two issues: late outcome latching after auxiliary
candidate validation and an overly permissive generic payload ceiling. Both were
fixed with regressions and independently rechecked; discovery was not reopened.
Evidence remains in `/tmp/li-snapshot-rotation-{race,extra-race,vet}.log`,
`/tmp/li-snapshot-rotation-review.md`, `/tmp/li-rotation-owner-verification.md`,
`/tmp/li-rotation-owner-*.log`, and `/tmp/li-rotation-cli-*.log`.
Task build caches were removed. The snapshot subtask is complete; phase 8 and
the overall plan remain open for journal and X3 work.

### Call incarnation foundation (2026-09-26)

Each new local call lifecycle generation now receives one cryptographically
generated UUID, retained through admission, finalization/tombstones, LI metadata,
destination fan-out and reorder callbacks. Numeric generations still reject stale
local callbacks; reused Call-IDs and new process registries receive distinct
incarnations. Existing memory-only cancellation and delivery behavior remains.
Zero identity is still permitted for legacy/non-call memory callers; the future
durable boundary must enforce full provenance rather than infer it.

Entropy failure or generation exhaustion latches new admission closed before
publishing an identity. Already allocated calls can still finalize and drain at
shutdown. Completion-before-admission failures now propagate through the writer
owner and are logged by the monitor. No fallback identity or per-packet UUID
allocation is used. This does not implement backlog permits, capture-closure
delivery, durable controls, or the new shutdown ordering.

The full affected LI processor/delivery/tree and command suites, non-LI processor
and command suites, and vet passed. Final focused race checks passed for processor
(1.123 s) and delivery (1.143 s), covering concurrent admission, Call-ID reuse,
detached callbacks, stale generations, short entropy reads, failure recovery
boundaries, queue metadata and shared/owned two-destination producer admission.
Exact commands and results are retained in
`/tmp/li-call-incarnation-verification.md`, with logs in
`/tmp/li-call-incarnation-{race-final,full-li,full-nonli,vet}.log`. The task cache
was removed. Phase 6 remains open for its integrated lifecycle obligations.

### Snapshot operator documentation (2026-09-26)

The security guide, example configuration, manual configuration/command reference,
LI deployment example and RADIUS deployment example now describe the implemented
encrypted snapshot requirements. They retain editable YAML for LI-disabled nodes,
document explicit offline initialization/migration and key references, and preserve
the encrypted administrative state's separate RADIUS allocator pin. Security
guidance distinguishes encrypted snapshots from other output files and explains
usage-ledger preservation, uncertain writes, backup/rollback limits and downgrade
constraints. Examples were checked against the implemented flag/config resolvers
and migration commands; Prettier parsed and formatted the Markdown/YAML changes,
and `git diff --check` passed. This documentation increment does not close the
phase-9 rollout task: X3 persistence/replay, completed rotation tools and their
qualification remain outstanding.

### Existing-store runtime diagnostics (2026-09-26)

Processor management status and `lc show status` now expose actual managed-filter,
administrative-state and X2 storage owners. Common filter status works in non-LI
builds and distinguishes YAML from encrypted storage. Additive protobuf fields
preserve existing tag numbers (`ProcessorStats.storage=14`,
`LIJournalStats.storage=10`); regeneration changed only the management binding
semantically. No X3 journal field or counter is inferred from memory-only delivery.

Immutable diagnostic views keep status reads independent of snapshot/usage sync
and close operations. They report loaded key IDs, conservative reserved-usage
highwaters and remaining limits, rotation advisory, fixed public fault categories,
policy admission blocks and per-owner write outcomes. Object commitment, auxiliary
usage-ledger uncertainty and transport uncertainty remain separate. Snapshot
counters describe backend Save attempts; X2 counts product/checkpoint attempts
and durable record removals. Committed cleanup errors retain their committed
classification. Closing/closed owners cannot be reopened by rejected diagnostic
state transitions. Public status omits raw storage errors and sensitive paths or
content; operator semantics are documented in `cmd/show/README.md`.

Full affected LI, filter/securestore, processor and status-client suites passed,
as did non-LI processor/status-client checks and vet. Final targeted race checks
passed for all six affected packages, covering stalled sync/close, terminal owner
state, usage thresholds/reservation outcomes, detached bounded key labels,
redaction and protobuf-to-JSON preservation. Logs remain in
`/tmp/li-storage-telemetry-{full,full-nonli,race-final,vet-final}.log`; the task cache
was cleaned. Phase 8 remains open for X3 accounting, full configuration/path
validation, journal tools and completed rotation/recovery qualification.
