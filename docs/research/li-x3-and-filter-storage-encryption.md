# Encrypted X3 buffering and processor/tap filter persistence

**Date:** 2026-09-26

**Status:** Research and proposed design; no implementation changes made

**Scope:** LI delivery buffering and the managed filter store used by processor
and tap, including builds without LI

## Findings and recommendation

lippycat currently supports an optional encrypted disk journal for X2 delivery
products. X3 content is buffered only in memory. The processor and tap filter
store, normally `~/.config/lippycat/filters.yaml`, is plaintext in both LI and
non-LI builds.

Add encrypted X3 persistence with its own capacity, retention, and recovery
controls. Encrypt managed filter persistence in common code available to both
build types. Share cryptographic and durable-file primitives while keeping the
delivery journals and filter-store transactions separate.

The recommended policy is to require encryption whenever managed filter
persistence is enabled, with an explicit migration path for existing files.
X3 disk persistence should require explicit configuration, a finite disk budget,
and a finite retention period. These are proposed product defaults, not current
behavior or a claim about an ETSI requirement.

This report is based on source inspection and the existing operational
documentation. It does not constitute a cryptographic audit or a performance
measurement. Runtime behavior was not tested for this report.

## Current implementation

| Storage                 | Current behavior                                                             | Principal evidence                                                                                                                                                                          |
| ----------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| X2 delivery             | Optional AES-256-GCM encrypted journal; disabled without a spool directory   | [client_journal.go](../../internal/pkg/li/delivery/client_journal.go), `initJournal` and `persistItem`; [journal.go](../../internal/pkg/li/delivery/journal.go), `OpenJournal` and `encode` |
| X3 delivery             | Memory queues, retries, optional age expiry; excluded from journaling        | [client.go](../../internal/pkg/li/delivery/client.go), `enqueueWithMetadata`; [client_journal.go](../../internal/pkg/li/delivery/client_journal.go), `persistItem`                          |
| Processor/tap filters   | Plaintext YAML; shared implementation regardless of LI build tag             | [persistence.go](../../internal/pkg/processor/filtering/persistence.go), `YAMLPersistence`; [parser.go](../../internal/pkg/filtering/parser.go), `WriteFile`                                |
| CLI batch input         | Plaintext YAML parsed for remote filter updates                              | [set.go](../../cmd/filter/set.go), `runSetFilterBatch`                                                                                                                                      |
| LI administrative state | Separate plaintext JSON containing tasks, destinations, and generation state | [persistence.go](../../internal/pkg/li/persistence.go), `persistedState` and `writePersistedState`                                                                                          |

### X2 journal guarantees and limits

Processor and tap expose `--li-delivery-x2-spool-dir`,
`--li-delivery-x2-spool-max-bytes`, and `--li-delivery-x2-spool-key-file`.
Validation requires a configured key and enough capacity for the journal's
reserved overhead. See the [processor flags](../../cmd/process/flags_li.go),
[tap flags](../../cmd/tap/flags_li.go), and
[limit validation](../../internal/pkg/li/delivery/config_limits.go).

The key file contains exactly 32 raw bytes. `OpenJournal` constructs AES-GCM;
`encode` encrypts each serialized record with a fresh random nonce and
authenticates the format marker as associated data. The extra CRC32 is framing
error detection; GCM supplies cryptographic authentication. Journal creation
requests a `0700` directory and `0600` files, checks private paths, and takes an
exclusive process lock. Writes use an exclusive temporary file, file sync,
rename, and directory sync.

Records preserve the original encoded PDU, interception and destination IDs,
lifecycle generations, call identity, and timestamps. Separate encrypted sequence
checkpoints survive completion of individual records. Recovery holds records
pending explicit approval and current ADMF reconciliation; UUID equality alone
does not authorize delivery.

Admission is asynchronous: a successful enqueue confirms memory admission,
while the journal callback confirms persistence after synchronization. A crash
between those points can lose the pending record. A successful local TLS write
does not establish MDF application receipt. A crash before the completion
checkpoint can leave a record available for duplicate delivery. Neither the
current journal nor the proposed X3 extension provides exactly-once delivery.

These operational distinctions are documented in
[LI_INTEGRATION.md](../LI_INTEGRATION.md#delivery-byte-limits-age-and-x2-persistence).

### X3 buffering and lifecycle behavior

X2 and X3 already have separate FIFO queues and delivery workers per destination.
X3 has independent PDU and byte limits, and `--li-delivery-x3-max-age` optionally
limits residence across reorder buffering and delivery retries. Its default of
zero disables expiry.

`CancelTask` and `CancelCall` remove matching queued X3 and cancel affected
writes. Processor callbacks invoke these operations on task changes and call
finalization. The X3 journal must account for this behavior: simply removing the
X2-only check in `persistItem` would omit durable cancellation, expiry, sequence
restoration, replay authorization, shutdown accounting, and capacity protection.

See [client.go](../../internal/pkg/li/delivery/client.go),
[processor_li.go](../../internal/pkg/processor/processor_li.go), and
[reorder.go](../../internal/pkg/li/delivery/reorder.go).

### Filter persistence and failure behavior

Both node roles construct `NewYAMLPersistence` through the processor core.
Startup loads the file; filter updates and deletions write snapshots through the
same manager. Tap's protocol commands also supply `Config.FilterFile` to this
core. The manager explicitly treats `Load` as a startup-only operation; an
encrypted design should not assume an existing runtime file-watcher contract.

The current writer marshals filters as YAML, requests a `0750` directory, writes
`path + ".tmp"` with mode `0600`, and renames it into place. This normally provides
private file permissions and atomic replacement, but it is not encrypted or
explicitly crash-durable. The path handling has no read-size limit or process
lock, and the fixed temporary filename can follow an existing symlink. Creation
modes do not repair permissions on an existing directory or temporary file.

Two failure paths need particular attention when adding encryption:

- [Processor startup](../../internal/pkg/processor/processor_lifecycle.go),
  `Start`, logs a load error and continues. An authentication failure must not
  become a successful startup with an empty filter set.
- [Filter mutations](../../internal/pkg/processor/filtering/manager.go),
  `Update` and `Delete`, change memory and distribute updates before saving.
  Save errors are logged while the request still returns success. Adding an
  encrypted writer alone would preserve this inconsistent durability contract.

## Why the filter store needs encryption

The [filter schema](../../internal/pkg/filtering/types.go) can contain SIP and
email identities, phone numbers, IMSI/IMEI values, IP addresses, call IDs, DNS
names, URLs, email subjects, and RADIUS identities or compound criteria. Hunter
scoping and descriptions can expose deployment details. LI-generated filter IDs
also encode task XIDs, as shown in [filters.go](../../internal/pkg/li/filters.go).

This information is sensitive in ordinary monitoring deployments as well as LI
deployments. File permissions constrain access through the running operating
system; application encryption additionally protects copied files, backups, or
snapshots when the decryption keys are not available with them.

That protection depends on key custody. A plaintext key backed up beside the
ciphertext does not protect against disclosure of that entire backup. Encryption
also does not protect against a compromised process already authorized to decrypt,
or eliminate plaintext in memory, exports, swap, or crash dumps. Full-disk
encryption and controlled backup access remain complementary measures.

Authenticated encryption detects modification of an encrypted object. It does
not independently detect replacement with an older valid object or deletion of
the store. Strong rollback detection would require a trusted generation or
checkpoint outside the replaceable storage; that is a separate design decision.

## Proposed shared storage foundation

Provide a small common package, available without the `li` build tag, for key
loading, versioned authenticated envelopes, and secure atomic file replacement.
Keep queue admission, delivery authorization, filter validation, and transactional
publication in their owning packages.

New envelopes should authenticate their complete header, including version,
storage purpose, algorithm identifier, and key ID. Encrypt the data and sensitive
metadata; enforce size limits before allocation and before decoding plaintext.
Use the existing AES-256-GCM approach through standard cryptographic libraries,
with explicit nonce-generation and per-key usage limits suitable for X3 volume.
The envelope must reject a filter-store object presented as a delivery record or
an X2 object presented as X3.

The file primitive should enforce private regular files and controlled parent
directories, use descriptor-based validation to avoid check/open races, create
exclusive temporary files, handle short writes and cleanup errors, synchronize
the file, rename, and synchronize the containing directory. Encrypt before
writing temporary data. Take an exclusive store lock covering reads, mutations,
migration, and rotation where multiple processes could otherwise own a path.

Distinguish a definite failure before replacement from an uncertain result after
rename but before directory sync. The caller cannot safely pretend that the old
state is authoritative after the replacement may already have occurred.

### Key provisioning and rotation

Use externally provisioned secrets. An initial interface can accept a private
key file, including a file supplied through a service credential mechanism.
Configuration and environment variables should carry key references, not raw
key bytes. Never print keys or decrypted records in diagnostics.

Independent keys for filters, X2, and X3 are straightforward and limit exposure
between stores. A common master secret with HKDF-SHA256-derived keys is also
reasonable if operators prefer one provisioned secret; derivation must include
separate, versioned purpose labels and a defined store identity. Master-key
compromise then affects all derived stores. The implementation should select and
document one initial provisioning model rather than add several unfinished ones.

Include key IDs in the new format and define one active write key plus a bounded
set of prior read keys. Rotation needs resumable rewriting or a documented
drain-and-retire procedure, with capacity reserved for temporary copies. Old
keys must remain available for retained journals and backups. Losing a required
key makes those objects unrecoverable.

Existing `LCX2` version-1 records use the configured raw key directly and contain
no key ID. Preserve that reader and its key semantics until an explicit migration
has completed. Reinterpreting the existing X2 key as an HKDF master would make
the old journal unreadable.

## Proposed encrypted X3 journal

### Isolation, admission, and performance

Generalize the journal implementation to an explicit interface type, then use
separate X2 and X3 instances with independent directories, capacities, pending
operations, workers, and statistics. This protects X2's configured capacity from
X3 backlog. Physical I/O contention still needs measurement when both directories
reside on the same filesystem.

Persist the original encoded X3 PDU at delivery admission, after RTP reorder where
that path applies. Preserve the journal's callback gate so delivery cannot claim
a record until its persistence succeeds. Include interface identity, XID, DID,
task and destination generations, call identity where applicable, capture and
admission times, and the absolute expiry deadline.

Protect durable queue heads from implicit drop-oldest eviction. Reject new
admissions when the configured persistent capacity is exhausted, with explicit
loss accounting. Charge pending reservations, file allocation overhead, sequence
checkpoints, cancellation metadata, and recovery/rotation working space. Preserve
bounded memory admission; disk capacity alone must not imply an unbounded index
or queue.

The current X2 design stores individual records as encrypted JSON, including a
base64-encoded PDU, and performs multiple synchronized file operations. Its
suitability for high-rate X3 is unmeasured. Benchmark small-packet workloads,
fan-out, outage accumulation, and simultaneous recovery/live traffic before
choosing the X3 layout. If batching or segmented storage is necessary, define the
durability acknowledgement and crash recovery boundaries explicitly.

### Retention, cancellation, and restart recovery

Require a finite X3 journal byte budget and finite maximum age. Persist the
original absolute deadline so restart does not reset retention. Check expiry
during recovery, while held, during replay admission, and immediately before
transport write. An online sweeper should reclaim expired records even without
MDF connectivity or replay approval. While the service is stopped it cannot
perform deletion; recovery must enforce overdue expiry before permitting replay.

On restart, hold recovered X3 by default. Approval should identify the journal,
interface, exact record, task generation, destination generation, and relevant
call/timestamp/deadline fields. Require current ADMF reconciliation and validate
task activity, X3 delivery authorization, destination membership, destination
identity, cancellation state, and remaining lifetime. A manifest by itself is
insufficient. Preserve FIFO order per destination and interface when only part
of the backlog is approved.

Current call generations are process-local and cannot by themselves prove that
a recovered record belongs to a currently authorized call. A durable lifecycle
identity or explicit historical-product authorization contract is needed before
claiming safe X3 replay across process lifetimes.

Cancellation must reach pending writes and held disk records as well as memory
queues. Under an admission barrier, stop new sends and durably record revocation
before reporting a completed revocation boundary. A compact authenticated
tombstone can permit asynchronous record deletion; recovery must apply it before
exposing records for replay. Failure to persist revocation must block affected
delivery and surface an error. Reserved control capacity is necessary so a full
spool cannot prevent recording a cancellation. Pending journal callbacks must
not resurrect revoked records.

There is a product-policy conflict to settle here. Today, normal call
finalization also cancels buffered X3. Preserving that rule means a call that
ends during an MDF outage loses its remaining deliverable backlog even with a
disk journal. If the intended feature must deliver previously admitted content
after normal call completion, distinguish normal completion from authorization
revocation and explicitly define historical delivery eligibility. The conservative
baseline preserves existing cancellation semantics until that decision is made.

Shutdown should retain eligible durable X3 with a distinct retained-on-disk
outcome. Destination removal or replacement must revoke replay approval; content
must never transfer to a replacement destination merely because its UUID matches.
Whether such content remains held until expiry or is purged immediately is a
retention policy to document. Partial or uncertain writes remain separately
accounted for and cannot be reclassified as confirmed MDF receipt.

### Sequence state and integration

Sequence persistence currently accepts only X2 in
[journal_sequence.go](../../internal/pkg/li/delivery/journal_sequence.go) and
[sequence_restore.go](../../internal/pkg/li/x2x3/sequence_restore.go).
Generalize validation to the expected interface, restore X3 checkpoints before
live encoding starts, and retain checkpoints after individual records are removed.
Update task cleanup, which currently clears X3 sequence state when X2 persistence
is configured. Replay must use the original encoded bytes and sequence number.

Proposed X3 options can mirror `--li-delivery-x2-spool-*` with the `x3` prefix,
including directory, capacity, key reference, hold/purge policy, and manifest
export/replay. Their names and formats remain proposals. Validate path aliases
so X2 and X3 cannot accidentally share a journal directory or overwrite a key or
manifest. Apply identical CLI, YAML, and environment behavior to processor and
every tap protocol, including the non-LI stub configuration structures.

Expose independent X3 journal statistics through the management protobuf and
`lc show status`: pending, persisted, held, replay-approved, retained, expired,
revoked, rejected, uncertain, bytes, limit, and fault state. Account for both
journals in the delivery memory reservation estimate.

## Proposed encrypted managed filter store

Implement an encrypted `PersistenceHandler` in common processor/filtering code.
Keep the existing logical filter schema, including revisions and compound RADIUS
criteria, inside the envelope. Extract serialization helpers as needed, while
preserving plaintext YAML batch input for `lc set filter --file`.

Managed persistence should require a valid encryption configuration before its
first mutation. Wrong or missing keys, malformed or unauthenticated ciphertext,
insecure storage, and unexpected plaintext must stop startup before filters are
applied or capture/delivery begins. Define explicit first-time initialization;
do not treat an existing unreadable store as empty. A separate, explicit
memory-only mode could support deployments that intentionally do not persist
filters, but is not an existing capability established by this report.

Change filter mutations to validate and stage a complete candidate snapshot,
persist it durably, and then publish the committed state to readers and targets
under the manager's mutation ordering. A definite save failure should leave the
old state published and return an error. An uncertain commit requires recovery
or a fault state, not an assumed rollback. Distribution remains a separate
outcome: persistence success cannot prove every remote hunter applied the update.
Review processor-local/tap target application and LI filter-pusher callbacks
alongside the manager to keep those boundaries consistent.

Migration should be an explicit offline operation that acquires store ownership,
reads and strictly validates all legacy filters, encrypts them without plaintext
temporary files, and performs durable replacement. A migration failure must not
silently omit invalid filters. Normal encrypted operation should reject legacy
plaintext instead of accepting a permanent downgrade path.

Do not create a plaintext backup automatically. Existing plaintext copies and
snapshots need an operator-controlled retention decision; replacing a file does
not guarantee physical erasure on modern filesystems or storage devices. Any
plaintext export should be explicit and use a private destination.

An encrypted envelope could occupy the existing configured path, but the default
`filters.yaml` extension would then be misleading. A new `.enc` default with an
explicit migration command is clearer. The rollout must specify precedence and
refuse ambiguous competing legacy/encrypted stores. Update examples that suggest
editing or displaying the live persistence file as YAML.

## Related plaintext exposure

Encrypting the filter file does not complete protection of all persisted target
information. The separate `--li-state-file` serializes tasks and destinations as
plaintext JSON. It also preserves generations needed for journal authorization;
backing up or restoring it independently can break lifecycle reconciliation.
Consider migrating it to the same shared encryption primitives under a separate
key purpose. This is an additional scope decision, not covered automatically by
encrypting filter persistence.

Filter-update handlers currently log raw patterns in
[processor_grpc_handlers.go](../../internal/pkg/processor/processor_grpc_handlers.go).
Redaction should be addressed alongside the encrypted filter store; otherwise
routine updates can leave sensitive selectors in logs. Error messages, command
history, batch-input files, and explicit exports deserve the same review.

Replay manifests currently contain plaintext record and task identities, protected
by private file permissions. Define their handling and retention as explicit
exports. PCAPs, structured logs, and upstream event spools are separate storage
systems and are not encrypted by the changes proposed here.

## Implementation boundaries and verification

| Area                               | Principal integration points                                                                                                                 |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared envelope and file handling  | New common package; existing LI journal codec and file writer                                                                                |
| X3 persistence and recovery        | `internal/pkg/li/delivery/{client,client_journal,journal,journal_replay,journal_manifest,journal_sequence}.go`                               |
| Lifecycle and sequence restoration | `internal/pkg/processor/processor_li.go`; `internal/pkg/li/x2x3/sequence_restore.go`                                                         |
| Filter transactions                | `internal/pkg/processor/filtering/{manager,persistence}.go`; `internal/pkg/filtering/parser.go`; processor startup and filter-target callers |
| Configuration parity               | `cmd/process/flags_li*.go`, `cmd/process/process.go`, `cmd/tap/flags_li*.go`, and all tap configuration constructors                         |
| Status                             | `api/proto/management.proto`, generated management code, `processor_li_delivery_stats.go`, CLI status formatting                             |
| Operator documentation             | `docs/LI_INTEGRATION.md`, processor/tap READMEs, security guide, manual command/config/filter references                                     |

Verification should exercise behavior at storage and lifecycle boundaries, with
fault injection and race tests rather than only encryption round trips:

- [ ] Detect wrong keys, tampering, truncation, unsupported versions, cross-store
      object substitution, oversized inputs, and insecure or aliased paths.
- [ ] Verify exclusive ownership, temporary-file safety, interrupted writes,
      file/directory sync failures, disk exhaustion, and uncertain commits.
- [ ] Preserve X2 version-1 recovery and validate interrupted migration/rotation.
- [ ] Demonstrate independent X2/X3 budgets and workers, bounded pending memory,
      and capacity rejection without silent eviction of durable records.
- [ ] Verify X3 persistence gating, shutdown retention, expiry across restart,
      held-by-default recovery, partial approval, and destination replacement.
- [ ] Exercise cancellation during admission, persistence callbacks, held replay,
      transport writes, and crash recovery; prevent resurrection after revocation.
- [ ] Verify X3 sequence restoration, interface separation, wrap behavior, and
      checkpoint retention after completion, expiry, and cancellation.
- [ ] Verify encrypted filter startup failures prevent activation; failed saves
      do not report success or prematurely publish changes to readers or targets.
- [ ] Preserve filter revisions, compound criteria, LI ownership, plaintext CLI
      import behavior, and processor/tap configuration precedence in both build types.
- [ ] Measure X3 throughput, disk growth, synchronization cost, cancellation
      latency, recovery time, and backlog drain alongside continuing live traffic.

The decisions needed before an implementation plan are the X3 post-call delivery
policy, durable call identity and replay authorization contract, key provisioning
model, default X3 retention, filter migration/default-path policy, and whether LI
administrative-state encryption joins the initial scope. The report recommends
addressing filter-log redaction in the same work because it directly duplicates
the selectors being protected.
