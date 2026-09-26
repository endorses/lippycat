# Encrypted managed storage contracts

Contract date: 2026-09-26. Audited baseline: `77f7abfe`.

This is the implementation contract for
[encrypted X3 buffering, filters, and LI state](../plans/li-x3-and-filter-storage-encryption.md).
It specifies required behavior; it is not a claim that the baseline implements
that behavior. The implementation plan records verified completion separately.
Existing X2 delivery authorization remains unchanged. X3 persistence remains
opt-in and must not be enabled before its durable revocation and recovery gates
are implemented.

Implementation status at contract freeze: the shared primitives and synthetic
legacy fixtures are starter implementation artifacts. Integrated encrypted
startup, administrative transactions, persistent X3, replay, migration/rotation,
and workload qualification are not established by this document or by primitive
unit tests. Their plan gates remain separate completion requirements.

## Shared envelope: LCS1 version 1

`internal/pkg/securestore` owns keys, framing, private files, durable replacement,
and ownership. It has no dependency on LI, filters, protobuf, or delivery policy.
Owners supply an expected purpose and an explicit expected store/object binding
on both seal and open. No reader chooses a key by attempting decryption with each
configured key.

All integer fields below are unsigned, big endian. Offsets are bytes. There is
exactly one envelope per object, with no trailing bytes or concatenated envelopes.

| Offset           | Length            | Field and validation                                           |
| ---------------- | ----------------- | -------------------------------------------------------------- |
| 0                | 4                 | Magic `LCS1`                                                   |
| 4                | 1                 | Envelope version, exactly `1`                                  |
| 5                | 1                 | Algorithm, exactly `1` = AES-256-GCM                           |
| 6                | 2                 | Purpose from the table below; must match the requested purpose |
| 8                | 2                 | Key ID byte length, 1–64                                       |
| 10               | 2                 | Nonce length, exactly 12                                       |
| 12               | 8                 | Ciphertext byte length, including the 16-byte GCM tag          |
| 20               | Key ID length     | Key ID, ASCII `[A-Za-z0-9._-]`; case-sensitive                 |
| Following key ID | 12                | Fresh nonce obtained with a complete `crypto/rand` read        |
| Following nonce  | Ciphertext length | Authenticated ciphertext and tag                               |

The complete header, including magic, framing, key ID, and nonce, is additional
authenticated data. The maximum header is 96 bytes. Plaintext is at most
67,108,864 bytes (64 MiB), ciphertext at most 67,108,880 bytes, and the complete
object at most 67,108,976 bytes. Owners impose smaller limits where applicable.
Before allocating or decrypting, validate the file size, fixed header, known
version and algorithm, purpose, key ID length, nonce length, overflow-safe total
length, exact file length, and configured purpose-specific ceiling.

Decrypted plaintext has the following framing: a nonzero 16-byte store UUID,
a two-byte object-name length, an object name of 1–512 bytes, and the owner's
payload. Object names are canonical UTF-8, contain no NUL, and are compared as
bytes without path normalization. Binding is encrypted because it can contain
sensitive identities. The total plaintext bound includes all binding bytes;
an owner cannot supply 64 MiB of payload in addition to binding overhead.
Authentication and binding validation precede owner schema decoding. Errors
identify an operation/classification, never plaintext, selectors, or key bytes.

| Purpose                      | Value | Owner payload                                                |
| ---------------------------- | ----- | ------------------------------------------------------------ |
| Filter snapshot              | 1     | Complete managed filter document                             |
| LI administrative state      | 2     | Complete state, obligations, intents, and watermarks         |
| X2 product                   | 3     | Immutable X2 record                                          |
| X3 product                   | 4     | Immutable X3 record                                          |
| Sequence checkpoint          | 5     | One interface-specific sequence context and next number      |
| Journal state                | 6     | Journal identity, highwaters, fault/rotation state           |
| Call control                 | 7     | Exact capture incarnation and closure state                  |
| Revocation control           | 8     | Exact revoked provenance and covered durable boundary        |
| Journal batch/index metadata | 9     | Bounded authenticated physical frame indexes and checkpoints |

Zero, unknown purposes, unknown versions, and unknown algorithms fail closed.
Envelope version dispatch is separate from each owner's payload schema version.
X2 and X3 use different store UUIDs even when sharing purpose 5, 6, 7, 8, or 9.
The production segmented journal uses purpose 9 for authenticated frame indexes
and strict typed batches of sequence, call, revocation, and terminal controls.
The batch binds the exact journal, interface, segment, generation and kind; each
logical control retains its complete identity and highwaters. Purposes 5, 7 and
8 remain assigned to their standalone objects. See the
[implemented physical layout](li-x3-journal-layout.md) for exact packing and bounds.
Snapshot object names are `filters` and `li-state`; journal names are canonical
decimal record IDs, `sequence/<context digest>`, `journal-state`,
`call/<incarnation UUID>/<XID>/<task generation>/<DID>/<destination generation>`,
and `revoke/<control UUID>`. The composite call-control name permits one capture
incarnation to serve several exact task/destination generations without control
replacement collisions. Sequence digests identify
the full canonical context; after decoding, the name is recomputed and compared.
Product IDs and sequence contexts must also match the selected file/index entry.

An initial snapshot open obtains its expected store UUID from authenticated
stable store metadata, including its key-usage ledger, before opening the
snapshot. It must not trust the snapshot's self-declared UUID as its own expected
binding. A journal likewise obtains its identity before recovering products.
Key rotation and migration preserve that UUID. Independent initialization creates
a new random UUID. The LI-state UUID and journal UUID are separate identities;
every X3 record binds both. This prevents mixing independently initialized state
with an older journal. Restoration of a coherent older backup is not detected.

## Keys and lifetime accounting

Every enabled encrypted store has one independent, externally provisioned raw
32-byte write key and at most four prior read keys. Configuration stores paths
and key IDs only. An ID uniquely selects one key; duplicate IDs, duplicate key
bytes under different IDs, and reuse between filters, state, X2, and X3 are
configuration errors. Key material and its comparison fingerprints are never
logged. Key files are read through validated descriptors with a 33-byte bounded
read so oversized files are rejected without unbounded allocation.

Nonces are uniformly random 96-bit values. Limit each raw key to at most `2^32`
GCM seals, following the invocation ceiling documented by the
[Go crypto/cipher package](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
Additionally limit the cumulative charged AES blocks to `2^40`. One seal charges
`ceil(header_bytes/16) + ceil(ciphertext_bytes/16) + 1` blocks, conservatively
including the tag and final length block. Both ceilings include snapshots,
products, checkpoints, controls, rewrites, failed writes, and abandoned attempts.
They are operational ceilings, not a promise of zero random-nonce collision risk.

Persist highwater reservations before using them. Round seal highwaters upward
in 4,096-invocation chunks and block highwaters upward in 1,048,576-block chunks
(16 MiB of block volume), with overflow checks and clamping at the applicable
admission ceiling. An individual large envelope may require several block chunks
in one extension; chunk size is not a maximum envelope or extension size.
Reservations count as consumed
after restart even if never used. A failed nonce read may waste a reservation;
it must never return it to persistent accounting. Decryption does not consume a
reservation. A missing or invalid usage ledger for an existing key is fatal;
runtime startup never silently creates one or reconstructs its count by scanning
only current objects, because deleted objects also consumed nonces.

The bounded ledger is authenticated with HMAC-SHA256 under that raw key using
a distinct fixed domain label. It does not use GCM, avoiding recursive nonce
accounting. Its authenticated fields include schema version, store UUID, and
invocation/block highwaters. Its filename is derived from a domain-separated
HMAC of a fixed label under the raw key, so changing a configured key ID cannot
create a fresh allowance. The usage owner holds a stable exclusive sidecar lock;
in-process reservations are serialized. Explicit offline initialization creates
the ledger; adding a new rotation key requires the same explicit initialization
under the already authenticated store UUID. Backups contain ledgers as well as
data. The exact ledger format is 72 bytes, with no trailing data:

| Offset | Length | LCUS version 1 field                                                                         |
| ------ | ------ | -------------------------------------------------------------------------------------------- |
| 0      | 4      | Magic `LCUS`                                                                                 |
| 4      | 1      | Version, exactly 1                                                                           |
| 5      | 3      | Reserved, all zero                                                                           |
| 8      | 16     | Nonzero store UUID                                                                           |
| 24     | 8      | Big-endian reserved invocation highwater, at most `2^32`                                     |
| 32     | 8      | Big-endian reserved block highwater, at most `2^40`                                          |
| 40     | 32     | HMAC-SHA256 over the domain bytes `lippycat/securestore/usage/v1\x00` followed by bytes 0–39 |

Here `\x00` denotes one zero byte, not four printable characters. The basename
is `.usage-` followed by lowercase hex HMAC-SHA256 of the sole byte string
`lippycat/securestore/usage-name/v1\x00` under the same raw key. No key ID enters
either MAC input. The ledger's 4 KiB resource allowance covers its allocated
storage; its wire length remains exactly 72 bytes. The random store UUID and
usage counters are intentionally visible, authenticated bootstrap/accounting
metadata. They identify no task, destination, call, selector, or payload; those
sensitive identities and contents remain inside encrypted envelopes.

Restoring old counters with continued use of the same key is unsupported;
rotate to a fresh key before resuming writes after a backup restore whose latest
usage highwater cannot be proven.

Expose an advisory at 75% of either ceiling. At 90%, reject ordinary admission
and snapshot mutations that increase enforcement, reserving the remaining 10%
for revocation, closure, fault, and sequence controls. Never exceed a hard ceiling.
If reserved control accounting cannot be advanced durably, block affected
admission/claims and return or latch a storage fault. Offline rotation decrypts
with the old read key and seals with the new active key, so it does not need old
GCM capacity. Keep old read keys until all live objects, sidecars, interrupted
rewrite artifacts, and required backups have been accounted for. A key with
unknown historical usage may be used only for legacy reading, never for new
LCS1 seals.

## Payload schemas and resource bounds

Owner schemas use strict typed decoding: reject unknown fields, duplicate map
keys/identifiers, trailing documents, null entries, unknown enum values, invalid
timestamps, and integer overflow. A successful partial decode is never a valid
managed store. Reject over-limit counts while traversing the input, before
building complete slices/maps or invoking policy conversion. YAML aliases and
merge keys are not accepted by managed snapshot/migration readers. General CLI
batch import remains a separate interface and does not become a managed loader.

The following are fixed reader ceilings. Configured capacities may be smaller;
exceeding them rejects startup/admission, never truncates a store. Decimal byte
values in diagnostics must correspond to these binary-unit limits.

| Resource                                                        | Ceiling                                                                                                         |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Filter snapshot owner document                                  | 16 MiB encoded; 65,536 filters                                                                                  |
| LI state owner document                                         | 32 MiB encoded; 65,536 tasks and 4,096 destinations                                                             |
| Individual identity/selector/description string                 | 4,096 UTF-8 bytes; narrower existing validators still apply                                                     |
| Filter target hunters                                           | 256 per filter; 1,048,576 total references                                                                      |
| RADIUS criteria                                                 | 64 per compound filter; 262,144 total criteria                                                                  |
| Task targets / destination references                           | 256 each per task; 1,048,576 total references of each kind                                                      |
| Cleanup obligations / lifecycle intents / generation watermarks | 262,144 each; each obligation has at most 256 filter IDs                                                        |
| Journal record owner document                                   | 64 MiB minus binding overhead; actual encoded PDU must fit after metadata/encoding overhead                     |
| Record metadata and individual control plaintext                | 64 KiB, including binding                                                                                       |
| Sequence checkpoint plaintext                                   | 16 KiB, including binding; existing context identity sum at most 512 bytes                                      |
| Journal state plaintext / usage ledger                          | 64 KiB / 4 KiB                                                                                                  |
| Product index entries                                           | X2: 1,000,000; X3: 2,000,000; configured smaller maximum applies                                                |
| Sequence contexts                                               | At most product-index capacity per journal; checkpoints retained independently of product removal               |
| Call/revocation controls                                        | At most twice product-index capacity plus 4,096 reserved entries per journal                                    |
| Pending product operations/callbacks                            | At most 4,096 per journal, additionally bounded by configured queue size and byte reservation                   |
| Pending control operations                                      | 256 reserved per journal; coalesce an already pending exact identity instead of allocating unbounded duplicates |
| Directory recovery batch                                        | 128 entries, never `ReadDir(-1)`                                                                                |
| Metadata index reservation                                      | 1,024 bytes per product/sequence/control entry, included in the configured memory budget                        |
| Replay payload residency                                        | One decoded record per journal feeder plus bounded delivery queues, charged before reading                      |
| X3 replay approval/export manifest                              | 16 MiB encoded and 10,000 records per file; reject the whole file if either bound is exceeded                   |
| Total transient decode reservation                              | 256 MiB per concurrently decoding owner; explicit startup memory reservation covers both journals and snapshots |

These limits also apply during offline migration/rotation and strict legacy
fixture loading. Source formats with existing tighter framing limits keep them.
A count cannot justify an oversized encoded document, and a small document cannot
justify too many decoded objects. Before reading a payload, reserve its maximum
encoded/decrypted/schema expansion and reject if the memory budget cannot cover
it. The process's declared reservation includes both journals, reorder, pending
callbacks, controls, candidates, and transient readers; it is not an RSS claim.

Managed YAML admission bounds the parser tree before constructing it. It charges
four times the encoded source length, 320 bytes per scalar, flow collection or
sequence item, and 80 bytes per mapping separator against the 256 MiB transient
ceiling. Quoted strings, comments and block-scalar bodies do not turn punctuation
into structural units. These combined resource limits can reject documents whose
individual collection counts are each below their maxima; no entries are skipped.
The canonical 65,536-filter case fits this admission rule. The lexical preflight
also limits nesting before the YAML parser allocates its tree; strict typed schema
validation follows parsing.

The filter payload schema is version 1 and contains `version` and `filters`.
The filters use every field of `internal/pkg/filtering/types.go`: `id`, `type`,
`pattern`, `revision`, `enabled`, `description`, `target_hunters`, and `radius`.
RADIUS retains MAC profile, target kind, group/task IDs, task generation, complete
scope, and each criterion's filter ID/revision/kind/value/profile/target kind.
Existing LI ownership conventions are preserved, including IDs and RADIUS task
metadata. YAML mode retains the existing top-level `filters` schema with no
envelope/version wrapper. Encrypted serialization must not manufacture deleted
RADIUS revision history that the current schema never persisted.

LI state payload schema is version 2: `version`, `written_at`, `incarnation`,
`tasks`, `destinations`, `cleanup_needed`, `generations`, `intents`, and
`revocations`, plus optional `radius_correlation_state_file`. The optional pin is
an absolute canonical UTF-8 path of at most 4,096 bytes; it is encrypted with the
snapshot. A configured override must match it. An absent pin permits non-RADIUS
operation but cannot initialize a RADIUS allocator from the new snapshot filename.
Legacy migration pins the original state path plus `.radius-correlation`, or the
explicit prior custom allocator path. Fresh initialization pins its selected
allocator path. `incarnation` must equal the envelope binding. Tasks retain every
field of `InterceptTask`, including status, activation generation, all timestamps,
RADIUS scope/profile, implicit-deactivation policy, and retained failure state.
Destinations retain DID, address, port, interface flags, protocol, description,
creation time, and delivery revision; TLS configuration and secrets are excluded.
Generation watermarks survive purging tasks and cleanup records. A retained
deactivated/failed task may legitimately reference a removed destination; an
enforcing task may not. Restored pending/active/suspended definitions are
unconfirmed until current ADMF or explicit X1 activation permits enforcement;
elapsed StartTime alone cannot confirm a restored pending definition. A restored
pending task remains queryable, but neither a timer nor a metadata-only update
confirms it. Fresh activation reserves a new generation and keeps a future start
pending; it does not create historical replay confirmation. Unchanged
non-RADIUS active/suspended generations require explicit startup confirmation
for historical replay. RADIUS candidates require fresh
activation/evidence and cannot authorize old X3.

State schema 2 preserves the legacy field names and typed representations inside
`tasks`, `destinations`, `cleanup_needed`, and `generations`; migration must not
route their 64-bit integers through floating-point decoding. UUID strings use
lowercase canonical hyphenated form. Integer tokens are decimal integers with no
fraction/exponent, decoded directly into the stated integer width. Legacy task
timestamps use UTC RFC3339Nano strings in schema 2. The explicit legacy reader
accepts valid RFC3339Nano zone offsets and normalizes the same instant to UTC,
because the old runtime used local-time timestamps. A zero Go time represents only the
existing optional start/end/activation/deactivation values. Newly introduced
control/product timestamps use the explicit time representation below. Snapshot
collections are nonnull arrays/maps, even when empty. Optional legacy fields
retain their established zero-value meaning.

`intents` is an array of objects with the following fields. Unknown fields and
unknown enum values fail; `null` is allowed only for the stated optional fields.

| Intent field                              | Type and meaning                                                                                                                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `operation_id`                            | Nonzero random UUID; stable through equivalent retries                                                                                                                                     |
| `kind`                                    | One of the exact operation names in the transition table below                                                                                                                             |
| `state_incarnation`                       | Nonzero UUID equal to the owning snapshot                                                                                                                                                  |
| `xid`, `did`                              | Subject UUID or `null`; task kinds and purge require XID only, destination kinds DID only, cleanup may name either; bounded legacy orphan cleanup may be subjectless                       |
| `previous_generation`                     | uint64; zero when no prior subject exists, for a legacy destination revision zero, or for the explicitly permitted transitions from a known non-enforcing legacy task with generation zero |
| `reserved_generation`                     | uint64; prospective task generation or destination revision; nonzero for create/activate/modify/promote                                                                                    |
| `phase`                                   | `reserved`, `revocation_committed`, `policy_committed`, or `finished`; allowed edges depend on kind, not lexical/enum order                                                                |
| `candidate_task`, `candidate_destination` | Detached complete candidate of the corresponding existing state type, or `null`; required when the operation creates/modifies/promotes that subject                                        |
| `cleanup_filter_ids`                      | Duplicate-free array of at most 256 exact strings; never raw selectors                                                                                                                     |
| `revocation_ids`                          | Duplicate-free array of at most 256 control UUIDs, linking the admin obligation to exact journal revocations                                                                               |
| `failed`                                  | Boolean persistent fault latch; a failed/uncertain operation cannot be treated as an equivalent successful retry                                                                           |

Candidate definitions are included because an operation kind and reserved
generation alone cannot recover the desired policy after a crash. Reserve both
the generation watermark and complete intent before changing persistent filters
or accepting product. Reservation never decrements a watermark, even if the
operation is subsequently abandoned. Generation/revision exhaustion fails
closed. One unfinished intent may exist per subject; conflicting mutations fail
until reconciliation resolves it. Equivalent retries use that same intent and
do not allocate another generation. Retry identity uses the existing canonical
task/destination definition, not runtime status or last-error text.

| Intent kinds                                  | Allowed successful phase path                                                                                            | Admission / failure rule                                                                                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `task_activate`, `task_reactivate`            | `reserved` → `policy_committed` → `finished`; future-start pending tasks may use `reserved` → `finished` without filters | New generation stays closed until committed final state; pending final state stays closed until promotion                                                               |
| `task_promote`                                | `reserved` → `policy_committed` → `finished`                                                                             | Reuses the already reserved pending activation generation; validates current destinations and ADMF state before opening admission                                       |
| `task_confirm`                                | `reserved` → `policy_committed` → `finished`                                                                             | Unchanged non-RADIUS ADMF startup confirmation reuses the positive persisted generation; requires exact prior activation evidence and does not reserve a new generation |
| `task_modify`                                 | `reserved` → `revocation_committed` → `policy_committed` → `finished`                                                    | Enforcement-changing modification revokes old generation permanently before publishing/releasing the new generation                                                     |
| `task_update`                                 | `reserved` → `finished`                                                                                                  | Definition change that existing `equivalentDeliveryDefinition` classifies as preserving delivery; no new generation or implicit retention extension                     |
| `task_deactivate`, `task_expire`, `task_fail` | `reserved` → `revocation_committed` → `policy_committed` → `finished`                                                    | Block old authorization before reservation I/O; policy commit removes old selectors; faults keep it blocked                                                             |
| `destination_create`                          | `reserved` → `policy_committed` → `finished`                                                                             | Policy commit persists the new endpoint/revision; do not expose it before final admin commit                                                                            |
| `destination_update`                          | `reserved` → `finished`                                                                                                  | Metadata-only update preserves the existing delivery revision and identity, including a legacy revision of zero; no revocation                                          |
| `destination_modify`, `destination_remove`    | `reserved` → `revocation_committed` → `policy_committed` → `finished`                                                    | Revoke old endpoint incarnation first; policy commit installs/removes endpoint; no old-incarnation rollback after revocation                                            |
| `cleanup`                                     | `reserved` → `policy_committed` → `finished`                                                                             | Reconcile previously recorded filter/endpoint cleanup, without enabling authorization                                                                                   |
| `purge`                                       | `reserved` → `finished`                                                                                                  | Remove only eligible retained task/tombstone data; preserve watermarks, unfinished cleanup and any journal-covered revocations                                          |

Withdrawal of a legacy pending/deactivated/failed task with generation zero
retains that zero watermark and cannot create a journal revocation control.
Active/suspended tasks and task-scoped controls require positive generations.
Modification of a known non-enforcing legacy pending task with generation zero
reserves a positive generation above the retained watermark. Its revocation boundary contains no
controls, since the old definition never authorized delivery. This exception
requires the recorded non-enforcing state; it cannot admit a zero-generation
active task or journal control.

Explicit reactivation of a retained legacy deactivated task with generation zero
likewise reserves a positive generation above its retained watermark after
identity and current destination validation (generation 1 only when that
watermark is zero). It cannot create a zero-generation revocation. An
unfinished reactivation must retain the matching non-enforcing prior definition;
finished intents remain historical evidence after later legitimate mutations.

Legacy orphan filter names may contain only an eight-character XID prefix, which
cannot identify a complete task UUID. A subjectless `cleanup` intent records a
nonempty, duplicate-free bounded list of exact recognized LI-owned filter IDs,
uses zero previous/reserved generations, and has no candidate or revocation IDs.
Its operation UUID supplies durable identity. Recovery removes only those exact
IDs idempotently; it never invents a subject UUID or broadens cleanup by prefix.
Other subjectless intents are invalid. Finished intents may retain historical
candidate definitions referring to subsequently removed destinations; unfinished
enforcing candidates and currently enforcing tasks require present destinations.

Every persisted cleanup ID must be a recognized LI-owned identifier. Task-owned
cleanup must match that task's full UUID or its recognized legacy short prefix;
neither a non-LI ID nor another task's selector is a valid reference. This rule
applies to decoded legacy documents as well as newly produced snapshots, before
any deletion occurs.

Purge applies only to retained task definitions. An unfinished purge names the
exact eligible non-enforcing task generation and cannot remove an active or newer
definition, outstanding cleanup, or retained journal controls. DID-only purge is
unsupported and rejected; endpoint withdrawal uses `destination_remove`.

Only revoking task/destination intent kinds may reference revocation controls,
and each link requires the same scope accepted by the live planning hook. A
call-scoped control cannot substitute for a task- or destination-scoped control.
An unfinished destination change retains the prior destination in its root
snapshot: its DID and numeric revision must match the intent, and each linked
control must carry that prior destination's exact delivery-identity hash. The
final snapshot replaces or removes the endpoint while marking the intent
finished. Finished historical links remain data when that old endpoint no
longer exists; they are never executed against a later incarnation. Standalone
retained controls remain typed historical data; they do not broaden an intent's
authority.

Destination removal conservatively withdraws every enforcing task that names
the removed DID, including tasks with other destinations, retaining definitions
and cleanup obligations. The bounded task-withdrawal and destination intents
are reserved together before effects; reconciliation withdraws tasks before
removing the endpoint. Metadata-only destination updates do not withdraw tasks.

Destination intent generations are numeric delivery revisions. A legacy
destination can have revision zero; modifying it reserves a strictly newer
revision. In contrast, a revocation control’s `destination_generation` is the
nonzero delivery-identity hash that binds DID, creation time, and revision. A
zero legacy revision therefore does not create an ambiguous zero-generation
revocation or authorize a recreated destination.

`revocation_committed` means all relevant journal controls and the matching
administrative revocation/obligation are durable, not merely that the first store
committed. `policy_committed` means the desired filter or endpoint transaction is
durable; it does not yet grant task admission. `finished` is committed with final
administrative state before effective admission or success acknowledgement.
Already satisfied boundaries are idempotent on retry. A partial multi-store
commit records/latches failure and resumes toward the required boundary; it is
never undone by restoring revoked authorization. Before any durable change,
definite failure may preserve the old committed candidate. Once a generation
reservation, revocation, or policy change is durable/uncertain, keep affected
admission closed until authenticated reconciliation completes or durably abandons
the candidate and its cleanup. Abandonment sets `failed` and final non-enforcing
state; it does not make the consumed generation reusable. Finished intents may
be collected only after their cleanup/control references are independently
durable and no retry can be mistaken for an unfinished operation.

`revocations` is an array of version-1 revocation objects using the exact scope
and binding described below; its control IDs match `revocation_ids`. Relevant
modification preserves the baseline distinction in
`internal/pkg/li/activation_identity.go:equivalentDeliveryDefinition`: targets,
delivery type, destination membership and RADIUS scope/profile changes revoke;
RADIUS validity-window changes also revoke. A non-RADIUS timing-only update may
preserve product but must still enforce the new current task validity and the
record's original deadline. An expired/invalid task never regains permission
because an unchanged generation was retained.

Journal payload schema version 2 uses these exact immutable metadata fields:
`version` (integer 2), `interface` (`x2` or `x3`), `journal_uuid` (UUID), `id`
(nonzero uint64), `content_sha256` (64 lowercase hex characters),
`state_incarnation` (UUID or absent for X2), `xid` (UUID), `task_generation`
(uint64), `did` (UUID), `destination_generation` (uint64), `admitted_at`,
`captured_at`, `deadline`, and `provenance`. `data` contains the original encoded
PDU bytes; the phase-5 physical layout gate chooses JSON/base64 or bounded binary
framing, without changing these logical fields or content identity. X3 requires
nonzero state/task/destination identities and generations. Unknown interfaces or
fields fail. Decode the actual encoded PDU header and require matching X2/X3 type
and XID; the outer interface label is insufficient.

Each new timestamp is an object with exactly `seconds` (signed int64 Unix seconds)
and `nanos` (uint32, 0–999,999,999). Require a representable UTC calendar instant
in years 1–9999, encode no timezone/monotonic clock component, and normalize
without changing the instant. Missing timestamps are permitted only where stated;
`null`, out-of-range values, or numeric overflow fail. X3 requires `admitted_at`,
`captured_at`, and a nonzero `deadline` strictly later than original admission,
computed exactly once using its configured positive maximum age. Capture time is
diagnostic and may differ from the admission clock; it cannot extend retention.

Provenance is a closed tagged union. All fields belonging to another variant are
rejected. The two supported `non_call.source_kind` values are `rtp` and `radius`:

| Variant                                 | Exact provenance fields and validity                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `kind: call`                            | `call_incarnation` (nonzero UUID), `call_generation` (nonzero uint64 local generation), `call_id` (nonempty string). X3 requires the exact durable call control.                                                                                                                                                                                                                                                   |
| `kind: non_call`, `source_kind: rtp`    | X3 only. `origin_node_id`, `source_id` (the capture interface), `capture_epoch` (nonzero random UUID), `observation_sequence` (nonzero uint64), `transport` (uint8 IP protocol), `source_address`, `destination_address`, `source_port`, `destination_port` (uint16), and `ssrc` (uint32). Addresses use canonical unmapped IP spelling without zones; zero transport means unknown, never inferred authorization. |
| `kind: non_call`, `source_kind: radius` | X2 only. `origin_node_id`, `source_id`, `capture_epoch`, `observation_sequence`, `operator_scope`, `profile_revision` from the validated RADIUS observation, plus `nfid`, `ipid` and `correlation_id` (uint64) from its allocator/encoded context. Epoch and sequence retain the original capture identity.                                                                                                        |
| `kind: legacy_x2`                       | X2 only. `call_id` (possibly empty) and `call_generation` (uint64, possibly zero) preserve optional legacy metadata without claiming a durable capture incarnation. This covers existing SIP X2 and migrated records whose richer provenance was never recorded.                                                                                                                                                   |

The RTP variant preserves an existing producer path: directly IP-selected RTP
in `processor_li.go` can have an empty `VoIPData.CallID`, skip `CallAdmission`,
and still encode/reorder/deliver X3. Assign its observation identity once before
fan-out/reorder and preserve it across retries and replay. The processor admission
owner issues a fresh capture epoch at startup and a monotonic sequence per
accepted observation; exhaustion fails closed. It does not invent a call or
make the epoch an authorization source. The RADIUS path in
`processor_radius_li.go` produces X2 only. Unknown source kinds and absent X3
provenance fail; an empty Call-ID alone is never converted into non-call approval.

New X2 records may omit `state_incarnation` and `deadline`; absent `provenance`
normalizes to `legacy_x2` with empty call ID and zero local generation. X2 does
not require encrypted LI state, nonzero X3 retention, or a call-control record.
Legacy zero-valued optional admission/capture metadata remains readable and is
represented as absent when migrating it. Existing X2 task-generation admission,
ADMF approval, sequence and historical post-task replay rules remain the authority;
the new envelope adds no X3-policy prerequisite to X2. Any X2 field supplied is
validated, but cannot silently grant X3 authorization. X3 never accepts
`legacy_x2`, absent state identity, or an absent deadline.

Content identity is SHA-256 of this exact binary concatenation, independent of
JSON property order or whitespace. It excludes `content_sha256` itself. All
integers are big endian; signed seconds use their 64-bit two's-complement bit
pattern. `LP(s)` means uint32 byte length followed by exact UTF-8 bytes; string
normalization is performed only where the schema explicitly requires it.
`OT(t)` means byte 0 for an absent permitted timestamp, otherwise byte 1 followed
by int64 seconds and uint32 nanos. `OU(u)` similarly means byte 0 if a UUID is
permitted absent, otherwise byte 1 followed by its 16 bytes.

```text
"lippycat/li-record/v2\x00"
uint16(interface: x2=1, x3=2), journal_uuid[16], uint64(id)
OU(state_incarnation), xid[16], uint64(task_generation)
did[16], uint64(destination_generation)
OT(admitted_at), OT(captured_at), OT(deadline)
provenance_encoding
uint64(len(original_encoded_pdu)), original_encoded_pdu
```

Provenance encoding begins with one tag byte. Tag 0 (`legacy_x2`) appends
`LP(call_id), uint64(call_generation)`. Tag 1 (`call`) appends incarnation[16],
uint64 local generation, and `LP(call_id)`. Tag 2 (`non_call/rtp`) appends
`LP(origin_node_id), LP(source_id), capture_epoch[16], uint64(observation_sequence),
uint8(transport), LP(source_address), LP(destination_address), uint16(source_port),
uint16(destination_port), uint32(ssrc)` in that order. Tag 3 (`non_call/radius`)
appends `LP(origin_node_id), LP(source_id), capture_epoch[16],
uint64(observation_sequence), LP(operator_scope), LP(profile_revision), LP(nfid),
LP(ipid), uint64(correlation_id)`. Unknown tags fail. Fan-out destination copies
have different content identities because DID, destination generation, and record
ID are part of this digest; their original encoded PDU bytes remain identical.

Sequence checkpoint schema 1 has `version`, `interface`, `xid`, `domain_id`,
`nfid`, `ipid`, `correlation_id` (uint64), and `next` (uint32). Context digest is
SHA-256 of `"lippycat/li-sequence/v1\x00"`, uint16 interface (1/2), XID[16],
`LP(domain_id), LP(nfid), LP(ipid), uint64(correlation_id)`, concatenated in that
order. The decimal interface mapping is shared with the record digest. New
sequence filenames use this digest; legacy `.seq` filename calculation remains
the original ordered JSON hash in the separate LCX2 reader. Sequence uint32 wrap
is preserved and is not an identity or generation wrap.

Call control schema version 1 contains exactly `version` (1), `journal_uuid`,
`state_incarnation`, `xid`, `task_generation`, `did`, `destination_generation`,
`call_incarnation`, `call_generation`, `call_id`, `state` (`open`,
`capture_closed`, or `revoked`), `covered_record_highwater` and
`covered_admission_highwater` (uint64), and `closed_at` (absent while open; otherwise a timestamp in the representation
above). All identities/generations are nonzero and the composite object binding
must match. Both `open` → `capture_closed` → `revoked` and `open` → `revoked` are
allowed; no transition reopens capture. One control can cover multiple records
with that exact task/destination/call provenance.

Revocation schema version 1 contains `version` (1), `control_id` (nonzero UUID),
`journal_uuid`, `state_incarnation`, `scope` (`task`, `destination`, or `call`),
`xid`, `task_generation`, `did`, `destination_generation`, `call_incarnation`,
`call_generation`, `covered_record_highwater`, `covered_admission_highwater`
(uint64, covering pending operations), and `revoked_at` (timestamp). Task scope
requires XID/task generation; destination scope requires DID/destination
generation; call scope requires all identities/generations. Nonapplicable UUIDs
and generations must be JSON `null`, not wildcard strings, zero UUIDs, or a
fallback Call-ID. State incarnation and journal UUID are always required. The
administrative snapshot uses one record per affected journal, retaining the
same control ID used by that journal's object binding. Reserve its capacity
before accepting covered product.
On process loss, a recovered `open` call becomes historical/capture-closed; it is
never reconstructed as a live admission. Missing/invalid controls fault recovery.
Garbage collection may remove controls only when no covered product, pending
write/callback, completion obligation, or retained replay approval can revive it;
sequence highwaters are not garbage-collected with products.

X3 approval schema version 2 is `{"version":2,"records":[...]}`. Each record
contains every immutable metadata field of the version-2 journal record above,
except `version` (owned by the manifest), and excludes only the PDU `data` field.
Interface must be `x3`; metadata and content digest must exactly match the journal.
Reject duplicate `(journal_uuid,id)` entries before building approval indexes.
Apply both the 16 MiB and 10,000-record limit while decoding; export stops at the
smaller complete FIFO prefix that fits both limits and reports continuation.
Existing X2 manifest version 1 retains its separate 4 MiB/10,000-record format
and policies. Strict private manifests
are explicit exports, not implicitly encrypted stores or authorization sources.
Admission and transport claim recheck current ADMF confirmation, active X3
permission, exact destination membership, no revocation, and unexpired deadline.
Unapproved heads retain FIFO order for each destination/interface until approval
or a recorded terminal expiry/revocation/purge. A completion marker grants no
authorization. Re-encoding on replay is prohibited.

## Legacy dispatch and migration

Runtime managed filters select their format from configuration alone. Runtime
state uses encrypted state only. Offline tools require an explicit source format.
Legacy X2 `.x2`, `.seq`, and `.state` use the existing `LCX2` version 1 decoder and
original raw-key semantics. LCS1 input uses the purpose/key-ID dispatcher above;
no failed decode or key lookup tries another format. Unknown magic/version fails.
An unchanged key-file-only X2 configuration retains legacy readability; after
changing the active key, exactly one explicit legacy read-key mapping identifies
the key for LCX2, whose header has no key ID. Ambiguous legacy mappings fail.

The compatibility fixtures must include an X2 product, sequence, and state triple
with fixed original bytes/sequence; full YAML including disabled/scoped/revised
RADIUS compound filters; and legacy LI JSON with active, pending, retained,
removed-destination, cleanup, and watermark cases. New tests preserve fixture
bytes and test legacy dispatch independently of LCS1 seal/open. Migration validates
the complete source, preserves identities/watermarks, and creates only encrypted
temporary output. It does not activate tasks, apply filters, or send product.

Offline initialization is exclusive/no-clobber. In-place rewrite is a separate
explicit mode. Source/destination locks are held together in stable order; a
durable encrypted progress manifest identifies exact source identity, target key,
and committed rewrite boundary. Resume verifies the manifest and every already
rewritten object's identity. Original source remains usable after definite failure.
After an uncertain replacement, restart authenticates both current object and
rewrite state; it does not guess that the source or destination won. No automatic
plaintext backup is created. The RADIUS allocator sidecar is preserved unchanged
and remains independently validated; resetting it is not a migration strategy.
The encrypted state pins the pre-migration allocator path so changing the
administrative snapshot path cannot silently allocate a fresh counter sidecar.

## Filter-mode matrix

Runtime LI enablement is authoritative in both CLI resolution and the processor
core, regardless of compilation tags. Default mode is `auto`. Explicitly empty
key/path options obey the normal CLI > environment > YAML > default precedence;
a supplied key never selects a mode. `--filter-file` remains the path override.

| Runtime LI                          | Requested mode | Effective mode                 | Default basename | Key requirement                              |
| ----------------------------------- | -------------- | ------------------------------ | ---------------- | -------------------------------------------- |
| Off, including an LI-capable binary | `auto`         | YAML                           | `filters.yaml`   | All key options rejected                     |
| Off                                 | `yaml`         | YAML                           | `filters.yaml`   | All key options rejected                     |
| Off                                 | `encrypted`    | Encrypted                      | `filters.enc`    | Active key/ID and initialized store required |
| On                                  | `auto`         | Encrypted                      | `filters.enc`    | Active key/ID and initialized store required |
| On                                  | `encrypted`    | Encrypted                      | `filters.enc`    | Active key/ID and initialized store required |
| On                                  | `yaml`         | Error before LI initialization | None             | A key cannot make this valid                 |

Default basenames live in `~/.config/lippycat/`. A custom explicitly selected path
is authoritative and is not checked for competing defaults, but its bytes must
match the resolved format. Without an explicit path, apply this matrix:

| Existing default files | YAML selected                                  | Encrypted selected                      |
| ---------------------- | ---------------------------------------------- | --------------------------------------- |
| Neither                | Empty first-run store; write on first mutation | Error; explicit initialization required |
| Only `filters.yaml`    | Strict YAML load                               | Error; explicit migration required      |
| Only `filters.enc`     | Error; select mode/path explicitly             | Authenticate and strictly load          |
| Both                   | Error; select path explicitly                  | Error; select path explicitly           |

For either selected path, unreadable, insecure, malformed, locked, or opposite-format
content is an error; never fall back to empty or another format. Missing custom
YAML starts empty. Missing custom encrypted content is an error. Resolving `auto`
after enabling LI must never overwrite an existing YAML file with encrypted data
or encrypted data with YAML. Stop-edit-restart remains the YAML editing workflow;
there is no watcher. During operation use management RPCs or a separate
`lc set filter --file` import. Direct live file edits are unsupported and can be
overwritten by the next management mutation.

## Files, ownership, and commit outcomes

Validate every opened component through its descriptor and retain directory
descriptors during replacement. Reject symlinks, nonregular data/key/lock files,
multiple hard links, unexpected owners, and insecure permission bits. Ancestors
may be owned by root or the effective UID and must not be writable by group or
other users. The sole writable-ancestor exception is the literal `/tmp` directory
when root-owned and sticky; descriptor walking still rejects every symlink and
validates all descendants. This permits private test and explicitly chosen
temporary roots without accepting arbitrary world-writable ancestors. The final
store directory is always effective-UID-owned, has owner rwx, at most group
read/execute, no other access, and no special mode bits (0700/0750 are typical;
0710/0740 are also private under this rule). `/tmp` itself cannot be the store
directory. Data, key, usage, and lock files must have exactly mode 0600 or 0400
with effective-UID ownership. Standard root-owned `/`, `/var`, `/var/lib`, and
`/etc` ancestors remain valid. This ancestor exception is a path-safety rule;
it does not qualify a temporary filesystem as durable production storage.

Keep a stable `.lock`/sidecar lock for the store lifetime, including runtime,
migration, and rotation. Locking the replaceable data inode alone is insufficient.
Canonical descriptor identity (device/inode plus basename for not-yet-created
files), hard-link rejection, and all-component symlink rejection prevent aliases
from bypassing ownership. For multiple stores lock in ascending canonical
descriptor identity/name order. Reject conflicting snapshots, journal directories,
keys, manifests, controls, temporary paths, usage ledgers, and RADIUS sidecar paths
before initialization can alter any of them.

Durable replacement writes an exclusive unpredictable temporary file in the
same validated private directory, handles short writes, syncs the complete file,
closes it, renames it, then syncs the directory. Encrypt before opening temporary
output for encrypted stores. YAML mode intentionally writes private plaintext.
Return a typed outcome independently of the primary/cleanup error:

| Outcome                  | Boundary                                                                                                             | Owner obligation                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Definitely not committed | Validation/encryption/create/write/file-sync/close or failed rename before replacement                               | Preserve previously published state; return failure; release candidate reservations correctly               |
| Commit uncertain         | Rename succeeded but directory sync did not establish durability, or replacement result itself cannot be established | Block affected mutations/admission/claims; do not restore old authorization; reconcile/restart before reuse |
| Committed                | Replacement and directory sync succeeded                                                                             | Publish committed candidate once, even if later cleanup/handle-close reports a separate error               |

Cleanup failure is joined/reported without replacing the primary error or turning
a committed replacement into a rollback. The same rule applies to durable delete:
after successful unlink, failed directory sync is uncertain. A typed error must
remain discoverable through wrapping. An uncertain usage-ledger reservation
blocks encryption before a nonce is generated from that reservation.

| Entry point                                                              | Required treatment                                                                                                                                                                                   |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Filter manager `Update`, `Delete`, `Save`                                | Stage a detached complete candidate; publish revision/maps/subscriber update only after committed save; definite failure changes nothing; uncertainty latches manager fault                          |
| Direct and processor-scoped filter RPCs                                  | One processor mutation path, same durable semantics; not-found, definite failure, uncertainty, and post-commit distribution failure remain distinct                                                  |
| LI `FilterPusher`                                                        | Uses that same path; failure must stop task activation; never apply local targets after manager failure                                                                                              |
| Local tap target application                                             | Validate before commit where possible; post-commit apply failure keeps desired policy, gates affected processing, and returns reconciliation fault                                                   |
| `ActivateTask`, `ModifyTask`, pending promotion                          | Durably reserve generation/intent, reconcile filters, persist final state, then open admission; any unresolved failure prevents effective activation                                                 |
| `DeactivateTask`, `MarkTaskFailed`, task expiry/reconciliation           | Close authorization first; persist journal revocation and admin obligations before durable acknowledgement; failure never restores authorization                                                     |
| `CreateDestination`, `ModifyDestination`, `RemoveDestination`, ADMF sync | Serialize with task/state snapshots; definite pre-commit failure may retain old candidate; uncertainty gates delivery rather than restoring old destination                                          |
| X1 wrappers                                                              | Return failure/uncertainty through the request boundary; a void callback cannot stand in for a durable revocation hook                                                                               |
| Background expiry, promotion, cleanup, purge                             | Latch affected scope fault and expose it in status; logging alone is insufficient; retain watermarks and cleanup obligations                                                                         |
| Journal asynchronous persist callback                                    | Exactly once; success only after product, necessary control, and sequence durability; uncertainty never makes transport claimable                                                                    |
| Startup/restore                                                          | Validate entire detached snapshot and stores first; no policy side effects from partial decode; close all handles/locks on failure                                                                   |
| Shutdown                                                                 | Stop capture, drain bounded accepted reorder with authorization available, resolve pending persistence, retain durable backlog, then release journals and locks; expose unresolved durability faults |

Filters, administrative state, and journals remain separate transactions. A
successful first commit followed by a failed second commit is a recoverable
partial operation, not an atomic rollback. Durable intent/cleanup and admission
gates resolve that state. Startup order is mode resolution; all locks, file/key
validation and authentication; watermarks/revocations/intents; LI filter and ADMF
reconciliation; sequence restoration; then live admission and explicitly approved
replay. X1 transport availability alone does not open capture/delivery.

## Synchronization and call lifecycle

Long-lived ownership locks are acquired before in-process work starts. A single
administrative transaction ordering boundary covers task and destination changes
and complete state snapshots; the existing separate `lifecycleMu`, `destinationMu`,
and `persistenceMu` must not permit a snapshot of another operation's provisional
registry state. The order is administrative transaction, task admission/lifecycle,
destination mutation, filter mutation ordering, then a store's persistence worker.
If an operation needs only a suffix it may take that suffix; it must not call
back into a preceding boundary while holding it. Filter mutation ordering can
cover disk I/O, but the filter map/subscriber mutex cannot. Publish and snapshot
subscription ordering are established by that mutation sequence.

Call and journal/queue locks are short critical sections rather than another
nested extension of that chain. Under a call-registry lock, close admission and
capture the exact incarnation/reference drain; release the lock before waiting
for references or invoking subscribers. Under reorder locks, disarm timers,
detach the exact call batch, and reserve its position in the callback chain;
release locks before waiting/invoking delivery. Under journal-control ordering,
mark the affected identity blocked before enqueueing a durable control request.
Workers do not reacquire the administrative transaction lock. Their completions
check the current blocked generation before publishing an eligible record.

Queue-map locks may precede a queue mutex for short ownership updates. No queue
mutex, index mutex, registry mutex, or reorder mutex may be held during disk I/O,
external callbacks, transport writes, or waits on another worker. Detach cancel
functions/callback batches under the lock and invoke them after unlock. A journal
worker must not wait for a delivery callback which itself waits for that worker.
Revocation may wait for its durable worker result under the administrative
transaction boundary because the worker cannot enter that boundary.

An ordinary `CallAdmission` reference is released after successful reorder
insertion and before its callback chain runs. Finalization waits for those
references before subscribers, so retaining one until finalization drain would
deadlock. Instead, successful pre-close insertion issues a bounded, one-use,
exact-product backlog permit bound to state/task/destination/call incarnation and
content identity. It authorizes only movement of that already accepted entry
through drain; it cannot capture another packet or survive revocation/expiry.
Call incarnations are random UUIDs distinct from monotonically increasing local
generations and must never be inferred from reused Call-IDs.

The following audit covers non-test production callers in the baseline, including
exported convenience methods with no external production callers. `manual` is
writer cleanup, not explicit LI authorization withdrawal.

| Production locus / trigger                                                                                                                                                               | Baseline reason / behavior                                                                                                                                                | Persistent-X3 behavior                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `CallCompletionMonitor.checkEndedCalls` and `processPendingClose`                                                                                                                        | ENDED, FAILED after retry deadline, CANCELLED, BUSY all schedule `protocol_complete`; preserves attempt-version checks and RTP/grace wait                                 | Close capture, drain accepted reorder, preserve admitted delivery; SIP CANCEL/failure is not task revocation                                |
| `CallCompletionMonitor.ScheduleClose`                                                                                                                                                    | Wrapper uses `protocol_complete`; no external non-test caller in baseline                                                                                                 | Same normal completion policy                                                                                                               |
| `SessionOutputManager.OnCallEnded` → `ScheduleCloseReason`                                                                                                                               | Registry `EndCompleted` maps to `protocol_complete`; `EndTimeout` to `idle_timeout`; `EndEvicted` to `capacity_eviction`; `EndShutdown` is skipped                        | All first three close capture and drain; registry output cleanup never revokes LI                                                           |
| `Processor.SetPacketSource` → `voip/processor.SourceAdapter.SetCompletionHandler`                                                                                                        | Wires the local/tap VoIP producer directly to `SessionOutputManager.OnCallEnded`, in addition to registry observation                                                     | This direct completion path must carry the same capture-incarnation and durable-closure contract as monitor/observer finalization           |
| `voip/processor.Processor.cleanupExpiredCalls`                                                                                                                                           | Emits `EndTimeout` through the completion handler, or directly removes from the registry without a handler                                                                | Normal capture closure/drain, not authorization revocation                                                                                  |
| `voip/processor.Processor.getOrCreateCall` → `evictOldestCallLocked`                                                                                                                     | Emits `EndEvicted` through the completion handler, or directly removes from registry; pending completion prevents repeated eviction                                       | Capacity closure/drain retains admitted product                                                                                             |
| `voip/processor.Processor.CompleteCall`, called by `detectSIPWithCompletion` terminal detection, `processorSIPRegistry.Complete`, and `TapTCPHandler.handleSIPMessage` terminal callback | Emits `EndCompleted` through the completion handler or direct registry removal; terminal TCP callback runs after accepted packet dispatch, including sink-failure cleanup | SIP/TCP protocol completion closes only the exact capture incarnation and preserves eligible accepted content                               |
| `voip/processor.Processor.FinalizeCallCleanup` → `removeCall`, called by the monitor's VoIP port-cleaner subscriber                                                                      | Replays the saved timeout/eviction/completion reason after lifecycle finalization; defaults to `EndCompleted`                                                             | Idempotent attribution cleanup; must not become a second LI revocation or reopen capture                                                    |
| `callregistry.Core.UpsertWithEviction` capacity removal, `Remove`, `CompleteCall`, `Clear`, `Close`                                                                                      | Eviction emits `EndEvicted`; explicit complete/clear emit `EndCompleted`; callers may supply timeout to `Remove`; `Close` emits `EndShutdown`                             | Resource eviction or clear retains accepted product; shutdown uses its dedicated drain path                                                 |
| Separate `voip.CallTracker.detachCallLocked` and `voip.SessionOutputManager.OnCallEnded`                                                                                                 | Legacy/sniff call tracker removes registry attribution with `EndCompleted` and closes its own output through a different observer interface                               | Output cleanup has no independent LI cancellation authority; any shared registry observer receives the normal completion classification     |
| `PcapWriterManager.sweepIdleExcept` → `finalizeCallIfIdle` → `finalizeCallGeneration`                                                                                                    | `idle_timeout`, generation checked after writer idle check; monitor excludes retained calls                                                                               | Drain exact incarnation, retain eligible durable product                                                                                    |
| `CallPcapWriter.Close`, `PcapWriterManager.CloseWriter`                                                                                                                                  | `manual`; writer close uses its exact generation, manager convenience method closes current generation; no external production callers in baseline                        | Close output/capture, drain accepted product; never interpret as explicit cancellation                                                      |
| `CallPcapWriter.CloseCall`, `PcapWriterManager.CloseCallWriter`                                                                                                                          | `protocol_complete`; no external production callers in baseline                                                                                                           | Normal completion policy                                                                                                                    |
| `PcapWriterManager.FinalizeCall`, `CallLifecycleRegistry.Finalize` / `FinalizeGeneration`                                                                                                | Shared once-only transition; callbacks after ordinary admission references drain; shutdown reason ignored by registry                                                     | Preserve once-only semantics, include incarnation and fault-returning durable closure/revocation boundary                                   |
| `SessionOutputManager.Close`, `CallLifecycleRegistry.ShutdownAndWait`, `PcapWriterManager.Close`                                                                                         | Shutdown excludes new writes, drains references, directly closes writers with `shutdown`; no finalization event/tombstone                                                 | Explicit shutdown drain for every accepted incarnation; do not rely on a finalization subscriber that never runs                            |
| `Processor.Shutdown` → `stopLIManager`                                                                                                                                                   | Currently stops LI before session output; `stopLIManager` stops manager before reorder flush                                                                              | Reorder/capture drain must move before stopping authorization infrastructure; retain durable unsent records                                 |
| `processor_li.go` call-lifecycle subscriber                                                                                                                                              | Currently `CancelCall` then `DiscardCall` for every finalization reason; clears media direction and pinned calls                                                          | Mode branch: persistent mode drains/closes, memory-only mode retains cancellation/discard; both clear direction and pinned state            |
| LI deactivation callback and `SetTaskModifiedCallback`                                                                                                                                   | Currently `CancelTask`, discard matching buffers, clear inherited state and sequence state                                                                                | Genuine authorization revocation, with exact generation control durability; do not clear durable X3 sequence continuity                     |
| Destination replacement/removal callback                                                                                                                                                 | Current transport update/removal invalidates destination delivery generation                                                                                              | Durably revoke the old exact endpoint incarnation and its backlog before acknowledging boundary                                             |
| Explicit delivery `Client.CancelCall`                                                                                                                                                    | Currently Call-ID + numeric generation memory suppression                                                                                                                 | Separate explicit LI revocation API binds call incarnation and returns definite/uncertain result; never invoked for ordinary writer cleanup |

Memory-only X3 retains its existing call-end cancellation, optional zero maximum
age, queue limits, and shutdown volatile-loss accounting. Persistent X3 drains
only accepted content; task withdrawal/expiry/failure, relevant modification,
destination replacement/removal, and explicit LI cancellation dominate concurrent
drain and revoke pending, held, queued, and claimed ownership. Revocation cannot
undo bytes already written to the transport; report partial/uncertain transport
separately from persistence uncertainty. Post-call eligibility is not permission
to attach late packets or a new call with the same Call-ID.

## Fault and process-death matrix

Run deterministic I/O faults and child-process death at each applicable boundary,
for filters/state, X2/X3 product, sequence, control, usage, and rotation artifacts.
Every restart must reacquire ownership and authenticate state before effects.

| Injected point                                                                 | Required live outcome                                                                    | Required restart evidence                                                                     |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Invalid key/header/purpose/binding/schema/size                                 | Reject without policy mutation or plaintext error                                        | Same rejection; no empty-store fallback                                                       |
| Ownership/path/lock failure                                                    | No reader/writer admitted                                                                | Competitor never writes; failed construction releases handles                                 |
| Before usage reservation sync                                                  | No seal under uncommitted reservation                                                    | Old highwater retained; no undercounted seal                                                  |
| After reservation sync, before nonce generation                                | Reservation may be wasted                                                                | Entire reserved range treated consumed                                                        |
| Short write / ENOSPC / file sync / close failure before rename                 | Definitely not committed                                                                 | Old snapshot/product boundary intact; only recognized encrypted temporary artifacts removable |
| Rename failure before replacement                                              | Definitely not committed                                                                 | Original authoritative object unchanged                                                       |
| After rename, before/failed directory sync                                     | Commit uncertain; latch fault                                                            | Authenticate installed object/intent; never blindly rollback or report success                |
| Directory sync success, cleanup/handle-close failure                           | Committed, with cleanup error                                                            | New object authoritative; no duplicate policy publication                                     |
| Generation reservation committed, filter commit fails                          | Task admission closed; recoverable intent                                                | Reserved generation cannot be reused; cleanup/retry remains blocked until resolved            |
| Filter commit succeeds, final admin save fails                                 | Keep committed desired filter state; gate affected enforcement                           | Resume intent and reconcile selector cleanup; uncommitted task never becomes active           |
| Admin revocation succeeds, journal control fails, or inverse                   | Authorization blocked; failure/uncertainty reaches caller                                | Complete missing revocation boundary before delivery; old approvals grant nothing             |
| Pending product callback races revocation                                      | Callback cannot resurrect eligibility                                                    | Covered pending highwater remains revoked even if product reached disk later                  |
| Call control creation/closure failure                                          | Product cannot become claimable without required control                                 | Missing/invalid control faults, never inferred permission                                     |
| Product durable, sequence update incomplete                                    | No successful persistence acknowledgement/claim until required checkpoint is durable     | Derive/check sequence from product or halt; never reuse an emitted sequence context           |
| Transport write partially succeeds / process dies before completion checkpoint | Transport uncertainty; possible duplicate after restart                                  | Original bytes/sequence retained; approved replay may duplicate, never re-encode              |
| Completion unlink succeeds, directory sync fails                               | Completion uncertain; preserve sequence highwater                                        | May recover product as held; no exactly-once claim                                            |
| Full data spool during revocation/expiry/shutdown                              | Reserved control capacity remains usable                                                 | No revoked product becomes eligible; control reserve/accounting survives restart              |
| Expiry with MDF disconnected or records unapproved                             | Independent bounded sweeper expires by original deadline                                 | Expired records excluded before approval/claim; no timestamp refresh                          |
| Crash while normal call drain or shutdown is in progress                       | Volatile losses distinguished from durable retained content                              | Open incarnation becomes historical; new capture cannot attach                                |
| Interrupted rotation/compaction or insufficient workspace                      | Stop at recorded durable boundary; do not consume data/control reserve                   | Mixed key objects read by exact IDs; resume is idempotent and preserves deadlines/identity    |
| Unrelated state UUID / replaced destination / reused XID/Call-ID               | Reject old product regardless of matching numeric generation                             | Zero unauthorized replay, including with a previously valid approval                          |
| Coherent backup restore                                                        | Require current ADMF reconciliation and fresh write key if counters may have rolled back | No claim of trusted rollback detection; RADIUS allocator is not reset                         |

## Performance observations and requirement provenance

This plan has no user-established numeric performance acceptance thresholds.
The earlier agent-selected latency, throughput, recovery, CPU and RSS gates have
been withdrawn at the user's request. They do not constrain layout selection,
implementation completion, or progression to another phase.

Benchmarks are observations of their actual workload and environment. Preserve
measured callback/admission latency, throughput, backlog, recovery, allocated
blocks and resource use in the measurement report, including shared-host activity
and harness limitations. A synthetic workload is not a supported-load promise.
Additional benchmarking or optimization is optional work requested for an actual
deployment objective; it is not an outstanding qualification campaign.

A future blocking performance requirement needs a traceable source: explicit user
acceptance, an applicable external specification, or an established project gate
predating the task. Identify its workload and environment. Agent-written plans,
commits and labels such as "frozen" are not that source.

Correctness and resource safety remain required: persistence acknowledgements
follow definite durable writes; revoked or expired products cannot become
claimable; pending/index/control/recovery allocations stay within configured
budgets; X3 cannot borrow X2 capacity; controls remain possible at full data
capacity. Account allocated blocks and reserve terminal-control and rewrite space
before admission or rewriting. Preserve the enforced cryptographic usage bounds
and strict bounded readers.

The implemented segment/batch protocol and its concrete size/accounting limits
are described in [the production journal contract](li-x3-journal-layout.md).
Authenticated selected data must recover exactly or fault; only uncommitted tail
data may be discarded. These are correctness requirements, independent of timing.
