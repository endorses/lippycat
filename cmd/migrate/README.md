# Offline store migration and key rotation

Stop the owning processor or tap before using these commands. Provision the
destination directory with mode 0700 or 0750. Snapshot and key files must be
private regular files (0600, or 0400 for read-only input). Keys contain exactly
32 raw bytes; options contain key references, never key bytes.

Initialize an empty encrypted filter store, or explicitly convert existing YAML:

```bash
lc migrate filter-store --init --destination /var/lib/lippycat/filters.enc \
  --key-id filters-1 --key-file /etc/lippycat/filters.key

lc migrate filter-store --source-format yaml \
  --source /var/lib/lippycat/filters.yaml --destination /var/lib/lippycat/filters.enc \
  --key-id filters-1 --key-file /etc/lippycat/filters.key
```

LI builds additionally provide `li-state` for legacy version-1 administrative JSON:

```bash
lc migrate li-state --init --destination /var/lib/lippycat/li-state.enc \
  --key-id state-1 --key-file /etc/lippycat/li-state.key

lc migrate li-state --source-format json \
  --source /var/lib/lippycat/li-state.json --destination /var/lib/lippycat/li-state.enc \
  --key-id state-1 --key-file /etc/lippycat/li-state.key
```

Migration validates the complete source and preserves task status, identities,
generation watermarks, cleanup obligations, destination revisions, and timestamp
instants. It never activates tasks or sends interception product. Changed-path
migration retains the original source. Replacing the same path requires
`--in-place`; other existing destinations are refused.

LI state migration pins the RADIUS correlation allocator at the canonical
absolute source path plus `.radius-correlation`. Empty initialization pins the
destination path plus that suffix. If the node used a custom allocator, supply
`--radius-state-file=/existing/allocator`. The allocator's bytes and inode are
retained; changing the administrative snapshot path must not reset its watermark.

After an interruption, preserve all snapshot, `.usage-*`, `.state-*`, and
`.filter-*` files. Repeat the identical command with `--resume`, including its
original source, destination, active key, and any RADIUS override. Resume verifies
the authenticated operation and source content; it does not recreate a usage
ledger after encryption has been enabled. A reported uncertain commit requires
the node to stay stopped until this reconciliation succeeds.

Each command accepts up to four `--read-key=id=path` references, with unique IDs
and distinct key material. Filter and LI-state stores require independent keys.

## Rotate an encrypted snapshot

On Linux, explicitly select `--source-format=encrypted` and supply the current
source active key separately from a newly provisioned output key:

```bash
lc migrate filter-store --source-format encrypted \
  --source /var/lib/lippycat/filters.enc \
  --destination /var/lib/lippycat/filters.enc --in-place \
  --source-key-id filters-1 --source-key-file /etc/lippycat/filters-1.key \
  --key-id filters-2 --key-file /etc/lippycat/filters-2.key

lc migrate li-state --source-format encrypted \
  --source /var/lib/lippycat/state.enc \
  --destination /var/lib/lippycat/state-next.enc \
  --source-key-id state-1 --source-key-file /etc/lippycat/state-1.key \
  --key-id state-2 --key-file /etc/lippycat/state-2.key
```

Source and destination must share the same descriptor-identified private parent
directory. A changed basename retains the original source; an occupied distinct
destination is refused. `--read-key=id=path` supplies prior **source** keys during
rotation. The new active key must differ in ID and material from every supplied
source key, and its usage ledger must be absent for a fresh operation. Renaming
an old key does not make it fresh. Exact authenticated resume is the only
exception to the absent-new-ledger rule.

Rotation validates the entire authenticated payload and preserves its exact
bytes and store UUID. LI state retains all generations, obligations, deadlines
and its optional RADIUS allocator pin, including an absent pin. Rotation rejects
`--radius-state-file`; it neither moves nor initializes that allocator. The
source-key options and `--max-working-bytes` are rejected for plaintext migration
and empty initialization.

Each attempt physically reserves all remaining stage files before sealing or
publishing new records. `--max-working-bytes` defaults to 134217728 (128 MiB),
including retained operation files and locks; pre-existing source and historical
usage allocation are reported separately. Unsupported allocation/publication
primitives fail. A partial attempt is not a reusable space guarantee: explicit
resume must reserve its complete remaining workspace again, while all previously
reserved encryption usage stays consumed.

Keep the node stopped after interruption and retain `.rotation-*`,
`.securestore-stage-*`, `.usage-*`, initialization/migration sidecars and all
required keys. Repeat the identical rotation command with `--resume`. A visible
new snapshot does not prove that its directory sync succeeded. The command can
report a **committed** snapshot together with a completion/cleanup error and
`resume required: true`; that output must not be treated as a rollback.

After successful completion, update runtime snapshot/key references explicitly
before restarting. The command reports bounded allocation and key-dependency
categories, including unknown artifacts and incomplete inventory. External
backups are outside that inventory. Rotation does not delete keys or historical
usage ledgers, declare a key safe to destroy, rotate journals, or edit runtime
configuration. Keep prior material until all remaining dependencies and required
backups have been accounted for.

## Rewrite or rotate an LI journal

LI builds provide `lc migrate li-journal`. Stop the owning node and explicitly
select `--interface=x2|x3` and `--source-format=lcx2|per-record|segments`. The
selected format must match the source; X3 uses `segments`. This command does not
initialize an empty store, activate tasks, approve replay, or send product.

```bash
lc migrate li-journal --interface x3 --source-format segments \
  --source /var/lib/lippycat/x3 --destination /var/lib/lippycat/x3-next \
  --source-key-id x3-1 --source-key-file /etc/lippycat/x3-1.key \
  --key-id x3-2 --key-file /etc/lippycat/x3-2.key \
  --max-bytes 4294967296 --max-working-bytes 1073741824
```

`--read-key=id=path` refers only to prior source keys. The destination key is
fresh and independent from every source key. For LCX2, additionally select the
legacy source key using `--source-legacy-key-id`. An LCX2 source without provable
allocation highwaters for deleted records is rejected; current surviving IDs
cannot prove that continued allocation would be safe.

The destination budget `--max-bytes` is required and includes fixed journal
reservations. `--max-working-bytes` defaults to 1 GiB and bounds allocated rewrite
workspace. Provide sufficient space for retained source artifacts, destination
records, controls, sequences, usage history and interrupted work. Insufficient
capacity fails before publication rather than shortening retention or skipping
records. Source and destination ownership locks exclude runtime use.

An occupied different destination is refused. Replacing the source directory
requires explicit `--in-place`. The rewrite preserves journal and state
incarnations, record and admission highwaters, original encoded bytes and sequence
numbers, absolute deadlines, exact call identities, closures and revocations.
It does not refresh retention or turn held records into approved records.

After interruption, keep the node stopped and retain the source, destination,
operation records, usage ledgers, temporary encrypted objects and required keys.
Repeat the identical command with `--resume`. A visible destination alone is not
proof of committed publication; a committed result with a completion error still
requires resume. After successful completion, update the node's explicit spool
path and key references before restarting. Retained source artifacts are recovery
and key-inventory dependencies, not a second journal to resume writing.

Changed-path publication retires the source under its ownership lock before the
new runtime catalog becomes available. In-place rotation retains the prior
authenticated catalog as lineage evidence. Subsequent rotations can use a third
fresh key after runtime activity; retain the prior keys and operation artifacts
until the inventory is resolved. A completed old operation cannot be resumed over
a catalog that has subsequently advanced during runtime.

Review the bounded output inventory before retiring old keys. Unknown objects,
external backups and historical usage records must be accounted for separately.
The command never removes keys or promises physical erasure of old ciphertext.
