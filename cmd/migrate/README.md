# Offline store migration

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
`--in-place`; other existing destinations are refused. These commands do not
perform encrypted-key rotation.

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
