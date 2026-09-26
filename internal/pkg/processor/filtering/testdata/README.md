# Legacy managed-filter fixture

`legacy_filters.yaml` is a hand-authored, synthetic fixture of the editable YAML
schema at `77f7abfe`. It is the canonical source; copying this checked-in text
reproduces it without a production serializer. All domains use `.invalid`, IP
selectors use documentation space, and numeric identities are synthetic.

The file covers all 22 legacy filter types, canonical and protobuf enum-name
spelling, enabled/disabled filters, absent optional values, descriptions, target
hunters and revisions. RADIUS examples include username, MAC with an explicit
profile, scoped line AVP, and a compound conjunction with task ownership, task
generation, complete scope and per-criterion revisions.

`TestYAMLPersistenceLegacyFixture` checks that every record is loaded, selector
text survives, the compound structure is exact and subsequent YAML save/reload
preserves the protobuf representation. The generic SIP entry deliberately has
revision 17; legacy entries without a revision remain zero.

Known baseline parser limitations must not become migration behavior:

- `ParseFileWithErrors` reports and skips invalid non-RADIUS filters; the managed
  wrapper logs those errors and still accepts the remaining subset.
- Duplicate IDs overwrite earlier entries in the map.
- Unknown non-RADIUS fields and top-level fields are not rejected by the current
  YAML decoder. RADIUS mappings already reject unknown fields.
- Readers do not impose file-size or collection-count bounds before decoding.

Strict startup and migration must reject an invalid entire snapshot instead of
silently accepting a subset. The valid fixture's completeness assertions are
intentional and must remain; no permissive malformed-input behavior is frozen by
these tests.
