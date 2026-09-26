# LCX2 v1 compatibility fixtures

These are public, synthetic fixtures for the storage schema at commit `77f7abfe`.
They contain no captured traffic, real selector, or operational encryption key.
`fixture.key` is exactly the 32 raw bytes `00 01 ... 1f`; it is not hex text.
Never use this key or this generator's deterministic nonce strategy in deployment.

The independent, standard-library-only `generate.go` freezes the old codec rather
than calling the current production writer. It emits the five-byte `LCX2\x01`
authenticated header, a 12-byte nonce, AES-256-GCM ciphertext/tag over the original
`JournalRecord` JSON schema, and a big-endian IEEE CRC32 over everything preceding
the checksum. Nonces end in `01`, `02`, and `03`, respectively. The separate object
directory intentionally contains only files accepted by journal recovery.

| Object                                                                         | Meaning                                                                                                                 |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `objects/00000000000000000007.x2`                                              | Record 7, original encoded X2 BYE, sequence 41, task generation 3, destination revision 5, call generation 9            |
| `objects/21140b0bbf82c1274cd208bf63e2ade1f5c935e5d5aeb2db6fa22385f8e7feb8.seq` | Next sequence 42 for X2/XID/domain/NFID/IPID/correlation tuple; filename is SHA256 of the original ordered context JSON |
| `objects/.state`                                                               | ID watermark 11, deliberately greater than the surviving product ID                                                     |
| `product.hex`                                                                  | Exact unencrypted synthetic PDU bytes used to verify immutable recovery                                                 |

The fixed identities are XID `11111111-1111-4111-8111-111111111111`, DID
`22222222-2222-4222-8222-222222222222`, Call-ID
`synthetic-call@example.invalid`, and correlation ID 23. Admission is
`2026-01-02T03:04:05.006Z`; capture is `2026-01-02T03:04:04.005Z`.

From the repository root, reproduce into a disposable directory and compare
against the checked-in files:

```bash
GOCACHE=/tmp/li-encryption-fixtures-cache go run internal/pkg/li/delivery/testdata/legacy_lcx2_v1/generate.go -out /tmp/li-legacy-fixtures
diff -r -x generate.go -x README.md internal/pkg/li/delivery/testdata/legacy_lcx2_v1 /tmp/li-legacy-fixtures
```

Remove the disposable output and cache after use. Generator SHA256 output is:

```text
630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd  fixture.key
c10b220a04338c2cf151492922b9f02c62e84f1e431b0bda5e5b4d98406c9ee9  product.hex
3775df021d6cbb9dcfa8b8477267affb4e56d1feffcfe270ba06dbe699a3badf  objects/00000000000000000007.x2
e10828253f32547307ccb510f3edcfce3c3bda84760fa1e723a59dabc280e116  objects/21140b0bbf82c1274cd208bf63e2ade1f5c935e5d5aeb2db6fa22385f8e7feb8.seq
c4346fae6ee520d575391107cebbf0fe2d42263fb066492812f42526878f3510  objects/.state
```

`TestJournalLegacyLCX2FixtureRecovery` copies files into a private test directory
before opening them. Git does not preserve private mode bits. The test verifies
held recovery, exact PDU/metadata, sequence restoration and ID continuity after
purge; it never mutates the frozen fixtures.

The v1 format has no key ID, purpose distinction, journal UUID or authenticated
store identity. Those are limitations of the compatibility reader, not properties
that a new envelope should reproduce. A future version must dispatch explicitly
to this legacy decoder and the configured legacy raw key.
