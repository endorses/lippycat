# QUIC Initial experiment

This is the bounded workstream-6 feasibility spike, separate from production
capture, event schemas, logs and TUI. No production package imports it. See the
[decision report](../../docs/research/quic-initial-feasibility.md).

```bash
go test -race -tags all ./experiments/quicinitial/...
go run -tags all ./experiments/quicinitial/cmd/inspect \
  -dcid 8394c8f03e515708 \
  -hex-file experiments/quicinitial/testdata/rfc9001-client.hex
go run -tags all ./experiments/quicinitial/cmd/survey testdata/pcaps/demo-mixed.pcap
```

`Inspect` recognizes bounded v1/v2 long headers and coalescing. `NewSession`
derives v1 Initial keys from an explicitly supplied original client DCID. `Feed`
requires externally proven client/server direction and a single correlated
connection epoch. It removes AES header protection, reconstructs packet numbers,
checks GCM tags and reassembles CRYPTO offsets. Call `Close` after use; Session is
not concurrent. IP fragments, flow discovery, Retry validation/following, migration,
v2 decryption and production admission/expiry are outside this experiment.

Results own their data. `Reason` distinguishes complete visible ClientHello,
ECH outer-only visibility, incomplete CRYPTO, unsupported version/type/frame,
version negotiation, Retry, malformed input, authentication failure, conflicting
overlaps and resource limits. Server Initial plaintext can be recovered but is
not presented as a ClientHello. v2 shapes return `unsupported_version` from
decryption while retaining their recognized version/type. `PacketNumberLength`
is available only after successful unprotection/decryption, never inferred from
protected bits. Retry shape is observed without verifying its integrity tag.

The existing TLS parser supplies visible ClientHello fields and JA3. Its TCP-only
JA4 is cleared, as is its synthetic TLS record version: QUIC has no TLS record
layer. Transport parameters retain exact ID/value TLVs and availability, without
claiming exhaustive semantic validation. ECH presence gives no inner ClientHello
or application identity. Initial keys are public; tag verification does not
authenticate the sender or prove capture provenance.

Fixed experimental bounds: 65,535-byte UDP payload, 16 packets per datagram,
64 datagrams per Session, 256 non-padding frame operations per packet, 65,536
CRYPTO bytes per direction, 128 transport parameters/version entries, and
20-byte CIDs. Retained CRYPTO storage is 73,728 bytes per direction (payload plus
bitmap), allocated after authenticated framing. Caller results and crypto/runtime
overhead are additional. Large valid inputs can return `resource_limit`; these
choices are experiment bounds, not product performance acceptance targets.

The checked-in client/server ciphertext vectors come from RFC 9001 Appendix A;
their license is in [testdata/LICENSE](testdata/LICENSE). Tests also create a fresh
ClientHello with Go's QUIC TLS client API and controlled segmented datagrams.
There is no new module dependency and no vendored QUIC implementation.

The survey caps effective PCAP record admission at 128 KiB before the reader
can allocate a payload buffer. Larger declarations fail explicitly; a large global
snaplen still permits ordinary small records. Frame types require shortest varint
encoding; other QUIC varints may use longer legal representations.
