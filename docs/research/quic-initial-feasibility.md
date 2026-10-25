# QUIC Initial feasibility study

Date: 2026-10-25. Scope: umbrella workstream 6B and the selected
[TLS-roadmap spike](../plans/tls-fingerprinting-roadmap.md#phase-6-quic-initial-fingerprinting-spike).
The experiment lives in [`experiments/quicinitial`](../../experiments/quicinitial/README.md)
and has no production analysis hooks or public schema.

## Decision

Defer production integration while retaining this reproducible experiment. V1
Initial decryption and visible ClientHello recovery are feasible using existing
TLS parsing and the Go standard library. Reference vectors and a controlled Go
client establish correctness for the implemented slice. Available repository
traffic supplies no representative QUIC Initial corpus, so it cannot establish
deployment coverage, failure distribution, or production cost. No latency or
throughput threshold was adopted, and the observations below do not require an
optimization cycle.

A separately scoped production proposal should address connection/Retry tracking,
admission and expiry across sources, raw/event authority and transport integration,
transport-aware fingerprints, and representative capture evidence. Full HTTP/3,
application attribution and cross-layer coherence remain separate work.

## Supported implementation

| Area                 | Implemented evidence and limit                                                                                                |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Long headers         | v1 and v2 version/type mapping, CIDs, Initial tokens, declared lengths and bounded coalescing                                 |
| Other shapes         | Explicit version-negotiation, Retry, unknown-version and short-header-tail outcomes                                           |
| V1 packet protection | Client/server Initial HKDF-SHA256, AES header unprotection, packet-number reconstruction and AES-128-GCM tag verification     |
| CRYPTO               | Offset-based bounded reassembly across datagrams, identical retransmissions/overlaps, holes and conflicting-overlap rejection |
| Initial frames       | PADDING, PING, ACK/ACK_ECN, CRYPTO and transport CONNECTION_CLOSE framing; other frames explicitly unsupported                |
| TLS                  | Shared complete ClientHello parsing; owned recovered bytes, visible SNI/ALPN and extension/algorithm evidence                 |
| Transport parameters | Extension 57 TLVs with exact IDs/value hex, duplicate-ID/extension rejection, bounded count and explicit absence              |
| Visibility           | ECH outer-only reason; no inner hello, encrypted handshake/application or server-identity claim                               |
| V2                   | Header recognition only; decryption explicitly unsupported                                                                    |

The header, frame and parameter layouts follow
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html).
Initial keys use the original client's DCID and the v1 salt/labels; header
protection samples at the prescribed offset and the recovered packet number
forms the AEAD nonce. The independent published ciphertexts are from
[RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A).
V2 uses a different wire version and type mapping; recognizing those fields does
not implement its different cryptographic salt/labels.
[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)

`Session` requires one externally correlated connection epoch, original client
DCID and explicit direction. Retry is reported without integrity validation or
automatic key changes; post-Retry analysis requires a new context. IP reassembly,
CID discovery/migration, role inference and lifecycle admission are caller work.
The plaintext framing is validated before committing CRYPTO fragments. Failed
authentication cannot contribute handshake bytes. Initial key material is public,
so a valid tag does not authenticate a remote endpoint.

The shared parser's TCP-only JA4 result is deliberately cleared rather than
misreported as a QUIC fingerprint. Its synthetic record version is also cleared;
QUIC transports handshake bytes without TLS records. JA3 is retained as visible
ClientHello evidence. Parameter values are parsed, not exhaustively checked
against every semantic transport rule.

The existing production `QUICSignature` remains a heuristic detector. It does
not decrypt packets or reassemble CRYPTO, and its existing long-header labels use
the v1 mapping even for v2. The experimental parser handles the version-specific
mapping independently. Production detector correction/integration is not claimed
by this isolated spike.

## Reproduction and available coverage

Run from the repository root with the installed Go toolchain:

```bash
go test -race -tags all ./experiments/quicinitial/... -count=1
go test -tags all ./experiments/quicinitial \
  -run '^(TestRFC9001ClientAndServer|TestGoQUICClientHello)$' -v
go run -tags all ./experiments/quicinitial/cmd/inspect \
  -dcid 8394c8f03e515708 \
  -hex-file experiments/quicinitial/testdata/rfc9001-client.hex
go run -tags all ./experiments/quicinitial/cmd/survey testdata/pcaps/demo-mixed.pcap
go test -tags all ./experiments/quicinitial -run '^$' \
  -bench '^BenchmarkReferenceInitial$' -benchtime=1x -benchmem
```

| Input                            | Observed result                                                                                                                                                |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC client Initial               | 1,200-byte protected packet; packet number 2, four-byte encoding; recovered 241-byte ClientHello, `example.com`, ALPN `alpn`, and transport-parameter evidence |
| RFC server Initial               | 135-byte protected packet; packet number 1, two-byte encoding; ACK/CRYPTO decoded with server keys and explicitly no ClientHello result                        |
| Fresh Go QUIC TLS client         | Recovered 1,477-byte ClientHello with `quic-spike.example`, `h3`, and two explicit parameters after deliberately reversed two-fragment arrival                 |
| `testdata/pcaps/demo-mixed.pcap` | 1,800 packets, 315 UDP datagrams, zero supported-version long-header candidates                                                                                |

The RFC examples are checked-in redistributable ciphertext, with the IETF code
component license. Controlled packet construction complements those independent
vectors rather than replacing them. Go's TLS client generates fresh random/key
material, so the exact ClientHello bytes vary; its intended fields and recovered
byte parity are asserted. No private or representative real-world QUIC capture
was available. The demo's zero coverage is not a successful production corpus
evaluation.

Tests also cover every truncated prefix of the reference client packet, tampered
tags, malformed lengths/CIDs/ACK ranges, version/type cases, CRYPTO holes,
reordering, overlap conflicts, duplicate parameters, ECH indication, owned
snapshots, unsupported frames, packet-number wrap and every configured bound.
Fuzz seeds exercise the same bounded parser entry points. The inspection CLI
reads at most one bounded hex datagram; the survey streams classic PCAP records
and reports shapes without guessing decryption contexts. Its effective PCAP
record limit is 128 KiB, enforced before payload allocation even when the global
snaplen is large. Authenticated frames with non-minimal type encodings are rejected
before CRYPTO admission; non-minimal offset/length varints remain supported.

## Cost and resource observations

No dependency was added: packet protection uses standard-library HKDF, SHA-256,
AES and GCM; TLS metadata and PCAP reading reuse existing project facilities.
There is no vendored QUIC stack. The principal additional implementation burden
is lifecycle/correlation integration rather than the tested cryptographic slice.

Experimental bounds are 65,535 bytes per UDP payload, 16 packets per datagram,
64 datagrams per session, 256 non-padding frame operations per packet, 65,536
CRYPTO bytes per direction, 128 parameters/version entries and 20-byte CIDs.
Each retained direction uses 73,728 bytes for payload and presence bitmap; both
directions use 147,456 bytes, excluding cipher/runtime overhead and caller results.
`Close` releases retained state. Valid larger inputs return an explicit resource
limit instead of growing state. These bounds would require deployment-informed
policy and admission accounting before production integration.

One unprofiled single-operation benchmark on linux/amd64, Go
`go1.27.1-X:nodwarf5`, Intel i9-13900HX, GOMAXPROCS 32, `all` tags without race,
reported 36,572 ns/op, 95,464 B/op and 147 allocations for new context + RFC
client decryption/reassembly/parsing + close. It used checked-in bytes with
uncontrolled warm OS/runtime state. This is one exploratory observation,
not a throughput, tail latency, RSS or multi-connection measurement. No product
acceptance target or follow-up optimization obligation follows from it.

## Closure verification

The single bounded review found two P2 issues, both corrected: file-controlled
PCAP lengths could bypass the survey's intended bounded allocation, and CRYPTO
Frame Type accepted non-shortest varints. Regressions exercise oversized headers
without requesting payload bytes, ordinary records in max-snaplen captures, and
authenticated non-minimal frame types versus legal longer offset/length fields.
The final full experiment race suite and vet pass. A bounded two-second fuzz run
before these closure fixes passed 6,648 executions; no repeat performance or
corpus campaign was required. One integrated check resolved the fixed finding
list; no production capability is implied by closure of this experiment.
