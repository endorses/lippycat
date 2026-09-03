# LI X3 call-attribution Phase 0 baseline

Recorded on 2026-09-03 after Phase 1's authoritative RTP resolver landed, but
before the remaining filter-inheritance, finalization, and PDU-version
refactoring. Historical v0.11.4 behavior is frozen separately by the synthetic
Phase 0 characterization tests. The inputs used by the relevant tests and
benchmarks are generated in memory; no production packet capture or real
subscriber identity was used.

## Environment

- Commit: `7626907b52a26d8acbec9fc3dfb7bbb326c5d646`
- Go: `go1.26.3-X:nodwarf5 linux/amd64`
- Host CPU: 13th Gen Intel(R) Core(TM) i9-13900HX, 32 logical CPUs
- Build tags: `all`, plus `li` for the LI manager benchmarks
- Benchmark duration: one second, three samples

These figures are a local comparison baseline, not a cross-machine performance
target.

## Existing behavior frozen by tests

The following command passed:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/processor/source ./internal/pkg/processor \
  ./internal/pkg/li/x2x3 \
  -run 'Test(LocalSourcePhase2_AssociatedCallIDUnionIsBounded|Phase9LatePacketAndGetOrCreateDuringFinalizationAreSuppressed|X2X3Correlation)' \
  -count=1 -v
```

Observed behavior:

- `TestLocalSourcePhase2_AssociatedCallIDUnionIsBounded` passed, confirming the
  current pre-Phase-2 source still supports collecting inherited filter IDs
  across associated Call-IDs.
- `TestPhase9LatePacketAndGetOrCreateDuringFinalizationAreSuppressed` passed,
  confirming that the PCAP manager rejects writes and writer creation after its
  own call-finalization boundary.
- No test named by the `X2X3Correlation` pattern existed in the selected package;
  the package reported `no tests to run` for that pattern.

The existing wire and correlation assertions also passed:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/li/x2x3 \
  -run 'Test(PDUHeader_MarshalBinary|X3Encoder_CorrelationID_MatchesX2WhenCallIDPresent)$' \
  -count=1 -v
```

`TestPDUHeader_MarshalBinary` asserts the current constants byte-for-byte. At
this baseline those constants encode version value 5 as major byte `0x05` and
minor byte `0x00`; the test therefore passes while preserving the erroneous
`05 00` wire representation that Phase 0's regression test must expose.
`TestX3Encoder_CorrelationID_MatchesX2WhenCallIDPresent` confirms that, once a
Call-ID is supplied, X3 hashes that Call-ID identically to X2. Consequently an
incorrectly stamped Call-ID also deterministically produces that wrong call's
correlation ID.

## Performance baseline

### Mixed local VoIP source

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/processor/source -run '^$' \
  -bench '^BenchmarkLocalSourceMixedVoIP$' -benchmem -benchtime=1s -count=3
```

| sample | ns/op | packets/s | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 4,251 | 235,246 | 1,885 | 27 |
| 2 | 4,024 | 248,484 | 1,885 | 27 |
| 3 | 4,273 | 234,037 | 1,885 | 27 |

The benchmark reported `0.0800 processor_identity_work/op` and
`0.0800 processor_matcher_calls/op` in every sample (rounded as printed).

### X3 encode and serialize

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/li/x2x3 \
  -run '^$' -bench '^BenchmarkX3Encoder_EncodeAndSerialize$' \
  -benchmem -benchtime=1s -count=3
```

| sample | ns/op | encoded bytes/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 505.4 | 252.0 | 864 | 12 |
| 2 | 517.2 | 252.0 | 864 | 12 |
| 3 | 525.9 | 252.0 | 864 | 12 |

### PCAP tombstone lookup

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/processor \
  -run '^$' -bench '^BenchmarkPcapWriterTombstoneLookup$' \
  -benchmem -benchtime=1s -count=3
```

| tombstones | ns/op samples | B/op | allocs/op |
| ---: | --- | ---: | ---: |
| 10 | 55.83, 56.22, 51.87 | 0 | 0 |
| 1,000 | 54.98, 55.60, 53.96 | 0 | 0 |
| 100,000 | 53.24, 49.66, 52.90 | 0 | 0 |

### LI manager packet selection

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags 'all li' ./internal/pkg/li \
  -run '^$' \
  -bench '^BenchmarkManager_ProcessPacket_(NoMatch|WithMatch|RTPStream)$' \
  -benchmem -benchtime=1s -count=3
```

The no-match path measured 1.625, 1.318, and 1.097 ns/op with zero allocations.
The one-match path measured 200.0, 200.4, and 197.7 ns/op, with 296 B/op and four
allocations/op. The command ultimately failed when it reached
`BenchmarkManager_ProcessPacket_RTPStream`: its IPv4-address/X2+X3 fixture is now
rejected by activation policy because the correlated raw-IP IRI/CC session model
is not implemented. This is an existing benchmark-fixture incompatibility and
means no trustworthy RTP-stream number is available from the pre-refactor suite.
