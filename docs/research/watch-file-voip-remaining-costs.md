# Remaining VoIP capture opening costs

## Scope and method

Follow-up to `7015120f` on the same Intel Core i9-13900HX, linux/amd64,
Go 1.26.3-X:nodwarf5 environment. Measurements use fresh benchmark processes,
warm input pages and completed compact-index readiness, including finalization.
They exclude terminal rendering and are not a direct Wireshark comparison.
Private packet contents are not included in this repository.

The baseline and candidates retain the same preexisting workspace changes.
An additional isolated HEAD checkout verifies that the scoped implementation
builds and passes capture/storage race tests independently of those changes.

## Profile and changes

The baseline profile measured 7.64 seconds elapsed and 15.37 sampled CPU seconds.
Nested CPU totals include 2.05 seconds in SIP decoding, 1.64 in generic compact
metadata encoding, and 1.10 in external sorting (0.83 in write syscalls during
merging). These overlap other totals and are not additive wall-clock savings.

Three changes target that work:

- Locator preparation skips terminal SIP application decoding for supported
  plain Ethernet/IP/TCP-or-UDP frames, including up to two VLAN tags. A cheap
  protocol/port precheck avoids duplicate header decoding for other traffic and
  honors the current decoder registry and destination-port precedence. Full replay
  and public cursor decoding remain intact. Fragments, tunnels, malformed
  transport headers and unsupported layouts use the existing decoder.
- VoIP-only metadata overrides use a typed encoder with the exact frozen wire
  schema. Generic encoding still handles mixed metadata and containers; the
  complete owned-memory admission check remains in place.
- External sort output uses an optional, accounted 16 KiB write buffer rather
  than issuing a syscall for every 192-byte key. Writes still reserve disk space
  before buffering. Each pass flushes before reading, and tight memory budgets
  fall back to unbuffered writes.

## Component measurements before the non-SIP precheck

Three interleaved fresh-process runs per candidate, with reversed order in the
middle round; no concurrent tests or builds. All runs produced 316,382 packets,
2,500 retained events and an identical completed index size of 314,252,031 bytes.

| Candidate | Readiness samples (seconds) | Median |
|---|---|---|
| Baseline | 7.590, 7.429, 7.500 | 7.500 |
| Scan shortcut | 6.207, 6.476, 6.309 | 6.309 |
| Typed VoIP encoding | 7.251, 7.426, 7.130 | 7.251 |
| Scan + typed encoding | 5.998, 6.168, 6.755 | 6.168 |
| All three | 5.573, 5.288, 5.685 | 5.573 |

The combined median improves by 25.7%. Allocation volume falls from about
5.96 GB to 4.26 GB per open, and allocations from 105.26 million to 77.62 million.
Peak process RSS remains approximately 200–210 MiB. The typed encoder's gain is
modest relative to timing variation; avoiding duplicate decoding and buffering
sort output provide the larger improvements.

## Correctness and resource verification

Both private captures passed `TestOfflineCompactIndexerPrivateOracle` again on
the final version with the precheck: comparison
against the legacy backend checks every logical record, raw bytes, metadata and
summary projection, nine query cases, PCAP exports, statistics, events and calls.

The capture/offline/TUI/callregistry/VoIP race suites passed. New tests cover
scan fallback and normalized replay, public cursor behavior, exact typed-encoder
parity over fields and budgets, and buffered-sort disk admission and fallback.
An independent reviewer found no additional issues; an isolated HEAD archive with
only the nine scoped code/test files passed capture/offline race tests and an
all-tag build. `make build` rebuilt `./lc` successfully in the working tree.

These improvements preserve full completed-open semantics and do not defer
required analysis until after readiness. The roughly three-second target for
the VoIP capture remains unmet; these results also do not establish a language
performance ceiling or a controlled comparison with Wireshark.

The first mixed-capture check exposed a 4% regression (3.011 to 3.131 seconds)
from probing and resetting the decoder for ordinary traffic. The final version
adds the protocol/port precheck before those operations. Focused race tests cover
runtime SIP port registration and destination-before-source precedence; the
ordinary-TCP microbenchmark measured about 4.5 ns extra for the precheck.

## Final paired measurements

After adding the precheck, three fresh-process pairs per capture produced:

| Capture | Baseline samples (seconds) | Final samples (seconds) | Median change |
|---|---|---|---|
| VoIP (`gtest6.pcap`) | 7.683, 7.643, 7.609 | 5.398, 5.538, 5.313 | 7.643 → 5.398 (29.4% faster) |
| Mixed traffic | 3.060, 3.139, 3.106 | 3.124, 3.144, 3.156 | 3.106 → 3.144 (1.2% slower) |

The small residual mixed-traffic overhead is reported rather than claimed as a
win: it is 38 ms in the median, with overlapping ranges in this small sample.
The ordinary-traffic precheck still has a small nonzero cost. VoIP allocation
volume remains approximately 4.26 GB versus 5.96 GB, with no material peak-RSS
reduction. Mixed traffic still produces 579,990 packets, 44,873 retained events
and an 89,246,448-byte completed index.

Raw timings, allocation counts, peak process RSS, capture hashes and the
preexisting tracked-workspace patch hash are in
[the measurements JSON](watch-file-voip-remaining-costs-measurements.json).
