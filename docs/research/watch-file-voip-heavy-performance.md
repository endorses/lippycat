# VoIP-heavy capture opening

The private `gtest6.pcap` capture exposed a call-tracking cost that the earlier
mixed-traffic capture did not exercise. Its baseline completed-open profile took
55.06 seconds and allocated approximately 61.1 GB while processing 316,382 logical
packets. The profile attributed 48.26 CPU seconds to `touchCallLocked`.

The final clean comparison measured **55.04 seconds for the original** and
**7.616 seconds median for the candidate** (three candidate runs), roughly a
sevenfold improvement. Allocation traffic fell from 61.1 GB to 5.96 GB.

## Cause and changes

For every newly tracked call, the TUI copied all active registry entries, inserted
the call, then looked up every previous entry to discover which one had been
evicted. At the 5,000-call bound, repeated insertions therefore copied and scanned
thousands of calls each time. The registry additionally scanned the entire LRU
list even when every unpinned call had the same eviction priority.

`Core.UpsertWithEviction` now reports the ID removed by its own mutation. The TUI
removes only that call's party information and RTP touch state. Existing `Upsert`
callers keep the same boolean API and observer ordering. With no custom eviction
priority, the registry stops at the first unpinned entry from the LRU end; custom
priorities retain their original scan and tie-breaking behavior.

The first candidate reduced completed opening to about 9.3 seconds. Its profile
then identified 2.18 CPU seconds in compact field splitting. Sparse metadata was
being decoded and re-encoded merely to find its two column boundaries after the
typed encoder had already validated and serialized it. The internal metadata
writer now supplies those boundaries directly. Generic callers still receive
full validation, and the exact persisted bytes remain unchanged.

## Measurements

Three alternating fresh-process comparisons measured the call-tracking-only
candidate at 9.335 seconds median and the combined candidate at 7.528 seconds.
The combined candidate was faster in every pair. Allocation traffic fell from
7.07 GB to 5.96 GB in that second step, following the much larger reduction from
61.1 GB achieved by fixing call tracking.

These measurements use the same input, default limits and Go runtime settings,
with a complete untimed input read before each process. They measure completed
analysis, not a controlled Wireshark GUI endpoint. The first unprofiled original
screening overlapped a brief test/build; separate final samples exclude competing
agent tests and builds and are recorded in the accompanying evidence.

A separate three-pair regression check on the earlier 323 MB mixed-traffic
capture measured 3.238 seconds original versus 3.169 seconds candidate median,
with identical counts and index size. Both remain around 3.2 seconds.

The completed index remains 314,252,031 bytes: 242,176,549 bytes of sparse metadata,
49,447,825 bytes of summaries, 20,248,480 bytes of directory entries, and a
33,814-byte manifest. Every run reports 316,382 logical packets and 2,500 arrived
events. This capture is not interchangeable with the earlier mixed-traffic input;
its metadata and call population produce very different work.

## Correctness and resource checks

The full private legacy-versus-compact oracle passed, comparing every normalized
record and metadata field, calls, normalized events, statistics, filter results,
and exports. Independent seeded tests compare the new eviction shortcut with the
unchanged full-scan algorithm over 4,500 mutations, including nested pins, shared
endpoints, observer ordering and snapshot-derived eviction identity. Tracker tests
verify evicted state cleanup and a constant number of existence probes at
capacities 1, 100 and 5,000.

Metadata tests compare bytes and exact errors across resource budgets, nil/empty
containers and protocol metadata. Explicit header checks prove both compressed
and uncompressed cases execute. Malformed generic input remains rejected.

Broad callregistry, offline, TUI and VoIP race tests and the complete build passed.
An isolated HEAD archive with only the nine changed implementation/test files
also passed its race tests and all-tag build. Preexisting working-tree edits are
excluded from this change. Insertion microbenchmarks were approximately 0.4
microseconds and 96 bytes per operation at both 100 and 5,000 active calls.

The registry retains its existing hard call/endpoint limits. The metadata change
uses the existing writer admission and cleanup paths. Process RSS and allocation
traffic are distinct measurements; removing the large repeated snapshots does
not imply a corresponding reduction in peak RSS.

## Remaining work

Opening is still above the user's few-second target. After the call-tracking fix,
the profile shows capture normalization/sorting, SIP decoding and metadata
construction as substantial remaining costs. The 242 MB metadata stream also
makes batching or more selective reconstruction worth investigating separately.
Those are future candidates, not verified savings or changes included here.

[Sanitized raw measurements and source identity](watch-file-voip-heavy-measurements.json)
record the conditions and results. Private packets, call IDs and profiles are
kept outside the repository.
