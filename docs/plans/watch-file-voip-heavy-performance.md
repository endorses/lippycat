# VoIP-heavy capture opening performance

Investigate the reported roughly 51-second opening of `gtest6.pcap`. Preserve
protocol analysis, call state, source integrity and bounded storage. Keep existing
uncommitted work separate.

- [x] Reproduce the slow completed-open path and identify its dominant cost with a CPU profile.
- [x] Implement only evidence-backed improvements and compare fresh-process measurements.
- [x] Verify record, metadata, call, query and export parity, resource behavior, and relevant race tests.
- [x] Check the previous mixed-traffic capture for regression, rebuild, and document results.

Commit the verified implementation and updated plan together with sanitized
measurement evidence. Keep private capture contents and profiles out of Git.

Outcome: clean original sample 55.04 s; final three-run candidate median 7.616 s.
Allocations fell from 61.1 GB to 5.96 GB; the index remains 314,252,031 bytes.
The previous capture remains around 3.2 s. Full private oracle, broad race tests,
isolated integration and build passed; preexisting edits remain unchanged.
The few-second goal for this VoIP capture is still not met. See
[results](../research/watch-file-voip-heavy-performance.md) and
[measurements](../research/watch-file-voip-heavy-measurements.json).
